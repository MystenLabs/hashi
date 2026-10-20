// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Instrument;

use crate::deposits::UnapprovedDepositError;
use crate::metrics::SIGNING_REFUSAL_BUSY;
use crate::metrics::SIGNING_REFUSAL_CAP;
use crate::metrics::SIGNING_REFUSAL_COMMITTEE;
use crate::metrics::SIGNING_REFUSAL_SHAPE;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::withdrawals::MalformedSigningRequest;
use crate::withdrawals::MpcInputSignaturesMessage;
use crate::withdrawals::WithdrawalAlreadyFinalized;
use crate::withdrawals::WithdrawalApprovalError;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use crate::withdrawals::WithdrawalTxSigning;
use hashi_types::bitcoin_txid::BitcoinTxid;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::SignCommitteeTransitionRequest;
use hashi_types::proto::SignCommitteeTransitionResponse;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use hashi_types::proto::SignGuardianWithdrawalRequestRequest;
use hashi_types::proto::SignGuardianWithdrawalRequestResponse;
use hashi_types::proto::SignMpcInputSignaturesRequest;
use hashi_types::proto::SignMpcInputSignaturesResponse;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalConfirmationResponse;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalRequestApprovalResponse;
use hashi_types::proto::SignWithdrawalTransactionPartial;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionResponse;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use hashi_types::proto::SignWithdrawalTxSigningResponse;
use hashi_types::proto::bridge_service_server::BridgeService;
use sui_sdk_types::Address;

use super::HttpService;
use super::peer_limit::CallerTaskSlot;
use super::peer_limit::SigningPlace;

#[tonic::async_trait]
impl BridgeService for HttpService {
    type SignWithdrawalTransactionStream =
        tokio_stream::wrappers::ReceiverStream<Result<SignWithdrawalTransactionPartial, Status>>;

    /// Query the service for general information about its current state.
    async fn get_service_info(
        &self,
        _request: Request<GetServiceInfoRequest>,
    ) -> Result<Response<GetServiceInfoResponse>, Status> {
        Ok(Response::new(GetServiceInfoResponse {
            server: Some(self.inner.server_version.to_string()),
            ..Default::default()
        }))
    }

    /// Validate and sign a confirmation of a bitcoin deposit request.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(deposit_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_deposit_confirmation(
        &self,
        request: Request<SignDepositConfirmationRequest>,
    ) -> Result<Response<SignDepositConfirmationResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let deposit_request = parse_deposit_request(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        tracing::Span::current().record("deposit_id", tracing::field::display(&deposit_request.id));
        let member_signature = self
            .inner
            .validate_and_sign_deposit_confirmation(&deposit_request)
            .await
            .map_err(deposit_refusal_status)?;
        tracing::info!(
            utxo_txid = %deposit_request.utxo.id.txid,
            utxo_vout = deposit_request.utxo.id.vout,
            amount = deposit_request.utxo.amount,
            "Signed deposit confirmation",
        );
        Ok(Response::new(SignDepositConfirmationResponse {
            member_signature: Some(member_signature),
        }))
    }

    /// Step 1: Validate and sign approval for a batch of unapproved withdrawal requests.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(request_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_withdrawal_request_approval(
        &self,
        request: Request<SignWithdrawalRequestApprovalRequest>,
    ) -> Result<Response<SignWithdrawalRequestApprovalResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let approval = parse_withdrawal_request_approval(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        tracing::Span::current()
            .record("request_id", tracing::field::display(&approval.request_id));
        let member_signature = self
            .inner
            .validate_and_sign_withdrawal_request_approval(&approval)
            .await
            .map_err(withdrawal_approval_refusal_status)?;
        tracing::info!("Signed withdrawal request approval");
        Ok(Response::new(SignWithdrawalRequestApprovalResponse {
            member_signature: Some(member_signature),
        }))
    }

    /// Step 2: Validate and sign a proposed withdrawal transaction construction.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(bitcoin_txid = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_withdrawal_tx_construction(
        &self,
        request: Request<SignWithdrawalTxConstructionRequest>,
    ) -> Result<Response<SignWithdrawalTxConstructionResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let approval = parse_withdrawal_tx_commitment(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        tracing::Span::current().record("bitcoin_txid", tracing::field::display(&approval.txid));
        let member_signature = self
            .inner
            .validate_and_sign_withdrawal_tx_commitment(&approval)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!(
            requests = approval.request_ids.len(),
            "Signed withdrawal tx construction",
        );
        Ok(Response::new(SignWithdrawalTxConstructionResponse {
            member_signature: Some(member_signature),
        }))
    }

    /// Validate and BLS-sign a `CommitteeTransitionRequest` for the guardian.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(from_epoch = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_committee_transition(
        &self,
        request: Request<SignCommitteeTransitionRequest>,
    ) -> Result<Response<SignCommitteeTransitionResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let from_epoch = request.get_ref().from_epoch;
        tracing::Span::current().record("from_epoch", from_epoch);
        let member_signature = self
            .inner
            .validate_and_sign_committee_transition(from_epoch, caller)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!(from_epoch, "Signed committee transition");
        Ok(Response::new(SignCommitteeTransitionResponse {
            member_signature: Some(member_signature),
        }))
    }

    /// Validate and BLS-sign a `StandardWithdrawalRequest` for the guardian.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_txn_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_guardian_withdrawal_request(
        &self,
        request: Request<SignGuardianWithdrawalRequestRequest>,
    ) -> Result<Response<SignGuardianWithdrawalRequestResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let req = request.get_ref();
        let withdrawal_txn_id = Address::from_bytes(&req.withdrawal_txn_id)
            .map_err(|e| Status::invalid_argument(format!("invalid withdrawal_txn_id: {e}")))?;
        tracing::Span::current().record(
            "withdrawal_txn_id",
            tracing::field::display(&withdrawal_txn_id),
        );
        let member_signature = self
            .inner
            .validate_and_sign_guardian_withdrawal_request(
                &withdrawal_txn_id,
                req.timestamp_secs,
                req.seq,
            )
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!(
            seq = req.seq,
            timestamp_secs = req.timestamp_secs,
            "Signed guardian withdrawal request",
        );
        Ok(Response::new(SignGuardianWithdrawalRequestResponse {
            member_signature: Some(member_signature),
        }))
    }

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_txn_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_withdrawal_transaction(
        &self,
        request: Request<SignWithdrawalTransactionRequest>,
    ) -> Result<Response<Self::SignWithdrawalTransactionStream>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let member = self.admit_committee_member(caller)?;
        let req = request.get_ref();
        let withdrawal_txn_id = Address::from_bytes(&req.withdrawal_txn_id).map_err(|e| {
            self.malformed_request(caller, format!("invalid withdrawal_txn_id: {e}"))
        })?;
        tracing::Span::current().record(
            "withdrawal_txn_id",
            tracing::field::display(&withdrawal_txn_id),
        );
        self.inner
            .check_withdrawal_signing_request(&withdrawal_txn_id, &req.input_indices)
            .inspect_err(|e| {
                if !e.is::<MalformedSigningRequest>() {
                    tracing::error!("sign_withdrawal_transaction failed: {e}");
                }
            })
            .map_err(|e| self.signing_refusal(caller, e))?;
        let slot = self.admit_withdrawal_signing(&member)?;
        let place = self.take_signing_place(&member)?;
        let requested_input_indices = req.input_indices.clone();
        tracing::info!("sign_withdrawal_transaction called");
        let concurrency = self.inner.config.withdrawal_signing_concurrency();
        let (tx, rx) = tokio::sync::mpsc::channel(concurrency);
        let inner = self.inner.clone();
        let work_seconds = self.work_seconds(caller);
        tokio::spawn(
            async move {
                let _slot = slot;
                let gate = place.run_gate(work_seconds.clone());
                let run = tokio::select! {
                    biased;
                    () = tx.closed() => return,
                    run = place.run() => run,
                };
                let job_inner = inner.clone();
                let (signing, place) = run
                    .run_blocking(work_seconds, move || {
                        job_inner
                            .prepare_withdrawal_signing(
                                &withdrawal_txn_id,
                                &requested_input_indices,
                            )
                            .map(|prepared| job_inner.sign_withdrawal_locally(prepared))
                    })
                    .await;
                drop(place);
                let signed = match signing {
                    Ok(signing) => {
                        inner
                            .mpc_sign_withdrawal_tx(signing, &gate, tx.clone())
                            .await
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = signed {
                    tracing::error!("sign_withdrawal_transaction failed: {e}");
                    let _ = tx
                        .send(Err(Status::failed_precondition(e.to_string())))
                        .await;
                }
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Step 3: Validate and sign the BLS certificate over witness signatures.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_withdrawal_tx_signing(
        &self,
        request: Request<SignWithdrawalTxSigningRequest>,
    ) -> Result<Response<SignWithdrawalTxSigningResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let member = self.admit_committee_member(caller)?;
        let req = request.get_ref();
        let expected_limiter_seq = req.expected_limiter_seq;
        let timestamp_secs = req.timestamp_secs;
        let message =
            parse_withdrawal_tx_signing(req).map_err(|e| self.malformed_request(caller, e))?;
        tracing::Span::current().record(
            "withdrawal_id",
            tracing::field::display(&message.withdrawal_id),
        );
        self.inner
            .check_withdrawal_tx_signing_request(&message)
            .map_err(|e| self.signing_refusal(caller, e))?;
        let run = self.take_signing_place(&member)?.run().await;
        let inner = self.inner.clone();
        let (verified, _place) = run
            .run_blocking(self.work_seconds(caller), move || {
                inner.verify_withdrawal_tx_signing(message, expected_limiter_seq, timestamp_secs)
            })
            .await;
        let verified = verified.map_err(|e| self.signing_refusal(caller, e))?;
        let member_signature = self
            .inner
            .sign_verified_withdrawal_tx_signing(verified)
            .await
            .map_err(|e| self.signing_refusal(caller, e))?;
        tracing::info!("Signed withdrawal tx signing");
        Ok(Response::new(SignWithdrawalTxSigningResponse {
            member_signature: Some(member_signature),
        }))
    }

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_mpc_input_signatures(
        &self,
        request: Request<SignMpcInputSignaturesRequest>,
    ) -> Result<Response<SignMpcInputSignaturesResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let member = self.admit_committee_member(caller)?;
        let message = parse_mpc_input_signatures(request.get_ref())
            .map_err(|e| self.malformed_request(caller, e))?;
        tracing::Span::current().record(
            "withdrawal_id",
            tracing::field::display(&message.withdrawal_id),
        );
        self.inner
            .check_mpc_input_signatures_request(&message)
            .map_err(|e| self.signing_refusal(caller, e))?;
        let run = self.take_signing_place(&member)?.run().await;
        let inner = self.inner.clone();
        let (member_signature, _place) = run
            .run_blocking(self.work_seconds(caller), move || {
                inner.validate_and_sign_mpc_input_signatures(&message)
            })
            .await;
        let member_signature = member_signature.map_err(|e| self.signing_refusal(caller, e))?;
        tracing::info!("Signed MPC input signatures chunk");
        Ok(Response::new(SignMpcInputSignaturesResponse {
            member_signature: Some(member_signature),
        }))
    }

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_txn_id = tracing::field::Empty, caller = tracing::field::Empty),
    )]
    async fn sign_withdrawal_confirmation(
        &self,
        request: Request<SignWithdrawalConfirmationRequest>,
    ) -> Result<Response<SignWithdrawalConfirmationResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let withdrawal_txn_id = Address::from_bytes(&request.get_ref().withdrawal_txn_id)
            .map_err(|e| Status::invalid_argument(format!("invalid withdrawal_txn_id: {e}")))?;
        tracing::Span::current().record(
            "withdrawal_txn_id",
            tracing::field::display(&withdrawal_txn_id),
        );
        let member_signature = self
            .inner
            .sign_withdrawal_confirmation(&withdrawal_txn_id)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!("Signed withdrawal confirmation");
        Ok(Response::new(SignWithdrawalConfirmationResponse {
            member_signature: Some(member_signature),
        }))
    }
}

const SIGNING_TASK_LIMIT_MSG: &str = "per-caller withdrawal signing limit reached";
const SIGNING_BUSY_MSG: &str = "per-caller withdrawal signing queue is full";

struct Member(Address);

impl HttpService {
    fn count_signing_refusal(&self, caller: Address, reason: &str) {
        self.inner
            .metrics
            .withdrawal_signing_refused_total
            .with_label_values(&[caller.to_string().as_str(), reason])
            .inc();
    }

    fn admit_committee_member(&self, caller: Address) -> Result<Member, Status> {
        let refusal = {
            let state = self.inner.onchain_state().state();
            let committees = &state.hashi().committees;
            let epoch = committees.epoch();
            match committees.current_committee() {
                Some(committee) if committee.index_of(&caller).is_some() => {
                    return Ok(Member(caller));
                }
                Some(_) => format!("caller is not in the epoch {epoch} committee"),
                None => format!("this node does not know the epoch {epoch} committee"),
            }
        };
        self.count_signing_refusal(caller, SIGNING_REFUSAL_COMMITTEE);
        Err(Status::permission_denied(refusal))
    }

    fn admit_withdrawal_signing(&self, member: &Member) -> Result<CallerTaskSlot, Status> {
        let limit = self.inner.config.withdrawal_signing_per_caller_limit();
        self.signing_tasks
            .try_admit(member.0, limit)
            .ok_or_else(|| {
                self.count_signing_refusal(member.0, SIGNING_REFUSAL_CAP);
                Status::unavailable(SIGNING_TASK_LIMIT_MSG)
            })
    }

    fn take_signing_place(&self, member: &Member) -> Result<SigningPlace, Status> {
        self.signing_work.try_take_place(member.0).ok_or_else(|| {
            self.count_signing_refusal(member.0, SIGNING_REFUSAL_BUSY);
            Status::unavailable(SIGNING_BUSY_MSG)
        })
    }

    fn work_seconds(&self, caller: Address) -> prometheus::Counter {
        self.inner
            .metrics
            .peer_bridge_work_seconds_total
            .with_label_values(&[caller.to_string().as_str()])
    }

    fn malformed_request(&self, caller: Address, err: impl std::fmt::Display) -> Status {
        self.count_signing_refusal(caller, SIGNING_REFUSAL_SHAPE);
        Status::invalid_argument(err.to_string())
    }

    fn signing_refusal(&self, caller: Address, err: anyhow::Error) -> Status {
        if err.is::<MalformedSigningRequest>() {
            self.count_signing_refusal(caller, SIGNING_REFUSAL_SHAPE);
        }
        withdrawal_signing_refusal_status(err)
    }
}

/// All a peer learns when this node's sanctions check has not approved a request:
/// its details are the operator's own.
pub(crate) const SANCTIONS_CHECK_REFUSAL_MSG: &str =
    "Sanctions check has not approved this request";

/// `AlreadyExists` tells the leader another leader already landed this epoch's
/// approval, so it can drop the deposit instead of retrying it.
pub(crate) fn deposit_refusal_status(err: UnapprovedDepositError) -> Status {
    match err {
        UnapprovedDepositError::AlreadyApprovedThisEpoch => Status::already_exists(err.to_string()),
        UnapprovedDepositError::AmlRejected(_) | UnapprovedDepositError::AmlServiceError(_) => {
            Status::failed_precondition(SANCTIONS_CHECK_REFUSAL_MSG)
        }
        err => Status::failed_precondition(err.to_string()),
    }
}

/// `AlreadyExists` tells the leader the request is already approved or
/// committed, so it can stop collecting signatures for it.
pub(crate) fn withdrawal_approval_refusal_status(err: WithdrawalApprovalError) -> Status {
    match err {
        WithdrawalApprovalError::AlreadyApproved(_) => Status::already_exists(err.to_string()),
        WithdrawalApprovalError::SanctionsCheckRejected(_)
        | WithdrawalApprovalError::AmlServiceError(_) => {
            Status::failed_precondition(SANCTIONS_CHECK_REFUSAL_MSG)
        }
        WithdrawalApprovalError::NeverRetry(_) => Status::failed_precondition(err.to_string()),
    }
}

/// `AlreadyExists` tells the leader the withdrawal is already finalized, so it
/// can stop collecting signatures for it.
pub(crate) fn withdrawal_signing_refusal_status(err: anyhow::Error) -> Status {
    if err.is::<WithdrawalAlreadyFinalized>() {
        Status::already_exists(err.to_string())
    } else {
        Status::failed_precondition(err.to_string())
    }
}

fn authenticate_caller<T>(request: &Request<T>) -> Result<Address, Status> {
    request
        .extensions()
        .get::<Address>()
        .copied()
        .ok_or_else(|| Status::permission_denied("unknown validator"))
}

fn parse_deposit_request(
    request: &SignDepositConfirmationRequest,
) -> anyhow::Result<DepositRequest> {
    let id = parse_address(&request.id)?;
    let txid = parse_address(&request.txid)?.into();
    let derivation_path = request
        .derivation_path
        .as_ref()
        .map(|bytes| parse_address(bytes))
        .transpose()?;
    let requester_address = parse_address(&request.requester_address)?;
    let sui_tx_digest = sui_sdk_types::Digest::new(
        request
            .sui_tx_digest
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("sui_tx_digest must be 32 bytes"))?,
    );

    Ok(DepositRequest {
        id,
        sender: requester_address,
        created_timestamp_ms: request.timestamp_ms,
        sui_tx_digest,
        utxo: Utxo {
            id: UtxoId {
                txid,
                vout: request.vout,
            },
            amount: request.amount,
            derivation_path,
        },
        // Approval state isn't carried by the proto. Validators look up
        // the on-chain version separately when verifying.
        approval_cert: None,
        approved_timestamp_ms: None,
        confirmed_timestamp_ms: None,
    })
}

fn parse_withdrawal_request_approval(
    request: &SignWithdrawalRequestApprovalRequest,
) -> anyhow::Result<WithdrawalRequestApproval> {
    let request_id = parse_address(&request.request_id)?;
    Ok(WithdrawalRequestApproval { request_id })
}

fn parse_withdrawal_tx_commitment(
    request: &SignWithdrawalTxConstructionRequest,
) -> anyhow::Result<WithdrawalTxCommitment> {
    let request_ids: Vec<Address> = request
        .request_ids
        .iter()
        .map(|bytes| parse_address(bytes))
        .collect::<anyhow::Result<_>>()?;
    let selected_utxos: Vec<UtxoId> = request
        .selected_utxos
        .iter()
        .map(|utxo_id| {
            let txid: BitcoinTxid = utxo_id
                .txid
                .as_ref()
                .map(|bytes| parse_address(bytes))
                .context("missing utxo txid")??
                .into();
            let vout = utxo_id.vout.context("missing utxo vout")?;
            Ok(UtxoId { txid, vout })
        })
        .collect::<anyhow::Result<_>>()?;
    let outputs = request
        .outputs
        .iter()
        .map(|output| OutputUtxo {
            amount: output.amount,
            bitcoin_address: output.bitcoin_address.to_vec(),
        })
        .collect();
    let txid = parse_address(&request.txid)?.into();

    Ok(WithdrawalTxCommitment {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    })
}

fn parse_withdrawal_tx_signing(
    request: &SignWithdrawalTxSigningRequest,
) -> anyhow::Result<WithdrawalTxSigning> {
    let withdrawal_id = parse_address(&request.withdrawal_id)?;
    let signatures: Vec<Vec<u8>> = request
        .signatures
        .iter()
        .map(|bytes| bytes.to_vec())
        .collect();
    let guardian_signatures: Vec<Vec<u8>> = request
        .guardian_signatures
        .iter()
        .map(|bytes| bytes.to_vec())
        .collect();
    Ok(WithdrawalTxSigning {
        withdrawal_id,
        signatures,
        guardian_signatures,
    })
}

fn parse_mpc_input_signatures(
    request: &SignMpcInputSignaturesRequest,
) -> anyhow::Result<MpcInputSignaturesMessage> {
    let withdrawal_id = parse_address(&request.withdrawal_id)?;
    let indices = request.indices.clone();
    let signatures: Vec<Vec<u8>> = request
        .signatures
        .iter()
        .map(|bytes| bytes.to_vec())
        .collect();
    Ok(MpcInputSignaturesMessage {
        withdrawal_id,
        indices,
        signatures,
    })
}

fn parse_address(bytes: &[u8]) -> anyhow::Result<sui_sdk_types::Address> {
    sui_sdk_types::Address::from_bytes(bytes).context("invalid address")
}
