// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use fastcrypto::serde_helpers::ToFromByteArray;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::onchain::types::DepositRequest;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use crate::withdrawals::WithdrawalTxSigning;
use hashi_types::bitcoin_txid::BitcoinTxid;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use hashi_types::proto::SignGuardianWithdrawalRequestRequest;
use hashi_types::proto::SignGuardianWithdrawalRequestResponse;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalConfirmationResponse;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalRequestApprovalResponse;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTransactionResponse;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionResponse;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use hashi_types::proto::SignWithdrawalTxSigningResponse;
use hashi_types::proto::bridge_service_server::BridgeService;
use sui_sdk_types::Address;

use super::HttpService;

#[tonic::async_trait]
impl BridgeService for HttpService {
    /// Query the service for general information about its current state.
    async fn get_service_info(
        &self,
        _request: Request<GetServiceInfoRequest>,
    ) -> Result<Response<GetServiceInfoResponse>, Status> {
        Ok(Response::new(GetServiceInfoResponse::default()))
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
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
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
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
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

    /// Validate and BLS-sign a `StandardWithdrawalRequest` for the guardian.
    ///
    /// Each validator independently reconstructs the request from on-chain
    /// `WithdrawalTransaction` data plus the leader-provided `timestamp_secs` and
    /// `seq`, then signs it. The leader aggregates these into a committee
    /// certificate and forwards it to the guardian before MPC signing.
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
    ) -> Result<Response<SignWithdrawalTransactionResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        tracing::Span::current().record("caller", tracing::field::display(&caller));
        let withdrawal_txn_id = Address::from_bytes(&request.get_ref().withdrawal_txn_id)
            .map_err(|e| Status::invalid_argument(format!("invalid withdrawal_txn_id: {e}")))?;
        tracing::Span::current().record(
            "withdrawal_txn_id",
            tracing::field::display(&withdrawal_txn_id),
        );
        tracing::info!("sign_withdrawal_transaction called");
        let signatures = self
            .inner
            .validate_and_sign_withdrawal_tx(&withdrawal_txn_id)
            .await
            .map_err(|e| {
                tracing::error!("sign_withdrawal_transaction failed: {e}");
                Status::failed_precondition(e.to_string())
            })?;
        tracing::info!("sign_withdrawal_transaction succeeded");
        Ok(Response::new(SignWithdrawalTransactionResponse {
            signatures_by_input: signatures
                .iter()
                .map(|sig| sig.to_byte_array().to_vec().into())
                .collect(),
        }))
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
        let message = parse_withdrawal_tx_signing(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        tracing::Span::current().record(
            "withdrawal_id",
            tracing::field::display(&message.withdrawal_id),
        );
        let member_signature = self
            .inner
            .validate_and_sign_withdrawal_tx_signing(&message)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!("Signed withdrawal tx signing");
        Ok(Response::new(SignWithdrawalTxSigningResponse {
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
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        tracing::info!("Signed withdrawal confirmation");
        Ok(Response::new(SignWithdrawalConfirmationResponse {
            member_signature: Some(member_signature),
        }))
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
        timestamp_ms: request.timestamp_ms,
        sui_tx_digest,
        utxo: Utxo {
            id: UtxoId {
                txid,
                vout: request.vout,
            },
            amount: request.amount,
            derivation_path,
        },
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
    let request_ids: Vec<Address> = request
        .request_ids
        .iter()
        .map(|bytes| parse_address(bytes))
        .collect::<anyhow::Result<_>>()?;
    let signatures: Vec<Vec<u8>> = request
        .signatures
        .iter()
        .map(|bytes| bytes.to_vec())
        .collect();
    Ok(WithdrawalTxSigning {
        withdrawal_id,
        request_ids,
        signatures,
    })
}

fn parse_address(bytes: &[u8]) -> anyhow::Result<sui_sdk_types::Address> {
    sui_sdk_types::Address::from_bytes(bytes).context("invalid address")
}
