// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::caller_membership;
use super::gates;
use crate::grpc::HttpService;
use crate::metrics::STORED_ROW_SERVE;
use crate::mpc::PreparedMessages;
use crate::mpc::RetrieveOutcome;
use crate::mpc::RetrieveReply;
use crate::mpc::finish_avid_retrieval;
use crate::mpc::retrieve_from_store;
use crate::mpc::spawn_blocking;
use crate::mpc::types;
use crate::mpc::types::MpcError;
use crate::mpc::types::SigningError;
use hashi_types::proto::ComplainRequest;
use hashi_types::proto::ComplainResponse;
use hashi_types::proto::GetPartialSignaturesRequest;
use hashi_types::proto::GetPartialSignaturesResponse;
use hashi_types::proto::GetPresigDealerSetSignatureRequest;
use hashi_types::proto::GetPresigDealerSetSignatureResponse;
use hashi_types::proto::GetPublicMpcOutputRequest;
use hashi_types::proto::GetPublicMpcOutputResponse;
use hashi_types::proto::GetReconfigCompletionSignatureRequest;
use hashi_types::proto::GetReconfigCompletionSignatureResponse;
use hashi_types::proto::RetrieveMessagesRequest;
use hashi_types::proto::RetrieveMessagesResponse;
use hashi_types::proto::SendMessagesRequest;
use hashi_types::proto::SendMessagesResponse;
use hashi_types::proto::mpc_service_server::MpcService;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use sui_sdk_types::Address;
use tonic::Status;

/// Concurrent store reads per requester.
const STORE_READ_PERMITS: usize = 4;

#[tonic::async_trait]
impl MpcService for HttpService {
    #[tracing::instrument(skip(self, request))]
    async fn send_messages(
        &self,
        request: tonic::Request<SendMessagesRequest>,
    ) -> Result<tonic::Response<SendMessagesResponse>, Status> {
        let sender = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let mpc_manager = self.mpc_manager()?;
        let service = self.clone();
        let process_duration = self
            .metrics()
            .mpc_rpc_handler_process_duration_seconds
            .clone();
        let rotation_received = self.metrics().mpc_rotation_messages_received_total.clone();
        let refusals = self.metrics().refusal_counters();
        let response = spawn_blocking(move || -> Result<_, Status> {
            let shape = service.shape_params()?;
            let epoch = external_request.epoch;
            validate_epoch(shape.epoch(), epoch)?;
            gates::check_send_messages(&shape, sender, &external_request).map_err(|e| {
                if matches!(e, MpcError::CountCheckRefused { .. }) {
                    refusals.request(
                        &sender,
                        "send_messages",
                        send_messages_protocol(&external_request),
                    );
                }
                send_messages_error(sender, e)
            })?;
            let internal_request = types::SendMessagesRequest::try_from(&external_request)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
            if let Some(wire_shape) = rotation_wire_shape(&external_request) {
                rotation_received.with_label_values(&[wire_shape]).inc();
                if wire_shape == "map" && shape.current().rotation_messages_bcs() {
                    tracing::warn!(
                        "send_messages from {sender:?}: epoch {} rotation messages arrived as a \
                         proto map, but the epoch's committee selects one BCS blob",
                        shape.epoch()
                    );
                }
            }
            drop(external_request);
            let prepared = PreparedMessages::new(internal_request.messages);
            let label = match &prepared {
                PreparedMessages::Dkg(_) => crate::metrics::MPC_LABEL_DKG,
                PreparedMessages::Rotation(_) => crate::metrics::MPC_LABEL_KEY_ROTATION,
                PreparedMessages::NonceGenerationAvid(_) | PreparedMessages::AvidNonceRetrieval => {
                    crate::metrics::MPC_LABEL_NONCE_GENERATION
                }
            };
            let _timer = process_duration.with_label_values(&[label]).start_timer();
            let signed = {
                let mut mgr = mpc_manager.write().unwrap();
                validate_epoch(mgr.mpc_config.epoch, epoch)?;
                mgr.handle_prepared_messages(sender, prepared)
                    .map_err(|e| send_messages_error(sender, e))?
            };
            Ok(SendMessagesResponse::from(&signed))
        })
        .await?;
        Ok(tonic::Response::new(response))
    }

    #[tracing::instrument(skip(self, request))]
    async fn retrieve_messages(
        &self,
        request: tonic::Request<RetrieveMessagesRequest>,
    ) -> Result<tonic::Response<RetrieveMessagesResponse>, Status> {
        let requester = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::RetrieveMessagesRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mpc_manager = self.mpc_manager()?;
        let refused = self.metrics().mpc_rpc_caller_refused_total.clone();
        let store_reads = self.store_reads();
        let store_reads_shed = self.metrics().peer_store_reads_shed_total.clone();
        let stored_rows = self.metrics().stored_row_refusals();
        let abandoned = Arc::new(AtomicBool::new(false));
        let _abandon_on_drop = SetOnDrop(Arc::clone(&abandoned));
        let response = spawn_blocking(move || -> Result<_, Status> {
            let to_status = |e: MpcError| match e {
                MpcError::StoredRowRefused { dealer, reason } => {
                    stored_rows.record(internal_request.protocol_type.label(), STORED_ROW_SERVE);
                    tracing::warn!(
                        "Stored row for dealer {dealer:?} refused ({reason}); not served"
                    );
                    mpc_error_to_status(MpcError::NotFound(format!(
                        "stored row for dealer {dealer:?} refused: {reason}"
                    )))
                }
                e => {
                    match &e {
                        MpcError::NotFound(_) => {
                            tracing::debug!("retrieve_messages: {e}");
                        }
                        _ => {
                            tracing::warn!("retrieve_messages failed: {e}");
                        }
                    }
                    mpc_error_to_status(e)
                }
            };
            let (outcome, store, shape) = {
                let mgr = mpc_manager.read().unwrap();
                if abandoned.load(Ordering::Relaxed) {
                    return Err(Status::cancelled("the caller abandoned this retrieval"));
                }
                validate_epoch_current_or_previous(
                    mgr.mpc_config.epoch,
                    mgr.previous_epoch,
                    internal_request.epoch,
                )?;
                caller_membership::check_current_or_previous(
                    &requester,
                    internal_request.epoch,
                    mgr.mpc_config.epoch,
                    &mgr.committee,
                    mgr.previous_committee.as_ref(),
                )
                .map_err(|refusal| {
                    caller_membership::refuse(
                        &refused,
                        "retrieve_messages",
                        &requester,
                        &format!("epoch {}", internal_request.epoch),
                        refusal,
                    )
                })?;
                let outcome = mgr
                    .begin_retrieve(requester, &internal_request)
                    .map_err(to_status)?;
                (
                    outcome,
                    std::sync::Arc::clone(&mgr.public_messages_store),
                    mgr.shape_params(),
                )
            };
            let _permit = outcome
                .reads_store()
                .then(|| {
                    store_reads
                        .try_admit(requester, STORE_READ_PERMITS)
                        .ok_or_else(|| {
                            store_reads_shed
                                .with_label_values(&[&requester.to_string()])
                                .inc();
                            Status::unavailable(format!(
                                "{} (store reads)",
                                crate::grpc::PEER_INFLIGHT_LIMIT_MSG
                            ))
                        })
                })
                .transpose()?;
            let reply = match outcome {
                RetrieveOutcome::Ready(reply) => reply,
                RetrieveOutcome::NeedsStore => {
                    retrieve_from_store(&*store, &internal_request).map_err(to_status)?
                }
                RetrieveOutcome::NeedsAvidStore(pending) => RetrieveReply::Avid(
                    finish_avid_retrieval(&*store, pending, &shape).map_err(to_status)?,
                ),
            };
            reply.to_proto(&shape, &internal_request).map_err(to_status)
        })
        .await?;
        Ok(tonic::Response::new(response))
    }

    #[tracing::instrument(skip(self, request))]
    async fn complain(
        &self,
        request: tonic::Request<ComplainRequest>,
    ) -> Result<tonic::Response<ComplainResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let protocol = proto_protocol_label(external_request.protocol_type);
        let mpc_manager = self.mpc_manager()?;
        let service = self.clone();
        let refused = self.metrics().mpc_rpc_caller_refused_total.clone();
        let result = spawn_blocking(move || -> Result<_, Status> {
            let epoch = external_request
                .epoch
                .ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
            let shape = service.shape_params()?;
            validate_epoch_current_or_previous(shape.epoch(), shape.previous_epoch(), epoch)?;
            let committee =
                gates::complain_committee(&shape, epoch, &caller).map_err(|refusal| {
                    caller_membership::refuse(
                        &refused,
                        "complain",
                        &caller,
                        &format!("epoch {epoch}"),
                        refusal,
                    )
                })?;
            if let Err(e) =
                gates::check_complain(&shape, committee, caller, epoch, &external_request)
            {
                return Ok(Err(e));
            }
            let internal_request = types::ComplainRequest::try_from(&external_request)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
            drop(external_request);
            let mut mgr = mpc_manager.write().unwrap();
            validate_epoch_current_or_previous(
                mgr.mpc_config.epoch,
                mgr.previous_epoch,
                internal_request.epoch,
            )?;
            Ok(mgr.handle_complain_request(caller, &internal_request))
        })
        .await?;
        let complaint = result.map_err(|e| {
            if matches!(e, MpcError::ComplaintWithheld { .. }) {
                self.metrics().mpc_complaints_withheld_total.inc();
            } else {
                if matches!(e, MpcError::CountCheckRefused { .. }) {
                    self.metrics()
                        .refusal_counters()
                        .request(&caller, "complain", protocol);
                }
                tracing::warn!("complain failed: {e}");
            }
            mpc_error_to_status(e)
        })?;
        Ok(tonic::Response::new(ComplainResponse::from(&complaint)))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_public_mpc_output(
        &self,
        request: tonic::Request<GetPublicMpcOutputRequest>,
    ) -> Result<tonic::Response<GetPublicMpcOutputResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::GetPublicMpcOutputRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mpc_manager = self.mpc_manager()?;
        let onchain_state = self.onchain_state_opt();
        let refused = self.metrics().mpc_rpc_caller_refused_total.clone();
        let response = spawn_blocking(move || -> Result<_, Status> {
            let epoch = internal_request.epoch;
            // Resolved before the manager lock is taken, so the two locks never nest.
            let membership = onchain_state.as_ref().map(|onchain_state| {
                caller_membership::check_epoch_or_successor(
                    onchain_state.state().hashi().committees.committees(),
                    epoch,
                    &caller,
                )
            });
            let output = {
                let mgr = mpc_manager.read().unwrap();
                mgr.handle_get_public_mpc_output_request(&internal_request)
                    .map_err(|e| {
                        tracing::warn!("get_public_mpc_output failed: {e}");
                        mpc_error_to_status(e)
                    })?
            };
            if let Some(Err(refusal)) = membership {
                return Err(caller_membership::refuse(
                    &refused,
                    "get_public_mpc_output",
                    &caller,
                    &format!("epoch {epoch} or the committee after it"),
                    refusal,
                ));
            }
            Ok(GetPublicMpcOutputResponse::from(&output))
        })
        .await?;
        Ok(tonic::Response::new(response))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_reconfig_completion_signature(
        &self,
        request: tonic::Request<GetReconfigCompletionSignatureRequest>,
    ) -> Result<tonic::Response<GetReconfigCompletionSignatureResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let epoch = external_request
            .epoch
            .ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
        let signature = self.get_reconfig_signature(epoch);
        if signature.is_some() {
            check_caller_in_epoch(self, "get_reconfig_completion_signature", &caller, epoch)?;
        }
        Ok(tonic::Response::new(
            GetReconfigCompletionSignatureResponse {
                signature: signature.map(Into::into),
            },
        ))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_presig_dealer_set_signature(
        &self,
        request: tonic::Request<GetPresigDealerSetSignatureRequest>,
    ) -> Result<tonic::Response<GetPresigDealerSetSignatureResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let epoch = external_request
            .epoch
            .ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
        let batch_index = external_request
            .batch_index
            .ok_or_else(|| Status::invalid_argument("batch_index: missing required field"))?;
        // Only present once this node has fixed the batch's dealer set.
        let signature = self.get_presig_seal_signature(epoch, batch_index);
        if signature.is_some() {
            check_caller_in_epoch(self, "get_presig_dealer_set_signature", &caller, epoch)?;
        }
        Ok(tonic::Response::new(GetPresigDealerSetSignatureResponse {
            signature: signature.map(Into::into),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_partial_signatures(
        &self,
        request: tonic::Request<GetPartialSignaturesRequest>,
    ) -> Result<tonic::Response<GetPartialSignaturesResponse>, Status> {
        let caller = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::GetPartialSignaturesRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let request_epoch = external_request
            .epoch
            .ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
        let response = {
            let signing_manager = self.signing_manager_for(request_epoch)?;
            caller_membership::check_member(signing_manager.committee(), &caller).map_err(
                |refusal| {
                    caller_membership::refuse(
                        &self.metrics().mpc_rpc_caller_refused_total,
                        "get_partial_signatures",
                        &caller,
                        &format!("epoch {request_epoch}"),
                        refusal,
                    )
                },
            )?;
            signing_manager
                .handle_get_partial_signatures_request(&internal_request)
                .map_err(|e| {
                    match &e {
                        SigningError::NotFound(_) => {
                            tracing::debug!("get_partial_signatures: {e}");
                        }
                        _ => {
                            tracing::warn!("get_partial_signatures failed: {e}");
                        }
                    }
                    signing_error_to_status(e)
                })?
        };
        Ok(tonic::Response::new(GetPartialSignaturesResponse::from(
            &response,
        )))
    }
}

fn authenticate_caller<T>(request: &tonic::Request<T>) -> Result<Address, Status> {
    request
        .extensions()
        .get::<Address>()
        .copied()
        .ok_or_else(|| Status::permission_denied("unknown validator"))
}

fn check_caller_in_epoch(
    service: &HttpService,
    handler: &str,
    caller: &Address,
    epoch: u64,
) -> Result<(), Status> {
    let Some(onchain_state) = service.onchain_state_opt() else {
        return Ok(());
    };
    let membership = caller_membership::check_epoch(
        onchain_state.state().hashi().committees.committees(),
        epoch,
        caller,
    );
    membership.map_err(|refusal| {
        caller_membership::refuse(
            &service.metrics().mpc_rpc_caller_refused_total,
            handler,
            caller,
            &format!("epoch {epoch}"),
            refusal,
        )
    })
}

fn send_messages_error(sender: Address, e: MpcError) -> Status {
    if matches!(&e, MpcError::NotReady(_)) {
        tracing::info!("send_messages from {sender:?}: {e}");
    } else {
        tracing::warn!("send_messages from {sender:?} failed: {e}");
    }
    mpc_error_to_status(e)
}

fn send_messages_protocol(request: &SendMessagesRequest) -> &'static str {
    use hashi_types::proto::send_messages_request::Messages;
    match &request.messages {
        Some(Messages::DkgMessage(_)) => crate::metrics::MPC_LABEL_DKG,
        Some(Messages::RotationMessages(_) | Messages::RotationMessagesBcs(_)) => {
            crate::metrics::MPC_LABEL_KEY_ROTATION
        }
        Some(Messages::AvidNonceMessage(_)) => crate::metrics::MPC_LABEL_NONCE_GENERATION,
        None => "unspecified",
    }
}

fn proto_protocol_label(protocol_type: Option<i32>) -> &'static str {
    use hashi_types::proto::MpcProtocolType;
    match protocol_type.and_then(|value| MpcProtocolType::try_from(value).ok()) {
        Some(MpcProtocolType::Dkg) => crate::metrics::MPC_LABEL_DKG,
        Some(MpcProtocolType::KeyRotation) => crate::metrics::MPC_LABEL_KEY_ROTATION,
        Some(MpcProtocolType::NonceGeneration) => crate::metrics::MPC_LABEL_NONCE_GENERATION,
        Some(MpcProtocolType::Unspecified) | None => "unspecified",
    }
}

struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn rotation_wire_shape(request: &SendMessagesRequest) -> Option<&'static str> {
    use hashi_types::proto::send_messages_request::Messages;
    match &request.messages {
        Some(Messages::RotationMessages(_)) => Some("map"),
        Some(Messages::RotationMessagesBcs(_)) => Some("blob"),
        _ => None,
    }
}

fn validate_epoch(expected: u64, request_epoch: Option<u64>) -> Result<(), Status> {
    let epoch =
        request_epoch.ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
    if epoch != expected {
        return Err(Status::failed_precondition(format!(
            "epoch mismatch: expected {expected}, got {epoch}"
        )));
    }
    Ok(())
}

fn validate_epoch_current_or_previous(
    current_epoch: u64,
    previous_epoch: u64,
    request_epoch: u64,
) -> Result<(), Status> {
    if request_epoch != current_epoch && request_epoch != previous_epoch {
        return Err(Status::failed_precondition(format!(
            "epoch mismatch: expected {current_epoch} or {previous_epoch}, got {request_epoch}"
        )));
    }
    Ok(())
}

pub(crate) fn signing_error_to_status(err: SigningError) -> Status {
    match &err {
        SigningError::InvalidMessage { .. } => Status::invalid_argument(err.to_string()),
        SigningError::NotFound(_) => Status::not_found(err.to_string()),
        SigningError::CryptoError(_) => Status::internal(err.to_string()),
        SigningError::Timeout { .. } => Status::deadline_exceeded(err.to_string()),
        SigningError::TooManyInvalidSignatures { .. } => {
            Status::failed_precondition(err.to_string())
        }
        SigningError::PoolExhausted => Status::resource_exhausted(err.to_string()),
        SigningError::RequestChanged { .. } => Status::failed_precondition(err.to_string()),
        SigningError::PresigBatchNotSealed { .. } => Status::unavailable(err.to_string()),
        SigningError::SealDealerSetMismatch { .. } => Status::failed_precondition(err.to_string()),
        SigningError::MalformedSealRandomness { .. } => {
            Status::failed_precondition(err.to_string())
        }
    }
}

fn mpc_error_to_status(err: MpcError) -> Status {
    use types::MpcError::*;
    match &err {
        InvalidThreshold(_)
        | InvalidMessage { .. }
        | CountCheckRefused { .. }
        | InvalidCertificate(_) => Status::invalid_argument(err.to_string()),
        Timeout { .. } => Status::deadline_exceeded(err.to_string()),
        NotEnoughParticipants { .. }
        | NotEnoughApprovals { .. }
        | InvalidConfig(_)
        | NotReady(_) => Status::failed_precondition(err.to_string()),
        NotFound(_) => Status::not_found(err.to_string()),
        ComplaintWithheld { .. } => Status::permission_denied(err.to_string()),
        _ => Status::internal(err.to_string()),
    }
}
