use crate::grpc::HttpService;
use crate::mpc::spawn_blocking;
use crate::mpc::types;
use crate::mpc::types::MpcError;
use crate::mpc::types::SigningError;
use hashi_types::proto::ComplainRequest;
use hashi_types::proto::ComplainResponse;
use hashi_types::proto::GetPartialSignaturesRequest;
use hashi_types::proto::GetPartialSignaturesResponse;
use hashi_types::proto::GetPublicDkgOutputRequest;
use hashi_types::proto::GetPublicDkgOutputResponse;
use hashi_types::proto::GetReconfigCompletionSignatureRequest;
use hashi_types::proto::GetReconfigCompletionSignatureResponse;
use hashi_types::proto::RetrieveMessagesRequest;
use hashi_types::proto::RetrieveMessagesResponse;
use hashi_types::proto::SendMessagesRequest;
use hashi_types::proto::SendMessagesResponse;
use hashi_types::proto::mpc_service_server::MpcService;
use sui_sdk_types::Address;
use tonic::Status;

#[tonic::async_trait]
impl MpcService for HttpService {
    #[tracing::instrument(skip(self, request))]
    async fn send_messages(
        &self,
        request: tonic::Request<SendMessagesRequest>,
    ) -> Result<tonic::Response<SendMessagesResponse>, Status> {
        let sender = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::SendMessagesRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mpc_manager = self.mpc_manager()?;
        let response = spawn_blocking(move || -> Result<_, Status> {
            let mut mgr = mpc_manager.write().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_send_messages_request(sender, &internal_request)
                .map_err(dkg_error_to_status)
        })
        .await?;
        Ok(tonic::Response::new(SendMessagesResponse::from(&response)))
    }

    #[tracing::instrument(skip(self, request))]
    async fn retrieve_messages(
        &self,
        request: tonic::Request<RetrieveMessagesRequest>,
    ) -> Result<tonic::Response<RetrieveMessagesResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::RetrieveMessagesRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let response = {
            let mpc_manager = self.mpc_manager()?;
            let mgr = mpc_manager.read().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_retrieve_messages_request(&internal_request)
                .map_err(dkg_error_to_status)?
        };
        Ok(tonic::Response::new(RetrieveMessagesResponse::from(
            &response,
        )))
    }

    #[tracing::instrument(skip(self, request))]
    async fn complain(
        &self,
        request: tonic::Request<ComplainRequest>,
    ) -> Result<tonic::Response<ComplainResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::ComplainRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mpc_manager = self.mpc_manager()?;
        let response = spawn_blocking(move || -> Result<_, Status> {
            let mut mgr = mpc_manager.write().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_complain_request(&internal_request)
                .map_err(dkg_error_to_status)
        })
        .await?;
        Ok(tonic::Response::new(ComplainResponse::from(&response)))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_public_dkg_output(
        &self,
        request: tonic::Request<GetPublicDkgOutputRequest>,
    ) -> Result<tonic::Response<GetPublicDkgOutputResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::GetPublicDkgOutputRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let response = {
            let mpc_manager = self.mpc_manager()?;
            let mgr = mpc_manager.read().unwrap();
            mgr.handle_get_public_dkg_output_request(&internal_request)
                .map_err(dkg_error_to_status)?
        };
        Ok(tonic::Response::new(GetPublicDkgOutputResponse::from(
            &response,
        )))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_reconfig_completion_signature(
        &self,
        request: tonic::Request<GetReconfigCompletionSignatureRequest>,
    ) -> Result<tonic::Response<GetReconfigCompletionSignatureResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let epoch = external_request
            .epoch
            .ok_or_else(|| Status::invalid_argument("epoch: missing required field"))?;
        let signature = self.get_reconfig_signature(epoch).map(Into::into);
        Ok(tonic::Response::new(
            GetReconfigCompletionSignatureResponse { signature },
        ))
    }

    #[tracing::instrument(skip(self, request))]
    async fn get_partial_signatures(
        &self,
        request: tonic::Request<GetPartialSignaturesRequest>,
    ) -> Result<tonic::Response<GetPartialSignaturesResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::GetPartialSignaturesRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let response = {
            let signing_manager = self.signing_manager();
            let mgr = signing_manager.read().unwrap();
            validate_epoch(mgr.epoch(), external_request.epoch)?;
            mgr.handle_get_partial_signatures_request(&internal_request)
                .map_err(signing_error_to_status)?
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

fn signing_error_to_status(err: SigningError) -> Status {
    match &err {
        SigningError::InvalidMessage { .. } => Status::invalid_argument(err.to_string()),
        SigningError::NotFound(_) => Status::not_found(err.to_string()),
        SigningError::CryptoError(_) => Status::internal(err.to_string()),
        SigningError::Timeout { .. } => Status::deadline_exceeded(err.to_string()),
        SigningError::TooManyInvalidSignatures { .. } => {
            Status::failed_precondition(err.to_string())
        }
        SigningError::PoolExhausted => Status::resource_exhausted(err.to_string()),
    }
}

fn dkg_error_to_status(err: MpcError) -> Status {
    use types::MpcError::*;
    match &err {
        InvalidThreshold(_) | InvalidMessage { .. } | InvalidCertificate(_) => {
            Status::invalid_argument(err.to_string())
        }
        Timeout { .. } => Status::deadline_exceeded(err.to_string()),
        NotEnoughParticipants { .. } | NotEnoughApprovals { .. } | InvalidConfig(_) => {
            Status::failed_precondition(err.to_string())
        }
        NotFound(_) => Status::not_found(err.to_string()),
        _ => Status::internal(err.to_string()),
    }
}
