use crate::dkg::types;
use crate::dkg::types::DkgError;
use crate::grpc::HttpService;
use hashi_types::proto::ComplainRequest;
use hashi_types::proto::ComplainResponse;
use hashi_types::proto::GetPublicDkgOutputRequest;
use hashi_types::proto::GetPublicDkgOutputResponse;
use hashi_types::proto::RetrieveMessageRequest;
use hashi_types::proto::RetrieveMessageResponse;
use hashi_types::proto::RetrieveRotationMessagesRequest;
use hashi_types::proto::RetrieveRotationMessagesResponse;
use hashi_types::proto::RotationComplainRequest;
use hashi_types::proto::RotationComplainResponse;
use hashi_types::proto::SendMessageRequest;
use hashi_types::proto::SendMessageResponse;
use hashi_types::proto::SendRotationMessagesRequest;
use hashi_types::proto::SendRotationMessagesResponse;
use hashi_types::proto::dkg_service_server::DkgService;
use hashi_types::proto::key_rotation_service_server::KeyRotationService;
use sui_sdk_types::Address;
use tonic::Status;

#[tonic::async_trait]
impl DkgService for HttpService {
    #[tracing::instrument(skip(self, request))]
    async fn send_message(
        &self,
        request: tonic::Request<SendMessageRequest>,
    ) -> Result<tonic::Response<SendMessageResponse>, Status> {
        let sender = authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::SendMessageRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let response = {
            let mut mgr = self.dkg_manager().lock().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_send_message_request(sender, &internal_request)
                .map_err(dkg_error_to_status)?
        };
        Ok(tonic::Response::new(SendMessageResponse::from(&response)))
    }

    #[tracing::instrument(skip(self, request))]
    async fn retrieve_message(
        &self,
        request: tonic::Request<RetrieveMessageRequest>,
    ) -> Result<tonic::Response<RetrieveMessageResponse>, Status> {
        authenticate_caller(&request)?;
        let external_request = request.into_inner();
        let internal_request = types::RetrieveMessageRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let response = {
            let mgr = self.dkg_manager().lock().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_retrieve_message_request(&internal_request)
                .map_err(dkg_error_to_status)?
        };
        Ok(tonic::Response::new(RetrieveMessageResponse::from(
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
        let response = {
            let mut mgr = self.dkg_manager().lock().unwrap();
            validate_epoch(mgr.dkg_config.epoch, external_request.epoch)?;
            mgr.handle_complain_request(&internal_request)
                .map_err(dkg_error_to_status)?
        };
        Ok(tonic::Response::new(ComplainResponse::from(&response)))
    }
}

#[tonic::async_trait]
impl KeyRotationService for HttpService {
    #[tracing::instrument(skip(self, _request))]
    async fn send_rotation_messages(
        &self,
        _request: tonic::Request<SendRotationMessagesRequest>,
    ) -> Result<tonic::Response<SendRotationMessagesResponse>, Status> {
        Err(Status::unimplemented(
            "send_rotation_messages not yet implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn retrieve_rotation_messages(
        &self,
        _request: tonic::Request<RetrieveRotationMessagesRequest>,
    ) -> Result<tonic::Response<RetrieveRotationMessagesResponse>, Status> {
        Err(Status::unimplemented(
            "retrieve_rotation_messages not yet implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn get_public_dkg_output(
        &self,
        _request: tonic::Request<GetPublicDkgOutputRequest>,
    ) -> Result<tonic::Response<GetPublicDkgOutputResponse>, Status> {
        Err(Status::unimplemented(
            "get_public_dkg_output not yet implemented",
        ))
    }

    #[tracing::instrument(skip(self, _request))]
    async fn rotation_complain(
        &self,
        _request: tonic::Request<RotationComplainRequest>,
    ) -> Result<tonic::Response<RotationComplainResponse>, Status> {
        Err(Status::unimplemented(
            "rotation_complain not yet implemented",
        ))
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

fn dkg_error_to_status(err: DkgError) -> Status {
    use types::DkgError::*;
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
