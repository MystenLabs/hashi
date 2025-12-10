use crate::dkg::types;
use crate::grpc::HttpService;
use crate::proto::dkg_service_server::DkgService;
use crate::proto::{
    ComplainRequest, ComplainResponse, RetrieveMessageRequest, RetrieveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use sui_sdk_types::{Address, Ed25519PublicKey};
use tonic::Status;

pub struct TlsRegistry {
    key_to_address: HashMap<Ed25519PublicKey, Address>,
}

impl TlsRegistry {
    pub fn new(key_to_address: HashMap<Ed25519PublicKey, Address>) -> Self {
        Self { key_to_address }
    }

    pub fn lookup(&self, public_key: &VerifyingKey) -> Option<Address> {
        let key = Ed25519PublicKey::new(*public_key.as_bytes());
        self.key_to_address.get(&key).copied()
    }
}

#[tonic::async_trait]
impl DkgService for HttpService {
    #[tracing::instrument(skip(self, request))]
    async fn send_message(
        &self,
        request: tonic::Request<SendMessageRequest>,
    ) -> Result<tonic::Response<SendMessageResponse>, Status> {
        let sender = authenticate_caller(self, &request)?;
        let external_request = request.into_inner();
        let internal_request = types::SendMessageRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut dkg_manager = self.dkg_manager().lock().unwrap();
        validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
        let response = dkg_manager
            .handle_send_message_request(sender, &internal_request)
            .map_err(dkg_error_to_status)?;
        Ok(tonic::Response::new(SendMessageResponse::from(&response)))
    }

    #[tracing::instrument(skip(self, request))]
    async fn retrieve_message(
        &self,
        request: tonic::Request<RetrieveMessageRequest>,
    ) -> Result<tonic::Response<RetrieveMessageResponse>, Status> {
        authenticate_caller(self, &request)?;
        let external_request = request.into_inner();
        let internal_request = types::RetrieveMessageRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let dkg_manager = self.dkg_manager().lock().unwrap();
        validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
        let response = dkg_manager
            .handle_retrieve_message_request(&internal_request)
            .map_err(dkg_error_to_status)?;
        Ok(tonic::Response::new(RetrieveMessageResponse::from(
            &response,
        )))
    }

    #[tracing::instrument(skip(self, request))]
    async fn complain(
        &self,
        request: tonic::Request<ComplainRequest>,
    ) -> Result<tonic::Response<ComplainResponse>, Status> {
        authenticate_caller(self, &request)?;
        let external_request = request.into_inner();
        let internal_request = types::ComplainRequest::try_from(&external_request)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut dkg_manager = self.dkg_manager().lock().unwrap();
        validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
        let response = dkg_manager
            .handle_complain_request(&internal_request)
            .map_err(dkg_error_to_status)?;
        Ok(tonic::Response::new(ComplainResponse::from(&response)))
    }
}

// TODO: Move authentication to a middleware layer and add validator address as a request extension.
fn authenticate_caller<T>(
    service: &HttpService,
    request: &tonic::Request<T>,
) -> Result<Address, Status> {
    let peer_certs = request
        .extensions()
        .get::<sui_http::PeerCertificates>()
        .ok_or_else(|| Status::unauthenticated("no TLS client certificate"))?;
    let cert = peer_certs
        .peer_certs()
        .first()
        .ok_or_else(|| Status::unauthenticated("no client certificate"))?;
    let public_key = crate::tls::public_key_from_certificate(cert)
        .map_err(|e| Status::unauthenticated(format!("invalid certificate: {e}")))?;
    service
        .tls_registry()
        .lookup(&public_key)
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

fn dkg_error_to_status(err: types::DkgError) -> Status {
    use types::DkgError::*;
    match &err {
        InvalidThreshold(_) | InvalidMessage { .. } | InvalidCertificate(_) => {
            Status::invalid_argument(err.to_string())
        }
        Timeout { .. } => Status::deadline_exceeded(err.to_string()),
        NotEnoughParticipants { .. } | NotEnoughApprovals { .. } => {
            Status::failed_precondition(err.to_string())
        }
        _ => Status::internal(err.to_string()),
    }
}
