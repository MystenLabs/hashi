use crate::dkg::types;
use crate::grpc::HttpService;
use crate::proto::dkg_service_server::DkgService;
use crate::proto::{
    ComplainRequest, ComplainResponse, RetrieveMessageRequest, RetrieveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use sui_sdk_types::Address;
use tonic::Code;

type Ed25519PublicKey = [u8; 32];
type Result<T> = std::result::Result<T, RpcError>;

pub struct TlsRegistry {
    key_to_address: HashMap<Ed25519PublicKey, Address>,
}

impl TlsRegistry {
    pub fn new(key_to_address: HashMap<Ed25519PublicKey, Address>) -> Self {
        Self { key_to_address }
    }

    pub fn lookup(&self, public_key: &VerifyingKey) -> Option<Address> {
        self.key_to_address.get(public_key.as_bytes()).copied()
    }
}

#[tonic::async_trait]
impl DkgService for HttpService {
    async fn send_message(
        &self,
        request: tonic::Request<SendMessageRequest>,
    ) -> std::result::Result<tonic::Response<SendMessageResponse>, tonic::Status> {
        send_message(self, request)
            .map(tonic::Response::new)
            .map_err(Into::into)
    }

    async fn retrieve_message(
        &self,
        request: tonic::Request<RetrieveMessageRequest>,
    ) -> std::result::Result<tonic::Response<RetrieveMessageResponse>, tonic::Status> {
        retrieve_message(self, request)
            .map(tonic::Response::new)
            .map_err(Into::into)
    }

    async fn complain(
        &self,
        request: tonic::Request<ComplainRequest>,
    ) -> std::result::Result<tonic::Response<ComplainResponse>, tonic::Status> {
        complain(self, request)
            .map(tonic::Response::new)
            .map_err(Into::into)
    }
}

#[tracing::instrument(skip(service, request))]
fn send_message(
    service: &HttpService,
    request: tonic::Request<SendMessageRequest>,
) -> Result<SendMessageResponse> {
    let sender = authenticate_caller(service, &request)?;
    let external_request = request.into_inner();
    let internal_request = types::SendMessageRequest::try_from(&external_request)?;
    let mut dkg_manager = service.dkg_manager().lock().unwrap();
    validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
    let response = dkg_manager.handle_send_message_request(sender, &internal_request)?;
    Ok(SendMessageResponse::from(&response))
}

#[tracing::instrument(skip(service, request))]
fn retrieve_message(
    service: &HttpService,
    request: tonic::Request<RetrieveMessageRequest>,
) -> Result<RetrieveMessageResponse> {
    authenticate_caller(service, &request)?;
    let external_request = request.into_inner();
    let internal_request = types::RetrieveMessageRequest::try_from(&external_request)?;
    let dkg_manager = service.dkg_manager().lock().unwrap();
    validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
    let response = dkg_manager.handle_retrieve_message_request(&internal_request)?;
    Ok(RetrieveMessageResponse::from(&response))
}

#[tracing::instrument(skip(service, request))]
fn complain(
    service: &HttpService,
    request: tonic::Request<ComplainRequest>,
) -> Result<ComplainResponse> {
    authenticate_caller(service, &request)?;
    let external_request = request.into_inner();
    let internal_request = types::ComplainRequest::try_from(&external_request)?;
    let mut dkg_manager = service.dkg_manager().lock().unwrap();
    validate_epoch(dkg_manager.dkg_config.epoch, external_request.epoch)?;
    let response = dkg_manager.handle_complain_request(&internal_request)?;
    Ok(ComplainResponse::from(&response))
}

fn authenticate_caller<T>(service: &HttpService, request: &tonic::Request<T>) -> Result<Address> {
    let peer_certs = request
        .extensions()
        .get::<sui_http::PeerCertificates>()
        .ok_or_else(|| RpcError::unauthenticated("no TLS client certificate"))?;
    let cert = peer_certs
        .peer_certs()
        .first()
        .ok_or_else(|| RpcError::unauthenticated("no client certificate"))?;
    let public_key = crate::tls::public_key_from_certificate(cert)
        .map_err(|e| RpcError::unauthenticated(format!("invalid certificate: {e}")))?;
    service
        .tls_registry()
        .lookup(&public_key)
        .ok_or_else(|| RpcError::permission_denied("unknown validator"))
}

fn validate_epoch(expected: u64, request_epoch: Option<u64>) -> Result<()> {
    let epoch = request_epoch
        .ok_or_else(|| RpcError::invalid_argument("epoch", "missing required field"))?;
    if epoch != expected {
        return Err(RpcError::failed_precondition(format!(
            "epoch mismatch: expected {expected}, got {epoch}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub struct RpcError {
    code: Code,
    message: String,
}

impl RpcError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(Code::Unauthenticated, message)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(Code::PermissionDenied, message)
    }

    pub fn invalid_argument(field: &str, description: impl Into<String>) -> Self {
        Self::new(
            Code::InvalidArgument,
            format!("{}: {}", field, description.into()),
        )
    }

    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(Code::FailedPrecondition, message)
    }
}

impl From<RpcError> for tonic::Status {
    fn from(err: RpcError) -> Self {
        tonic::Status::new(err.code, err.message)
    }
}

impl From<sui_rpc::proto::TryFromProtoError> for RpcError {
    fn from(err: sui_rpc::proto::TryFromProtoError) -> Self {
        Self::new(Code::InvalidArgument, err.to_string())
    }
}

impl From<types::DkgError> for RpcError {
    fn from(err: types::DkgError) -> Self {
        use types::DkgError::*;
        match &err {
            InvalidThreshold(_) | InvalidMessage { .. } | InvalidCertificate(_) => {
                Self::new(Code::InvalidArgument, err.to_string())
            }
            Timeout { .. } => Self::new(Code::DeadlineExceeded, err.to_string()),
            NotEnoughParticipants { .. } | NotEnoughApprovals { .. } => {
                Self::new(Code::FailedPrecondition, err.to_string())
            }
            _ => Self::new(Code::Internal, err.to_string()),
        }
    }
}
