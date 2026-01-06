use crate::setup;
use crate::Enclave;
use hashi::proto;
use hashi_guardian_shared::proto_conversions;
use hashi_guardian_shared::GuardianError;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::SetupNewKeyRequest;
use std::sync::Arc;

#[derive(Clone)]
pub struct GuardianGrpc {
    pub enclave: Arc<Enclave>,
    pub setup_mode: bool,
}

fn to_status(e: GuardianError) -> tonic::Status {
    match e {
        InvalidInputs(msg) => tonic::Status::invalid_argument(msg),
        InternalError(msg) => tonic::Status::internal(msg),
    }
}

#[tonic::async_trait]
impl proto::guardian_service_server::GuardianService for GuardianGrpc {
    // TODO: Add more fields in info
    async fn get_guardian_info(
        &self,
        _request: tonic::Request<proto::GetGuardianInfoRequest>,
    ) -> anyhow::Result<tonic::Response<proto::GetGuardianInfoResponse>, tonic::Status> {
        // Expose the enclave's signing verification key and encryption public key.
        let signing_vk = self.enclave.signing_pubkey();

        let public_key = signing_vk.to_bytes().to_vec();

        Ok(tonic::Response::new(proto::GetGuardianInfoResponse {
            public_key: Some(public_key.into()),
            server: Some("v1".into()),
        }))
    }

    async fn setup_new_key(
        &self,
        request: tonic::Request<proto::SetupNewKeyRequest>,
    ) -> anyhow::Result<tonic::Response<proto::SignedSetupNewKeyResponse>, tonic::Status> {
        if !self.setup_mode {
            return Err(tonic::Status::failed_precondition(
                "setup_new_key is disabled when SETUP_MODE=false",
            ));
        }

        // Proto -> validated domain request (TryFrom impl lives in hashi-guardian-shared).
        let domain_req: SetupNewKeyRequest = request.into_inner().try_into().map_err(to_status)?;

        // Core logic
        let signed = setup::setup_new_key_impl(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        // Domain -> proto signed response
        let resp = proto_conversions::setup_new_key_response_signed_to_pb(signed);

        Ok(tonic::Response::new(resp))
    }
}
