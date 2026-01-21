use crate::getters;
use crate::init;
use crate::setup;
use crate::withdraw;
use crate::Enclave;
use hashi_guardian_shared::proto_conversions;
use hashi_guardian_shared::proto_conversions::pb_to_signed_standard_withdrawal_request_wire;
use hashi_guardian_shared::AddressValidation;
use hashi_guardian_shared::GuardianError;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::GuardianError::S3Error;
use hashi_guardian_shared::HashiSigned;
use hashi_guardian_shared::OperatorInitRequest;
use hashi_guardian_shared::SetupNewKeyRequest;
use hashi_guardian_shared::StandardWithdrawalRequest;
use hashi_types::proto;
use std::sync::Arc;
use tonic::Request;
use tonic::Response;
use tonic::Status;

#[derive(Clone)]
pub struct GuardianGrpc {
    pub enclave: Arc<Enclave>,
    pub setup_mode: bool,
}

fn to_status(e: GuardianError) -> Status {
    match e {
        InvalidInputs(msg) => Status::invalid_argument(msg),
        InternalError(msg) => Status::internal(msg),
        S3Error(msg) => Status::internal(msg),
    }
}

#[tonic::async_trait]
impl proto::guardian_service_server::GuardianService for GuardianGrpc {
    async fn get_guardian_info(
        &self,
        _request: Request<proto::GetGuardianInfoRequest>,
    ) -> anyhow::Result<Response<proto::GetGuardianInfoResponse>, Status> {
        let resp = getters::get_guardian_info(self.enclave.clone())
            .await
            .map_err(to_status)?;

        let resp_pb = proto_conversions::get_guardian_info_response_to_pb(resp);

        Ok(Response::new(resp_pb))
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> anyhow::Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        if !self.setup_mode {
            return Err(Status::failed_precondition(
                "setup_new_key is disabled when SETUP_MODE=false",
            ));
        }

        let domain_req: SetupNewKeyRequest = request.into_inner().try_into().map_err(to_status)?;

        let signed = setup::setup_new_key(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        let resp = proto_conversions::setup_new_key_response_signed_to_pb(signed);

        Ok(Response::new(resp))
    }

    // Note: operator_init should be available both in setup and normal modes.
    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        let domain_req: OperatorInitRequest = request.into_inner().try_into().map_err(to_status)?;

        init::operator_init(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorInitResponse {}))
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::ProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        if self.setup_mode {
            return Err(Status::failed_precondition(
                "provisioner_init is disabled when SETUP_MODE=true",
            ));
        }

        let domain_req = request.into_inner().try_into().map_err(to_status)?;

        init::provisioner_init(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::ProvisionerInitResponse {}))
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        if self.setup_mode {
            return Err(Status::failed_precondition(
                "standard_withdrawal is disabled when SETUP_MODE=true",
            ));
        }

        // proto to domain
        let domain_req = pb_to_signed_standard_withdrawal_request_wire(request.into_inner())
            .map_err(to_status)?;

        // validate address with network
        let network = self.enclave.config.bitcoin_network().map_err(to_status)?;
        let validated_req =
            HashiSigned::<StandardWithdrawalRequest>::validate_addr(domain_req, network)
                .map_err(to_status)?;

        // core withdraw call
        let response = withdraw::standard_withdrawal(self.enclave.clone(), validated_req)
            .await
            .map_err(to_status)?;

        // domain to proto
        let resp_pb = proto_conversions::standard_withdrawal_response_signed_to_pb(response);
        Ok(Response::new(resp_pb))
    }
}
