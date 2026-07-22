// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ceremony_mode::rotate;
use crate::ceremony_mode::setup;
use crate::info;
use crate::operator_init;
use crate::withdraw_mode::committee_update;
use crate::withdraw_mode::operator_activate;
use crate::withdraw_mode::provisioner_init;
use crate::withdraw_mode::provisioner_rotate_cert;
use crate::withdraw_mode::standard_withdrawal;
use crate::Enclave;
use hashi_types::guardian::proto_conversions;
use hashi_types::guardian::proto_conversions::pb_to_signed_committee_transition;
use hashi_types::guardian::proto_conversions::pb_to_signed_standard_withdrawal_request_wire;
use hashi_types::guardian::AddressValidation;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::*;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::RotateKpsRequest;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::proto;
use std::sync::Arc;
use tonic::Request;
use tonic::Response;
use tonic::Status;

#[derive(Clone)]
pub struct GuardianGrpc {
    pub enclave: Arc<Enclave>,
}

fn to_status(e: GuardianError) -> Status {
    match e {
        InvalidInputs(msg) => Status::invalid_argument(msg),
        InternalError(msg) => Status::internal(msg),
        Unavailable(msg) => Status::unavailable(msg),
        S3Error(msg) => Status::internal(msg),
        EnclaveUninitialized => Status::failed_precondition("Enclave is not fully initialized"),
        RateLimitExceeded => Status::internal("Rate limit exceeded"),
    }
}

#[tonic::async_trait]
impl proto::guardian_service_server::GuardianService for GuardianGrpc {
    async fn get_guardian_info(
        &self,
        _request: Request<proto::GetGuardianInfoRequest>,
    ) -> anyhow::Result<Response<proto::GetGuardianInfoResponse>, Status> {
        let resp = info::get_guardian_info(self.enclave.clone())
            .await
            .map_err(to_status)?;

        let resp_pb = proto_conversions::get_guardian_info_response_to_pb(resp);

        Ok(Response::new(resp_pb))
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> anyhow::Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        let domain_req: SetupNewKeyRequest = request.into_inner().try_into().map_err(to_status)?;

        let signed = setup::setup_new_key(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        let resp = proto_conversions::setup_new_key_response_signed_to_pb(signed);

        Ok(Response::new(resp))
    }

    async fn rotate_kps(
        &self,
        request: Request<proto::RotateKpsRequest>,
    ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
        let domain_req: RotateKpsRequest = request.into_inner().try_into().map_err(to_status)?;

        let signed = rotate::rotate_kps(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        let resp = proto_conversions::rotate_kps_response_signed_to_pb(signed);

        Ok(Response::new(resp))
    }

    // operator_init is available in both ceremony and withdraw modes.
    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        let domain_req: OperatorInitRequest = request.into_inner().try_into().map_err(to_status)?;

        operator_init::operator_init(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorInitResponse {}))
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::ProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        let domain_req = request.into_inner().try_into().map_err(to_status)?;

        provisioner_init::provisioner_init(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::ProvisionerInitResponse {}))
    }

    async fn provisioner_rotate_cert(
        &self,
        request: Request<proto::SignedProvisionerRotateCertRequest>,
    ) -> Result<Response<proto::SignedProvisionerRotateCertResponse>, Status> {
        let domain_req: KpSigned<ProvisionerRotateCertRequest> =
            request.into_inner().try_into().map_err(to_status)?;
        let signed =
            provisioner_rotate_cert::provisioner_rotate_cert(self.enclave.clone(), domain_req)
                .await
                .map_err(to_status)?;

        Ok(Response::new(
            proto_conversions::provisioner_rotate_cert_response_signed_to_pb(signed),
        ))
    }

    async fn operator_activate(
        &self,
        request: Request<proto::OperatorActivateRequest>,
    ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
        let domain_req: OperatorActivateRequest =
            request.into_inner().try_into().map_err(to_status)?;

        operator_activate::operator_activate(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorActivateResponse {}))
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        // proto to domain
        let domain_req = pb_to_signed_standard_withdrawal_request_wire(request.into_inner())
            .map_err(to_status)?;

        // validate address with network
        let network = self.enclave.config.bitcoin_network().map_err(to_status)?;
        let validated_req =
            HashiSigned::<StandardWithdrawalRequest>::validate_addr(domain_req, network)
                .map_err(to_status)?;

        // core withdraw call
        let response =
            standard_withdrawal::standard_withdrawal(self.enclave.clone(), validated_req)
                .await
                .map_err(to_status)?;

        // domain to proto
        let resp_pb = proto_conversions::standard_withdrawal_response_signed_to_pb(response);
        Ok(Response::new(resp_pb))
    }

    async fn update_committee(
        &self,
        request: Request<proto::SignedCommitteeTransition>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        let signed = pb_to_signed_committee_transition(request.into_inner()).map_err(to_status)?;
        let current_committee_epoch =
            committee_update::update_committee(self.enclave.clone(), signed)
                .await
                .map_err(to_status)?;

        Ok(Response::new(proto::UpdateCommitteeResponse {
            current_committee_epoch: Some(current_committee_epoch),
        }))
    }

    async fn update_committee_chain(
        &self,
        request: Request<proto::UpdateCommitteeChainRequest>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        let transitions = request
            .into_inner()
            .transitions
            .into_iter()
            .map(pb_to_signed_committee_transition)
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_status)?;
        let current_committee_epoch =
            committee_update::update_committee_chain(self.enclave.clone(), transitions)
                .await
                .map_err(to_status)?;

        Ok(Response::new(proto::UpdateCommitteeResponse {
            current_committee_epoch: Some(current_committee_epoch),
        }))
    }
}
