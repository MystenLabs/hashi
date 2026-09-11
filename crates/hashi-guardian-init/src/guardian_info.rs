// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_relay_service_client::GuardianRelayServiceClient;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::Code;
use tonic::transport::Channel;

pub async fn verified_live_guardian_info(
    client: &mut GuardianServiceClient<Channel>,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    verify_info_response(info_pb, current_build)
}

/// Like [`verified_live_guardian_info`], but over the relay's provisioning
/// surface: `GetProvisioningTargetInfo` answers for the guardian KPs are
/// provisioning (the proxy's standby backend when one is configured, else the
/// active guardian), where the node-facing `GetGuardianInfo` always answers for
/// the active one.
pub async fn verified_provisioning_target_info(
    client: &mut GuardianRelayServiceClient<Channel>,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_pb = client
        .get_provisioning_target_info(pb::GetProvisioningTargetInfoRequest {})
        .await
        .context("GetProvisioningTargetInfo RPC failed")?
        .into_inner();
    verify_info_response(info_pb, current_build)
}

/// The ceremony guardian a KP confirms to or signs a rotation for: through
/// the proxy, the relay's provisioning target (the standby during a KP-set
/// rotation); a bare guardian answers for itself.
pub async fn verified_ceremony_guardian_info(
    endpoint: &str,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    verify_info_response(ceremony_guardian_info_pb(endpoint).await?, current_build)
}

/// `GetProvisioningTargetInfo` from `endpoint`, or its `GetGuardianInfo` when
/// it serves no relay (a bare guardian answers `Unimplemented`).
async fn ceremony_guardian_info_pb(endpoint: &str) -> anyhow::Result<pb::GetGuardianInfoResponse> {
    let channel = Channel::from_shared(endpoint.to_string())
        .with_context(|| format!("invalid ceremony guardian endpoint {endpoint}"))?
        .connect()
        .await
        .with_context(|| format!("connect to ceremony guardian at {endpoint}"))?;
    match GuardianRelayServiceClient::new(channel.clone())
        .get_provisioning_target_info(pb::GetProvisioningTargetInfoRequest {})
        .await
    {
        Ok(response) => Ok(response.into_inner()),
        Err(status) if status.code() == Code::Unimplemented => {
            Ok(GuardianServiceClient::new(channel)
                .get_guardian_info(pb::GetGuardianInfoRequest {})
                .await
                .context("GetGuardianInfo RPC failed")?
                .into_inner())
        }
        Err(status) => Err(status).context("GetProvisioningTargetInfo RPC failed"),
    }
}

fn verify_info_response(
    info_pb: pb::GetGuardianInfoResponse,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    info_resp
        .verify_live(current_build)
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e}"))
}

/// The OI log captures the final pre-transition snapshot. Apart from the
/// lifecycle advancing once, it must match the live post-OI GuardianInfo.
pub fn ensure_oi_info_matches_post_init(
    oi_info: &GuardianInfo,
    live_info: &GuardianInfo,
) -> anyhow::Result<()> {
    ensure!(
        live_info.lifecycle.predecessor() == Some(oi_info.lifecycle),
        "S3 OI lifecycle {:?} is not the predecessor of live lifecycle {:?}",
        oi_info.lifecycle,
        live_info.lifecycle
    );

    let mut expected_live_info = oi_info.clone();
    expected_live_info.lifecycle = live_info.lifecycle;
    ensure!(
        &expected_live_info == live_info,
        "S3 OI GuardianInfo differs from live post-OperatorInit GuardianInfo"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::proto::guardian_relay_service_server::GuardianRelayService;
    use hashi_types::proto::guardian_relay_service_server::GuardianRelayServiceServer;
    use hashi_types::proto::guardian_service_server::GuardianService;
    use hashi_types::proto::guardian_service_server::GuardianServiceServer;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;
    use tonic::transport::Server;
    use tonic::transport::server::Router;
    use tonic::transport::server::TcpIncoming;

    fn tagged(tag: u8) -> pb::GetGuardianInfoResponse {
        pb::GetGuardianInfoResponse {
            signing_pub_key: Some(vec![tag; 32].into()),
            ..Default::default()
        }
    }

    /// A guardian whose `GetGuardianInfo` carries `[tag; 32]`.
    #[derive(Clone)]
    struct Guardian(u8);

    #[tonic::async_trait]
    impl GuardianService for Guardian {
        async fn get_guardian_info(
            &self,
            _: Request<pb::GetGuardianInfoRequest>,
        ) -> Result<Response<pb::GetGuardianInfoResponse>, Status> {
            Ok(Response::new(tagged(self.0)))
        }
        async fn setup_new_key(
            &self,
            _: Request<pb::SetupNewKeyRequest>,
        ) -> Result<Response<pb::SignedSetupNewKeyResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn confirm_ceremony(
            &self,
            _: Request<pb::SignedCeremonyConfirmationRequest>,
        ) -> Result<Response<pb::CeremonyConfirmationResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn rotate_kp_set(
            &self,
            _: Request<pb::BatchProvisionerRotateKpSetRequest>,
        ) -> Result<Response<pb::SignedRotateKpSetResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn operator_init(
            &self,
            _: Request<pb::OperatorInitRequest>,
        ) -> Result<Response<pb::OperatorInitResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn provisioner_init(
            &self,
            _: Request<pb::BatchProvisionerInitRequest>,
        ) -> Result<Response<pb::ProvisionerInitResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn provisioner_rotate_cert(
            &self,
            _: Request<pb::SignedProvisionerRotateCertRequest>,
        ) -> Result<Response<pb::SignedProvisionerRotateCertResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn operator_activate(
            &self,
            _: Request<pb::OperatorActivateRequest>,
        ) -> Result<Response<pb::OperatorActivateResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn standard_withdrawal(
            &self,
            _: Request<pb::SignedStandardWithdrawalRequest>,
        ) -> Result<Response<pb::SignedStandardWithdrawalResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn update_committee(
            &self,
            _: Request<pb::SignedCommitteeTransition>,
        ) -> Result<Response<pb::UpdateCommitteeResponse>, Status> {
            unimplemented!("not exercised")
        }
        async fn update_committee_chain(
            &self,
            _: Request<pb::UpdateCommitteeChainRequest>,
        ) -> Result<Response<pb::UpdateCommitteeResponse>, Status> {
            unimplemented!("not exercised")
        }
    }

    /// A proxy's relay surface, fronting a guardian whose info carries `[tag; 32]`.
    #[derive(Clone)]
    struct Relay(u8);

    #[tonic::async_trait]
    impl GuardianRelayService for Relay {
        async fn get_provisioning_target_info(
            &self,
            _: Request<pb::GetProvisioningTargetInfoRequest>,
        ) -> Result<Response<pb::GetGuardianInfoResponse>, Status> {
            Ok(Response::new(tagged(self.0)))
        }
        async fn single_provisioner_init(
            &self,
            _: Request<pb::SignedProvisionerInitRequest>,
        ) -> Result<Response<pb::SingleProvisionerInitResponse>, Status> {
            unimplemented!("not exercised")
        }
    }

    async fn serve(router: Router) -> String {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(router.serve_with_incoming(incoming));
        format!("http://{addr}")
    }

    /// Through the proxy, the relay answers for the guardian KPs are
    /// provisioning, not for the active guardian its node-facing surface fronts.
    #[tokio::test]
    async fn a_proxy_answers_with_its_provisioning_target() {
        let endpoint = serve(
            Server::builder()
                .add_service(GuardianServiceServer::new(Guardian(0xA)))
                .add_service(GuardianRelayServiceServer::new(Relay(0xB))),
        )
        .await;

        let info = ceremony_guardian_info_pb(&endpoint).await.unwrap();
        assert_eq!(info.signing_pub_key.unwrap().as_ref(), &[0xB; 32]);
    }

    #[tokio::test]
    async fn a_bare_guardian_answers_for_itself() {
        let endpoint =
            serve(Server::builder().add_service(GuardianServiceServer::new(Guardian(0xA)))).await;

        let info = ceremony_guardian_info_pb(&endpoint).await.unwrap();
        assert_eq!(info.signing_pub_key.unwrap().as_ref(), &[0xA; 32]);
    }
}
