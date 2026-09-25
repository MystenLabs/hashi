// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::EnclaveLifecycle;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::OperatorInitInfo;
use hashi_types::guardian::OperatorInitMode;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::WithdrawStage;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_relay_service_client::GuardianRelayServiceClient;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::Code;
use tonic::transport::Channel;
use tonic::transport::Endpoint;

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
/// rotation); a bare guardian answers for itself. Whichever answered must be
/// a ceremony enclave, so an endpoint that hides the relay and answers for
/// the active guardian is named rather than blamed downstream.
pub async fn verified_ceremony_guardian_info(
    endpoint: &str,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let (info_pb, rpc) = ceremony_guardian_info_pb(endpoint).await?;
    let verified = verify_info_response(info_pb, current_build)?;
    ensure!(
        matches!(verified.info.lifecycle, EnclaveLifecycle::Ceremony(_)),
        "{rpc} at {endpoint} answers for a guardian in lifecycle {:?}, not a ceremony \
         guardian: a proxy must route GuardianRelayService and front the ceremony guardian \
         as its provisioning target; a bare endpoint must be the ceremony guardian itself",
        verified.info.lifecycle
    );
    Ok(verified)
}

/// `GetProvisioningTargetInfo` from `endpoint`, or its `GetGuardianInfo` when
/// it serves no relay, with the RPC that answered. A bare guardian answers
/// `Unimplemented`; so does an ingress that hides the relay service (tonic
/// maps an HTTP 404 to it), which the caller's lifecycle check catches.
async fn ceremony_guardian_info_pb(
    endpoint: &str,
) -> anyhow::Result<(pb::GetGuardianInfoResponse, &'static str)> {
    // `Endpoint::new`, not `from_shared`: only the former enables TLS for an
    // https endpoint (the relay), as every `Client::connect` in this crate does.
    let channel = Endpoint::new(endpoint.to_string())
        .with_context(|| format!("invalid ceremony guardian endpoint {endpoint}"))?
        .connect()
        .await
        .with_context(|| format!("connect to ceremony guardian at {endpoint}"))?;
    match GuardianRelayServiceClient::new(channel.clone())
        .get_provisioning_target_info(pb::GetProvisioningTargetInfoRequest {})
        .await
    {
        Ok(response) => Ok((response.into_inner(), "GetProvisioningTargetInfo")),
        Err(status) if status.code() == Code::Unimplemented => Ok((
            GuardianServiceClient::new(channel)
                .get_guardian_info(pb::GetGuardianInfoRequest {})
                .await
                .context("GetGuardianInfo RPC failed")?
                .into_inner(),
            "GetGuardianInfo",
        )),
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

/// Compare completed OI facts with the live response immediately after OI.
/// Later-stage fields are checked on the live response, not stored in the log.
pub fn ensure_oi_info_matches_post_init(
    oi_info: &OperatorInitInfo,
    live_info: &GuardianInfo,
) -> anyhow::Result<()> {
    let expected_lifecycle = match &oi_info.initialization {
        OperatorInitMode::Ceremony => CeremonyStage::OperatorInitialized.into(),
        OperatorInitMode::Withdraw(_) => WithdrawStage::OperatorInitialized.into(),
    };
    ensure!(
        live_info.lifecycle == expected_lifecycle,
        "S3 OI mode {:?} does not match live post-OperatorInit lifecycle {:?}",
        oi_info.mode(),
        live_info.lifecycle
    );
    ensure!(
        live_info.deployment_info.as_ref() == Some(&oi_info.deployment_info),
        "S3 OI deployment differs from live post-OperatorInit GuardianInfo"
    );
    ensure!(
        live_info.encryption_pubkey == oi_info.encryption_pubkey,
        "S3 OI encryption pubkey differs from live post-OperatorInit GuardianInfo"
    );
    ensure!(
        live_info.enclave_btc_pubkey.is_none()
            && live_info.limiter_state.is_none()
            && live_info.current_committee_epoch.is_none(),
        "live post-OperatorInit GuardianInfo contains later-stage state"
    );
    match &oi_info.initialization {
        OperatorInitMode::Ceremony => ensure!(
            live_info.secret_sharing_instance.is_none()
                && live_info.config_hash.is_none()
                && live_info.limiter_config.is_none()
                && live_info.hashi_object_id.is_none()
                && live_info.mpc_master_g.is_none()
                && live_info.genesis_state_hash.is_none(),
            "live ceremony GuardianInfo contains withdraw initialization state"
        ),
        OperatorInitMode::Withdraw(withdraw) => {
            ensure!(
                live_info.secret_sharing_instance.as_ref()
                    == Some(&withdraw.secret_sharing_instance),
                "S3 OI secret-sharing instance differs from live post-OperatorInit GuardianInfo"
            );
            ensure!(
                live_info.config_hash == Some(withdraw.config_hash),
                "S3 OI config_hash differs from live post-OperatorInit GuardianInfo"
            );
            ensure!(
                live_info.limiter_config == Some(withdraw.limiter_config),
                "S3 OI limiter config differs from live post-OperatorInit GuardianInfo"
            );
            ensure!(
                live_info.hashi_object_id == Some(withdraw.hashi_object_id),
                "S3 OI Hashi object ID differs from live post-OperatorInit GuardianInfo"
            );
            ensure!(
                live_info.mpc_master_g == Some(withdraw.mpc_master_g),
                "S3 OI MPC master G differs from live post-OperatorInit GuardianInfo"
            );
            ensure!(
                live_info.genesis_state_hash == withdraw.genesis_state_hash,
                "S3 OI genesis_state_hash differs from live post-OperatorInit GuardianInfo"
            );
        }
    }
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

    #[test]
    fn post_init_comparison_preserves_withdraw_bindings_and_stage_checks() {
        let mut oi = OperatorInitInfo::mock_for_testing();
        for genesis_state_hash in [None, Some([3; 32])] {
            let OperatorInitMode::Withdraw(withdraw) = &mut oi.initialization else {
                unreachable!();
            };
            withdraw.genesis_state_hash = genesis_state_hash;
            let live = GuardianInfo {
                lifecycle: WithdrawStage::OperatorInitialized.into(),
                deployment_info: Some(oi.deployment_info.clone()),
                encryption_pubkey: oi.encryption_pubkey.clone(),
                secret_sharing_instance: Some(withdraw.secret_sharing_instance.clone()),
                config_hash: Some(withdraw.config_hash),
                limiter_config: Some(withdraw.limiter_config),
                hashi_object_id: Some(withdraw.hashi_object_id),
                mpc_master_g: Some(withdraw.mpc_master_g),
                genesis_state_hash,
                enclave_btc_pubkey: None,
                limiter_state: None,
                current_committee_epoch: None,
            };
            ensure_oi_info_matches_post_init(&oi, &live).unwrap();
            let mutations: &[fn(&mut GuardianInfo)] = &[
                |info| info.lifecycle = WithdrawStage::ProvisionerInitialized.into(),
                |info| info.lifecycle = CeremonyStage::OperatorInitialized.into(),
                |info| {
                    info.deployment_info
                        .as_mut()
                        .unwrap()
                        .git_revision
                        .push_str("-other")
                },
                |info| info.encryption_pubkey[0] ^= 1,
                |info| info.secret_sharing_instance = None,
                |info| info.config_hash = Some([9; 32]),
                |info| info.limiter_config = None,
                |info| info.hashi_object_id = None,
                |info| info.mpc_master_g = None,
                |info| info.genesis_state_hash = Some([9; 32]),
                |info| {
                    info.enclave_btc_pubkey = Some(
                        hashi_types::bitcoin::create_btc_keypair_for_test(&[1; 32])
                            .x_only_public_key()
                            .0,
                    )
                },
                |info| {
                    info.limiter_state = Some(hashi_types::guardian::LimiterState {
                        num_tokens_available: 0,
                        last_updated_at: 0,
                        next_seq: 0,
                    })
                },
                |info| info.current_committee_epoch = Some(0),
            ];
            for (index, mutate) in mutations.iter().enumerate() {
                let mut changed = live.clone();
                mutate(&mut changed);
                assert!(
                    ensure_oi_info_matches_post_init(&oi, &changed).is_err(),
                    "mutation {index}"
                );
            }
        }
    }

    #[test]
    fn post_init_comparison_accepts_ceremony_without_withdraw_state() {
        let mut oi = OperatorInitInfo::mock_for_testing();
        oi.initialization = OperatorInitMode::Ceremony;
        let mut live = GuardianInfo::mock_for_testing();
        live.lifecycle = CeremonyStage::OperatorInitialized.into();
        live.deployment_info = Some(oi.deployment_info.clone());
        live.encryption_pubkey = oi.encryption_pubkey.clone();
        ensure_oi_info_matches_post_init(&oi, &live).unwrap();
        live.lifecycle = CeremonyStage::Uninitialized.into();
        assert!(ensure_oi_info_matches_post_init(&oi, &live).is_err());
        live.lifecycle = CeremonyStage::OperatorInitialized.into();
        live.config_hash = Some([2; 32]);
        assert!(ensure_oi_info_matches_post_init(&oi, &live).is_err());
    }

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

        let (info, rpc) = ceremony_guardian_info_pb(&endpoint).await.unwrap();
        assert_eq!(info.signing_pub_key.unwrap().as_ref(), &[0xB; 32]);
        assert_eq!(rpc, "GetProvisioningTargetInfo");
    }

    #[tokio::test]
    async fn a_bare_guardian_answers_for_itself() {
        let endpoint =
            serve(Server::builder().add_service(GuardianServiceServer::new(Guardian(0xA)))).await;

        let (info, rpc) = ceremony_guardian_info_pb(&endpoint).await.unwrap();
        assert_eq!(info.signing_pub_key.unwrap().as_ref(), &[0xA; 32]);
        assert_eq!(rpc, "GetGuardianInfo");
    }
}
