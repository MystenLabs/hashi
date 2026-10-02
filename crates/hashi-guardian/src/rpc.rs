// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::GuardianService;
use hashi_types::guardian::proto_conversions;
use hashi_types::guardian::BatchProvisionerRotateKpSetRequest;
use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::*;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SignedStandardWithdrawalRequestWire;
use hashi_types::proto;
use tonic::Request;
use tonic::Response;
use tonic::Status;

#[derive(Clone)]
pub struct GuardianGrpc {
    pub service: GuardianService,
}

fn to_status(e: GuardianError) -> Status {
    tracing::error!(error = ?e, "Guardian RPC failed");
    match e {
        InvalidInputs(msg) => Status::invalid_argument(msg),
        Unauthenticated(msg) => Status::unauthenticated(msg),
        BuildNotAllowlisted(msg) | BuildNotCurrent(msg) => Status::failed_precondition(msg),
        LifecycleMismatch { expected, actual } => Status::failed_precondition(format!(
            "expected enclave lifecycle {expected:?}, but enclave is {actual:?}"
        )),
        // Guardian reserves `Aborted` and `ResourceExhausted` exclusively for
        // limiter sequence mismatches and rate limiting, respectively, so
        // Hashi can classify them without parsing error messages.
        LimiterSequenceMismatch { expected, actual } => Status::aborted(format!(
            "limiter sequence mismatch: expected {expected}, got {actual}"
        )),
        CurrentSessionHeartbeatNotLive {
            session_id,
            heartbeat_age_secs,
            retry_after_secs,
        } => {
            let detail = match heartbeat_age_secs {
                Some(heartbeat_age_secs) => {
                    format!("last heartbeated {heartbeat_age_secs}s ago")
                }
                None => "has no heartbeat in the recent scan".into(),
            };
            Status::unavailable(format!(
                "operator_activate blocked: current guardian session {session_id} {detail}; \
                 expected a heartbeat within {}s; retry in {retry_after_secs}s",
                crate::LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE.as_secs()
            ))
        }
        PriorSessionHeartbeatStillRecent {
            session_id,
            heartbeat_age_secs,
            required_quiet_secs,
        } => Status::unavailable(format!(
            "operator_activate blocked: prior guardian session {session_id} heartbeated \
             {heartbeat_age_secs}s ago; required quiet period is {required_quiet_secs}s; retry in \
             {}s",
            required_quiet_secs.saturating_sub(heartbeat_age_secs)
        )),
        RateLimitExceeded => Status::resource_exhausted("Rate limit exceeded"),
        S3Error(msg) => Status::internal(msg),
        InvalidS3Log(msg) => Status::internal(msg),
        InternalError(msg) => Status::internal(msg),
        Unavailable(msg) => Status::unavailable(msg),
    }
}

#[tonic::async_trait]
impl proto::guardian_service_server::GuardianService for GuardianGrpc {
    async fn get_guardian_info(
        &self,
        _request: Request<proto::GetGuardianInfoRequest>,
    ) -> anyhow::Result<Response<proto::GetGuardianInfoResponse>, Status> {
        let resp = self.service.get_guardian_info().await.map_err(to_status)?;

        let resp_pb = proto_conversions::get_guardian_info_response_to_pb(resp);

        Ok(Response::new(resp_pb))
    }

    async fn get_attested_guardian_info(
        &self,
        _request: Request<proto::GetAttestedGuardianInfoRequest>,
    ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
        let resp = self
            .service
            .get_attested_guardian_info()
            .await
            .map_err(to_status)?;
        Ok(Response::new(
            proto_conversions::get_attested_guardian_info_response_to_pb(resp),
        ))
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> anyhow::Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        let domain_req: SetupNewKeyRequest = request.into_inner().try_into().map_err(to_status)?;

        let signed = self
            .service
            .setup_new_key(domain_req)
            .await
            .map_err(to_status)?;

        let resp = proto_conversions::setup_new_key_response_signed_to_pb(signed);

        Ok(Response::new(resp))
    }

    async fn confirm_ceremony(
        &self,
        request: Request<proto::SignedCeremonyConfirmationRequest>,
    ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
        let domain_req: KpSigned<CeremonyConfirmationRequest> =
            request.into_inner().try_into().map_err(to_status)?;
        let response = self
            .service
            .confirm_ceremony(domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(
            proto_conversions::ceremony_confirmation_response_to_pb(response),
        ))
    }

    async fn rotate_kp_set(
        &self,
        request: Request<proto::BatchProvisionerRotateKpSetRequest>,
    ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
        let domain_req: BatchProvisionerRotateKpSetRequest =
            request.into_inner().try_into().map_err(to_status)?;

        let signed = self
            .service
            .rotate_kp_set(domain_req)
            .await
            .map_err(to_status)?;

        let resp = proto_conversions::rotate_kp_set_response_signed_to_pb(signed);

        Ok(Response::new(resp))
    }

    // operator_init is available in both ceremony and withdraw modes.
    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        let domain_req: OperatorInitRequest = request.into_inner().try_into().map_err(to_status)?;

        self.service
            .operator_init(domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorInitResponse {}))
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::BatchProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        let domain_req = request.into_inner().try_into().map_err(to_status)?;

        self.service
            .provisioner_init(domain_req)
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
        let signed = self
            .service
            .provisioner_rotate_cert(domain_req)
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

        self.service
            .operator_activate(domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorActivateResponse {}))
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        // proto to domain
        let domain_req = SignedStandardWithdrawalRequestWire::try_from(request.into_inner())
            .map_err(to_status)?;

        // core withdraw call
        let response = self
            .service
            .standard_withdrawal(domain_req)
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
        let signed = HashiSigned::<CommitteeTransitionRequest>::try_from(request.into_inner())
            .map_err(to_status)?;
        let current_committee_epoch = self
            .service
            .update_committee(signed)
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
            .map(HashiSigned::<CommitteeTransitionRequest>::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_status)?;
        let current_committee_epoch = self
            .service
            .update_committee_chain(transitions)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::UpdateCommitteeResponse {
            current_committee_epoch: Some(current_committee_epoch),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::activate_enclave_for_testing;
    use crate::test_utils::decrypt_kp_shares;
    use crate::test_utils::finalize_enclave;
    use crate::test_utils::mock_kp_certs_roster_with_secrets;
    use crate::test_utils::mock_logger_capturing;
    use crate::test_utils::CapturedPuts;
    use crate::test_utils::MockKpSecretKeys;
    use crate::test_utils::OperatorInitTestArgs;
    use crate::Enclave;
    use hashi_types::guardian::CeremonyArtifacts;
    use hashi_types::guardian::CeremonyState;
    use hashi_types::guardian::KpCertRoster;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::ProvisionerInitRequest;
    use hashi_types::guardian::ProvisionerRotateKpSetRequest;
    use hashi_types::guardian::SecretSharingParams;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use proto::guardian_service_server::GuardianService;

    // Domain setup trusts only the private test issuer. Sending the same bundles
    // through RPC must still fail the production-pinned Yubico verifier.
    async fn pending_ceremony() -> (
        GuardianGrpc,
        CeremonyState,
        KpCertRoster,
        MockKpSecretKeys,
        CapturedPuts,
    ) {
        let (roster, secrets) = mock_kp_certs_roster_with_secrets(3);
        let (logger, puts) = mock_logger_capturing();
        let mut enclave = Enclave::create_operator_initialized_ceremony(logger);
        let response = crate::ceremony_mode::setup::setup_new_key(
            &mut enclave,
            SetupNewKeyRequest::new(roster.clone(), 3, 2).unwrap(),
        )
        .await
        .unwrap()
        .verify_into_data(&enclave.signing_pubkey())
        .unwrap()
        .response;
        (
            GuardianGrpc {
                service: crate::GuardianService::new(enclave),
            },
            response.into(),
            roster,
            secrets,
            puts,
        )
    }

    #[tokio::test]
    async fn guardian_info_rpcs_separate_attestation_from_ordinary_info() {
        let enclave = Enclave::create_with_random_keys();
        let expected_info = enclave.info();
        let signing_pubkey = enclave.signing_pubkey();
        let rpc = GuardianGrpc {
            service: crate::GuardianService::new(enclave),
        };

        let response = rpc
            .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        let info = hashi_types::guardian::GuardianResponse::<
            hashi_types::guardian::GuardianInfo,
        >::try_from(response)
        .unwrap();
        assert_eq!(info.response, expected_info);
        assert_eq!(info.response.signing_pub_key, signing_pubkey);

        let response = rpc
            .get_attested_guardian_info(Request::new(proto::GetAttestedGuardianInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(response.attestation.is_some());
        let signed_info = hashi_types::guardian::GuardianSignedResponse::<
            hashi_types::guardian::GuardianInfo,
        >::try_from(response.signed_info.unwrap())
        .unwrap();
        assert_eq!(
            signed_info
                .verify_signature(&signing_pubkey)
                .unwrap()
                .response,
            expected_info
        );
    }

    #[tokio::test]
    async fn setup_rpc_rejects_missing_attestation_without_starting_ceremony() {
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            service: crate::GuardianService::new(Enclave::create_operator_initialized_ceremony(
                logger,
            )),
        };
        let before_puts = puts.lock().unwrap().clone();
        let mut request = proto_conversions::setup_new_key_request_to_pb(
            SetupNewKeyRequest::new(mock_kp_certs_roster_with_secrets(3).0, 3, 2).unwrap(),
        );
        request.key_provisioner_pgp_certs[0].device_pem.clear();

        let error = rpc.setup_new_key(Request::new(request)).await.unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(rpc
            .service
            .enclave_for_testing()
            .await
            .state
            .pending_ceremony()
            .is_err());
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn confirmation_rpc_rejects_untrusted_signer_without_recording_confirmation() {
        let (rpc, state, roster, secrets, puts) = pending_ceremony().await;
        let cert = roster.iter().next().unwrap().clone();
        let request = {
            let enclave = rpc.service.enclave_for_testing().await;
            CeremonyConfirmationRequest::new(
                enclave.s3_session_id(),
                CeremonyArtifacts {
                    deployment: enclave.config.deployment().unwrap().clone(),
                    ceremony_state: state,
                }
                .digest(),
            )
        };
        let signature = sign_detached_in_process(
            &secrets[&cert.fingerprint().to_hex()],
            &KpSigned::signed_bytes(&request),
        );
        let signed = KpSigned::from_parts(request.clone(), cert, signature);
        signed.verify_signature().unwrap();
        let previous_cert = roster.iter().nth(1).unwrap().clone();
        let previous_signature = sign_detached_in_process(
            &secrets[&previous_cert.fingerprint().to_hex()],
            &KpSigned::signed_bytes(&request),
        );
        crate::ceremony_mode::confirm::confirm_ceremony(
            &mut *rpc.service.enclave_for_testing().await,
            KpSigned::from_parts(request, previous_cert, previous_signature),
        )
        .await
        .unwrap();
        let before = rpc
            .service
            .enclave_for_testing()
            .await
            .state
            .pending_ceremony()
            .unwrap()
            .status()
            .unwrap();
        let before_puts = puts.lock().unwrap().clone();

        let error = rpc
            .confirm_ceremony(Request::new(signed.into()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let after = rpc
            .service
            .enclave_for_testing()
            .await
            .state
            .pending_ceremony()
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(
            (after.have, after.need, after.completed),
            (before.have, before.need, before.completed)
        );
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn provision_rpc_rejects_untrusted_signer_without_installing_key() {
        let (_, state, roster, secrets, _) = pending_ceremony().await;
        let shares = decrypt_kp_shares(&state.encrypted_shares, &secrets);
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            service: crate::GuardianService::new(Enclave::create_operator_initialized_with(
                OperatorInitTestArgs {
                    s3_logger: logger,
                    ceremony_state: state.clone(),
                    ..Default::default()
                },
            )),
        };
        let before = rpc
            .service
            .enclave_for_testing()
            .await
            .state
            .temporary_init_state()
            .unwrap()
            .clone();
        let before_puts = puts.lock().unwrap().clone();
        let submissions = {
            let enclave = rpc.service.enclave_for_testing().await;
            shares
                .iter()
                .take(2)
                .map(|share| {
                    let recipient = &state
                        .encrypted_shares
                        .iter()
                        .find(|entry| entry.id == share.id)
                        .unwrap()
                        .recipient_fingerprint;
                    let cert = roster
                        .cert_for_fingerprint(&recipient.parse().unwrap())
                        .unwrap()
                        .clone();
                    let request = ProvisionerInitRequest::build_from_share(
                        enclave.s3_session_id(),
                        before.config_hash,
                        before.genesis_state.as_ref().map(|state| state.digest()),
                        share,
                        enclave.encryption_public_key(),
                        &mut rand::thread_rng(),
                    );
                    let signature = sign_detached_in_process(
                        &secrets[&cert.fingerprint().to_hex()],
                        &KpSigned::signed_bytes(&request),
                    );
                    let signed = KpSigned::from_parts(request, cert, signature);
                    signed.verify_signature().unwrap();
                    signed.into()
                })
                .collect()
        };

        let error = rpc
            .provisioner_init(Request::new(proto::BatchProvisionerInitRequest {
                submissions,
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(!rpc
            .service
            .enclave_for_testing()
            .await
            .config
            .is_enclave_btc_keypair_set());
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn cert_rotation_rpc_rejects_untrusted_replacement_without_writing_rotation() {
        let (_, state, roster, secrets, _) = pending_ceremony().await;
        let shares = decrypt_kp_shares(&state.encrypted_shares, &secrets);
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            service: crate::GuardianService::new(Enclave::create_operator_initialized_with(
                OperatorInitTestArgs {
                    s3_logger: logger,
                    ceremony_state: state.clone(),
                    ..Default::default()
                },
            )),
        };
        finalize_enclave(&mut *rpc.service.enclave_for_testing().await).unwrap();
        let (_, committee) = StandardWithdrawalRequest::mock_signed_and_committee_for_testing(
            bitcoin::Network::Regtest,
        );
        activate_enclave_for_testing(
            &mut *rpc.service.enclave_for_testing().await,
            committee,
            LimiterConfig {
                refill_rate: 0,
                max_bucket_capacity: 1000,
            },
            LimiterState {
                num_tokens_available: 1000,
                last_updated_at: 0,
                next_seq: 0,
            },
        )
        .unwrap();
        let recipient = &state
            .encrypted_shares
            .iter()
            .find(|entry| entry.id == shares[0].id)
            .unwrap()
            .recipient_fingerprint;
        let cert = roster
            .cert_for_fingerprint(&recipient.parse().unwrap())
            .unwrap()
            .clone();
        let replacement = hashi_types::guardian::test_utils::mock_attested_kp_keypair().0;
        let request = {
            let enclave = rpc.service.enclave_for_testing().await;
            ProvisionerRotateCertRequest::new(
                enclave.s3_session_id(),
                state.cert_seq,
                replacement,
                &shares[0],
                enclave.encryption_public_key(),
                &mut rand::thread_rng(),
            )
        };
        let signature = sign_detached_in_process(
            &secrets[&cert.fingerprint().to_hex()],
            &KpSigned::signed_bytes(&request),
        );
        let signed = KpSigned::from_parts(request, cert, signature);
        signed.verify_signature().unwrap();
        let lifecycle = rpc.service.enclave_for_testing().await.state.lifecycle();
        let before_puts = puts.lock().unwrap().clone();

        // Replacement decoding precedes signer decoding; this does not exercise
        // rejection of the signer certificate or the persisted-state lookup.
        let error = rpc
            .provisioner_rotate_cert(Request::new(signed.into()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            rpc.service.enclave_for_testing().await.state.lifecycle(),
            lifecycle
        );
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn kp_set_rotation_rpc_rejects_untrusted_signer_without_starting_rotation() {
        let (_, state, roster, secrets, _) = pending_ceremony().await;
        let shares = decrypt_kp_shares(&state.encrypted_shares, &secrets);
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            service: crate::GuardianService::new(Enclave::create_operator_initialized_ceremony(
                logger,
            )),
        };
        let submissions = {
            let enclave = rpc.service.enclave_for_testing().await;
            shares
                .iter()
                .take(2)
                .map(|share| {
                    let recipient = &state
                        .encrypted_shares
                        .iter()
                        .find(|entry| entry.id == share.id)
                        .unwrap()
                        .recipient_fingerprint;
                    let cert = roster
                        .cert_for_fingerprint(&recipient.parse().unwrap())
                        .unwrap()
                        .clone();
                    let request = ProvisionerRotateKpSetRequest::build_from_share(
                        enclave.s3_session_id(),
                        enclave.config.deployment().unwrap().digest(),
                        share,
                        enclave.encryption_public_key(),
                        roster.clone(),
                        SecretSharingParams::new(3, 2).unwrap(),
                        &mut rand::thread_rng(),
                    )
                    .unwrap();
                    let signature = sign_detached_in_process(
                        &secrets[&cert.fingerprint().to_hex()],
                        &KpSigned::signed_bytes(&request),
                    );
                    let signed = KpSigned::from_parts(request, cert, signature);
                    signed.verify_signature().unwrap();
                    signed.into()
                })
                .collect()
        };
        let before_puts = puts.lock().unwrap().clone();

        // Signer decoding fails first, so this cannot cover the new roster's
        // attestation admission without a production-accepted signer bundle.
        let error = rpc
            .rotate_kp_set(Request::new(proto::BatchProvisionerRotateKpSetRequest {
                submissions,
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(rpc
            .service
            .enclave_for_testing()
            .await
            .state
            .pending_ceremony()
            .is_err());
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[test]
    fn heartbeat_readiness_errors_have_actionable_status_codes() {
        let missing_error = CurrentSessionHeartbeatNotLive {
            session_id: "current".into(),
            heartbeat_age_secs: None,
            retry_after_secs: 60,
        };
        assert_eq!(missing_error.retry_after_secs(), Some(60));
        let missing = to_status(missing_error);
        assert_eq!(missing.code(), tonic::Code::Unavailable);

        let stale_error = CurrentSessionHeartbeatNotLive {
            session_id: "current".into(),
            heartbeat_age_secs: Some(200),
            retry_after_secs: 60,
        };
        assert_eq!(stale_error.retry_after_secs(), Some(60));
        let stale = to_status(stale_error);
        assert_eq!(stale.code(), tonic::Code::Unavailable);

        let prior_error = PriorSessionHeartbeatStillRecent {
            session_id: "prior".into(),
            heartbeat_age_secs: 30,
            required_quiet_secs: 600,
        };
        assert_eq!(prior_error.retry_after_secs(), Some(570));
        let prior = to_status(prior_error);
        assert_eq!(prior.code(), tonic::Code::Unavailable);
    }
}
