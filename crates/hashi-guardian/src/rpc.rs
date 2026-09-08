// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::info;
use crate::task_spawner;
use crate::Enclave;
use hashi_types::guardian::proto_conversions;
use hashi_types::guardian::AddressValidation;
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

        let signed = task_spawner::setup_new_key(self.enclave.clone(), domain_req)
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
        let response = task_spawner::confirm_ceremony(self.enclave.clone(), domain_req)
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

        let signed = task_spawner::rotate_kp_set(self.enclave.clone(), domain_req)
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

        task_spawner::operator_init(self.enclave.clone(), domain_req)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proto::OperatorInitResponse {}))
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::BatchProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        let domain_req = request.into_inner().try_into().map_err(to_status)?;

        task_spawner::provisioner_init(self.enclave.clone(), domain_req)
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
        let signed = task_spawner::provisioner_rotate_cert(self.enclave.clone(), domain_req)
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

        task_spawner::operator_activate(self.enclave.clone(), domain_req)
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

        // validate address with network
        let network = self.enclave.config.bitcoin_network().map_err(to_status)?;
        let validated_req =
            HashiSigned::<StandardWithdrawalRequest>::validate_addr(domain_req, network)
                .map_err(to_status)?;

        // core withdraw call
        let response = task_spawner::standard_withdrawal(self.enclave.clone(), validated_req)
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
        let current_committee_epoch = task_spawner::update_committee(self.enclave.clone(), signed)
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
        let current_committee_epoch =
            task_spawner::update_committee_chain(self.enclave.clone(), transitions)
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
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::CeremonyState;
    use hashi_types::guardian::KpCertRoster;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::PcrAllowlist;
    use hashi_types::guardian::ProvisionerInitRequest;
    use hashi_types::guardian::ProvisionerRotateKpSetRequest;
    use hashi_types::guardian::SecretSharingParams;
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
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        let response = crate::ceremony_mode::setup::setup_new_key(
            enclave.clone(),
            SetupNewKeyRequest::new(roster.clone(), 3, 2).unwrap(),
        )
        .await
        .unwrap()
        .verify_into_data(&enclave.signing_pubkey())
        .unwrap()
        .response;
        (
            GuardianGrpc { enclave },
            response.into(),
            roster,
            secrets,
            puts,
        )
    }

    #[tokio::test]
    async fn setup_rpc_rejects_missing_attestation_without_starting_ceremony() {
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            enclave: Enclave::create_operator_initialized_ceremony(logger),
        };
        let before_puts = puts.lock().unwrap().clone();
        let mut request = proto_conversions::setup_new_key_request_to_pb(
            SetupNewKeyRequest::new(mock_kp_certs_roster_with_secrets(3).0, 3, 2).unwrap(),
        );
        request.key_provisioner_pgp_certs[0].device_pem.clear();

        let error = rpc.setup_new_key(Request::new(request)).await.unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(rpc.enclave.pending_ceremony().is_err());
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn confirmation_rpc_rejects_untrusted_signer_without_recording_confirmation() {
        let (rpc, state, roster, secrets, puts) = pending_ceremony().await;
        let cert = roster.iter().next().unwrap().clone();
        let request = CeremonyConfirmationRequest::new(rpc.enclave.s3_session_id(), state.digest());
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
            rpc.enclave.clone(),
            KpSigned::from_parts(request, previous_cert, previous_signature),
        )
        .await
        .unwrap();
        let before = rpc.enclave.pending_ceremony().unwrap().status().unwrap();
        let before_puts = puts.lock().unwrap().clone();

        let error = rpc
            .confirm_ceremony(Request::new(signed.into()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let after = rpc.enclave.pending_ceremony().unwrap().status().unwrap();
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
            enclave: Enclave::create_operator_initialized_with(OperatorInitTestArgs {
                s3_logger: logger,
                ceremony_state: state,
                ..Default::default()
            })
            .await,
        };
        let before = rpc.enclave.temporary_init_state().unwrap();
        let before_puts = puts.lock().unwrap().clone();
        let submissions = shares
            .iter()
            .take(2)
            .map(|share| {
                let cert = roster.cert_for_share(share.id).unwrap().clone();
                let request = ProvisionerInitRequest::build_from_share(
                    rpc.enclave.s3_session_id(),
                    before.config_hash,
                    before.genesis_state.as_ref().map(|state| state.digest()),
                    share,
                    rpc.enclave.encryption_public_key(),
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
            .collect();

        let error = rpc
            .provisioner_init(Request::new(proto::BatchProvisionerInitRequest {
                submissions,
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(!rpc.enclave.config.is_enclave_btc_keypair_set());
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn cert_rotation_rpc_rejects_untrusted_replacement_without_writing_rotation() {
        let (_, state, roster, secrets, _) = pending_ceremony().await;
        let shares = decrypt_kp_shares(&state.encrypted_shares, &secrets);
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            enclave: Enclave::create_operator_initialized_with(OperatorInitTestArgs {
                s3_logger: logger,
                ceremony_state: state.clone(),
                ..Default::default()
            })
            .await,
        };
        finalize_enclave(&rpc.enclave).unwrap();
        let (_, committee) = StandardWithdrawalRequest::mock_signed_and_committee_for_testing(
            bitcoin::Network::Regtest,
        );
        activate_enclave_for_testing(
            &rpc.enclave,
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
        let cert = roster.cert_for_share(shares[0].id).unwrap().clone();
        let replacement = hashi_types::guardian::test_utils::mock_attested_kp_keypair().0;
        let request = ProvisionerRotateCertRequest::new(
            rpc.enclave.s3_session_id(),
            state.cert_seq,
            replacement,
            &shares[0],
            rpc.enclave.encryption_public_key(),
            &mut rand::thread_rng(),
        );
        let signature = sign_detached_in_process(
            &secrets[&cert.fingerprint().to_hex()],
            &KpSigned::signed_bytes(&request),
        );
        let signed = KpSigned::from_parts(request, cert, signature);
        signed.verify_signature().unwrap();
        let lifecycle = rpc.enclave.lifecycle();
        let before_puts = puts.lock().unwrap().clone();

        // Replacement decoding precedes signer decoding; this does not exercise
        // rejection of the signer certificate or the persisted-state lookup.
        let error = rpc
            .provisioner_rotate_cert(Request::new(signed.into()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(rpc.enclave.lifecycle(), lifecycle);
        assert_eq!(*puts.lock().unwrap(), before_puts);
    }

    #[tokio::test]
    async fn kp_set_rotation_rpc_rejects_untrusted_signer_without_starting_rotation() {
        let (_, state, roster, secrets, _) = pending_ceremony().await;
        let shares = decrypt_kp_shares(&state.encrypted_shares, &secrets);
        let (logger, puts) = mock_logger_capturing();
        let rpc = GuardianGrpc {
            enclave: Enclave::create_operator_initialized_ceremony(logger),
        };
        let submissions = shares
            .iter()
            .take(2)
            .map(|share| {
                let cert = roster.cert_for_share(share.id).unwrap().clone();
                let request = ProvisionerRotateKpSetRequest::build_from_share(
                    rpc.enclave.s3_session_id(),
                    PcrAllowlist::new(BuildPcrs::new("test", vec![0]), []).unwrap(),
                    share,
                    rpc.enclave.encryption_public_key(),
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
            .collect();
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
        assert!(rpc.enclave.pending_ceremony().is_err());
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
