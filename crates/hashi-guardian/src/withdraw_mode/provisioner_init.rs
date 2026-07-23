// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `provisioner_init` (withdraw mode): verifies the current KPs' signed share
//! submissions and reconstructs the BTC key once threshold shares are present.
//! Runs after the shared `crate::operator_init`.

use crate::withdraw_mode::genesis::ensure_no_serving_committee;
use crate::Enclave;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_verify_shares;
use hashi_types::guardian::crypto::k256_sk_to_btc_keypair;
use hashi_types::guardian::InitLogMessage::PIEnclaveFullyInitialized;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Validated provisioner-init state ready for its fail-stop commit.
///
/// Construction performs every request-dependent fallible operation without
/// mutating the enclave. Once built, installation must either complete or abort
/// the enclave process.
struct PIInstall {
    enclave_btc_keypair: bitcoin::secp256k1::Keypair,
    genesis_log: Option<GenesisLogMessage>,
    completion_log: InitLogMessage,
}

impl PIInstall {
    async fn from_request(
        enclave: &Enclave,
        request: ProvisionerInitRequest,
    ) -> GuardianResult<Self> {
        let initialization = enclave
            .temporary_init_state()
            .expect("temporary initialization state should be set after operator_init");
        let ceremony_state = &initialization.ceremony_state;
        let instance = &ceremony_state.secret_sharing_instance;
        let threshold = instance.threshold();
        let sharing_seq = instance.sharing_seq();
        let config_hash = initialization.config_hash;
        let session_id = enclave.s3_session_id();
        let genesis_state = initialization.genesis_state.clone();
        let genesis_state_hash = genesis_state.as_ref().map(GenesisState::digest);

        let encrypted_shares = verify_signed_submissions(
            &request,
            &session_id,
            &config_hash,
            genesis_state_hash,
            &ceremony_state.encrypted_shares,
        )?;
        let shares = decrypt_verify_shares(
            &encrypted_shares,
            enclave.encryption_secret_key(),
            None,
            instance.commitments(),
            threshold,
        )?;
        info!("Verified {} shares (threshold {threshold}).", shares.len());

        info!("Threshold reached, combining shares.");
        let enclave_k256_sk = combine_shares(&shares, threshold)?;
        let enclave_btc_keypair = k256_sk_to_btc_keypair(&enclave_k256_sk);
        let enclave_btc_pubkey = enclave_btc_keypair.x_only_public_key().0;
        let share_ids = shares.iter().map(|share| share.id).collect();

        if genesis_state.is_some() {
            ensure_no_serving_committee(enclave).await?;
        }

        Ok(Self {
            enclave_btc_keypair,
            genesis_log: genesis_state.map(|state| GenesisLogMessage {
                committee: state.into_committee(),
            }),
            completion_log: PIEnclaveFullyInitialized {
                sharing_seq,
                share_ids,
                enclave_btc_pubkey,
            },
        })
    }
}

/// Receives the current KPs' signed share submissions in one batch. The relay
/// may pre-verify them as a DoS guard, but the enclave authoritatively verifies
/// each signature and session/config binding before decrypting and
/// commitment-checking any share.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    enclave.require_lifecycle(
        "provisioner_init",
        WithdrawStage::OperatorInitialized.into(),
    )?;
    info!("Lifecycle stage validated.");

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----
    let install = PIInstall::from_request(&enclave, request).await?;

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    info!("Committing enclave BTC keypair.");
    commit_provisioner_init(&enclave, install).await;

    info!("Provisioner initialization complete.");
    Ok(())
}

/// Install the prepared key, durably mark PI complete, and then expose the new
/// lifecycle. This fail-stop phase never returns an error after mutation begins.
async fn commit_provisioner_init(enclave: &Enclave, install: PIInstall) {
    enclave
        .config
        .set_btc_keypair(install.enclave_btc_keypair)
        .expect("Unable to set enclave keypair");

    if let Some(genesis_log) = install.genesis_log {
        let epoch = genesis_log.committee.epoch;
        enclave
            .log_genesis(genesis_log)
            .await
            .expect("Unable to log KP-authorized genesis state");
        info!(epoch, "KP-authorized genesis committee written");
    }

    // OA waits for this durable marker before activating the enclave.
    enclave
        .log_init(install.completion_log)
        .await
        .expect("Unable to log EnclaveFullyInitialized");

    enclave
        .advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())
        .expect("provisioner_init should advance an operator-initialized enclave");
}

fn verify_signed_submissions(
    request: &ProvisionerInitRequest,
    live_session_id: &SessionID,
    live_config_hash: &[u8; 32],
    live_genesis_state_hash: Option<[u8; 32]>,
    expected_kp_encrypted_shares: &KPEncryptedSharesRoster,
) -> GuardianResult<Vec<GuardianEncryptedShare>> {
    request
        .0
        .iter()
        .map(|signed| {
            let signer_fingerprint = signed.signer_fingerprint().to_hex();
            signed
                .verify_signature()
                .map_err(|error| GuardianError::Unauthenticated(error.to_string()))?;
            let submission = &signed.data;

            if submission.expected_session_id() != live_session_id.as_str() {
                return Err(GuardianError::InvalidInputs(format!(
                    "PI submission expected guardian session {}, live session is {}",
                    submission.expected_session_id(),
                    live_session_id
                )));
            }
            if submission.expected_config_hash() != live_config_hash {
                return Err(GuardianError::InvalidInputs(format!(
                    "PI submission expected config hash {}, live config hash is {}",
                    hex::encode(submission.expected_config_hash()),
                    hex::encode(live_config_hash)
                )));
            }
            if submission.expected_genesis_state_hash() != live_genesis_state_hash {
                return Err(GuardianError::InvalidInputs(format!(
                    "PI submission expected genesis state hash {:?}, live genesis state hash is {:?}",
                    submission.expected_genesis_state_hash().map(hex::encode),
                    live_genesis_state_hash.map(hex::encode)
                )));
            }

            let share_id = submission.encrypted_share().id;
            let (assigned_share, _) = expected_kp_encrypted_shares
                .find_by_fingerprint(&signer_fingerprint)
                .ok_or_else(|| {
                    GuardianError::InvalidInputs(format!(
                        "PI submission signer {signer_fingerprint} is not in the current KP \
                         encrypted-share roster"
                    ))
                })?;
            if assigned_share.id != share_id {
                return Err(GuardianError::InvalidInputs(format!(
                    "PI submission signer {signer_fingerprint} is assigned to KP share id {}, \
                     not submitted share id {}",
                    assigned_share.id.get(),
                    share_id.get()
                )));
            }

            info!(
                share_id = share_id.get(),
                signer_fingerprint, "verified signed PI submission"
            );
            Ok(submission.encrypted_share().clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::GuardianError::InvalidInputs;
    use hashi_types::guardian::GuardianError::LifecycleMismatch;
    use hashi_types::guardian::GuardianError::Unauthenticated;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;
    use k256::SecretKey;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    struct TestContext {
        shares: Vec<Share>,
        enclave: Arc<Enclave>,
        captures: crate::test_utils::CapturedPuts,
        kp_keys: Vec<(PgpPublicCert, String)>,
        alternate_first_kp_key: (PgpPublicCert, String),
    }

    async fn setup() -> TestContext {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let share_commitments = ShareCommitments::from_shares(&shares).unwrap();
        let kp_keys = (0..TEST_N)
            .map(|_| {
                let (cert, secret) = mock_pgp_keypair();
                (PgpPublicCert::new(cert).unwrap(), secret)
            })
            .collect::<Vec<_>>();
        let (alternate_cert, alternate_secret) = mock_pgp_keypair();
        let alternate_first_kp_key = (
            PgpPublicCert::new(alternate_cert).unwrap(),
            alternate_secret,
        );
        let kp_encrypted_shares = KPEncryptedSharesRoster::new(
            kp_keys
                .iter()
                .enumerate()
                .map(|(i, (cert, _))| KPEncryptedShares {
                    id: std::num::NonZeroU16::new((i + 1) as u16).unwrap(),
                    ciphertexts_by_fingerprint: if i == 0 {
                        [
                            (cert.fingerprint().to_hex(), "dummy".into()),
                            (
                                alternate_first_kp_key.0.fingerprint().to_hex(),
                                "dummy".into(),
                            ),
                        ]
                        .into_iter()
                        .collect()
                    } else {
                        [(cert.fingerprint().to_hex(), "dummy".into())]
                            .into_iter()
                            .collect()
                    },
                })
                .collect(),
        )
        .unwrap();
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default()
                .with_s3_logger(logger)
                .with_commitments(share_commitments)
                .with_kp_encrypted_shares(kp_encrypted_shares),
        )
        .await;
        TestContext {
            shares,
            enclave,
            captures,
            kp_keys,
            alternate_first_kp_key,
        }
    }

    impl TestContext {
        fn config_hash(&self) -> [u8; 32] {
            self.enclave
                .temporary_init_state()
                .expect("test enclave should retain temporary initialization state")
                .config_hash
        }

        fn signed_submission(
            &self,
            share: &Share,
            signer_index: usize,
            expected_session_id: SessionID,
            expected_config_hash: [u8; 32],
        ) -> KpSigned<SingleProvisionerInitRequest> {
            self.signed_submission_with_key_and_genesis_hash(
                share,
                &self.kp_keys[signer_index],
                expected_session_id,
                expected_config_hash,
                self.enclave
                    .temporary_init_state()
                    .expect("test enclave should retain temporary initialization state")
                    .genesis_state
                    .as_ref()
                    .map(GenesisState::digest),
            )
        }

        fn signed_submission_with_key(
            &self,
            share: &Share,
            signer: &(PgpPublicCert, String),
            expected_session_id: SessionID,
            expected_config_hash: [u8; 32],
        ) -> KpSigned<SingleProvisionerInitRequest> {
            self.signed_submission_with_key_and_genesis_hash(
                share,
                signer,
                expected_session_id,
                expected_config_hash,
                self.enclave
                    .temporary_init_state()
                    .expect("test enclave should retain temporary initialization state")
                    .genesis_state
                    .as_ref()
                    .map(GenesisState::digest),
            )
        }

        fn signed_submission_with_genesis_hash(
            &self,
            share: &Share,
            signer_index: usize,
            expected_session_id: SessionID,
            expected_config_hash: [u8; 32],
            expected_genesis_state_hash: Option<[u8; 32]>,
        ) -> KpSigned<SingleProvisionerInitRequest> {
            self.signed_submission_with_key_and_genesis_hash(
                share,
                &self.kp_keys[signer_index],
                expected_session_id,
                expected_config_hash,
                expected_genesis_state_hash,
            )
        }

        fn signed_submission_with_key_and_genesis_hash(
            &self,
            share: &Share,
            signer: &(PgpPublicCert, String),
            expected_session_id: SessionID,
            expected_config_hash: [u8; 32],
            expected_genesis_state_hash: Option<[u8; 32]>,
        ) -> KpSigned<SingleProvisionerInitRequest> {
            let request = SingleProvisionerInitRequest::build_from_share(
                expected_session_id,
                expected_config_hash,
                expected_genesis_state_hash,
                share,
                self.enclave.encryption_public_key(),
                &mut rand::thread_rng(),
            );
            let (cert, secret) = signer;
            KpSigned {
                signature: sign_detached_in_process(secret, &KpSigned::signed_bytes(&request)),
                data: request,
                signer_cert: cert.clone(),
            }
        }

        fn request(&self, shares: &[Share]) -> ProvisionerInitRequest {
            let session_id = self.enclave.s3_session_id();
            let config_hash = self.config_hash();
            let submissions = shares
                .iter()
                .map(|share| {
                    self.signed_submission(
                        share,
                        usize::from(share.id.get() - 1),
                        session_id.clone(),
                        config_hash,
                    )
                })
                .collect();
            ProvisionerInitRequest(submissions)
        }

        async fn provision(&self, request: ProvisionerInitRequest) -> GuardianResult<()> {
            provisioner_init(self.enclave.clone(), request).await
        }
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let ctx = setup().await;
        ctx.provision(ctx.request(&ctx.shares[..TEST_T]))
            .await
            .expect("ok");
        assert!(
            ctx.enclave.config.is_enclave_btc_keypair_set(),
            "Bitcoin key should be set after threshold"
        );
        assert_eq!(
            ctx.enclave.lifecycle(),
            WithdrawStage::ProvisionerInitialized.into(),
            "provisioner init complete"
        );
        let captured = ctx.captures.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "provisioner init should write one record"
        );
        let record: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        let VersionedLogMessage::V2(LogMessage::Init(message)) = record.message else {
            panic!("expected V2 init record");
        };
        assert_eq!(
            captured[0].0,
            message.object_key(&ctx.enclave.s3_session_id())
        );
        let PIEnclaveFullyInitialized {
            sharing_seq,
            share_ids,
            enclave_btc_pubkey,
        } = *message
        else {
            panic!("expected provisioner-init completion record");
        };
        assert_eq!(sharing_seq, 0);
        assert_eq!(
            share_ids,
            ctx.shares[..TEST_T]
                .iter()
                .map(|share| share.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            enclave_btc_pubkey,
            ctx.enclave.config.enclave_btc_pubkey().unwrap()
        );
    }

    #[tokio::test]
    async fn accepts_alternate_cert_assigned_to_same_share() {
        let ctx = setup().await;
        let mut submissions = vec![ctx.signed_submission_with_key(
            &ctx.shares[0],
            &ctx.alternate_first_kp_key,
            ctx.enclave.s3_session_id(),
            ctx.config_hash(),
        )];
        submissions.extend(ctx.request(&ctx.shares[1..TEST_T]).0);

        ctx.provision(ProvisionerInitRequest(submissions))
            .await
            .expect("either cert assigned to the share should authorize PI");
    }

    #[tokio::test]
    async fn rejects_second_call_after_complete() {
        let ctx = setup().await;
        ctx.provision(ctx.request(&ctx.shares[..TEST_T]))
            .await
            .expect("ok");

        let err = ctx
            .provision(ctx.request(&ctx.shares[..TEST_T]))
            .await
            .expect_err("should reject");
        assert!(matches!(err, LifecycleMismatch { .. }));
    }

    #[tokio::test]
    async fn rejects_below_threshold() {
        let ctx = setup().await;
        let err = ctx
            .provision(ctx.request(&ctx.shares[..TEST_T - 1]))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
        assert!(
            !ctx.enclave.config.is_enclave_btc_keypair_set(),
            "Bitcoin key should not be set below threshold"
        );
        assert_eq!(
            ctx.enclave.lifecycle(),
            WithdrawStage::OperatorInitialized.into(),
            "failed preparation should not advance the lifecycle"
        );

        ctx.provision(ctx.request(&ctx.shares[..TEST_T]))
            .await
            .expect("valid retry should succeed");
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let enclave = Enclave::create_with_random_keys();
        let err = provisioner_init(enclave, ProvisionerInitRequest(vec![]))
            .await
            .expect_err("should fail");
        assert!(matches!(err, LifecycleMismatch { .. }));
    }

    #[tokio::test]
    async fn rejects_mismatched_config_hash() {
        let ctx = setup().await;
        let wrong_config_hash = [0xABu8; 32];
        let submissions = ctx.shares[..TEST_T]
            .iter()
            .map(|share| {
                ctx.signed_submission(
                    share,
                    usize::from(share.id.get() - 1),
                    ctx.enclave.s3_session_id(),
                    wrong_config_hash,
                )
            })
            .collect();
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_mismatched_genesis_state_hash() {
        let ctx = setup().await;
        let submissions = ctx.shares[..TEST_T]
            .iter()
            .map(|share| {
                ctx.signed_submission_with_genesis_hash(
                    share,
                    usize::from(share.id.get() - 1),
                    ctx.enclave.s3_session_id(),
                    ctx.config_hash(),
                    Some([0xAB; 32]),
                )
            })
            .collect();
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_mismatched_session() {
        let ctx = setup().await;
        let config_hash = ctx.config_hash();
        let submissions = ctx.shares[..TEST_T]
            .iter()
            .map(|share| {
                ctx.signed_submission(
                    share,
                    usize::from(share.id.get() - 1),
                    "other-session".into(),
                    config_hash,
                )
            })
            .collect();
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_invalid_signature() {
        let ctx = setup().await;
        let mut submissions = ctx.request(&ctx.shares[..TEST_T]).0;
        submissions[0].signature = "invalid signature".into();
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, Unauthenticated(_)));
    }

    #[tokio::test]
    async fn rejects_signer_not_assigned_to_share() {
        let ctx = setup().await;
        let mut submissions = ctx.request(&ctx.shares[..TEST_T]).0;
        submissions[0] = ctx.signed_submission(
            &ctx.shares[0],
            1,
            ctx.enclave.s3_session_id(),
            ctx.config_hash(),
        );
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(message) if message.contains("assigned to KP")));
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let ctx = setup().await;
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let mut submissions = vec![ctx.signed_submission(
            &bogus_share,
            0,
            ctx.enclave.s3_session_id(),
            ctx.config_hash(),
        )];
        submissions.extend(ctx.request(&ctx.shares[1..TEST_T]).0);
        let err = ctx
            .provision(ProvisionerInitRequest(submissions))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id_in_batch() {
        let ctx = setup().await;
        let first = ctx.signed_submission(
            &ctx.shares[0],
            0,
            ctx.enclave.s3_session_id(),
            ctx.config_hash(),
        );
        let err = ctx
            .provision(ProvisionerInitRequest(vec![
                first.clone(),
                first,
                ctx.signed_submission(
                    &ctx.shares[1],
                    1,
                    ctx.enclave.s3_session_id(),
                    ctx.config_hash(),
                ),
            ]))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
