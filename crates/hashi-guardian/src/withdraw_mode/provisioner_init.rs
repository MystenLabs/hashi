// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `provisioner_init` (withdraw mode): verifies the current KPs' signed share
//! submissions and reconstructs the BTC key once threshold shares are present.
//! Runs after the shared `crate::operator_init`.

use crate::Enclave;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_verify_shares;
use hashi_types::guardian::crypto::k256_sk_to_btc_keypair;
use hashi_types::guardian::crypto::Share;
use hashi_types::guardian::InitLogMessage::PIEnclaveFullyInitialized;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Receives the current KPs' signed share submissions in one batch. The relay
/// may pre-verify them as a DoS guard, but the enclave authoritatively verifies
/// each signature and session/config binding before decrypting and
/// commitment-checking any share.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Serialize so concurrent callers can't race the check-then-finalize below.
    let _guard = enclave.control_lock.lock().await;

    enclave.require_lifecycle(WithdrawStage::OperatorInitialized.into())?;
    info!("Enclave state validated.");

    let ceremony_state = enclave
        .ceremony_state()
        .expect("ceremony state should be set after operator_init");
    let instance = &ceremony_state.secret_sharing_instance;
    let threshold = instance.threshold();
    let sharing_seq = instance.sharing_seq();
    let config_hash = enclave
        .config_hash()
        .expect("withdraw-mode operator_init installs the config_hash");
    let session_id = enclave.s3_session_id();

    let encrypted_shares = verify_signed_submissions(
        request,
        &session_id,
        &config_hash,
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

    let share_ids = shares.iter().map(|s| s.id).collect();
    let enclave_btc_pubkey = finalize_init(&shares, threshold, &enclave).await;
    // Log to S3 indicating that the BTC key has been reconstructed. OA waits for
    // this durable marker before activating the enclave for withdrawals.
    enclave
        .log_init(PIEnclaveFullyInitialized {
            sharing_seq,
            share_ids,
            enclave_btc_pubkey,
        })
        .await
        .expect("Unable to log EnclaveFullyInitialized");

    enclave
        .advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())
        .expect("provisioner_init should advance an operator-initialized enclave");

    Ok(())
}

fn verify_signed_submissions(
    request: ProvisionerInitRequest,
    live_session_id: &SessionID,
    live_config_hash: &[u8; 32],
    expected_kp_encrypted_shares: &KPEncryptedShares,
) -> GuardianResult<Vec<GuardianEncryptedShare>> {
    request
        .0
        .into_iter()
        .map(|signed| {
            let signer_fingerprint = signed.signer_fingerprint().to_hex();
            let submission = signed.verify()?;

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

            let share_id = submission.encrypted_share().id;
            let expected_fingerprint = expected_kp_encrypted_shares
                .as_slice()
                .get(usize::from(share_id.get() - 1))
                .ok_or_else(|| {
                    GuardianError::InvalidInputs(format!(
                        "PI submission share id {} has no KP assignment",
                        share_id.get()
                    ))
                })?
                .recipient_fingerprint
                .as_str();
            if signer_fingerprint != expected_fingerprint {
                return Err(GuardianError::InvalidInputs(format!(
                    "PI submission share id {} is assigned to KP {}, not signer {}",
                    share_id.get(),
                    expected_fingerprint,
                    signer_fingerprint
                )));
            }

            info!(
                share_id = share_id.get(),
                signer_fingerprint, "verified signed PI submission"
            );
            let (_, _, encrypted_share) = submission.into_parts();
            Ok(encrypted_share)
        })
        .collect()
}

/// Reconstruct the BTC key from the threshold shares and install it. Live
/// serving state is installed later by operator_activate.
/// Panics upon an error as the enclaves state is irrecoverable at this point.
async fn finalize_init(
    shares: &[Share],
    threshold: usize,
    enclave: &Arc<Enclave>,
) -> BitcoinPubkey {
    info!("Threshold reached, combining shares.");
    let enclave_k256_sk = combine_shares(shares, threshold).expect("Unable to combine shares");
    let enclave_btc_keypair = k256_sk_to_btc_keypair(&enclave_k256_sk);
    let enclave_btc_pubkey = enclave_btc_keypair.x_only_public_key().0;

    info!("Setting enclave keypair.");
    enclave
        .config
        .set_btc_keypair(enclave_btc_keypair)
        .expect("Unable to set enclave keypair");

    info!("Enclave initialization complete.");
    enclave_btc_pubkey
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::GuardianError::InvalidInputs;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;
    use k256::SecretKey;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    struct TestContext {
        shares: Vec<Share>,
        enclave: Arc<Enclave>,
        kp_keys: Vec<(PgpPublicCert, String)>,
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
        let kp_encrypted_shares = KPEncryptedShares::new(
            kp_keys
                .iter()
                .enumerate()
                .map(|(i, (cert, _))| KPEncryptedShare {
                    id: std::num::NonZeroU16::new((i + 1) as u16).unwrap(),
                    recipient_fingerprint: cert.fingerprint().to_hex(),
                    armored_ciphertext: "dummy".into(),
                })
                .collect(),
        )
        .unwrap();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default()
                .with_commitments(share_commitments)
                .with_kp_encrypted_shares(kp_encrypted_shares),
        )
        .await;
        TestContext {
            shares,
            enclave,
            kp_keys,
        }
    }

    impl TestContext {
        fn signed_submission(
            &self,
            share: &Share,
            signer_index: usize,
            expected_session_id: SessionID,
            expected_config_hash: [u8; 32],
        ) -> KpSigned<SingleProvisionerInitRequest> {
            let request = SingleProvisionerInitRequest::build_from_share(
                expected_session_id,
                expected_config_hash,
                share,
                self.enclave.encryption_public_key(),
                &mut rand::thread_rng(),
            );
            let (cert, secret) = &self.kp_keys[signer_index];
            KpSigned {
                signature: sign_detached_in_process(secret, &KpSigned::signed_bytes(&request)),
                data: request,
                signer_cert: cert.clone(),
            }
        }

        fn request(&self, shares: &[Share]) -> ProvisionerInitRequest {
            let session_id = self.enclave.s3_session_id();
            let config_hash = self.enclave.config_hash().unwrap();
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
        assert!(!ctx.enclave.is_fully_initialized(), "not active before OA");
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
        assert!(matches!(err, InvalidInputs(_)));
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
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let enclave = Enclave::create_with_random_keys();
        let err = provisioner_init(enclave, ProvisionerInitRequest(vec![]))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
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
    async fn rejects_mismatched_session() {
        let ctx = setup().await;
        let config_hash = ctx.enclave.config_hash().unwrap();
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
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_signer_not_assigned_to_share() {
        let ctx = setup().await;
        let mut submissions = ctx.request(&ctx.shares[..TEST_T]).0;
        submissions[0] = ctx.signed_submission(
            &ctx.shares[0],
            1,
            ctx.enclave.s3_session_id(),
            ctx.enclave.config_hash().unwrap(),
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
            ctx.enclave.config_hash().unwrap(),
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
            ctx.enclave.config_hash().unwrap(),
        );
        let err = ctx
            .provision(ProvisionerInitRequest(vec![
                first.clone(),
                first,
                ctx.signed_submission(
                    &ctx.shares[1],
                    1,
                    ctx.enclave.s3_session_id(),
                    ctx.enclave.config_hash().unwrap(),
                ),
            ]))
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
