// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_verify_shares;
use hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

struct VerifiedShareSubmission {
    signer_fingerprint: KPFingerprint,
    encrypted_share: GuardianEncryptedShare,
}

struct VerifiedRotationProposal {
    pcr_allowlist: PcrAllowlist,
    share_submissions: Vec<VerifiedShareSubmission>,
    new_kp_certs_roster: KpCertRoster,
    new_params: SecretSharingParams,
}

/// Verify the current KPs' signed rotation submissions, reconstruct the BTC key,
/// and re-split it to the new KP set. Returning the encrypted shares leaves this
/// enclave awaiting confirmation from every new KP.
pub async fn rotate_kp_set(
    enclave: Arc<Enclave>,
    request: BatchProvisionerRotateKpSetRequest,
) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
    info!("/rotate_kp_set - Received request.");

    enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;

    let proposal = verify_signed_submissions(request.submissions(), &enclave.s3_session_id())?;
    let mut reader = enclave.new_guardian_reader_with_allowlist(proposal.pcr_allowlist.clone())?;
    let latest_s3_state = reader.read_latest_ceremony_state().await?;

    complete_rotation(&enclave, proposal, latest_s3_state).await
}

async fn complete_rotation(
    enclave: &Arc<Enclave>,
    proposal: VerifiedRotationProposal,
    latest_s3_state: CeremonyState,
) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
    let CeremonyState {
        secret_sharing_instance: old_instance,
        btc_master_pubkey,
        encrypted_shares: old_kp_encrypted_shares,
        ..
    } = latest_s3_state;
    let encrypted_old_shares =
        authorize_share_submissions(&proposal.share_submissions, &old_kp_encrypted_shares)?;

    let old_shares = decrypt_verify_shares(
        &encrypted_old_shares,
        enclave.encryption_secret_key(),
        &old_instance,
    )?;
    let old_t = old_instance.threshold();
    info!(
        "Verified {} old shares (threshold {old_t}).",
        old_shares.len()
    );

    let response = finalize_rotation(
        enclave,
        &old_shares,
        &old_instance,
        btc_master_pubkey,
        proposal.new_kp_certs_roster,
        proposal.new_params,
    )
    .await?;
    enclave
        .advance_lifecycle_into(CeremonyStage::AwaitingKeyProvisionerConfirmations.into())
        .expect("rotate_kp_set should await new key provisioner confirmations");
    Ok(response)
}

fn verify_signed_submissions(
    submissions: &[KpSigned<ProvisionerRotateKpSetRequest>],
    live_session_id: &SessionID,
) -> GuardianResult<VerifiedRotationProposal> {
    let mut agreed_pcr_allowlist = None;
    let mut agreed_new_kp_certs_roster = None;
    let mut agreed_new_params = None;
    let mut share_submissions = Vec::with_capacity(submissions.len());

    for signed in submissions {
        let signer_fingerprint = signed.signer_fingerprint().to_hex();
        let submission = signed
            .verify_signature()
            .map_err(|error| GuardianError::Unauthenticated(error.to_string()))?;

        submission.validate_session(live_session_id)?;
        require_agreement(
            &mut agreed_pcr_allowlist,
            submission.pcr_allowlist(),
            "PCR allowlist",
        )?;
        require_agreement(
            &mut agreed_new_kp_certs_roster,
            submission.new_kp_certs_roster(),
            "new KP certificate roster",
        )?;
        require_agreement(
            &mut agreed_new_params,
            submission.new_params(),
            "new secret-sharing parameters",
        )?;

        let encrypted_share = submission.encrypted_old_share().clone();
        info!(
            share_id = encrypted_share.id.get(),
            signer_fingerprint, "verified signed KP rotation submission"
        );
        share_submissions.push(VerifiedShareSubmission {
            signer_fingerprint,
            encrypted_share,
        });
    }

    Ok(VerifiedRotationProposal {
        pcr_allowlist: agreed_pcr_allowlist
            .expect("batch construction rejects an empty submission list"),
        share_submissions,
        new_kp_certs_roster: agreed_new_kp_certs_roster
            .expect("batch construction rejects an empty submission list"),
        new_params: agreed_new_params.expect("batch construction rejects an empty submission list"),
    })
}

fn require_agreement<T: Clone + PartialEq>(
    agreed: &mut Option<T>,
    submitted: &T,
    field: &str,
) -> GuardianResult<()> {
    match agreed {
        Some(expected) if expected != submitted => Err(GuardianError::InvalidInputs(format!(
            "KP rotation submissions disagree on {field}"
        ))),
        Some(_) => Ok(()),
        None => {
            *agreed = Some(submitted.clone());
            Ok(())
        }
    }
}

fn authorize_share_submissions(
    submissions: &[VerifiedShareSubmission],
    old_kp_encrypted_shares: &KpEncryptedShareRoster,
) -> GuardianResult<Vec<GuardianEncryptedShare>> {
    submissions
        .iter()
        .map(|submission| {
            let share_id = submission.encrypted_share.id;
            old_kp_encrypted_shares
                .validate_share_assignment(&submission.signer_fingerprint, share_id)?;
            Ok(submission.encrypted_share.clone())
        })
        .collect()
}

async fn finalize_rotation(
    enclave: &Arc<Enclave>,
    old_shares: &[Share],
    old_instance: &SecretSharingInstance,
    expected_btc_master_pubkey: BitcoinPubkey,
    new_certs_roster: KpCertRoster,
    new_params: SecretSharingParams,
) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
    info!("Threshold reached, reconstructing BTC key.");

    let k256_sk =
        combine_shares(old_shares, old_instance.threshold()).expect("threshold shares reach");

    // Rotation re-shares the same key, so its x-only pubkey is unchanged; record it.
    let btc_master_pubkey = k256_sk_to_btc_xonly_pubkey(&k256_sk);
    if btc_master_pubkey != expected_btc_master_pubkey {
        return Err(GuardianError::InvalidInputs(format!(
            "reconstructed BTC pubkey {btc_master_pubkey:?} differs from latest ceremony BTC \
             pubkey {expected_btc_master_pubkey:?}"
        )));
    }

    let n = new_params.num_shares();
    let t = new_params.threshold();
    info!(
        share_count = n,
        threshold = t,
        "Received new key provisioner OpenPGP certificate roster."
    );
    for (index, cert) in new_certs_roster.iter().enumerate() {
        info!(
            share_id = index + 1,
            recipient_fingerprint = %cert.fingerprint().to_hex(),
            "Received new KP certificate."
        );
    }

    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments) = {
        let mut rng = rand::thread_rng();
        split_and_encrypt_for_kps(&k256_sk, &new_certs_roster, &new_params, &mut rng)
    };
    info!(
        share_count = encrypted_shares.share_count(),
        "Re-encrypted one share for each new key provisioner."
    );

    let new_sharing_seq = old_instance.sharing_seq() + 1;
    let new_instance = SecretSharingInstance::new(share_commitments, n, t, new_sharing_seq)?;
    info!(
        "Persisting rotation sharing_seq={new_sharing_seq} cert_seq=0 to kp-shares/ + ceremony/."
    );
    enclave
        .log_kp_share_state(new_sharing_seq, 0, encrypted_shares.clone())
        .await?;

    let ceremony_log = CeremonyLogMessage::Rotate {
        old_instance: old_instance.clone(),
        new_instance: new_instance.clone(),
        btc_master_pubkey,
    };
    enclave.log_ceremony(ceremony_log.clone()).await?;

    info!("Rotation complete; awaiting every new key provisioner's confirmation.");
    let response = RotateKpSetResponse {
        encrypted_shares,
        new_instance,
    };
    let pending_state = CeremonyState::new(
        ceremony_log,
        KpShareStateLogMessage::new(new_sharing_seq, 0, response.encrypted_shares.clone()),
    )?;
    enclave.install_pending_ceremony(pending_state)?;
    Ok(enclave.sign(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use crate::test_utils::decrypt_kp_shares;
    use crate::test_utils::mock_kp_certs_roster_with_secrets;
    use crate::test_utils::CapturedPuts;
    use crate::test_utils::MockKpSecretKeys;
    use hashi_types::guardian::crypto::split_secret;
    use hashi_types::guardian::test_utils::mock_kp_certs_roster;
    use hashi_types::guardian::GuardianError::InvalidInputs;
    use hashi_types::guardian::GuardianError::LifecycleMismatch;
    use hashi_types::guardian::GuardianError::Unauthenticated;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;
    use k256::SecretKey;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    async fn rotate_kp_set_with_state(
        enclave: Arc<Enclave>,
        request: BatchProvisionerRotateKpSetRequest,
        latest_s3_state: CeremonyState,
    ) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
        enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;
        let proposal = verify_signed_submissions(request.submissions(), &enclave.s3_session_id())?;
        complete_rotation(&enclave, proposal, latest_s3_state).await
    }

    struct TestContext {
        shares: Vec<Share>,
        old_instance: SecretSharingInstance,
        old_kp_encrypted_shares: KpEncryptedShareRoster,
        btc_master_pubkey: BitcoinPubkey,
        pcr_allowlist: PcrAllowlist,
        kp_keys: Vec<(PgpPublicCert, String)>,
        alternate_kp_key: (PgpPublicCert, String),
        captures: CapturedPuts,
        enclave: Arc<Enclave>,
    }

    async fn setup_rotation_enclave() -> TestContext {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let btc_master_pubkey = k256_sk_to_btc_xonly_pubkey(&sk);
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let old_instance = SecretSharingInstance::new(
            ShareCommitments::from_shares(&shares).unwrap(),
            TEST_N,
            TEST_T,
            0,
        )
        .unwrap();
        let kp_keys = (0..TEST_N)
            .map(|_| {
                let (cert, secret) = mock_pgp_keypair();
                (PgpPublicCert::new(cert).unwrap(), secret)
            })
            .collect::<Vec<_>>();
        let (alternate_cert, alternate_secret) = mock_pgp_keypair();
        let alternate_kp_key = (
            PgpPublicCert::new(alternate_cert).unwrap(),
            alternate_secret,
        );
        let old_kp_encrypted_shares = KpEncryptedShareRoster::new(
            kp_keys
                .iter()
                .enumerate()
                .map(|(index, (cert, _))| KpEncryptedShare {
                    id: ShareID::new((index + 1) as u16).unwrap(),
                    recipient_fingerprint: cert.fingerprint().to_hex(),
                    armored_ciphertext: "dummy".into(),
                })
                .collect(),
        )
        .unwrap();
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        TestContext {
            shares,
            old_instance,
            old_kp_encrypted_shares,
            btc_master_pubkey,
            pcr_allowlist: PcrAllowlist::new(BuildPcrs::new("test", vec![0]), []).unwrap(),
            kp_keys,
            alternate_kp_key,
            captures,
            enclave,
        }
    }

    impl TestContext {
        fn latest_s3_state(&self) -> CeremonyState {
            CeremonyState::from(SetupNewKeyResponse {
                encrypted_shares: self.old_kp_encrypted_shares.clone(),
                secret_sharing_instance: self.old_instance.clone(),
                btc_master_pubkey: self.btc_master_pubkey,
            })
        }

        fn build_roster_with_secrets(&self, num_shares: usize) -> (KpCertRoster, MockKpSecretKeys) {
            mock_kp_certs_roster_with_secrets(num_shares)
        }

        fn signed_submission_with_key(
            &self,
            share: &Share,
            signer: &(PgpPublicCert, String),
            expected_session_id: SessionID,
            new_kp_certs_roster: &KpCertRoster,
            new_threshold: usize,
        ) -> KpSigned<ProvisionerRotateKpSetRequest> {
            let request = ProvisionerRotateKpSetRequest::build_from_share(
                expected_session_id,
                self.pcr_allowlist.clone(),
                share,
                self.enclave.encryption_public_key(),
                new_kp_certs_roster.clone(),
                SecretSharingParams::new(new_kp_certs_roster.num_kps(), new_threshold).unwrap(),
                &mut rand::thread_rng(),
            )
            .unwrap();
            let (cert, secret) = signer;
            let signature = sign_detached_in_process(secret, &KpSigned::signed_bytes(&request));
            KpSigned::from_parts(request, cert.clone(), signature)
        }

        fn signed_submission(
            &self,
            share: &Share,
            signer_index: usize,
            expected_session_id: SessionID,
            new_kp_certs_roster: &KpCertRoster,
            new_threshold: usize,
        ) -> KpSigned<ProvisionerRotateKpSetRequest> {
            self.signed_submission_with_key(
                share,
                &self.kp_keys[signer_index],
                expected_session_id,
                new_kp_certs_roster,
                new_threshold,
            )
        }

        fn request(
            &self,
            shares: &[Share],
            new_kp_certs_roster: KpCertRoster,
            new_threshold: usize,
        ) -> GuardianResult<BatchProvisionerRotateKpSetRequest> {
            let submissions = shares
                .iter()
                .map(|share| {
                    self.signed_submission(
                        share,
                        usize::from(share.id.get() - 1),
                        self.enclave.s3_session_id(),
                        &new_kp_certs_roster,
                        new_threshold,
                    )
                })
                .collect();
            BatchProvisionerRotateKpSetRequest::new(submissions)
        }
    }

    /// Run one rotation and return its verified response.
    async fn rotate_and_verify(
        context: &TestContext,
        req: BatchProvisionerRotateKpSetRequest,
    ) -> RotateKpSetResponse {
        let signed =
            rotate_kp_set_with_state(context.enclave.clone(), req, context.latest_s3_state())
                .await
                .expect("ok");
        signed
            .verify_into_data(&context.enclave.signing_pubkey())
            .expect("response signed by enclave")
            .response
    }

    /// Assert the rotation returned `new_n` PGP-armored shares and produced
    /// exactly one `ceremony/` log at `sharing_seq = 1` carrying the instance
    /// only (no ciphertexts).
    fn assert_rotation_output(
        captures: &CapturedPuts,
        response: &RotateKpSetResponse,
        secret_keys: &MockKpSecretKeys,
        new_n: usize,
        new_t: usize,
    ) {
        let response_shares = &response.encrypted_shares;
        assert_eq!(response_shares.share_count(), new_n);
        for encrypted_share in response_shares.iter() {
            assert!(
                encrypted_share
                    .armored_ciphertext
                    .starts_with("-----BEGIN PGP MESSAGE-----"),
                "expected a PGP-armored share in the response"
            );
        }

        let captured = captures.lock().unwrap();
        let ceremony_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("ceremony/"))
            .collect();
        assert_eq!(ceremony_logs.len(), 1, "expected one ceremony/ log");
        let (key, body) = ceremony_logs[0];
        assert!(
            key.starts_with("ceremony/00000000000000000001-"),
            "expected sharing_seq=1, got key {key}"
        );
        assert!(
            !std::str::from_utf8(body)
                .unwrap()
                .contains("BEGIN PGP MESSAGE"),
            "ceremony log must not contain ciphertexts"
        );

        let record: LogRecord = serde_json::from_slice(body).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::Ceremony(ceremony)) = record.message() else {
            panic!("expected V2 Ceremony variant");
        };
        let CeremonyLogMessage::Rotate {
            old_instance,
            new_instance,
            btc_master_pubkey,
        } = ceremony.as_ref()
        else {
            panic!("expected Rotate variant");
        };
        // The consumed old instance is recorded for chain auditability.
        assert_eq!(old_instance.sharing_seq(), 0);
        assert_eq!(old_instance.num_shares(), TEST_N);
        assert_eq!(old_instance.threshold(), TEST_T);
        assert_eq!(new_instance.sharing_seq(), 1);
        assert_eq!(new_instance.num_shares(), new_n);
        assert_eq!(new_instance.threshold(), new_t);
        assert_eq!(&response.new_instance, new_instance);

        let decrypted_shares = decrypt_kp_shares(response_shares, secret_keys);
        for share in &decrypted_shares {
            new_instance
                .commitments()
                .verify_share(share)
                .expect("decrypted rotation share should match its commitment");
        }
        let reconstructed = combine_shares(&decrypted_shares[..new_t], new_t).unwrap();
        assert_eq!(
            k256_sk_to_btc_xonly_pubkey(&reconstructed),
            *btc_master_pubkey,
            "threshold decrypted rotation shares should reconstruct the original key"
        );

        // The new shares are persisted to kp-shares/ keyed by the new sharing_seq
        // and initial cert_seq=0.
        let shares_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("kp-shares/"))
            .collect();
        assert_eq!(shares_logs.len(), 1, "expected one kp-shares/ log");
        let (shares_key, shares_body) = shares_logs[0];
        assert!(
            shares_key.starts_with("kp-shares/00000000000000000001/00000000000000000000-"),
            "expected sharing_seq=1 cert_seq=0, got key {shares_key}"
        );
        let shares_record: LogRecord = serde_json::from_slice(shares_body).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::KpShareState(shares)) = shares_record.message()
        else {
            panic!("expected V2 KpShareState variant");
        };
        let shares = shares.as_ref();
        assert_eq!(shares.sharing_seq, 1);
        assert_eq!(shares.cert_seq, 0);
        assert_eq!(shares.encrypted_shares, *response_shares);
        assert_eq!(shares.encrypted_shares.share_count(), new_n);
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let ctx = setup_rotation_enclave().await;
        let (roster, secret_keys) = ctx.build_roster_with_secrets(TEST_N);
        let req = ctx.request(&ctx.shares[..TEST_T], roster, TEST_T).unwrap();
        let response = rotate_and_verify(&ctx, req).await;
        assert_rotation_output(&ctx.captures, &response, &secret_keys, TEST_N, TEST_T);
        assert_eq!(
            ctx.enclave.lifecycle(),
            CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
        );
    }

    #[tokio::test]
    async fn happy_path_asymmetric_n_t() {
        // Old (n=5, t=3); rotate to new (n=3, t=2).
        let ctx = setup_rotation_enclave().await;
        let (roster, secret_keys) = ctx.build_roster_with_secrets(3);
        let req = ctx.request(&ctx.shares[..TEST_T], roster, 2).unwrap();
        let response = rotate_and_verify(&ctx, req).await;
        assert_rotation_output(&ctx.captures, &response, &secret_keys, 3, 2);
    }

    #[tokio::test]
    async fn rejects_second_call_while_awaiting_confirmations() {
        let ctx = setup_rotation_enclave().await;

        // First call reaches threshold, re-splits, and awaits the new KPs.
        let req = ctx
            .request(&ctx.shares[..TEST_T], mock_kp_certs_roster(TEST_N), TEST_T)
            .unwrap();
        rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect("ok");

        // A second call is rejected outright — no re-split.
        let req2 = ctx
            .request(&ctx.shares[..TEST_T], mock_kp_certs_roster(TEST_N), TEST_T)
            .unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req2, ctx.latest_s3_state())
            .await
            .expect_err("should reject");
        assert!(matches!(err, LifecycleMismatch { .. }));

        let captured = ctx.captures.lock().unwrap();
        let count = captured
            .iter()
            .filter(|(k, _)| k.starts_with("ceremony/"))
            .count();
        assert_eq!(count, 1, "rotation must finalize exactly once");
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id_in_batch() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        // Two submissions from the same KP (same share id).
        let first = ctx.signed_submission(
            &ctx.shares[0],
            0,
            ctx.enclave.s3_session_id(),
            &roster,
            TEST_T,
        );
        let submissions = vec![
            first.clone(),
            first,
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("duplicate share id should fail");
        assert!(matches!(&err, InvalidInputs(_)));
        assert!(format!("{err}").contains("Duplicate share ID"));
    }

    #[tokio::test]
    async fn rejects_below_threshold() {
        let ctx = setup_rotation_enclave().await;
        // Only T-1 submissions.
        let req = ctx
            .request(
                &ctx.shares[..TEST_T - 1],
                mock_kp_certs_roster(TEST_N),
                TEST_T,
            )
            .unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("below-threshold shares should fail");
        assert!(matches!(&err, InvalidInputs(_)));
        assert!(format!("{err}").contains("need at least"));
    }

    #[tokio::test]
    async fn rejects_more_shares_than_old_instance() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let mut submissions = ctx
            .shares
            .iter()
            .map(|share| {
                ctx.signed_submission(
                    share,
                    usize::from(share.id.get() - 1),
                    ctx.enclave.s3_session_id(),
                    &roster,
                    TEST_T,
                )
            })
            .collect::<Vec<_>>();
        submissions.push(submissions[0].clone());

        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("too many shares should fail");
        assert!(matches!(&err, InvalidInputs(_)));
        assert!(format!("{err}").contains("at most"));
    }

    #[tokio::test]
    async fn rejects_share_id_outside_old_instance() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let out_of_range_share = Share {
            id: ShareID::new((TEST_N + 1) as u16).unwrap(),
            value: ctx.shares[0].value,
        };
        let submissions = vec![
            ctx.signed_submission(
                &out_of_range_share,
                0,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[2],
                2,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(&err, InvalidInputs(message) if message.contains("assigned share id")));
    }

    #[tokio::test]
    async fn rejects_submissions_for_different_proposals() {
        let ctx = setup_rotation_enclave().await;
        let roster1 = mock_kp_certs_roster(TEST_N);
        let roster2 = mock_kp_certs_roster(TEST_N);
        assert_ne!(roster1, roster2);

        let submissions = vec![
            ctx.signed_submission(
                &ctx.shares[0],
                0,
                ctx.enclave.s3_session_id(),
                &roster1,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster2,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[2],
                2,
                ctx.enclave.s3_session_id(),
                &roster2,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(
            &err,
            InvalidInputs(message) if message.contains("disagree on new KP certificate roster")
        ));
    }

    #[tokio::test]
    async fn rejects_mismatched_session() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let submissions = ctx.shares[..TEST_T]
            .iter()
            .map(|share| {
                ctx.signed_submission(
                    share,
                    usize::from(share.id.get() - 1),
                    "other-session".into(),
                    &roster,
                    TEST_T,
                )
            })
            .collect();
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(
            &err,
            InvalidInputs(message) if message.contains("expected guardian session")
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_signature() {
        let ctx = setup_rotation_enclave().await;
        let mut submissions = ctx
            .request(&ctx.shares[..TEST_T], mock_kp_certs_roster(TEST_N), TEST_T)
            .unwrap()
            .into_submissions();
        submissions[0].signature = "invalid signature".into();
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(err, Unauthenticated(_)));
    }

    #[tokio::test]
    async fn rejects_signer_not_assigned_to_share() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let submissions = vec![
            ctx.signed_submission(
                &ctx.shares[0],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[2],
                2,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(&err, InvalidInputs(message) if message.contains("assigned share id")));
    }

    #[tokio::test]
    async fn rejects_alternate_cert_for_rostered_share() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let submissions = vec![
            ctx.signed_submission_with_key(
                &ctx.shares[0],
                &ctx.alternate_kp_key,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[2],
                2,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("an alternate certificate must not authorize the rostered share");
        assert!(matches!(
            &err,
            InvalidInputs(message) if message.contains("not present in the encrypted-share roster")
        ));
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let ctx = setup_rotation_enclave().await;
        let roster = mock_kp_certs_roster(TEST_N);
        let bogus_share = Share {
            id: ShareID::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let submissions = vec![
            ctx.signed_submission(
                &bogus_share,
                0,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[1],
                1,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
            ctx.signed_submission(
                &ctx.shares[2],
                2,
                ctx.enclave.s3_session_id(),
                &roster,
                TEST_T,
            ),
        ];
        let req = BatchProvisionerRotateKpSetRequest::new(submissions).unwrap();
        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, ctx.latest_s3_state())
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_reconstructed_key_not_matching_latest_ceremony() {
        let ctx = setup_rotation_enclave().await;
        let req = ctx
            .request(&ctx.shares[..TEST_T], mock_kp_certs_roster(TEST_N), TEST_T)
            .unwrap();
        let mut latest_s3_state = ctx.latest_s3_state();
        latest_s3_state.btc_master_pubkey =
            k256_sk_to_btc_xonly_pubkey(&SecretKey::random(&mut rand::thread_rng()));

        let err = rotate_kp_set_with_state(ctx.enclave.clone(), req, latest_s3_state)
            .await
            .expect_err("latest ceremony BTC pubkey must match reconstructed key");
        assert!(
            matches!(&err, InvalidInputs(message) if message.contains("reconstructed BTC pubkey"))
        );
        assert!(
            ctx.captures.lock().unwrap().is_empty(),
            "a mismatched reconstructed key must not write rotation state"
        );
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let ctx = setup_rotation_enclave().await;
        let req = ctx
            .request(&ctx.shares[..TEST_T], mock_kp_certs_roster(TEST_N), TEST_T)
            .unwrap();
        // No operator_init. The call must reject before inspecting the request.
        let enclave = Enclave::create_with_random_keys();
        let err = rotate_kp_set(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, LifecycleMismatch { .. }));
    }
}
