// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_verify_shares;
use hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Operator-relayed setup-mode rotation: the operator submits the current KPs'
/// encrypted old shares in one call. The enclave verifies them, reconstructs and
/// re-splits the BTC key to the new KP set, logs the new instance, returns the new shares.
pub async fn rotate_kps(
    enclave: Arc<Enclave>,
    request: RotateKpsRequest,
) -> GuardianResult<GuardianSigned<RotateKpsResponse>> {
    info!("/rotate_kps - Received request.");

    // Serialize the whole ceremony. The exact lifecycle check prevents setup
    // and rotation from interleaving and rejects another ceremony afterward.
    let _guard = enclave.control_lock.lock().await;
    enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;

    let (encrypted_old_shares, old_instance, state) = request.into_parts();
    let old_t = old_instance.threshold();

    let sk = enclave.encryption_secret_key();
    let state_hash = state.digest();

    // Decrypt and verify every submission. A share only decrypts if its KP bound
    // this same `state` as AAD, so the decrypted shares all agree on the target.
    // TODO: Move RotateKps to the PI model: collect typed, signed per-KP
    // submissions and verify them in the enclave. That first requires a
    // per-KP rotation submission/aggregation path; today the operator supplies
    // this batch directly, so AAD remains its authorization binding.
    let old_shares = decrypt_verify_shares(
        &encrypted_old_shares,
        sk,
        Some(&state_hash),
        old_instance.commitments(),
        old_t,
    )?;
    info!(
        "Verified {} old shares (threshold {old_t}).",
        old_shares.len()
    );

    let response = finalize_rotation(&enclave, &old_shares, &old_instance, state).await?;
    enclave
        .advance_lifecycle_into(CeremonyStage::Completed.into())
        .expect("rotate_kps should complete a ceremony lifecycle");
    Ok(response)
}

async fn finalize_rotation(
    enclave: &Arc<Enclave>,
    old_shares: &[Share],
    old_instance: &SecretSharingInstance,
    state: RotateKpsState,
) -> GuardianResult<GuardianSigned<RotateKpsResponse>> {
    info!("Threshold reached, reconstructing BTC key.");

    let k256_sk =
        combine_shares(old_shares, old_instance.threshold()).expect("threshold shares reach");

    // Rotation re-shares the same key, so its x-only pubkey is unchanged; record it.
    let btc_master_pubkey = k256_sk_to_btc_xonly_pubkey(&k256_sk);

    let (new_certs_roster, new_params) = state.into_parts();
    let n = new_params.num_shares();
    let t = new_params.threshold();
    let certificate_count: usize = new_certs_roster
        .iter()
        .map(|set| set.pgp_certs().len())
        .sum();
    info!(
        share_count = n,
        threshold = t,
        certificate_count,
        "Received new key provisioner OpenPGP certificate roster."
    );
    for (index, cert_set) in new_certs_roster.iter().enumerate() {
        info!(
            share_id = index + 1,
            certificate_count = cert_set.pgp_certs().len(),
            recipient_fingerprints = ?cert_set.fingerprints(),
            "Received new KP certificate set."
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
        ciphertext_count = encrypted_shares.ciphertext_count(),
        "Re-encrypted each share once per new KP certificate."
    );

    let new_sharing_seq = old_instance.sharing_seq() + 1;
    let new_instance = SecretSharingInstance::new(share_commitments, n, t, new_sharing_seq)?;
    info!(
        "Persisting rotation sharing_seq={new_sharing_seq} cert_seq=0 to kp-shares/ + ceremony/."
    );
    enclave
        .log_kp_share_state(new_sharing_seq, 0, encrypted_shares.clone())
        .await?;

    enclave
        .log_ceremony(CeremonyLogMessage::Rotate {
            old_instance: old_instance.clone(),
            new_instance,
            btc_master_pubkey,
        })
        .await?;

    info!("Rotation complete.");
    Ok(enclave.sign(RotateKpsResponse { encrypted_shares }))
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
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;
    use k256::SecretKey;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    /// Build (old shares, old instance, captures, enclave).
    async fn setup_rotation_enclave() -> (
        Vec<Share>,
        SecretSharingInstance,
        CapturedPuts,
        Arc<Enclave>,
    ) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let old_instance = SecretSharingInstance::new(
            ShareCommitments::from_shares(&shares).unwrap(),
            TEST_N,
            TEST_T,
            0,
        )
        .unwrap();
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        (shares, old_instance, captures, enclave)
    }

    fn build_state() -> RotateKpsState {
        RotateKpsState::new(mock_kp_certs_roster(TEST_N), TEST_N, TEST_T).unwrap()
    }

    fn build_state_with_secrets(
        num_shares: usize,
        threshold: usize,
    ) -> (RotateKpsState, MockKpSecretKeys) {
        let (roster, secret_keys) = mock_kp_certs_roster_with_secrets(num_shares);
        (
            RotateKpsState::new(roster, num_shares, threshold).unwrap(),
            secret_keys,
        )
    }

    /// Bundle one submission per share, all bound to `state.digest()` as AAD —
    /// i.e. what the operator assembles from the current KPs.
    fn build_request(
        shares: &[Share],
        enclave: &Enclave,
        old_instance: &SecretSharingInstance,
        state: RotateKpsState,
    ) -> RotateKpsRequest {
        let submissions = shares
            .iter()
            .map(|s| {
                RotateKpsRequest::build_from_share_and_state(
                    s,
                    enclave.encryption_public_key(),
                    &state,
                    &mut rand::thread_rng(),
                )
            })
            .collect();
        RotateKpsRequest::new(submissions, old_instance.clone(), state)
    }

    /// Run one rotation and return its verified response shares.
    async fn rotate_and_verify(
        enclave: &Arc<Enclave>,
        req: RotateKpsRequest,
    ) -> KPEncryptedSharesRoster {
        let signed = rotate_kps(enclave.clone(), req).await.expect("ok");
        signed
            .verify(&enclave.signing_pubkey())
            .expect("response signed by enclave")
            .encrypted_shares
    }

    /// Assert the rotation returned `new_n` PGP-armored shares and produced
    /// exactly one `ceremony/` log at `sharing_seq = 1` carrying the instance
    /// only (no ciphertexts).
    fn assert_rotation_output(
        captures: &CapturedPuts,
        response_shares: &KPEncryptedSharesRoster,
        secret_keys: &MockKpSecretKeys,
        new_n: usize,
        new_t: usize,
    ) {
        assert_eq!(response_shares.share_count(), new_n);
        for enc in response_shares.iter() {
            for ciphertext in enc.ciphertexts_by_fingerprint.values() {
                assert!(
                    ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"),
                    "expected a PGP-armored share in the response"
                );
            }
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
        let VersionedLogMessage::V2(LogMessage::Ceremony(ceremony)) = record.message else {
            panic!("expected V2 Ceremony variant");
        };
        let CeremonyLogMessage::Rotate {
            old_instance,
            new_instance,
            btc_master_pubkey,
        } = *ceremony
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
            btc_master_pubkey,
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
        let VersionedLogMessage::V2(LogMessage::KpShareState(shares)) = shares_record.message
        else {
            panic!("expected V2 KpShareState variant");
        };
        assert_eq!(shares.sharing_seq, 1);
        assert_eq!(shares.cert_seq, 0);
        assert_eq!(shares.encrypted_shares, *response_shares);
        assert_eq!(shares.encrypted_shares.share_count(), new_n);
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let (shares, old_instance, captures, enclave) = setup_rotation_enclave().await;
        let (state, secret_keys) = build_state_with_secrets(TEST_N, TEST_T);
        let req = build_request(&shares[..TEST_T], &enclave, &old_instance, state);
        let response_shares = rotate_and_verify(&enclave, req).await;
        assert_rotation_output(&captures, &response_shares, &secret_keys, TEST_N, TEST_T);
    }

    #[tokio::test]
    async fn happy_path_asymmetric_n_t() {
        // Old (n=5, t=3); rotate to new (n=3, t=2).
        let (shares, old_instance, captures, enclave) = setup_rotation_enclave().await;
        let (state, secret_keys) = build_state_with_secrets(3, 2);
        let req = build_request(&shares[..TEST_T], &enclave, &old_instance, state);
        let response_shares = rotate_and_verify(&enclave, req).await;
        assert_rotation_output(&captures, &response_shares, &secret_keys, 3, 2);
    }

    #[tokio::test]
    async fn rejects_second_call_after_complete() {
        let (shares, old_instance, captures, enclave) = setup_rotation_enclave().await;

        // First call reaches threshold and finalizes.
        let req = build_request(&shares[..TEST_T], &enclave, &old_instance, build_state());
        rotate_kps(enclave.clone(), req).await.expect("ok");

        // A second call is rejected outright — no re-split.
        let req2 = build_request(&shares[..TEST_T], &enclave, &old_instance, build_state());
        let err = rotate_kps(enclave, req2).await.expect_err("should reject");
        assert!(matches!(err, InvalidInputs(_)));

        let captured = captures.lock().unwrap();
        let count = captured
            .iter()
            .filter(|(k, _)| k.starts_with("ceremony/"))
            .count();
        assert_eq!(count, 1, "rotation must finalize exactly once");
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id_in_batch() {
        let (shares, old_instance, _captures, enclave) = setup_rotation_enclave().await;
        let state = build_state();
        let mut rng = rand::thread_rng();
        // Two submissions from the same KP (same share id).
        let submissions = vec![
            RotateKpsRequest::build_from_share_and_state(
                &shares[0],
                enclave.encryption_public_key(),
                &state,
                &mut rng,
            ),
            RotateKpsRequest::build_from_share_and_state(
                &shares[0],
                enclave.encryption_public_key(),
                &state,
                &mut rng,
            ),
            RotateKpsRequest::build_from_share_and_state(
                &shares[1],
                enclave.encryption_public_key(),
                &state,
                &mut rng,
            ),
        ];
        let req = RotateKpsRequest::new(submissions, old_instance, state);

        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_below_threshold() {
        let (shares, old_instance, _captures, enclave) = setup_rotation_enclave().await;
        // Only T-1 submissions.
        let req = build_request(
            &shares[..TEST_T - 1],
            &enclave,
            &old_instance,
            build_state(),
        );
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_with_mismatched_aad() {
        // A submission bound to a different `state` won't decrypt under the
        // request's `state` AAD, so the whole request is rejected gracefully
        // (no panic — the old cross-call state-hash check is gone).
        let (shares, old_instance, _captures, enclave) = setup_rotation_enclave().await;
        let state1 = build_state();
        let state2 = build_state();
        assert_ne!(state1.new_kp_certs_roster(), state2.new_kp_certs_roster());

        let mut rng = rand::thread_rng();
        let submissions = vec![
            RotateKpsRequest::build_from_share_and_state(
                &shares[0],
                enclave.encryption_public_key(),
                &state1,
                &mut rng,
            ),
            RotateKpsRequest::build_from_share_and_state(
                &shares[1],
                enclave.encryption_public_key(),
                &state2,
                &mut rng,
            ),
            RotateKpsRequest::build_from_share_and_state(
                &shares[2],
                enclave.encryption_public_key(),
                &state2,
                &mut rng,
            ),
        ];
        let req = RotateKpsRequest::new(submissions, old_instance, state2);

        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let (_shares, old_instance, _captures, enclave) = setup_rotation_enclave().await;
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let req = build_request(
            std::slice::from_ref(&bogus_share),
            &enclave,
            &old_instance,
            build_state(),
        );
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        // No operator_init, so the enclave has no instance to read; build the old
        // instance standalone. The call must reject before ever touching it.
        let enclave = Enclave::create_with_random_keys();
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let state = build_state();
        let mut rng = rand::thread_rng();
        let submissions = shares[..TEST_T]
            .iter()
            .map(|s| {
                RotateKpsRequest::build_from_share_and_state(
                    s,
                    enclave.encryption_public_key(),
                    &state,
                    &mut rng,
                )
            })
            .collect();
        let old_instance = SecretSharingInstance::new(
            ShareCommitments::from_shares(&shares).unwrap(),
            TEST_N,
            TEST_T,
            0,
        )
        .unwrap();
        let req = RotateKpsRequest::new(submissions, old_instance, state);
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
