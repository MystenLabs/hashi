// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingLogMessage;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Setup-mode rotation flow. Each *current* KP submits one of these. The
/// enclave digest-matches `state` across the current threshold submissions
/// (HPKE AAD on the encrypted old share is the same digest), verifies each
/// old share against the enclave's stored commitments, and on threshold:
///   1. reconstructs the BTC key in memory,
///   2. re-splits it with fresh randomness, encrypting to `state.new_kp_pgp_certs`,
///   3. writes `SecretSharingLogMessage` with `sharing_seq = prev + 1`.
///      New KPs fetch their encrypted shares from there.
///
/// The enclave does not persist the reconstructed BTC key — its only job is
/// to mint the new `SecretSharingLogMessage`.
pub async fn rotate_kps(enclave: Arc<Enclave>, request: RotateKpsRequest) -> GuardianResult<()> {
    info!("/rotate_kps - Received request.");

    // Serialize calls; reuses the shared decrypted_shares mutex (provisioner_init
    // is disabled in setup mode so the vec is only ever touched by rotate_kps here).
    let mut received_shares = enclave.decrypted_shares().lock().await;

    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }
    info!("Enclave state validated.");

    let state = request.state();

    let instance = enclave
        .secret_sharing_instance()
        .expect("secret-sharing instance should be set after operator_init");

    let sk = enclave.encryption_secret_key();
    let share_id = request.encrypted_old_share().id;
    let state_hash = state.digest();
    info!("Share ID: {:?}.", share_id);

    // 1) Decrypt the share (HPKE AAD = state digest)
    let old_share = decrypt_share(request.encrypted_old_share(), sk, Some(&state_hash))?;
    info!("Share decrypted.");

    // 2) Verify the share against the enclave's stored commitments
    instance.commitments().verify_share(&old_share)?;
    info!("Share verified.");

    // 3) State hash must match across submissions
    enclave.check_or_set_state_hash(state_hash)?;

    // MILESTONE: legitimate payload (both share & state) confirmed.

    // 4) Persist share, rejecting duplicates
    if received_shares.iter().any(|s| s.id == old_share.id) {
        return Err(InvalidInputs("Duplicate share ID".into()));
    }
    received_shares.push(old_share);
    let count = received_shares.len();
    let old_t = instance.threshold();
    info!("Total shares received: {count}/{old_t}.");

    // 5) On threshold: reconstruct, re-split, emit new SecretSharingLogMessage
    if count >= old_t {
        let shares_vec: Vec<Share> = received_shares.iter().cloned().collect();
        finalize_rotation(&enclave, &shares_vec, instance, request.into_state()).await?;
    }

    Ok(())
}

async fn finalize_rotation(
    enclave: &Arc<Enclave>,
    old_shares: &[Share],
    old_instance: &SecretSharingInstance,
    state: RotateKpsState,
) -> GuardianResult<()> {
    info!("Threshold reached, reconstructing BTC key.");

    let k256_sk =
        combine_shares(old_shares, old_instance.threshold()).expect("threshold shares reach");

    let new_params = state.new_params();
    let n = new_params.num_shares();
    let t = new_params.threshold();
    info!("Re-splitting for {n} new KPs (threshold: {t}).");
    let new_certs = state
        .new_kp_pgp_certs()
        .iter()
        .cloned()
        .map(PgpPublicCert::new)
        .collect::<GuardianResult<Vec<_>>>()?;

    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments) = {
        let mut rng = rand::thread_rng();
        split_and_encrypt_for_kps(&k256_sk, &new_certs, new_params, &mut rng)
    };

    let new_sharing_seq = old_instance.sharing_seq() + 1;
    let new_secret_sharing_instance =
        SecretSharingInstance::new(share_commitments, n, t, new_sharing_seq)?;
    info!("Writing SecretSharingLogMessage sharing_seq={new_sharing_seq} to secret_sharing/.");
    enclave
        .log_secret_sharing(SecretSharingLogMessage {
            encrypted_shares,
            secret_sharing_instance: new_secret_sharing_instance,
        })
        .await?;

    info!("Rotation complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use crate::test_utils::CapturedPuts;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::crypto::split_secret;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use k256::SecretKey;
    use sequoia_openpgp::cert::prelude::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    /// Build (original sk, old shares, captures, enclave).
    async fn setup_rotation_enclave() -> (SecretKey, Vec<Share>, CapturedPuts, Arc<Enclave>) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let commitments = ShareCommitments::from_shares(&shares).unwrap();
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default()
                .with_commitments(commitments)
                .with_s3_logger(logger),
        )
        .await;
        (sk, shares, captures, enclave)
    }

    /// Generate `n` fresh armored OpenPGP certs to serve as the new KP set.
    fn fresh_new_kp_certs(n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                let (cert, _) = CertBuilder::general_purpose(["kp@example.com"])
                    .generate()
                    .unwrap();
                let mut armored = Vec::new();
                cert.armored().export(&mut armored).unwrap();
                String::from_utf8(armored).unwrap()
            })
            .collect()
    }

    fn build_state() -> RotateKpsState {
        RotateKpsState::new(fresh_new_kp_certs(TEST_N), TEST_N, TEST_T).unwrap()
    }

    /// Assert the rotation captured a single secret_sharing/ log at
    /// `sharing_seq = 1` with the expected instance params and one PGP-armored
    /// share per new KP.
    ///
    /// TODO: strengthen this (and setup_new_key's test) to decrypt the armored
    /// shares with the new KPs' PGP secret keys and verify they reconstruct the
    /// original BTC key, once a PGP-decrypt test helper exists.
    fn assert_rotation_output(captures: &CapturedPuts, new_n: usize, new_t: usize) {
        let captured = captures.lock().unwrap();
        let ss_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("secret_sharing/"))
            .collect();
        assert_eq!(ss_logs.len(), 1, "expected one secret_sharing/ log");
        let (key, body) = ss_logs[0];

        assert!(
            key.starts_with("secret_sharing/00000000000000000001-"),
            "expected sharing_seq=1, got key {key}"
        );

        let record: LogRecord = serde_json::from_slice(body).unwrap();
        let LogMessage::SecretSharing(ss) = record.message else {
            panic!("expected SecretSharing variant");
        };
        assert_eq!(ss.secret_sharing_instance.sharing_seq(), 1);
        assert_eq!(ss.secret_sharing_instance.num_shares(), new_n);
        assert_eq!(ss.secret_sharing_instance.threshold(), new_t);
        assert_eq!(ss.encrypted_shares.len(), new_n);
        for enc in &ss.encrypted_shares {
            assert!(
                enc.armored_ciphertext
                    .starts_with("-----BEGIN PGP MESSAGE-----"),
                "expected a PGP-armored share"
            );
        }
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let (_sk, shares, captures, enclave) = setup_rotation_enclave().await;
        let state = RotateKpsState::new(fresh_new_kp_certs(TEST_N), TEST_N, TEST_T).unwrap();

        for share in shares.iter().take(TEST_T) {
            let req = RotateKpsRequest::build_from_share_and_state(
                share,
                enclave.encryption_public_key(),
                state.clone(),
                &mut rand::thread_rng(),
            );
            rotate_kps(enclave.clone(), req).await.expect("ok");
        }

        assert_rotation_output(&captures, TEST_N, TEST_T);
    }

    #[tokio::test]
    async fn happy_path_asymmetric_n_t() {
        // Old (n=5, t=3); rotate to new (n=3, t=2).
        let (_sk, shares, captures, enclave) = setup_rotation_enclave().await;
        let state = RotateKpsState::new(fresh_new_kp_certs(3), 3, 2).unwrap();

        for share in shares.iter().take(TEST_T) {
            let req = RotateKpsRequest::build_from_share_and_state(
                share,
                enclave.encryption_public_key(),
                state.clone(),
                &mut rand::thread_rng(),
            );
            rotate_kps(enclave.clone(), req).await.expect("ok");
        }

        assert_rotation_output(&captures, 3, 2);
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id() {
        let (_sk, shares, _captures, enclave) = setup_rotation_enclave().await;
        let state = build_state();

        let req1 = RotateKpsRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state.clone(),
            &mut rand::thread_rng(),
        );
        rotate_kps(enclave.clone(), req1).await.unwrap();

        // Same KP submits again.
        let req2 = RotateKpsRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        );
        let err = rotate_kps(enclave, req2).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    #[should_panic(expected = "State hash mismatch")]
    async fn rejects_mismatched_state() {
        let (_sk, shares, _captures, enclave) = setup_rotation_enclave().await;
        let state1 = build_state();
        // Different `new_kp_pgp_certs` ⇒ different digest.
        let state2 = build_state();
        assert_ne!(state1.new_kp_pgp_certs(), state2.new_kp_pgp_certs());

        let req1 = RotateKpsRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state1,
            &mut rand::thread_rng(),
        );
        rotate_kps(enclave.clone(), req1).await.unwrap();

        let req2 = RotateKpsRequest::build_from_share_and_state(
            &shares[1],
            enclave.encryption_public_key(),
            state2,
            &mut rand::thread_rng(),
        );
        let _ = rotate_kps(enclave, req2).await;
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let (_sk, _shares, _captures, enclave) = setup_rotation_enclave().await;
        let state = build_state();
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let req = RotateKpsRequest::build_from_share_and_state(
            &bogus_share,
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        );
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn rotate_kps_state_new_rejects_wrong_cert_count() {
        let mut certs = fresh_new_kp_certs(TEST_N);
        certs.pop();
        let err = RotateKpsState::new(certs, TEST_N, TEST_T).expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn rotate_kps_state_new_rejects_duplicate_certs() {
        let mut certs = fresh_new_kp_certs(TEST_N);
        certs[1] = certs[0].clone();
        let err = RotateKpsState::new(certs, TEST_N, TEST_T).expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let enclave = Enclave::create_with_random_keys();
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let state = build_state();

        let req = RotateKpsRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        );
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
