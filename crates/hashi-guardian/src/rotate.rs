// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::*;
use hashi_types::pgp::PgpPublicCert;
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

    // Hold the ceremony guard for the whole call: blocks a concurrent
    // setup_new_key, and the flag rejects re-entry after one ceremony finalizes.
    let mut ceremony_complete = enclave.scratchpad.ceremony_complete.lock().await;
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }
    if *ceremony_complete {
        return Err(InvalidInputs("setup or rotation already complete".into()));
    }

    let (encrypted_old_shares, old_instance, state) = request.into_parts();
    let old_t = old_instance.threshold();

    let sk = enclave.encryption_secret_key();
    let state_hash = state.digest();

    // Decrypt and verify every submission. A share only decrypts if its KP bound
    // this same `state` as AAD, so the decrypted shares all agree on the target.
    let mut old_shares: Vec<Share> = Vec::with_capacity(encrypted_old_shares.len());
    for enc in &encrypted_old_shares {
        let share = decrypt_share(enc, sk, Some(&state_hash))?;
        old_instance.commitments().verify_share(&share)?;
        if old_shares.iter().any(|s| s.id == share.id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
        old_shares.push(share);
    }
    info!("Verified {}/{old_t} old shares.", old_shares.len());

    if old_shares.len() < old_t {
        return Err(InvalidInputs(format!(
            "need at least {old_t} shares, got {}",
            old_shares.len()
        )));
    }

    let response = finalize_rotation(&enclave, &old_shares, &old_instance, state).await?;
    *ceremony_complete = true;
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

    let (new_kp_pgp_certs, new_params) = state.into_parts();
    let n = new_params.num_shares();
    let t = new_params.threshold();
    info!("Re-splitting for {n} new KPs (threshold: {t}).");
    let new_certs = new_kp_pgp_certs
        .into_iter()
        .map(|cert| PgpPublicCert::new(cert).map_err(|e| InvalidInputs(e.to_string())))
        .collect::<GuardianResult<Vec<_>>>()?;

    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments) = {
        let mut rng = rand::thread_rng();
        split_and_encrypt_for_kps(&k256_sk, &new_certs, &new_params, &mut rng)
    };

    let new_sharing_seq = old_instance.sharing_seq() + 1;
    let new_instance = SecretSharingInstance::new(share_commitments, n, t, new_sharing_seq)?;
    info!("Writing CeremonyLogMessage sharing_seq={new_sharing_seq} to ceremony/.");
    enclave
        .log_ceremony(CeremonyLogMessage::Rotate {
            old_instance: old_instance.clone(),
            new_instance,
        })
        .await?;

    enclave.set_latest_encrypted_shares(encrypted_shares.clone())?;

    info!("Rotation complete.");
    Ok(enclave.sign(RotateKpsResponse { encrypted_shares }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use crate::test_utils::CapturedPuts;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::crypto::split_secret;
    use hashi_types::guardian::test_utils::mock_pgp_certs_armored;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use k256::SecretKey;

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

    fn build_state() -> RotateKpsState {
        RotateKpsState::new(mock_pgp_certs_armored(TEST_N), TEST_N, TEST_T).unwrap()
    }

    /// Bundle one submission per share, all bound to `state.digest()` as AAD —
    /// i.e. what the operator assembles from the current KPs.
    fn build_request(
        shares: &[Share],
        enclave: &Enclave,
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
        // The old instance the operator would read from `ceremony/`; here it's the
        // one the enclave was set up with (matches the shares being submitted).
        let old_instance = enclave.secret_sharing_instance().unwrap().clone();
        RotateKpsRequest::new(submissions, old_instance, state)
    }

    /// Run one rotation and return its verified response shares.
    async fn rotate_and_verify(
        enclave: &Arc<Enclave>,
        req: RotateKpsRequest,
    ) -> Vec<KPEncryptedShare> {
        let signed = rotate_kps(enclave.clone(), req).await.expect("ok");
        signed
            .verify(&enclave.signing_pubkey())
            .expect("response signed by enclave")
            .encrypted_shares
    }

    /// Assert the rotation returned `new_n` PGP-armored shares and produced
    /// exactly one `ceremony/` log at `sharing_seq = 1` carrying the instance
    /// only (no ciphertexts).
    ///
    /// TODO: strengthen this (and setup_new_key's test) to decrypt the armored
    /// shares with the new KPs' PGP secret keys and verify they reconstruct the
    /// original BTC key, once a PGP-decrypt test helper exists.
    fn assert_rotation_output(
        captures: &CapturedPuts,
        response_shares: &[KPEncryptedShare],
        new_n: usize,
        new_t: usize,
    ) {
        assert_eq!(response_shares.len(), new_n);
        for enc in response_shares {
            assert!(
                enc.armored_ciphertext
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
        let LogMessage::Ceremony(ceremony) = record.message else {
            panic!("expected Ceremony variant");
        };
        let CeremonyLogMessage::Rotate {
            old_instance,
            new_instance,
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
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let (_sk, shares, captures, enclave) = setup_rotation_enclave().await;
        let req = build_request(&shares[..TEST_T], &enclave, build_state());
        let response_shares = rotate_and_verify(&enclave, req).await;
        assert_rotation_output(&captures, &response_shares, TEST_N, TEST_T);
    }

    #[tokio::test]
    async fn happy_path_asymmetric_n_t() {
        // Old (n=5, t=3); rotate to new (n=3, t=2).
        let (_sk, shares, captures, enclave) = setup_rotation_enclave().await;
        let state = RotateKpsState::new(mock_pgp_certs_armored(3), 3, 2).unwrap();
        let req = build_request(&shares[..TEST_T], &enclave, state);
        let response_shares = rotate_and_verify(&enclave, req).await;
        assert_rotation_output(&captures, &response_shares, 3, 2);
    }

    #[tokio::test]
    async fn rejects_second_call_after_complete() {
        let (_sk, shares, captures, enclave) = setup_rotation_enclave().await;

        // First call reaches threshold and finalizes.
        let req = build_request(&shares[..TEST_T], &enclave, build_state());
        rotate_kps(enclave.clone(), req).await.expect("ok");

        // A second call is rejected outright — no re-split.
        let req2 = build_request(&shares[..TEST_T], &enclave, build_state());
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
        let (_sk, shares, _captures, enclave) = setup_rotation_enclave().await;
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
        let old_instance = enclave.secret_sharing_instance().unwrap().clone();
        let req = RotateKpsRequest::new(submissions, old_instance, state);

        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_below_threshold() {
        let (_sk, shares, _captures, enclave) = setup_rotation_enclave().await;
        // Only T-1 submissions.
        let req = build_request(&shares[..TEST_T - 1], &enclave, build_state());
        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_with_mismatched_aad() {
        // A submission bound to a different `state` won't decrypt under the
        // request's `state` AAD, so the whole request is rejected gracefully
        // (no panic — the old cross-call state-hash check is gone).
        let (_sk, shares, _captures, enclave) = setup_rotation_enclave().await;
        let state1 = build_state();
        let state2 = build_state();
        assert_ne!(state1.new_kp_pgp_certs(), state2.new_kp_pgp_certs());

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
        let old_instance = enclave.secret_sharing_instance().unwrap().clone();
        let req = RotateKpsRequest::new(submissions, old_instance, state2);

        let err = rotate_kps(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let (_sk, _shares, _captures, enclave) = setup_rotation_enclave().await;
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let req = build_request(std::slice::from_ref(&bogus_share), &enclave, build_state());
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
