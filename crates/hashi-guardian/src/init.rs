// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::getters::get_attestation;
use crate::Enclave;
use crate::S3Logger;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::k256_sk_to_btc_keypair;
use hashi_types::guardian::crypto::Share;
use hashi_types::guardian::InitLogMessage::OIAttestationUnsigned;
use hashi_types::guardian::InitLogMessage::OIGuardianInfo;
use hashi_types::guardian::InitLogMessage::PIEnclaveFullyInitialized;
use hashi_types::guardian::InitLogMessage::PISuccess;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;
use GuardianError::*;

/// Receives S3 API keys, secret-sharing instance, BTC network, and the
/// `EnclaveInitState` (committee, limiter, withdrawal config, BTC master pubkey);
/// installs them and fixes the `state_hash`. Errors on malformed/dup calls, panics otherwise.
pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");

    // Validation
    if enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Operator init finished".into()));
    }
    if enclave.is_operator_init_partially_complete() {
        // shouldn't reach inside as we panic
        unreachable!("Operator init did not fully complete.");
    }
    info!("Enclave state validated.");

    // A normal enclave must carry the init state and a ceremony enclave must not;
    // reject the mismatch up front so no half-initialized state is left behind.
    request.validate(enclave.ceremony_mode())?;

    let (s3_config, secret_sharing_instance, network, state) = request.into_parts();
    let logger = S3Logger::new_checked(&s3_config).await?;
    info!("S3 connectivity check complete.");

    info!("Storing S3 configuration.");
    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    info!("Setting bitcoin network to {:?}.", network);
    enclave
        .config
        .set_bitcoin_network(network)
        .expect("Unable to set network");

    info!(
        "Storing secret-sharing instance: n={}, t={}, {} commitments.",
        secret_sharing_instance.num_shares(),
        secret_sharing_instance.threshold(),
        secret_sharing_instance.commitments().len()
    );
    for (i, share_commitment) in secret_sharing_instance.commitments().iter().enumerate() {
        info!(
            "Share {}: ID {} Digest {:x?}.",
            i, share_commitment.id, share_commitment.digest
        );
    }
    enclave
        .set_secret_sharing_instance(secret_sharing_instance)
        .expect("Unable to set secret-sharing instance");

    // Install the operator-supplied init state and bind its digest as the
    // state_hash — the AAD every KP's share submission must match. Only a
    // withdrawal-serving (normal-mode) enclave carries this; ceremony-mode
    // enclaves (setup/rotate) leave it unset.
    if let Some(state) = state {
        let state_hash = state.digest();
        let (committee, limiter_config, limiter_state, hashi_btc_master_pubkey) =
            state.into_parts();
        let rate_limiter = RateLimiter::new(limiter_config, limiter_state)?;

        info!("Setting state hash.");
        enclave
            .set_state_hash(state_hash)
            .expect("Unable to set state hash");

        info!("Setting hashi BTC master pubkey.");
        enclave
            .config
            .set_hashi_btc_pk(hashi_btc_master_pubkey)
            .expect("Unable to set hashi BTC master pubkey");

        info!("Installing committee and rate limiter.");
        enclave
            .state
            .init(committee, rate_limiter)
            .expect("Unable to init enclave state");
    }

    // Log to S3!
    // 1) Attestation and pub key help authenticate all subsequent enclave-signed messages.
    let signing_pk = enclave.signing_pubkey();
    enclave
        .log_init(OIAttestationUnsigned {
            attestation: get_attestation(&signing_pk).expect("Unable to get attestation"),
            signing_public_key: signing_pk,
        })
        .await
        .expect("Unable to log OperatorInitAttestationUnsigned");

    // 2) Share commitments help KPs confirm that the right private key will be constructed.
    enclave
        .log_init(OIGuardianInfo(enclave.info()))
        .await
        .expect("Unable to log GuardianInfo");

    enclave
        .scratchpad
        .operator_init_logging_complete
        .set(())
        .expect("operator_init_logging_complete should only be set once");

    info!("Operator initialization complete.");
    Ok(())
}

/// Receives one KP's encrypted share. Decrypts it under the enclave's state_hash
/// (set at operator_init) as AAD — so only shares from KPs that agreed on the
/// operator-supplied state decrypt — verifies it against the commitments, and
/// reconstructs the BTC key once threshold shares arrive.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Ensure only one provisioner_init request runs at a time to keep things simple.
    // We reuse the decrypted_shares mutex lock for this purpose.
    let mut received_shares = enclave.decrypted_shares().lock().await;

    // Validation
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Do operator init first".into()));
    }
    if enclave.is_provisioner_init_complete() {
        return Err(InvalidInputs("Provisioner init already complete".into()));
    }
    info!("Enclave state validated.");

    let sk = enclave.encryption_secret_key();
    let share_id = request.encrypted_share().id;
    // The state_hash was fixed at operator_init; it is the AAD every KP binds.
    // Absent means the operator booted this enclave without an EnclaveInitState
    // (a ceremony-mode config) — surface it gracefully rather than panicking.
    let state_hash = enclave
        .state_hash()
        .copied()
        .ok_or_else(|| InvalidInputs("operator did not supply init state".into()))?;
    info!("Share ID: {:?}.", share_id);

    // 1) Decrypt the share (AAD = enclave state_hash). A share only decrypts if
    //    the KP bound the same state the operator configured.
    info!("Decrypting share.");
    let share = decrypt_share(request.encrypted_share(), sk, Some(&state_hash))?;
    info!("Share decrypted.");

    // 2) Verify the share against the commitment
    info!("Verifying share against commitment.");
    let instance = enclave
        .secret_sharing_instance()
        .expect("secret-sharing instance should be set after operator_init");
    instance.commitments().verify_share(&share)?;
    info!("Share verified.");

    // MILESTONE: a share that decrypts under the enclave state_hash and matches a
    // commitment is a legitimate submission from a KP that agreed on the state.

    // 3) Persist share
    info!("Persisting share.");
    let share_id = share.id;
    // Check for duplicate share ID (linear search is fine for small share count)
    if received_shares.iter().any(|s| s.id == share_id) {
        return Err(InvalidInputs("Duplicate share ID".into()));
    }
    received_shares.push(share);
    let current_share_count = received_shares.len();
    let threshold = instance.threshold();
    info!("Total shares received: {current_share_count}/{threshold}.");

    // Note: This S3 log does not serve any security purpose.
    enclave
        .log_init(PISuccess {
            share_id,
            state_hash,
        })
        .await
        .expect("Unable to log ProvisionerInitSuccess");

    // 4) If we have enough shares, reconstruct the BTC key & finish initialization.
    if current_share_count >= threshold {
        let shares_vec: Vec<Share> = received_shares.iter().cloned().collect();
        finalize_init(&shares_vec, threshold, &enclave).await;
        // Log to S3 indicating that withdrawals can be expected henceforth
        enclave
            .log_init(PIEnclaveFullyInitialized)
            .await
            .expect("Unable to log EnclaveFullyInitialized");

        // Clear shares as we are done using them
        received_shares.clear();
        enclave
            .scratchpad
            .provisioner_init_logging_complete
            .set(())
            .expect("provisioner_init_logging_complete should only be set once");
    }

    Ok(())
}

/// Reconstruct the BTC key from the threshold shares and install it. The rest of
/// the enclave state was set at operator_init.
/// Panics upon an error as the enclaves state is irrecoverable at this point.
async fn finalize_init(shares: &[Share], threshold: usize, enclave: &Arc<Enclave>) {
    info!("Threshold reached, combining shares.");
    let enclave_k256_sk = combine_shares(shares, threshold).expect("Unable to combine shares");
    let enclave_btc_keypair = k256_sk_to_btc_keypair(&enclave_k256_sk);

    info!("Setting enclave keypair.");
    enclave
        .config
        .set_btc_keypair(enclave_btc_keypair)
        .expect("Unable to set enclave keypair");

    info!("Enclave initialization complete.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use k256::SecretKey;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    /// Helper: Generate test shares and initialized enclave
    /// Returns (shares, enclave)
    async fn setup_test_shares_and_enclave() -> (Vec<Share>, Arc<Enclave>) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let shares = split_secret(&sk, &params, &mut rand::thread_rng());
        let share_commitments = ShareCommitments::from_shares(&shares).unwrap();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_commitments(share_commitments),
        )
        .await;
        (shares, enclave)
    }

    #[tokio::test]
    async fn test_provisioner_init() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let state_hash = *enclave.state_hash().unwrap();

        // Simulate KPs submitting share-only requests, each bound to the
        // enclave's state_hash.
        for (i, share) in shares.iter().enumerate().take(TEST_N) {
            let request = ProvisionerInitRequest::build_from_share(
                share,
                enclave.encryption_public_key(),
                state_hash,
                &mut rand::thread_rng(),
            );

            let result = provisioner_init(enclave.clone(), request).await;

            if i == TEST_T - 1 {
                // At exactly threshold (first time), the BTC key is reconstructed.
                assert!(
                    result.is_ok(),
                    "Should succeed at threshold (iteration {i})"
                );
                assert!(
                    enclave.config.is_enclave_btc_keypair_set(),
                    "Bitcoin key should be set after threshold"
                );
                assert!(
                    enclave.is_fully_initialized(),
                    "fully initialized at threshold"
                );
            } else if i >= TEST_T {
                // After threshold, subsequent calls fail (already complete).
                assert!(result.is_err(), "Should fail at iteration {i}: {result:?}");
                assert!(
                    enclave.config.is_enclave_btc_keypair_set(),
                    "Bitcoin key should still be set"
                );
            } else {
                // Before threshold, the BTC key is not yet reconstructed.
                assert!(result.is_ok(), "Init should succeed before threshold");
                assert!(
                    !enclave.config.is_enclave_btc_keypair_set(),
                    "Bitcoin key should not be set before threshold"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_provisioner_init_before_operator_init() {
        // Enclave without operator_init: no state_hash, so the request is
        // rejected before its AAD is ever used.
        let enclave = Enclave::create_with_random_keys();
        let share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::ONE,
        };
        let request = ProvisionerInitRequest::build_from_share(
            &share,
            enclave.encryption_public_key(),
            [0u8; 32],
            &mut rand::thread_rng(),
        );

        let result = provisioner_init(enclave, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_rejects_mismatched_state_hash() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // A KP that binds a state_hash differing from the enclave's (i.e. it
        // disagreed on the operator-supplied state) produces a share that fails
        // to decrypt — rejected gracefully, not via a panic.
        let wrong_state_hash = [0xABu8; 32];
        assert_ne!(&wrong_state_hash, enclave.state_hash().unwrap());
        let request = ProvisionerInitRequest::build_from_share(
            &shares[0],
            enclave.encryption_public_key(),
            wrong_state_hash,
            &mut rand::thread_rng(),
        );

        let result = provisioner_init(enclave, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_invalid_share() {
        let (_shares, enclave) = setup_test_shares_and_enclave().await;

        // A bogus share decrypts (correct AAD) but fails the commitment check.
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let state_hash = *enclave.state_hash().unwrap();
        let request = ProvisionerInitRequest::build_from_share(
            &bogus_share,
            enclave.encryption_public_key(),
            state_hash,
            &mut rand::thread_rng(),
        );

        let result = provisioner_init(enclave, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_duplicate_share() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let state_hash = *enclave.state_hash().unwrap();

        let request1 = ProvisionerInitRequest::build_from_share(
            &shares[0],
            enclave.encryption_public_key(),
            state_hash,
            &mut rand::thread_rng(),
        );
        provisioner_init(enclave.clone(), request1)
            .await
            .expect("should not fail");

        // Re-submitting the same share id is rejected.
        let request2 = ProvisionerInitRequest::build_from_share(
            &shares[0],
            enclave.encryption_public_key(),
            state_hash,
            &mut rand::thread_rng(),
        );
        let result = provisioner_init(enclave, request2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }
}
