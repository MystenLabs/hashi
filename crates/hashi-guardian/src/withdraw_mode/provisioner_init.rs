// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `provisioner_init` (withdraw mode): collects the current KPs' encrypted
//! shares, decrypts/verifies them under the enclave's `config_hash`, and
//! reconstructs the BTC key once threshold shares are present. Runs after the
//! shared `crate::operator_init`.

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

/// Receives the current KPs' encrypted shares in one submission. Decrypts each
/// under the enclave's config_hash (set at operator_init) as AAD — so only shares
/// from KPs that agreed on the operator-supplied stable config decrypt — verifies
/// them against the commitments, and reconstructs the BTC key once threshold
/// shares are present.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Serialize so concurrent callers can't race the check-then-finalize below.
    let _guard = enclave.control_lock.lock().await;

    enclave.require_lifecycle(WithdrawStage::OperatorInitialized.into())?;
    info!("Enclave state validated.");

    let sk = enclave.encryption_secret_key();
    let instance = enclave
        .secret_sharing_instance()
        .expect("secret-sharing instance should be set after operator_init");
    let threshold = instance.threshold();
    let sharing_seq = instance.sharing_seq();
    // Always set here: provisioner_init is withdraw-mode only, and the
    // operator_init check above guarantees a withdraw-mode enclave installed it.
    let config_hash = enclave
        .config_hash()
        .expect("withdraw-mode operator_init installs the config_hash");

    // Decrypt and verify every submission. A share only decrypts if its KP bound
    // the enclave's config_hash as AAD, so the decrypted shares all agree on the
    // operator-supplied stable config.
    let shares = decrypt_verify_shares(
        request.encrypted_shares(),
        sk,
        &config_hash,
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

    /// Bundle one submission per share, all bound to the enclave's config_hash as
    /// AAD — i.e. what the relay assembles from the current KPs.
    fn build_request(shares: &[Share], enclave: &Enclave) -> ProvisionerInitRequest {
        let config_hash = enclave.config_hash().unwrap();
        let submissions = shares
            .iter()
            .map(|s| {
                ProvisionerInitRequest::build_from_share(
                    s,
                    enclave.encryption_public_key(),
                    config_hash,
                    &mut rand::thread_rng(),
                )
            })
            .collect();
        ProvisionerInitRequest::new(submissions)
    }

    #[tokio::test]
    async fn happy_path_threshold_reached() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let req = build_request(&shares[..TEST_T], &enclave);

        provisioner_init(enclave.clone(), req).await.expect("ok");
        assert!(
            enclave.config.is_enclave_btc_keypair_set(),
            "Bitcoin key should be set after threshold"
        );
        assert_eq!(
            enclave.lifecycle(),
            WithdrawStage::ProvisionerInitialized.into(),
            "provisioner init complete"
        );
        assert!(!enclave.is_fully_initialized(), "not active before OA");
    }

    #[tokio::test]
    async fn rejects_second_call_after_complete() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        let req = build_request(&shares[..TEST_T], &enclave);
        provisioner_init(enclave.clone(), req).await.expect("ok");

        // A second call is rejected outright (already complete).
        let req2 = build_request(&shares[..TEST_T], &enclave);
        let err = provisioner_init(enclave, req2)
            .await
            .expect_err("should reject");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_below_threshold() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let req = build_request(&shares[..TEST_T - 1], &enclave);
        let err = provisioner_init(enclave.clone(), req)
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
        assert!(
            !enclave.config.is_enclave_btc_keypair_set(),
            "Bitcoin key should not be set below threshold"
        );
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        // Enclave without operator_init: rejected before any AAD is used.
        let enclave = Enclave::create_with_random_keys();
        let share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::ONE,
        };
        let enc = ProvisionerInitRequest::build_from_share(
            &share,
            enclave.encryption_public_key(),
            [0u8; 32],
            &mut rand::thread_rng(),
        );
        let req = ProvisionerInitRequest::new(vec![enc]);

        let err = provisioner_init(enclave, req)
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_with_mismatched_config_hash() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // A KP that binds a config_hash differing from the enclave's (i.e. it
        // disagreed on the operator-supplied stable config) produces a share
        // that fails to decrypt — rejected gracefully, not via a panic.
        let wrong_config_hash = [0xABu8; 32];
        assert_ne!(wrong_config_hash, enclave.config_hash().unwrap());
        let enc = ProvisionerInitRequest::build_from_share(
            &shares[0],
            enclave.encryption_public_key(),
            wrong_config_hash,
            &mut rand::thread_rng(),
        );
        let req = ProvisionerInitRequest::new(vec![enc]);

        let err = provisioner_init(enclave, req)
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_not_matching_commitments() {
        let (_shares, enclave) = setup_test_shares_and_enclave().await;

        // A bogus share decrypts (correct AAD) but fails the commitment check.
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32),
        };
        let req = build_request(std::slice::from_ref(&bogus_share), &enclave);

        let err = provisioner_init(enclave, req)
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id_in_batch() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        // Two submissions from the same KP (same share id).
        let dupes = [shares[0], shares[0], shares[1]];
        let req = build_request(&dupes, &enclave);

        let err = provisioner_init(enclave, req)
            .await
            .expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
