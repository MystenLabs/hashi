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

/// The withdraw-mode state to install, built from `WithdrawModeConfig` (incl. the
/// computed `state_hash` and the constructed rate limiter).
pub(crate) struct WithdrawInstall {
    state_hash: [u8; 32],
    network: bitcoin::Network,
    secret_sharing_instance: SecretSharingInstance,
    hashi_btc_master_pubkey: HashiMasterG,
    committee: HashiCommittee,
    rate_limiter: RateLimiter,
}

impl WithdrawInstall {
    /// Decompose a `WithdrawModeConfig` into the install bundle, constructing the
    /// rate limiter (the only fallible step). Shared by `operator_init` and tests.
    pub(crate) fn from_config(config: WithdrawModeConfig) -> GuardianResult<Self> {
        let (withdraw_state, secret_sharing_instance, network) = config.into_parts();
        let state_hash = withdraw_state.digest();
        let (committee, limiter_config, limiter_state, hashi_btc_master_pubkey) =
            withdraw_state.into_parts();
        let rate_limiter = RateLimiter::new(limiter_config, limiter_state)?;
        Ok(Self {
            state_hash,
            network,
            secret_sharing_instance,
            hashi_btc_master_pubkey,
            committee,
            rate_limiter,
        })
    }

    /// Install the bundle onto a fresh enclave. Infallible by design (see the
    /// `operator_init` invariant): every set runs once on a fresh enclave.
    pub(crate) fn install_into(self, enclave: &Enclave) {
        info!("Setting bitcoin network to {:?}.", self.network);
        enclave
            .config
            .set_bitcoin_network(self.network)
            .expect("Unable to set network");

        info!(
            "Storing secret-sharing instance: n={}, t={}, {} commitments.",
            self.secret_sharing_instance.num_shares(),
            self.secret_sharing_instance.threshold(),
            self.secret_sharing_instance.commitments().len()
        );
        enclave
            .set_secret_sharing_instance(self.secret_sharing_instance)
            .expect("Unable to set secret-sharing instance");

        info!("Setting state hash.");
        enclave
            .set_state_hash(self.state_hash)
            .expect("Unable to set state hash");

        info!("Setting hashi BTC master pubkey.");
        enclave
            .config
            .set_hashi_btc_pk(self.hashi_btc_master_pubkey)
            .expect("Unable to set hashi BTC master pubkey");

        info!("Installing committee and rate limiter.");
        enclave
            .state
            .init(self.committee, self.rate_limiter)
            .expect("Unable to init enclave state");
    }
}

/// Receives S3 API keys and — for a withdraw-mode enclave — the `WithdrawModeConfig`
/// (committee, limiter, BTC master pubkey, secret-sharing instance, network);
/// installs them and fixes the `state_hash`. A ceremony enclave carries only S3.
///
/// Invariant: operator_init never returns an `Err` from a partially-initialized
/// enclave. Every fallible step (request validation, S3 connectivity, rate-limiter
/// construction) runs before any state is mutated, so an early `Err` leaves the
/// enclave untouched and retryable. The mutation then happens entirely in
/// `commit_operator_init`, which returns `()` — it cannot report an error, so a
/// half-mutated enclave is never observed via an `Err`.
pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");

    // Serialize so concurrent callers can't race the check-then-commit below.
    let _guard = enclave.control_lock.lock().await;

    if enclave.is_operator_init_complete() {
        return Err(InvalidInputs("operator_init already complete".into()));
    }

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----

    // A withdraw-mode enclave must carry the config and a ceremony enclave must not.
    request.validate(enclave.mode())?;

    let (s3_config, state) = request.into_parts();
    let logger = S3Logger::new_checked(&s3_config).await?;
    info!("S3 connectivity check complete.");

    // Build the withdraw-mode install bundle (incl. the rate limiter, the last
    // fallible step) up front; `None` for a ceremony enclave.
    let withdraw = match state {
        Some(config) => Some(WithdrawInstall::from_config(config)?),
        None => None,
    };

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    commit_operator_init(&enclave, logger, withdraw).await;
    Ok(())
}

/// Install the validated config on the enclave and write the operator_init logs.
/// Infallible by design (returns `()`, see the `operator_init` invariant): every
/// `set` here runs on a fresh enclave under the control lock, and the I/O steps
/// (attestation, S3 logging) panic on failure rather than return.
async fn commit_operator_init(
    enclave: &Enclave,
    logger: S3Logger,
    withdraw: Option<WithdrawInstall>,
) {
    info!("Storing S3 configuration.");
    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    // Withdraw-mode state (committee, limiter, BTC master pubkey, instance, network,
    // state_hash); a ceremony enclave installs none of it.
    if let Some(install) = withdraw {
        install.install_into(enclave);
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
}

/// Receives the current KPs' encrypted shares in one submission. Decrypts each
/// under the enclave's state_hash (set at operator_init) as AAD — so only shares
/// from KPs that agreed on the operator-supplied state decrypt — verifies them
/// against the commitments, and reconstructs the BTC key once threshold shares
/// are present.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Serialize so concurrent callers can't race the check-then-finalize below.
    let _guard = enclave.control_lock.lock().await;

    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Do operator init first".into()));
    }
    if enclave.is_provisioner_init_complete() {
        return Err(InvalidInputs("Provisioner init already complete".into()));
    }
    info!("Enclave state validated.");

    let sk = enclave.encryption_secret_key();
    let instance = enclave
        .secret_sharing_instance()
        .expect("secret-sharing instance should be set after operator_init");
    let threshold = instance.threshold();
    // Always set here: provisioner_init is withdraw-mode only, and the
    // operator_init check above guarantees a withdraw-mode enclave installed it.
    let state_hash = *enclave
        .state_hash()
        .expect("withdraw-mode operator_init installs the state_hash");

    let encrypted_shares = request.into_parts();

    // Decrypt and verify every submission. A share only decrypts if its KP bound
    // the enclave's state_hash as AAD, so the decrypted shares all agree on the
    // operator-supplied state.
    let mut shares: Vec<Share> = Vec::with_capacity(encrypted_shares.len());
    for enc in &encrypted_shares {
        let share = decrypt_share(enc, sk, Some(&state_hash))?;
        instance.commitments().verify_share(&share)?;
        if shares.iter().any(|s| s.id == share.id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
        // Note: This S3 log does not serve any security purpose.
        enclave
            .log_init(PISuccess {
                share_id: share.id,
                state_hash,
            })
            .await
            .expect("Unable to log ProvisionerInitSuccess");
        shares.push(share);
    }
    info!("Verified {}/{threshold} shares.", shares.len());

    if shares.len() < threshold {
        return Err(InvalidInputs(format!(
            "need at least {threshold} shares, got {}",
            shares.len()
        )));
    }

    finalize_init(&shares, threshold, &enclave).await;
    // Log to S3 indicating that withdrawals can be expected henceforth.
    enclave
        .log_init(PIEnclaveFullyInitialized)
        .await
        .expect("Unable to log EnclaveFullyInitialized");

    enclave
        .scratchpad
        .provisioner_init_logging_complete
        .set(())
        .expect("provisioner_init_logging_complete should only be set once");

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

    /// Run commit_operator_init on a fresh enclave for the given mode (withdraw =>
    /// carries the WithdrawModeConfig install bundle; ceremony => none).
    async fn commit_for_mode(mode: EnclaveMode) -> Arc<Enclave> {
        let enclave = Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
            mode,
        ));

        let withdraw = match mode {
            EnclaveMode::Withdraw => Some(
                WithdrawInstall::from_config(WithdrawModeConfig::mock_for_testing(None)).unwrap(),
            ),
            EnclaveMode::Ceremony => None,
        };

        commit_operator_init(&enclave, crate::test_utils::mock_logger(), withdraw).await;
        enclave
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_withdraw_mode() {
        let enclave = commit_for_mode(EnclaveMode::Withdraw).await;
        assert!(enclave.is_operator_init_complete());
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_ceremony_mode() {
        let enclave = commit_for_mode(EnclaveMode::Ceremony).await;
        assert!(enclave.is_operator_init_complete());
    }

    /// Bundle one submission per share, all bound to the enclave's state_hash as
    /// AAD — i.e. what the relay assembles from the current KPs.
    fn build_request(shares: &[Share], enclave: &Enclave) -> ProvisionerInitRequest {
        let state_hash = *enclave.state_hash().unwrap();
        let submissions = shares
            .iter()
            .map(|s| {
                ProvisionerInitRequest::build_from_share(
                    s,
                    enclave.encryption_public_key(),
                    state_hash,
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
        assert!(enclave.is_fully_initialized(), "fully initialized");
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

        let err = provisioner_init(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_share_with_mismatched_state_hash() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // A KP that binds a state_hash differing from the enclave's (i.e. it
        // disagreed on the operator-supplied state) produces a share that fails
        // to decrypt — rejected gracefully, not via a panic.
        let wrong_state_hash = [0xABu8; 32];
        assert_ne!(&wrong_state_hash, enclave.state_hash().unwrap());
        let enc = ProvisionerInitRequest::build_from_share(
            &shares[0],
            enclave.encryption_public_key(),
            wrong_state_hash,
            &mut rand::thread_rng(),
        );
        let req = ProvisionerInitRequest::new(vec![enc]);

        let err = provisioner_init(enclave, req).await.expect_err("should fail");
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

        let err = provisioner_init(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[tokio::test]
    async fn rejects_duplicate_share_id_in_batch() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        // Two submissions from the same KP (same share id).
        let dupes = [shares[0].clone(), shares[0].clone(), shares[1].clone()];
        let req = build_request(&dupes, &enclave);

        let err = provisioner_init(enclave, req).await.expect_err("should fail");
        assert!(matches!(err, InvalidInputs(_)));
    }
}
