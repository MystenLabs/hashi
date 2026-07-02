// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_init`: receives S3 config and (in withdraw mode) the
//! `WithdrawModeConfig`, installs them, and writes the init logs. Enabled in
//! both modes. The companion `provisioner_init` (withdraw-only) lives in
//! `withdraw::provisioner_init`.

use crate::attestation::get_attestation;
use crate::Enclave;
use crate::GuardianS3Client;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::InitLogMessage::OIAttestationUnsigned;
use hashi_types::guardian::InitLogMessage::OIGuardianInfo;
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
    authorized_kp_fingerprints: Vec<KPFingerprint>,
}

impl WithdrawInstall {
    /// Decompose a `WithdrawModeConfig` into the install bundle, constructing the
    /// rate limiter (the only fallible step). Shared by `operator_init` and tests.
    pub(crate) fn from_config(config: WithdrawModeConfig) -> GuardianResult<Self> {
        let (withdraw_state, secret_sharing_instance, network, authorized_kp_fingerprints) =
            config.into_parts();
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
            authorized_kp_fingerprints,
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

        info!(
            "Storing {} authorized KP fingerprint(s).",
            self.authorized_kp_fingerprints.len()
        );
        enclave
            .set_authorized_kp_fingerprints(self.authorized_kp_fingerprints)
            .expect("Unable to set authorized KP fingerprints");

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
    let logger = GuardianS3Client::new_checked(&s3_config).await?;
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
    logger: GuardianS3Client,
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
        .log_init(OIGuardianInfo(Box::new(enclave.info().await)))
        .await
        .expect("Unable to log GuardianInfo");

    enclave
        .scratchpad
        .operator_init_logging_complete
        .set(())
        .expect("operator_init_logging_complete should only be set once");

    info!("Operator initialization complete.");
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
