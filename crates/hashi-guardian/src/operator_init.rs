// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_init`: receives S3 config and (in withdraw mode) the stable
//! `InitConfig`, installs arming state, and writes the init logs. Enabled in
//! both modes. The companion `provisioner_init` (withdraw-only) lives in
//! `withdraw::provisioner_init`.

use crate::attestation::get_attestation;
use crate::s3_reader::BuildPolicy;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use crate::GuardianS3Client;
use hashi_types::guardian::InitLogMessage::OIAttestationUnsigned;
use hashi_types::guardian::InitLogMessage::OIGuardianInfo;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;
use GuardianError::*;

/// The withdraw-mode arming state to install, built from `InitConfig`.
pub(crate) struct InitInstall {
    init_config: InitConfig,
    ceremony_state: CeremonyState,
    genesis_state: Option<GenesisState>,
}

impl InitInstall {
    pub(crate) fn from_parts(
        config: InitConfig,
        ceremony_state: CeremonyState,
        genesis_state: Option<GenesisState>,
    ) -> Self {
        Self {
            init_config: config,
            ceremony_state,
            genesis_state,
        }
    }

    /// Build the arming bundle from the stable config and S3-derived ceremony +
    /// KP share state. Shared by `operator_init` and tests.
    pub(crate) async fn from_config(
        logger: &GuardianS3Client,
        config: InitConfig,
        genesis_state: Option<GenesisState>,
    ) -> GuardianResult<Self> {
        let mut reader =
            GuardianReader::from_s3_client(logger.clone(), config.pcr_allowlist().clone());
        let ceremony_state = reader
            .read_latest_ceremony_state(BuildPolicy::AnyAllowlisted)
            .await
            .map_err(|e| InvalidInputs(format!("read latest ceremony and KP share state: {e}")))?
            .ok_or_else(|| InvalidInputs("no ceremony log found for withdraw init".into()))?;

        Ok(Self::from_parts(config, ceremony_state, genesis_state))
    }

    /// Install the bundle onto a fresh enclave. Infallible by design (see the
    /// `operator_init` invariant): every set runs once on a fresh enclave.
    pub(crate) fn install_into(self, enclave: &Enclave) {
        let network = self.init_config.network();
        let hashi_btc_master_pubkey = self.init_config.hashi_btc_master_pubkey();

        info!("Setting bitcoin network to {:?}.", network);
        enclave
            .config
            .set_bitcoin_network(network)
            .expect("Unable to set network");

        info!(
            "Storing secret-sharing instance: n={}, t={}, {} commitments.",
            self.ceremony_state.secret_sharing_instance.num_shares(),
            self.ceremony_state.secret_sharing_instance.threshold(),
            self.ceremony_state
                .secret_sharing_instance
                .commitments()
                .len()
        );
        enclave
            .set_ceremony_state(self.ceremony_state)
            .expect("Unable to set ceremony state");

        if let Some(genesis_state) = self.genesis_state {
            info!(
                genesis_state_hash = hex::encode(genesis_state.digest()),
                "Storing genesis state."
            );
            enclave
                .set_genesis_state(genesis_state)
                .expect("Unable to set genesis state");
        }

        info!("Setting init config.");
        enclave
            .set_init_config(self.init_config)
            .expect("Unable to set init config");

        info!("Setting hashi BTC master pubkey.");
        enclave
            .config
            .set_hashi_btc_pk(hashi_btc_master_pubkey)
            .expect("Unable to set hashi BTC master pubkey");
    }
}

/// Receives S3 API keys and — for a withdraw-mode enclave — the stable `InitConfig`;
/// installs arming state and fixes the `config_hash`. A ceremony enclave carries only S3.
///
/// Invariant: operator_init never returns an `Err` from a partially-initialized
/// enclave. Every fallible step (request validation, S3 connectivity, S3 reads)
/// runs before any state is mutated, so an early `Err` leaves the enclave
/// untouched and retryable. The mutation then happens entirely in
/// `commit_operator_init`, which returns `()` — it cannot report an error, so a
/// half-mutated enclave is never observed via an `Err`.
pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");

    // Serialize so concurrent callers can't race the check-then-commit below.
    let _guard = enclave.control_lock.lock().await;

    let uninitialized = match enclave.mode() {
        EnclaveMode::Ceremony => CeremonyStage::Uninitialized.into(),
        EnclaveMode::Withdraw => WithdrawStage::Uninitialized.into(),
    };
    enclave.require_lifecycle(uninitialized)?;

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----

    // A withdraw-mode enclave must carry the config and a ceremony enclave must not.
    request.validate(enclave.mode())?;

    let (s3_config, init_config, genesis_state) = request.into_parts();
    let logger = GuardianS3Client::new_checked(&s3_config).await?;
    info!("S3 connectivity check complete.");

    // Build the withdraw-mode install bundle up front; `None` for a ceremony enclave.
    let withdraw = match init_config {
        Some(config) => Some(InitInstall::from_config(&logger, config, genesis_state).await?),
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
    withdraw: Option<InitInstall>,
) {
    info!("Storing S3 configuration.");
    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    // Withdraw-mode arming state (InitConfig, BTC master pubkey, instance,
    // network, config_hash); a ceremony enclave installs none of it.
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
    // This pre-transition snapshot reports `Uninitialized`; successfully
    // writing it completes operator initialization.
    enclave
        .log_init(OIGuardianInfo(Box::new(enclave.info().await)))
        .await
        .expect("Unable to log GuardianInfo");

    let initialized = match enclave.mode() {
        EnclaveMode::Ceremony => CeremonyStage::OperatorInitialized.into(),
        EnclaveMode::Withdraw => WithdrawStage::OperatorInitialized.into(),
    };
    enclave
        .advance_lifecycle_into(initialized)
        .expect("operator_init should advance an uninitialized enclave");

    info!("Operator initialization complete.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run commit_operator_init on a fresh enclave for the given mode (withdraw =>
    /// carries the InitConfig install bundle; ceremony => none).
    async fn commit_for_mode(mode: EnclaveMode) -> Arc<Enclave> {
        let enclave = Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
            mode,
        ));

        let withdraw = match mode {
            EnclaveMode::Withdraw => {
                let config = InitConfig::mock_for_testing(None);
                let args = crate::test_utils::OperatorInitTestArgs::default();
                Some(InitInstall::from_parts(config, args.ceremony_state, None))
            }
            EnclaveMode::Ceremony => None,
        };

        commit_operator_init(&enclave, crate::test_utils::mock_logger(), withdraw).await;
        enclave
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_withdraw_mode() {
        let enclave = commit_for_mode(EnclaveMode::Withdraw).await;
        assert_eq!(
            enclave.lifecycle(),
            WithdrawStage::OperatorInitialized.into()
        );
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_ceremony_mode() {
        let enclave = commit_for_mode(EnclaveMode::Ceremony).await;
        assert_eq!(
            enclave.lifecycle(),
            CeremonyStage::OperatorInitialized.into()
        );
    }
}
