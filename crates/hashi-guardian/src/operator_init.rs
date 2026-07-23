// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_init`: receives S3 config and (in withdraw mode) the stable
//! `InitConfig`, installs arming state, and writes the init logs. Enabled in
//! both modes. The companion `provisioner_init` (withdraw-only) lives in
//! `withdraw::provisioner_init`.

use crate::attestation::get_attestation;
use crate::enclave::TemporaryInitState;
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

/// Complete operator-init state ready for its fail-stop commit.
pub struct OIInstall {
    logger: GuardianS3Client,
    withdraw_mode: Option<OIWithdrawModeInstall>,
}

/// Withdraw-mode arming state built from `InitConfig` and the ceremony logs.
pub struct OIWithdrawModeInstall {
    init_config: InitConfig,
    ceremony_state: CeremonyState,
    genesis_state: Option<GenesisState>,
}

impl OIInstall {
    fn new(logger: GuardianS3Client, withdraw_mode: Option<OIWithdrawModeInstall>) -> Self {
        Self {
            logger,
            withdraw_mode,
        }
    }
}

impl OIWithdrawModeInstall {
    pub fn from_parts(
        init_config: InitConfig,
        ceremony_state: CeremonyState,
        genesis_state: Option<GenesisState>,
    ) -> Self {
        Self {
            init_config,
            ceremony_state,
            genesis_state,
        }
    }

    /// Build the arming bundle from the stable config and S3-derived ceremony +
    /// KP share state.
    pub async fn from_config(
        logger: &GuardianS3Client,
        config: InitConfig,
        genesis_state: Option<GenesisState>,
    ) -> GuardianResult<Self> {
        let mut reader =
            GuardianReader::from_s3_client(logger.clone(), config.pcr_allowlist().clone());
        let ceremony_state = reader
            .read_latest_ceremony_state(BuildPolicy::AnyAllowlisted)
            .await?
            .ok_or_else(|| InvalidInputs("no ceremony log found for withdraw init".into()))?;

        Ok(Self::from_parts(config, ceremony_state, genesis_state))
    }

    /// Install the bundle onto a fresh enclave. Infallible by design (see the
    /// `operator_init` invariant): every set runs once on a fresh enclave.
    pub fn install_into(self, enclave: &Enclave) {
        let config_hash = self.init_config.digest();
        let (limiter_config, hashi_btc_master_pubkey, pcr_allowlist, network) =
            self.init_config.into_parts();

        info!(
            "Setting secret-sharing instance: n={}, t={}, {} commitments.",
            self.ceremony_state.secret_sharing_instance.num_shares(),
            self.ceremony_state.secret_sharing_instance.threshold(),
            self.ceremony_state
                .secret_sharing_instance
                .commitments()
                .len()
        );
        if let Some(genesis_state) = &self.genesis_state {
            info!(
                genesis_state_hash = hex::encode(genesis_state.digest()),
                "Storing genesis state."
            );
        }
        enclave
            .set_temporary_init_state(TemporaryInitState {
                ceremony_state: self.ceremony_state,
                genesis_state: self.genesis_state,
                config_hash,
            })
            .expect("Unable to set temporary initialization state");

        info!(?network, "Setting enclave configuration.");
        enclave
            .install_config(
                network,
                hashi_btc_master_pubkey,
                pcr_allowlist,
                limiter_config,
            )
            .expect("Unable to set enclave configuration");
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
/// Validate and commit operator initialization under the cancellation-safe
/// control lock so concurrent callers cannot race the check-then-commit.
pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");

    let uninitialized = match enclave.mode() {
        EnclaveMode::Ceremony => CeremonyStage::Uninitialized.into(),
        EnclaveMode::Withdraw => WithdrawStage::Uninitialized.into(),
    };
    enclave.require_lifecycle(uninitialized)?;
    info!("Lifecycle stage validated.");

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----

    // A withdraw-mode enclave must carry the config and a ceremony enclave must not.
    request.validate(enclave.mode())?;

    let (s3_config, init_config, genesis_state) = request.into_parts();
    let logger = GuardianS3Client::new_checked(&s3_config).await?;
    info!("S3 connectivity check complete.");

    // Build the withdraw-mode install bundle up front; `None` for a ceremony enclave.
    let withdraw_mode = match init_config {
        Some(config) => {
            Some(OIWithdrawModeInstall::from_config(&logger, config, genesis_state).await?)
        }
        None => None,
    };
    let install = OIInstall::new(logger, withdraw_mode);

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    info!("Committing S3 logger and mode-specific initialization state.");
    commit_operator_init(&enclave, install).await;

    info!("Operator initialization complete.");
    Ok(())
}

/// Install the validated config on the enclave and write the operator_init logs.
/// Infallible by design (returns `()`, see the `operator_init` invariant): every
/// `set` here runs on a fresh enclave under the control lock, and the I/O steps
/// (attestation, S3 logging) panic on failure rather than return.
async fn commit_operator_init(enclave: &Enclave, install: OIInstall) {
    let OIInstall {
        logger,
        withdraw_mode,
    } = install;

    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    // A ceremony enclave has no withdraw-mode arming state.
    if let Some(withdraw_mode) = withdraw_mode {
        withdraw_mode.install_into(enclave);
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
    // TODO(testnet-wipe): Replace the full GuardianInfo snapshot with a
    // purpose-built OI payload containing only the data readers and KPs need;
    // the evolving status response should not define the durable log schema.
    // Include the retention environment in that payload for audit provenance.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::CapturedPuts;

    /// Run commit_operator_init on a fresh enclave for the given mode (withdraw =>
    /// carries the InitConfig install bundle; ceremony => none).
    async fn commit_for_mode(mode: EnclaveMode) -> (Arc<Enclave>, CapturedPuts) {
        let enclave = Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
            mode,
        ));

        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let install = match mode {
            EnclaveMode::Withdraw => {
                let config = InitConfig::mock_for_testing(None);
                let args = crate::test_utils::OperatorInitTestArgs::default();
                OIInstall::new(
                    logger,
                    Some(OIWithdrawModeInstall::from_parts(
                        config,
                        args.ceremony_state,
                        None,
                    )),
                )
            }
            EnclaveMode::Ceremony => OIInstall::new(logger, None),
        };

        commit_operator_init(&enclave, install).await;
        (enclave, captures)
    }

    fn assert_operator_init_logs(
        enclave: &Enclave,
        captures: &CapturedPuts,
        expected_lifecycle: EnclaveLifecycle,
    ) {
        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 2, "operator init should write two records");
        let session_id = enclave.s3_session_id();
        assert_eq!(
            captured[0].0,
            InitLogMessage::attestation_object_key(&session_id)
        );
        assert_eq!(
            captured[1].0,
            InitLogMessage::guardian_info_object_key(&session_id)
        );

        let attestation: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        assert!(matches!(
            attestation.message,
            VersionedLogMessage::V2(LogMessage::Init(message))
                if matches!(*message, OIAttestationUnsigned { .. })
        ));

        let guardian_info: LogRecord = serde_json::from_slice(&captured[1].1).unwrap();
        let VersionedLogMessage::V2(LogMessage::Init(message)) = guardian_info.message else {
            panic!("expected V2 init record");
        };
        let OIGuardianInfo(info) = *message else {
            panic!("expected operator-init GuardianInfo record");
        };
        assert_eq!(info.lifecycle, expected_lifecycle);
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_withdraw_mode() {
        let (enclave, captures) = commit_for_mode(EnclaveMode::Withdraw).await;
        assert_eq!(
            enclave.lifecycle(),
            WithdrawStage::OperatorInitialized.into()
        );
        assert_operator_init_logs(&enclave, &captures, WithdrawStage::Uninitialized.into());
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_ceremony_mode() {
        let (enclave, captures) = commit_for_mode(EnclaveMode::Ceremony).await;
        assert_eq!(
            enclave.lifecycle(),
            CeremonyStage::OperatorInitialized.into()
        );
        assert_operator_init_logs(&enclave, &captures, CeremonyStage::Uninitialized.into());
    }
}
