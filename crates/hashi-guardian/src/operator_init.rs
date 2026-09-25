// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_init`: receives S3 config and (in withdraw mode) the stable
//! `InitConfig`, installs arming state, and writes the init logs. Enabled in
//! both modes. The companion `provisioner_init` (withdraw-only) lives in
//! `withdraw::provisioner_init`.

use crate::attestation::get_attestation;
use crate::enclave::TemporaryInitState;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use crate::GuardianS3Client;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::InitLogMessage::OIAttestationUnsigned;
use hashi_types::guardian::InitLogMessage::OIGuardianInfo;
use hashi_types::guardian::*;
use hpke::Serializable;
use std::sync::Arc;
use tracing::info;
use GuardianError::*;

/// Complete operator-init state ready for its fail-stop commit.
pub struct OIInstall {
    deployment: DeploymentConfig,
    attestation: NitroAttestation,
    logger: GuardianS3Client,
    withdraw_mode: Option<OIWithdrawModeInstall>,
}

/// Withdraw-mode arming state built from `InitConfig` and the ceremony logs.
pub struct OIWithdrawModeInstall {
    init_config: InitConfig,
    ceremony_state: CeremonyState,
    genesis_state: Option<GenesisState>,
    hashi_object_id: hashi_types::sui_sdk_types::Address,
    mpc_master_g: HashiMasterG,
}

impl OIInstall {
    fn new(
        deployment: DeploymentConfig,
        attestation: NitroAttestation,
        logger: GuardianS3Client,
        withdraw_mode: Option<OIWithdrawModeInstall>,
    ) -> Self {
        Self {
            deployment,
            attestation,
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
        hashi_object_id: hashi_types::sui_sdk_types::Address,
        mpc_master_g: HashiMasterG,
    ) -> Self {
        Self {
            init_config,
            ceremony_state,
            genesis_state,
            hashi_object_id,
            mpc_master_g,
        }
    }

    /// Build the arming bundle from the stable config, verified ceremony state,
    /// and either supplied bootstrap state or verified persisted genesis.
    async fn from_ceremony_state(
        reader: &mut GuardianReader,
        config: InitConfig,
        ceremony_state: CeremonyState,
        genesis_state: Option<GenesisState>,
    ) -> GuardianResult<Self> {
        // First deployment pins these values for KP authorization during PI.
        // Subsequent enclaves recover them from the verified immutable record.
        let (hashi_object_id, mpc_master_g) = match &genesis_state {
            Some(state) => {
                let (_, hashi_object_id, mpc_master_g) = state.clone().into_parts();
                (hashi_object_id, mpc_master_g)
            }
            None => {
                let genesis = reader.read_genesis().await?.ok_or_else(|| {
                    InvalidInputs("no genesis record found; genesis bootstrap is required".into())
                })?;
                (genesis.hashi_object_id, genesis.mpc_master_g)
            }
        };

        Ok(Self::from_parts(
            config,
            ceremony_state,
            genesis_state,
            hashi_object_id,
            mpc_master_g,
        ))
    }

    /// Install the bundle onto a fresh enclave. Infallible by design (see the
    /// `operator_init` invariant): every set runs once on a fresh enclave.
    pub fn install_into(self, enclave: &Enclave) {
        let config_hash = self.init_config.digest();
        let limiter_config = *self.init_config.limiter_config();

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

        info!("Setting withdraw configuration.");
        enclave
            .install_config(self.mpc_master_g, limiter_config, self.hashi_object_id)
            .expect("Unable to set enclave configuration");
    }
}

/// Receives S3 API keys and mode-specific configuration. A ceremony enclave
/// installs the shared deployment policy; a withdraw enclave additionally
/// installs the stable `InitConfig`, arming state, and fixed `config_hash`.
///
/// Invariant: operator_init never returns an `Err` from a partially-initialized
/// enclave. Every fallible preparation step (validation, attestation, S3 access)
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

    let (deployment, s3_credentials, withdraw_inputs) = match (enclave.mode(), request) {
        (
            EnclaveMode::Ceremony,
            OperatorInitRequest::Ceremony(CeremonyOperatorInitRequest {
                deployment,
                s3_credentials,
            }),
        ) => (deployment, s3_credentials, None),
        (EnclaveMode::Withdraw, OperatorInitRequest::Withdraw(request)) => {
            let WithdrawOperatorInitRequest {
                s3_credentials,
                init_config,
                genesis_state,
            } = *request;
            (
                init_config.deployment().clone(),
                s3_credentials,
                Some((init_config, genesis_state)),
            )
        }
        (EnclaveMode::Ceremony, OperatorInitRequest::Withdraw(_)) => {
            return Err(InvalidInputs(
                "ceremony-mode guardian received a withdraw operator-init request".into(),
            ));
        }
        (EnclaveMode::Withdraw, OperatorInitRequest::Ceremony(_)) => {
            return Err(InvalidInputs(
                "withdraw-mode guardian received a ceremony operator-init request".into(),
            ));
        }
    };
    validate_deployment(&enclave, &deployment)?;
    let attestation = get_attestation(&enclave.signing_pubkey())?;
    attestation
        .verify_live(
            &enclave.signing_pubkey(),
            deployment.pcr_allowlist.current_build(),
        )
        .map_err(|error| InvalidInputs(format!("deployment attestation check failed: {error}")))?;
    let logger = GuardianS3Client::new(
        &deployment.bucket_info,
        deployment.retention_environment,
        &s3_credentials,
    )
    .await?;
    info!("S3 connectivity check complete.");

    // Build the withdraw-mode install bundle up front; `None` for a ceremony enclave.
    let withdraw_mode = match withdraw_inputs {
        Some((config, genesis_state)) => {
            let mut reader =
                GuardianReader::from_s3_client(logger.clone(), config.deployment().clone());
            let ceremony_state = reader.read_latest_ceremony_state().await?;
            Some(
                OIWithdrawModeInstall::from_ceremony_state(
                    &mut reader,
                    config,
                    ceremony_state,
                    genesis_state,
                )
                .await?,
            )
        }
        None => None,
    };
    let install = OIInstall::new(deployment, attestation, logger, withdraw_mode);

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    info!("Committing S3 logger and mode-specific initialization state.");
    commit_operator_init(&enclave, install).await;

    info!("Operator initialization complete.");
    Ok(())
}

/// This precursor retains the compiled revision. The runtime-config follow-up
/// removes this comparison together with the corresponding build input.
fn validate_deployment(enclave: &Enclave, deployment: &DeploymentConfig) -> GuardianResult<()> {
    if deployment.pcr_allowlist.current_build().git_revision() != enclave.reported_git_revision() {
        return Err(InvalidInputs(
            "deployment revision does not match the compiled build".into(),
        ));
    }
    Ok(())
}

/// Install the validated config on the enclave and write the operator_init logs.
/// Infallible by design (returns `()`, see the `operator_init` invariant): every
/// `set` here runs on a fresh enclave under the control lock, and S3 logging
/// panics on failure rather than returning an error.
async fn commit_operator_init(enclave: &Enclave, install: OIInstall) {
    let OIInstall {
        deployment,
        attestation,
        logger,
        withdraw_mode,
    } = install;

    let oi_info = OperatorInitInfo {
        deployment: deployment.clone(),
        encryption_pubkey: enclave.encryption_public_key().to_bytes().to_vec(),
        mode: match &withdraw_mode {
            None => OperatorInitMode::Ceremony,
            Some(withdraw) => OperatorInitMode::Withdraw(Box::new(WithdrawOperatorInitInfo {
                secret_sharing_instance: withdraw.ceremony_state.secret_sharing_instance.clone(),
                config_hash: withdraw.init_config.digest(),
                limiter_config: *withdraw.init_config.limiter_config(),
                hashi_object_id: withdraw.hashi_object_id,
                mpc_master_g: withdraw.mpc_master_g,
                genesis_state_hash: withdraw.genesis_state.as_ref().map(GenesisState::digest),
            })),
        },
    };

    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    enclave
        .config
        .set_deployment(deployment)
        .expect("deployment is installed once");

    // A ceremony enclave has no withdraw-mode arming state.
    if let Some(withdraw_mode) = withdraw_mode {
        withdraw_mode.install_into(enclave);
    }

    // Log to S3!
    // 1) Attestation and pub key help authenticate all subsequent enclave-signed messages.
    let signing_pk = enclave.signing_pubkey();
    enclave
        .log_init(OIAttestationUnsigned {
            attestation,
            signing_public_key: signing_pk,
        })
        .await
        .expect("S3 logger must be initialized to log the OI attestation");

    // 2) Share commitments help KPs confirm that the right private key will be constructed.
    // Successfully writing this record completes operator initialization before
    // the live lifecycle advances. Its schema contains only durable OI facts.
    enclave
        .log_init(OIGuardianInfo(Box::new(oi_info)))
        .await
        .expect("S3 logger must be initialized to log operator initialization");

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

    #[tokio::test]
    async fn wrong_build_policy_leaves_initialization_retryable() {
        let enclave = Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
            EnclaveMode::Ceremony,
        ));
        let mut deployment = DeploymentConfig::mock_for_testing();
        deployment.pcr_allowlist =
            PcrAllowlist::new(BuildPcrs::new("other-build", vec![0]), []).unwrap();
        let request =
            OperatorInitRequest::new_ceremony_mode(deployment, S3Credentials::mock_for_testing());
        assert!(operator_init(enclave.clone(), request)
            .await
            .unwrap_err()
            .to_string()
            .contains("compiled build"));
        assert_eq!(enclave.lifecycle(), CeremonyStage::Uninitialized.into());
        assert!(enclave.config.deployment().is_err());
        assert!(enclave.config.s3_logger().is_err());
        let deployment = DeploymentConfig::mock_for_testing();
        assert!(validate_deployment(&enclave, &deployment).is_ok());
    }

    fn genesis_record(state: GenesisState, key: &GuardianSignKeyPair) -> LogRecord {
        let (committee, hashi_object_id, mpc_master_g) = state.into_parts();
        LogRecord::new(
            SessionID::from_signing_pubkey(&key.verification_key()),
            LogMessage::Genesis(Box::new(GenesisLogMessage {
                committee,
                hashi_object_id,
                mpc_master_g,
            })),
            key,
        )
    }

    #[tokio::test]
    async fn installs_immutable_bindings_from_genesis_after_committee_updates() {
        let key = GuardianSignKeyPair::from([42; 32]);
        let (committee, _, _) = GenesisState::mock_for_testing().into_parts();
        let object_id = hashi_types::sui_sdk_types::Address::new([19; 32]);
        let master_g = hashi_types::bitcoin::hashi_master_g_from_btc_xonly_for_test(
            &hashi_types::bitcoin::create_btc_keypair_for_test(&[23; 32])
                .x_only_public_key()
                .0,
        );
        let genesis = GenesisState::from_parts(committee, object_id, master_g);
        let mut reader = crate::s3_reader::genesis_reader_for_test(
            Some(genesis_record(genesis, &key)),
            key.verification_key(),
            vec!["committee-update/00000000000000000009-later-session.json".into()],
        );
        let args = crate::test_utils::OperatorInitTestArgs::default();
        let install = OIWithdrawModeInstall::from_ceremony_state(
            &mut reader,
            args.config,
            args.ceremony_state,
            None,
        )
        .await
        .unwrap();
        let enclave = Enclave::create_with_random_keys();
        enclave
            .config
            .set_deployment(install.init_config.deployment().clone())
            .unwrap();
        install.install_into(&enclave);
        let info = enclave.info().await;
        assert_eq!(info.hashi_object_id, Some(object_id));
        assert_eq!(info.mpc_master_g, Some(master_g));
        assert_eq!(info.genesis_state_hash, None);
    }

    #[tokio::test]
    async fn bootstrap_installs_supplied_genesis_bindings_and_authorization_hash() {
        // This logger cannot service reads: bootstrap must use the supplied state.
        let args = crate::test_utils::OperatorInitTestArgs::default();
        let mut reader =
            GuardianReader::from_s3_client(args.s3_logger, args.config.deployment().clone());
        let genesis = GenesisState::mock_for_testing();
        let expected_hash = genesis.digest();
        let (_, object_id, master_g) = genesis.clone().into_parts();
        let install = OIWithdrawModeInstall::from_ceremony_state(
            &mut reader,
            args.config,
            args.ceremony_state,
            Some(genesis),
        )
        .await
        .unwrap();
        let enclave = Enclave::create_with_random_keys();
        enclave
            .config
            .set_deployment(install.init_config.deployment().clone())
            .unwrap();
        install.install_into(&enclave);
        let info = enclave.info().await;
        assert_eq!(info.hashi_object_id, Some(object_id));
        assert_eq!(info.mpc_master_g, Some(master_g));
        assert_eq!(info.genesis_state_hash, Some(expected_hash));
    }

    #[tokio::test]
    async fn missing_or_invalid_genesis_rejects_install_preparation() {
        let key = GuardianSignKeyPair::from([42; 32]);
        let record = genesis_record(GenesisState::mock_for_testing(), &key);
        // Keep the expected session identity while changing signed contents.
        let mut json = serde_json::to_value(record).unwrap();
        json["timestamp_ms"] = serde_json::json!(json["timestamp_ms"].as_u64().unwrap() + 1);
        let invalid_record = serde_json::from_value(json).unwrap();
        for record in [None, Some(invalid_record)] {
            let missing = record.is_none();
            let mut reader =
                crate::s3_reader::genesis_reader_for_test(record, key.verification_key(), vec![]);
            let args = crate::test_utils::OperatorInitTestArgs::default();
            let result = OIWithdrawModeInstall::from_ceremony_state(
                &mut reader,
                args.config,
                args.ceremony_state,
                None,
            )
            .await;
            let error = result
                .err()
                .expect("invalid genesis must not produce an install bundle");
            if missing {
                assert!(
                    matches!(error, InvalidInputs(message) if message.contains("no genesis record"))
                );
            } else {
                assert!(
                    matches!(error, InvalidS3Log(message) if message.contains("invalid log signature"))
                );
            }
        }
    }

    /// Run commit_operator_init on a fresh enclave for the given mode (withdraw =>
    /// carries the InitConfig install bundle; ceremony => none).
    async fn commit_for_mode(mode: EnclaveMode) -> (Arc<Enclave>, CapturedPuts) {
        let enclave = Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
            mode,
        ));

        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let (deployment, withdraw_mode) = match mode {
            EnclaveMode::Withdraw => {
                let config = InitConfig::mock_for_testing();
                let args = crate::test_utils::OperatorInitTestArgs::default();
                (
                    config.deployment().clone(),
                    Some(OIWithdrawModeInstall::from_parts(
                        config,
                        args.ceremony_state,
                        None,
                        args.hashi_object_id,
                        args.mpc_master_g,
                    )),
                )
            }
            EnclaveMode::Ceremony => (DeploymentConfig::mock_for_testing(), None),
        };

        let attestation = get_attestation(&enclave.signing_pubkey()).unwrap();
        let install = OIInstall::new(deployment, attestation, logger, withdraw_mode);
        commit_operator_init(&enclave, install).await;
        (enclave, captures)
    }

    async fn assert_operator_init_logs(
        enclave: &Enclave,
        captures: &CapturedPuts,
        expected_mode: EnclaveMode,
    ) {
        let live_info = enclave.info().await;
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
            attestation.message(),
            VersionedLogMessage::V1(LogMessageV1::Init(message))
                if matches!(message.as_ref(), OIAttestationUnsigned { .. })
        ));

        let guardian_info: LogRecord = serde_json::from_slice(&captured[1].1).unwrap();
        let VersionedLogMessage::V1(LogMessageV1::Init(message)) = guardian_info.message() else {
            panic!("expected V1 init record");
        };
        let OIGuardianInfo(info) = message.as_ref() else {
            panic!("expected operator-init completion record");
        };
        assert_eq!(info.mode(), expected_mode);
        assert_eq!(&info.deployment, enclave.config.deployment().unwrap());
        assert_eq!(
            info.encryption_pubkey,
            enclave.encryption_public_key().to_bytes().to_vec()
        );
        if let OperatorInitMode::Withdraw(withdraw) = &info.mode {
            let state = enclave.temporary_init_state().unwrap();
            assert_eq!(
                withdraw.secret_sharing_instance,
                state.ceremony_state.secret_sharing_instance
            );
            assert_eq!(withdraw.config_hash, state.config_hash);
            assert_eq!(
                withdraw.genesis_state_hash,
                state.genesis_state.as_ref().map(GenesisState::digest)
            );
            assert_eq!(withdraw.limiter_config, enclave.limiter_config().unwrap());
            assert_eq!(Some(withdraw.hashi_object_id), live_info.hashi_object_id);
            assert_eq!(Some(withdraw.mpc_master_g), live_info.mpc_master_g);
        }
        guardian_info
            .validate(Some(&enclave.signing_pubkey()))
            .unwrap();
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_withdraw_mode() {
        let (enclave, captures) = commit_for_mode(EnclaveMode::Withdraw).await;
        assert_eq!(
            enclave.lifecycle(),
            WithdrawStage::OperatorInitialized.into()
        );
        assert_operator_init_logs(&enclave, &captures, EnclaveMode::Withdraw).await;
    }

    #[tokio::test]
    async fn commit_marks_operator_init_complete_ceremony_mode() {
        let (enclave, captures) = commit_for_mode(EnclaveMode::Ceremony).await;
        assert_eq!(
            enclave.lifecycle(),
            CeremonyStage::OperatorInitialized.into()
        );
        assert_operator_init_logs(&enclave, &captures, EnclaveMode::Ceremony).await;
    }
}
