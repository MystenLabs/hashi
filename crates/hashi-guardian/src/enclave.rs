// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Plain enclave data and domain helpers. `GuardianService` owns the control
//! mutex; domain handlers borrow this object for their entire execution.

use bitcoin::secp256k1::Keypair;
use bitcoin::Network;
use bitcoin::Txid;
use hashi_types::bitcoin::sign_btc_tx;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::BitcoinSignature;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::bitcoin::TxUTXOs;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::LifecycleMismatch;
use hashi_types::guardian::GuardianError::Unauthenticated;
use hashi_types::guardian::*;
use hpke::Serializable;
use std::collections::BTreeSet;
use tracing::info;

use crate::log_writer::LogWriter;
use crate::s3_client::GuardianS3Client;
use crate::s3_reader::GuardianReader;
use hashi_types::guardian::RuntimeCommittee;

/// Plain domain data, exclusively borrowed by the control task.
pub struct Enclave {
    /// Immutable config (set once during init)
    pub config: EnclaveConfig,
    pub state: EnclaveState,
    /// Write ordering follows the service control lock; the fence remains local.
    log_writer: LogWriter,
}

/// Configuration set during initialization (immutable after set)
pub struct EnclaveConfig {
    /// Ephemeral signing keypair generated at boot.
    signing_keys: GuardianSignKeyPair,
    /// Ephemeral encryption keypair generated at boot.
    encryption_keys: GuardianEncKeyPair,
    /// S3 client & config (set in operator_init)
    s3_logger: Option<GuardianS3Client>,
    /// Enclave BTC private key (set in provisioner_init)
    enclave_btc_keypair: Option<Keypair>,
    /// Complete deployment policy, installed once in either mode during OI.
    deployment: Option<DeploymentConfig>,
    /// Raw MPC verifying key as a curve point. Stored with y-parity so the
    /// 2-of-2 child-key derivation matches the MPC's signing protocol.
    /// Set in operator_init.
    hashi_btc_master_pubkey: Option<HashiMasterG>,
    /// Operator-supplied limiter configuration.
    /// Note: This struct is duplicated in two places: `RateLimiter` stores a copy after activation.
    limiter_config: Option<LimiterConfig>,
    /// The Hashi shared-object id this guardian serves; bound into every
    /// committee-certificate preimage verified here (set in operator_init).
    hashi_object_id: Option<hashi_types::sui_sdk_types::Address>,
}

/// Mutable state that changes during operation.
/// Committee and rate limiter are installed during operator activation.
/// The service exclusively borrows the whole enclave; fields need no inner locks.
#[derive(Default)]
pub struct EnclaveState {
    /// Advanced only after a durable heartbeat write.
    next_heartbeat_seq: u64,
    /// Authoritative mode-specific lifecycle, absent until operator init commits.
    lifecycle: Option<EnclaveLifecycle>,
    /// Current Hashi committee.
    committee: Option<RuntimeCommittee>,
    /// Rate limiter. Set once during operator_activate.
    rate_limiter: Option<RateLimiter>,
    /// Retained until operator activation commits.
    temporary_init_state: Option<TemporaryInitState>,
    /// Retained until every KP confirms successful share recovery.
    pending_ceremony: Option<PendingCeremony>,
}

/// Inputs needed only between operator initialization and activation.
/// The enclave drops this entire capability when activation commits.
#[derive(Clone)]
pub struct TemporaryInitState {
    pub ceremony_state: CeremonyState,
    pub genesis_state: Option<GenesisState>,
    pub config_hash: [u8; 32],
}

pub(crate) struct PendingCeremony {
    proposal: CeremonyProposalLogMessage,
    ceremony_artifacts_digest: [u8; 32],
    confirmed_share_ids: BTreeSet<ShareID>,
}

impl PendingCeremony {
    fn new(
        proposal: CeremonyProposalLogMessage,
        deployment: &DeploymentConfig,
    ) -> GuardianResult<Self> {
        let artifacts = CeremonyArtifacts {
            deployment: deployment.clone(),
            ceremony_state: CeremonyState::from_proposal(proposal.clone())?,
        };
        Ok(Self {
            proposal,
            ceremony_artifacts_digest: artifacts.digest(),
            confirmed_share_ids: BTreeSet::new(),
        })
    }

    pub(crate) fn validate_confirmation(
        &self,
        signer_fingerprint: &str,
        ceremony_artifacts_digest: &[u8; 32],
    ) -> GuardianResult<(ShareID, bool)> {
        if ceremony_artifacts_digest != &self.ceremony_artifacts_digest {
            return Err(InvalidInputs(
                "ceremony confirmation digest differs from pending ceremony".into(),
            ));
        }
        let share = self
            .proposal
            .encrypted_shares
            .find_by_fingerprint(signer_fingerprint)
            .ok_or_else(|| {
                Unauthenticated(format!(
                    "KP fingerprint {signer_fingerprint} is not present in the pending ceremony roster"
                ))
            })?;
        let confirmed = self.confirmed_share_ids.contains(&share.id);
        Ok((share.id, confirmed))
    }

    pub(crate) fn record_confirmation(
        &mut self,
        share_id: ShareID,
    ) -> GuardianResult<CeremonyConfirmationResponse> {
        self.confirmed_share_ids.insert(share_id);
        self.status()
    }

    pub(crate) fn status(&self) -> GuardianResult<CeremonyConfirmationResponse> {
        CeremonyConfirmationResponse::new(
            self.confirmed_share_ids.len(),
            self.proposal.encrypted_shares.share_count(),
        )
    }

    fn is_complete(&self) -> bool {
        self.status().is_ok_and(|status| status.completed)
    }
}

impl EnclaveConfig {
    // ========================================================================
    // Construction
    // ========================================================================

    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        EnclaveConfig {
            signing_keys,
            encryption_keys,
            s3_logger: None,
            enclave_btc_keypair: None,
            deployment: None,
            hashi_btc_master_pubkey: None,
            limiter_config: None,
            hashi_object_id: None,
        }
    }

    // ========================================================================
    // Bitcoin Configuration
    // ========================================================================

    pub fn deployment(&self) -> GuardianResult<&DeploymentConfig> {
        self.deployment
            .as_ref()
            .ok_or(InvalidInputs("Deployment is uninitialized".into()))
    }

    pub fn set_deployment(&mut self, deployment: DeploymentConfig) -> GuardianResult<()> {
        if self.deployment.is_some() {
            return Err(InvalidInputs("Deployment is already initialized".into()));
        }
        self.deployment = Some(deployment);
        Ok(())
    }

    pub fn bitcoin_network(&self) -> GuardianResult<Network> {
        Ok(self.deployment()?.bitcoin_network)
    }

    pub fn set_btc_keypair(&mut self, keypair: Keypair) -> GuardianResult<()> {
        if self.enclave_btc_keypair.is_some() {
            return Err(InvalidInputs("Bitcoin key already set".into()));
        }
        self.enclave_btc_keypair = Some(keypair);
        Ok(())
    }

    /// Returns the x-only pubkey of the enclave's BTC signing key.
    /// Returns `Err` until `provisioner_init` has set the keypair.
    pub fn enclave_btc_pubkey(&self) -> GuardianResult<BitcoinPubkey> {
        self.enclave_btc_keypair
            .as_ref()
            .map(|kp| kp.x_only_public_key().0)
            .ok_or(InvalidInputs("Bitcoin key is not initialized".into()))
    }

    /// Sign a BTC tx. Returns an Err if enclave btc keypair or hashi btc pk is not set.
    pub fn btc_sign(&self, tx_utxos: &TxUTXOs) -> GuardianResult<(Txid, Vec<BitcoinSignature>)> {
        let enclave_keypair = self
            .enclave_btc_keypair
            .as_ref()
            .ok_or(InvalidInputs("Bitcoin key is not initialized".into()))?;
        let hashi_btc_pk = self
            .hashi_btc_master_pubkey
            .as_ref()
            .ok_or(InvalidInputs("Hashi BTC public key not set".into()))?;

        let enclave_btc_pk = enclave_keypair.x_only_public_key().0;
        let (messages, txid) = tx_utxos.signing_messages_and_txid(&enclave_btc_pk, hashi_btc_pk);
        Ok((txid, sign_btc_tx(&messages, enclave_keypair)))
    }

    pub fn is_enclave_btc_keypair_set(&self) -> bool {
        self.enclave_btc_keypair.is_some()
    }

    // ========================================================================
    // S3 Logger
    // ========================================================================

    pub fn s3_logger(&self) -> GuardianResult<&GuardianS3Client> {
        self.s3_logger
            .as_ref()
            .ok_or(InvalidInputs("S3 logger is not initialized".into()))
    }

    pub fn set_s3_logger(&mut self, logger: GuardianS3Client) -> GuardianResult<()> {
        if self.s3_logger.is_some() {
            return Err(InvalidInputs("S3 logger already set".into()));
        }
        self.s3_logger = Some(logger);
        Ok(())
    }
}

impl EnclaveState {
    /// Install the activation-derived committee and limiter.
    pub fn init(
        &mut self,
        committee: RuntimeCommittee,
        rate_limiter: RateLimiter,
    ) -> GuardianResult<()> {
        self.set_committee(committee)?;
        self.set_rate_limiter(rate_limiter)
    }

    /// Get the current committee.
    pub fn get_committee(&self) -> GuardianResult<&RuntimeCommittee> {
        self.committee
            .as_ref()
            .ok_or_else(|| InvalidInputs("committee not initialized".into()))
    }

    /// Called only from activation state installation.
    fn set_committee(&mut self, committee: RuntimeCommittee) -> GuardianResult<()> {
        info!("Setting committee for epoch {}.", committee.epoch());
        if self.committee.is_some() {
            return Err(InvalidInputs("committee already initialized".into()));
        }
        self.committee = Some(committee);
        Ok(())
    }

    /// Replace the committee only if the current epoch matches the expected epoch.
    pub fn replace_committee(
        &mut self,
        committee: RuntimeCommittee,
        expected_current_epoch: u64,
    ) -> GuardianResult<()> {
        info!("Replacing committee for epoch {}.", committee.epoch());
        let current_epoch = self
            .committee
            .as_ref()
            .ok_or_else(|| InvalidInputs("committee not initialized".into()))?
            .epoch();
        if current_epoch != expected_current_epoch {
            return Err(InvalidInputs(format!(
                "committee epoch mismatch: expected {expected_current_epoch}, actual {current_epoch}"
            )));
        }
        self.committee = Some(committee);
        Ok(())
    }

    fn set_rate_limiter(&mut self, limiter: RateLimiter) -> GuardianResult<()> {
        info!("Setting rate limiter.");
        if self.rate_limiter.is_some() {
            return Err(InvalidInputs("rate_limiter already initialized".into()));
        }
        self.rate_limiter = Some(limiter);
        Ok(())
    }

    /// Consume tokens and return the post-consume state.
    pub fn consume_from_limiter(
        &mut self,
        seq: u64,
        timestamp: u64,
        amount_sats: u64,
    ) -> GuardianResult<LimiterState> {
        let limiter = self
            .rate_limiter
            .as_mut()
            .ok_or_else(|| InternalError("rate limiter not initialized".into()))?;
        limiter.consume(seq, timestamp, amount_sats)?;
        Ok(*limiter.state())
    }

    /// The current limiter state, absent until activation installs it.
    pub fn limiter_state(&self) -> Option<LimiterState> {
        self.rate_limiter.as_ref().map(|limiter| *limiter.state())
    }

    /// Which flows this enclave serves after operator initialization.
    pub fn mode(&self) -> Option<EnclaveMode> {
        self.lifecycle().map(EnclaveLifecycle::mode)
    }

    pub fn lifecycle(&self) -> Option<EnclaveLifecycle> {
        self.lifecycle
    }

    pub(crate) fn install_pending_ceremony(
        &mut self,
        deployment: &DeploymentConfig,
        proposal: CeremonyProposalLogMessage,
    ) -> GuardianResult<()> {
        let pending = PendingCeremony::new(proposal, deployment)?;
        if self.pending_ceremony.is_some() {
            return Err(InvalidInputs("Pending ceremony state already set".into()));
        }
        self.pending_ceremony = Some(pending);
        Ok(())
    }

    pub(crate) fn pending_ceremony(&self) -> GuardianResult<&PendingCeremony> {
        self.pending_ceremony
            .as_ref()
            .ok_or_else(|| InvalidInputs("Pending ceremony state not set".into()))
    }

    pub(crate) fn pending_ceremony_mut(&mut self) -> GuardianResult<&mut PendingCeremony> {
        self.pending_ceremony
            .as_mut()
            .ok_or_else(|| InvalidInputs("Pending ceremony state not set".into()))
    }

    // ========================================================================
    // Temporary Initialization State
    // ========================================================================

    /// Borrow initialization state under the control lock. Activation takes the
    /// stored value, so this capability is unavailable once the enclave is active.
    /// Keep this as the only accessor for `TemporaryInitState`. Its readers are
    /// restricted to provisioner initialization, operator activation, and
    /// status reporting; active request handlers must not depend on it.
    pub fn temporary_init_state(&self) -> GuardianResult<&TemporaryInitState> {
        self.temporary_init_state
            .as_ref()
            .ok_or_else(|| InvalidInputs("Temporary initialization state not set".into()))
    }

    /// Operator initialization is the sole installer of temporary state.
    pub fn set_temporary_init_state(&mut self, state: TemporaryInitState) -> GuardianResult<()> {
        if self.temporary_init_state.is_some() {
            return Err(InvalidInputs(
                "Temporary initialization state already set".into(),
            ));
        }
        self.temporary_init_state = Some(state);
        Ok(())
    }

    pub fn clear_temporary_init_state(&mut self) {
        self.temporary_init_state
            .take()
            .expect("temporary initialization state must exist before activation");
    }
}

impl Enclave {
    // ========================================================================
    // Construction
    // ========================================================================

    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: EnclaveState::default(),
            log_writer: LogWriter::new(),
        }
    }

    /// Require an exact mode and lifecycle stage.
    pub fn require_lifecycle(&self, expected: Option<EnclaveLifecycle>) -> GuardianResult<()> {
        let actual = self.state.lifecycle();
        if actual != expected {
            return Err(LifecycleMismatch { expected, actual });
        }
        Ok(())
    }

    /// Transition after the operation's durable log succeeds. The lifecycle is
    /// the single source of completion state.
    pub fn advance_lifecycle_into(&mut self, next: EnclaveLifecycle) -> GuardianResult<()> {
        let expected = next.predecessor();
        if self.state.lifecycle != expected {
            return Err(LifecycleMismatch {
                expected,
                actual: self.state.lifecycle,
            });
        }
        self.assert_state_installed_for(next);
        self.state.lifecycle = Some(next);
        Ok(())
    }

    fn assert_state_installed_for(&self, next: EnclaveLifecycle) {
        let installed = match next {
            EnclaveLifecycle::Ceremony(CeremonyStage::OperatorInitialized) => {
                self.operator_init_state_installed(EnclaveMode::Ceremony)
            }
            EnclaveLifecycle::Ceremony(CeremonyStage::AwaitingKeyProvisionerConfirmations) => {
                self.state.pending_ceremony.is_some()
            }
            EnclaveLifecycle::Ceremony(CeremonyStage::Completed) => self
                .state
                .pending_ceremony
                .as_ref()
                .is_some_and(PendingCeremony::is_complete),
            EnclaveLifecycle::Withdraw(WithdrawStage::OperatorInitialized) => {
                self.operator_init_state_installed(EnclaveMode::Withdraw)
            }
            EnclaveLifecycle::Withdraw(WithdrawStage::ProvisionerInitialized) => {
                self.config.is_enclave_btc_keypair_set()
                    && self.state.temporary_init_state.is_some()
            }
            EnclaveLifecycle::Withdraw(WithdrawStage::Activated) => {
                self.state.committee.is_some()
                    && self.state.rate_limiter.is_some()
                    && self.state.temporary_init_state.is_none()
            }
        };
        assert!(
            installed,
            "cannot advance lifecycle to {next:?}: state is incomplete"
        );
    }

    /// Whether every field operator_init installs is present (mode-aware).
    fn operator_init_state_installed(&self, mode: EnclaveMode) -> bool {
        // Both modes install S3 and the shared deployment policy.
        if self.config.s3_logger.is_none() || self.config.deployment.is_none() {
            return false;
        }
        match mode {
            EnclaveMode::Ceremony => true,
            // Withdraw enclaves additionally install their stable configuration.
            EnclaveMode::Withdraw => {
                self.config.limiter_config.is_some()
                    && self.state.temporary_init_state.is_some()
                    && self.config.hashi_btc_master_pubkey.is_some()
                    && self.config.hashi_object_id.is_some()
            }
        }
    }

    /// Require the activated withdraw lifecycle.
    pub fn require_fully_initialized(&self) -> GuardianResult<()> {
        self.require_lifecycle(WithdrawStage::Activated.into())
    }

    // ========================================================================
    // Ephemeral Keypairs (Encryption & Signing)
    // ========================================================================

    /// Get the enclave's encryption secret key
    pub fn encryption_secret_key(&self) -> &EncSecKey {
        self.config.encryption_keys.secret_key()
    }

    /// Get the enclave's encryption public key
    pub fn encryption_public_key(&self) -> &EncPubKey {
        self.config.encryption_keys.public_key()
    }

    /// Get the enclave's verification key
    pub fn signing_pubkey(&self) -> GuardianPubKey {
        self.config.signing_keys.verification_key()
    }

    pub fn sign<T>(&self, response: T) -> GuardianSignedResponse<T>
    where
        GuardianResponse<T>: GuardianSigningIntent,
    {
        let kp = &self.config.signing_keys;
        let timestamp = now_timestamp_ms();
        GuardianSigned::sign(GuardianResponse::new(response, timestamp), kp)
    }

    // ========================================================================
    // Enclave Info
    // ========================================================================

    /// Collect status from the enclave already borrowed by the caller.
    pub fn info(&self) -> GuardianInfo {
        let state = &self.state;
        let lifecycle = state.lifecycle();
        let temporary_init_state = state.temporary_init_state().ok();
        GuardianInfo {
            signing_pub_key: self.signing_pubkey(),
            lifecycle,
            secret_sharing_instance: temporary_init_state
                .as_ref()
                .map(|state| state.ceremony_state.secret_sharing_instance.clone()),
            deployment_info: self
                .config
                .deployment
                .as_ref()
                .map(DeploymentConfig::summary),
            encryption_pubkey: self.encryption_public_key().to_bytes().to_vec(),
            config_hash: temporary_init_state.as_ref().map(|state| state.config_hash),
            genesis_state_hash: temporary_init_state
                .as_ref()
                .and_then(|state| state.genesis_state.as_ref().map(GenesisState::digest)),
            enclave_btc_pubkey: self.config.enclave_btc_pubkey().ok(),
            limiter_state: state.limiter_state(),
            limiter_config: self.limiter_config().ok(),
            current_committee_epoch: state.get_committee().ok().map(|c| c.epoch()),
            mpc_master_g: self.config.hashi_btc_master_pubkey,
            hashi_object_id: self.config.hashi_object_id,
        }
    }

    // ========================================================================
    // S3 Logging
    // ========================================================================

    /// A unique session ID for the current enclave session.
    pub fn s3_session_id(&self) -> SessionID {
        SessionID::from_signing_pubkey(&self.signing_pubkey())
    }

    pub(crate) async fn write_log(&mut self, message: LogMessage) -> GuardianResult<()> {
        let session_id = self.s3_session_id();
        self.log_writer
            .write(
                self.config.s3_logger()?,
                session_id,
                message,
                &self.config.signing_keys,
            )
            .await;
        Ok(())
    }

    /// Runs under the same control lock as RPC operations.
    pub(crate) async fn heartbeat(&mut self) -> GuardianResult<()> {
        self.write_log(LogMessage::Heartbeat(HeartbeatLogMessage::new(
            self.state.next_heartbeat_seq,
        )))
        .await?;
        self.state.next_heartbeat_seq += 1;
        Ok(())
    }

    pub async fn log_init(&mut self, msg: InitLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Init(Box::new(msg))).await
    }

    pub async fn log_withdraw(&mut self, msg: WithdrawalLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Withdrawal(Box::new(msg))).await
    }

    pub async fn log_committee_update(
        &mut self,
        msg: CommitteeUpdateLogMessage,
    ) -> GuardianResult<()> {
        self.write_log(LogMessage::CommitteeUpdate(Box::new(msg)))
            .await
    }

    pub async fn log_genesis(&mut self, msg: GenesisLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Genesis(Box::new(msg))).await
    }

    pub async fn log_ceremony_proposal(
        &mut self,
        proposal: CeremonyProposalLogMessage,
    ) -> GuardianResult<()> {
        self.write_log(LogMessage::CeremonyProposal(Box::new(proposal)))
            .await
    }

    /// Publish the pending ceremony to the established authoritative locations.
    /// The ceremony record is written last and therefore acts as the commit.
    pub(crate) async fn publish_pending_ceremony(&mut self) -> GuardianResult<()> {
        let CeremonyProposalLogMessage {
            ceremony,
            encrypted_shares,
        } = self.state.pending_ceremony()?.proposal.clone();
        let kp_share_state =
            KpShareStateLogMessage::new(ceremony.sharing_seq(), 0, encrypted_shares);
        self.write_log(LogMessage::KpShareState(Box::new(kp_share_state)))
            .await?;
        self.write_log(LogMessage::Ceremony(Box::new(ceremony)))
            .await
    }

    /// Persist the current encrypted KP share state to `kp-shares/` for recovery.
    /// `sharing_seq` pairs it with the matching `ceremony/` instance, while
    /// `cert_seq` versions recipient-cert rotations within that instance.
    pub async fn log_kp_share_state(
        &mut self,
        sharing_seq: u64,
        cert_seq: u64,
        encrypted_shares: KpEncryptedShareRoster,
    ) -> GuardianResult<()> {
        self.write_log(LogMessage::KpShareState(Box::new(
            KpShareStateLogMessage::new(sharing_seq, cert_seq, encrypted_shares),
        )))
        .await
    }

    // ========================================================================
    // Enclave Configuration
    // ========================================================================

    /// Construct a verified reader with the enclave's fixed deployment configuration
    /// and S3 client. Each operation gets a fresh, operation-scoped session cache.
    pub fn new_guardian_reader(&self) -> GuardianResult<GuardianReader> {
        Ok(GuardianReader::from_s3_client(
            self.config.s3_logger()?.clone(),
            self.config.deployment()?.clone(),
        ))
    }

    pub fn limiter_config(&self) -> GuardianResult<LimiterConfig> {
        self.config
            .limiter_config
            .ok_or_else(|| InvalidInputs("Limiter config is uninitialized".into()))
    }

    pub fn install_config(
        &mut self,
        hashi_btc_master_pubkey: HashiMasterG,
        limiter_config: LimiterConfig,
        hashi_object_id: hashi_types::sui_sdk_types::Address,
    ) -> GuardianResult<()> {
        if self.config.hashi_btc_master_pubkey.is_some() {
            return Err(InvalidInputs("Hashi BTC key is already initialized".into()));
        }
        self.config.hashi_btc_master_pubkey = Some(hashi_btc_master_pubkey);
        if self.config.limiter_config.is_some() {
            return Err(InvalidInputs(
                "Limiter config is already initialized".into(),
            ));
        }
        self.config.limiter_config = Some(limiter_config);
        if self.config.hashi_object_id.is_some() {
            return Err(InvalidInputs(
                "Hashi object id is already initialized".into(),
            ));
        }
        self.config.hashi_object_id = Some(hashi_object_id);
        Ok(())
    }

    /// The Hashi shared-object id certificates verified by this guardian must
    /// be bound to. Errors before operator_init has installed the config.
    pub fn hashi_object_id(&self) -> GuardianResult<hashi_types::sui_sdk_types::Address> {
        self.config
            .hashi_object_id
            .ok_or_else(|| InvalidInputs("Hashi object id is not initialized".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::LogMessageV1;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;

    #[tokio::test]
    async fn heartbeat_is_a_noop_before_operator_init() {
        let mut writer = HeartbeatWriter::new(Enclave::create_with_random_keys());
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 0);
    }

    #[tokio::test]
    async fn heartbeat_advances_after_durable_write() {
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;
        let mut writer = HeartbeatWriter::new(enclave);
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 1);

        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1, "heartbeat tick should write one record");
        let record: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        assert_eq!(captured[0].0, record.object_key());
        let VersionedLogMessage::V1(LogMessageV1::Heartbeat(message)) = record.message() else {
            panic!("expected V1 heartbeat record");
        };
        assert_eq!(message.seq, 0);
    }

    #[tokio::test]
    #[should_panic(expected = "heartbeats are only supported in withdraw mode")]
    async fn ceremony_mode_rejects_heartbeats() {
        Enclave::create_operator_initialized_ceremony(crate::test_utils::mock_logger())
            .log_heartbeat(HeartbeatLogMessage::new(0))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn heartbeat_writer_stays_idle_in_ceremony_mode() {
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let mut writer =
            HeartbeatWriter::new(Enclave::create_operator_initialized_ceremony(logger));
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 0);
        assert!(captures.lock().unwrap().is_empty());
    }
}
