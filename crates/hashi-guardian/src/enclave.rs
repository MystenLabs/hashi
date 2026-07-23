// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core enclave types: `Enclave` holds all guardian state (durable config,
//! mutable runtime state, and temporary initialization state). Lives in the
//! library so external crates
//! (integration test harnesses, ops tooling) can construct and drive an
//! enclave without going through `main`.

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
use hashi_types::guardian::GuardianError::Unavailable;
use hashi_types::guardian::*;
use hpke::Serializable;
use serde::Serialize;
use std::future::Future;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use tokio::sync::OwnedMutexGuard;
use tracing::info;

use crate::s3_client::GuardianS3Client;
use crate::s3_reader::GuardianReader;
use hashi_types::committee::Committee as HashiCommittee;

/// Enclave's config & state
pub struct Enclave {
    /// Immutable config (set once during init)
    pub config: EnclaveConfig,
    /// Mutable state
    pub state: EnclaveState,
    /// Temporary state retained until operator activation commits.
    temporary_init_state: RwLock<Option<TemporaryInitState>>,
    /// Serializes lifecycle and control-plane transitions so concurrent
    /// operations cannot race a check-then-set.
    control_lock: tokio::sync::Mutex<()>,
}

/// Configuration set during initialization (immutable after set)
pub struct EnclaveConfig {
    /// Ephemeral signing keypair generated at boot.
    signing_keys: GuardianSignKeyPair,
    /// Ephemeral encryption keypair generated at boot.
    encryption_keys: GuardianEncKeyPair,
    /// S3 client & config (set in operator_init)
    s3_logger: OnceLock<GuardianS3Client>,
    /// Enclave BTC private key (set in provisioner_init)
    enclave_btc_keypair: OnceLock<Keypair>,
    /// BTC network: mainnet, testnet, regtest (set in operator_init)
    btc_network: OnceLock<Network>,
    /// Raw MPC verifying key as a curve point. Stored with y-parity so the
    /// 2-of-2 child-key derivation matches the MPC's signing protocol.
    /// Set in operator_init.
    hashi_btc_master_pubkey: OnceLock<HashiMasterG>,
    /// Guardian build PCR pins used to verify attested guardian sessions.
    pcr_allowlist: OnceLock<PcrAllowlist>,
    /// Operator-supplied limiter configuration.
    /// Note: This struct is duplicated in two places: `RateLimiter` stores a copy after activation.
    limiter_config: OnceLock<LimiterConfig>,
}

/// Mutable state that changes during operation.
/// Committee + rate limiter are installed during operator_activate.
pub struct EnclaveState {
    /// Authoritative mode-specific lifecycle, initialized at boot.
    lifecycle: RwLock<EnclaveLifecycle>,
    /// Current Hashi committee.
    committee: RwLock<Option<Arc<HashiCommittee>>>,
    /// Rate limiter. Set once during operator_activate.
    /// Uses `Arc<tokio::Mutex>` so the guard can be held across `.await`.
    rate_limiter: OnceLock<Arc<tokio::sync::Mutex<RateLimiter>>>,
}

/// Inputs needed only between operator initialization and activation.
/// The enclave drops this entire capability when activation commits.
#[derive(Clone)]
pub struct TemporaryInitState {
    pub ceremony_state: CeremonyState,
    pub genesis_state: Option<GenesisState>,
    pub config_hash: [u8; 32],
}

impl EnclaveConfig {
    // ========================================================================
    // Construction
    // ========================================================================

    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        EnclaveConfig {
            signing_keys,
            encryption_keys,
            s3_logger: OnceLock::new(),
            enclave_btc_keypair: OnceLock::new(),
            btc_network: OnceLock::new(),
            hashi_btc_master_pubkey: OnceLock::new(),
            pcr_allowlist: OnceLock::new(),
            limiter_config: OnceLock::new(),
        }
    }

    // ========================================================================
    // Bitcoin Configuration
    // ========================================================================

    pub fn bitcoin_network(&self) -> GuardianResult<Network> {
        self.btc_network
            .get()
            .copied()
            .ok_or(InvalidInputs("Network is uninitialized".into()))
    }

    pub fn set_btc_keypair(&self, keypair: Keypair) -> GuardianResult<()> {
        self.enclave_btc_keypair
            .set(keypair)
            .map_err(|_| InvalidInputs("Bitcoin key already set".into()))
    }

    /// Returns the x-only pubkey of the enclave's BTC signing key.
    /// Returns `Err` until `provisioner_init` has set the keypair.
    pub fn enclave_btc_pubkey(&self) -> GuardianResult<BitcoinPubkey> {
        self.enclave_btc_keypair
            .get()
            .map(|kp| kp.x_only_public_key().0)
            .ok_or(InvalidInputs("Bitcoin key is not initialized".into()))
    }

    /// Sign a BTC tx. Returns an Err if enclave btc keypair or hashi btc pk is not set.
    pub fn btc_sign(&self, tx_utxos: &TxUTXOs) -> GuardianResult<(Txid, Vec<BitcoinSignature>)> {
        let enclave_keypair = self
            .enclave_btc_keypair
            .get()
            .ok_or(InvalidInputs("Bitcoin key is not initialized".into()))?;
        let hashi_btc_pk = self
            .hashi_btc_master_pubkey
            .get()
            .ok_or(InvalidInputs("Hashi BTC public key not set".into()))?;

        let enclave_btc_pk = enclave_keypair.x_only_public_key().0;
        let (messages, txid) = tx_utxos.signing_messages_and_txid(&enclave_btc_pk, hashi_btc_pk);
        Ok((txid, sign_btc_tx(&messages, enclave_keypair)))
    }

    pub fn is_enclave_btc_keypair_set(&self) -> bool {
        self.enclave_btc_keypair.get().is_some()
    }

    // ========================================================================
    // S3 Logger
    // ========================================================================

    pub fn s3_logger(&self) -> GuardianResult<&GuardianS3Client> {
        self.s3_logger
            .get()
            .ok_or(InvalidInputs("S3 logger is not initialized".into()))
    }

    pub fn set_s3_logger(&self, logger: GuardianS3Client) -> GuardianResult<()> {
        self.s3_logger
            .set(logger)
            .map_err(|_| InvalidInputs("S3 logger already set".into()))
    }
}

impl EnclaveState {
    // ========================================================================
    // Activation State Installation
    // ========================================================================

    /// Install the activation-derived committee + rate limiter. Called from operator_activate.
    pub fn init(&self, committee: HashiCommittee, rate_limiter: RateLimiter) -> GuardianResult<()> {
        self.set_committee(committee)?;
        self.set_rate_limiter(rate_limiter)?;
        Ok(())
    }

    // ========================================================================
    // Committee Management
    // ========================================================================

    /// Get the current committee.
    pub fn get_committee(&self) -> GuardianResult<Arc<HashiCommittee>> {
        let guard = self
            .committee
            .read()
            .expect("rwlock should never throw an error");
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| InvalidInputs("committee not initialized".into()))
    }

    /// Whether the committee is installed, without cloning the `Arc`.
    fn has_committee(&self) -> bool {
        self.committee
            .read()
            .expect("rwlock should never throw an error")
            .is_some()
    }

    /// Set committee. Called only from `init` during operator activation.
    fn set_committee(&self, committee: HashiCommittee) -> GuardianResult<()> {
        info!("Setting committee for epoch {}.", committee.epoch());

        let mut guard = self
            .committee
            .write()
            .expect("rwlock should never throw an error");
        if guard.is_some() {
            return Err(InvalidInputs("committee already initialized".into()));
        }
        *guard = Some(Arc::new(committee));
        Ok(())
    }

    /// Replace an already-initialized committee. Rejects the swap unless
    /// the in-memory epoch matches `expected_current_epoch`.
    pub fn replace_committee(
        &self,
        committee: HashiCommittee,
        expected_current_epoch: u64,
    ) -> GuardianResult<()> {
        info!("Replacing committee for epoch {}.", committee.epoch());

        let mut guard = self
            .committee
            .write()
            .expect("rwlock should never throw an error");
        let current_epoch = guard
            .as_ref()
            .ok_or_else(|| InvalidInputs("committee not initialized".into()))?
            .epoch();
        if current_epoch != expected_current_epoch {
            return Err(InvalidInputs(format!(
                "committee epoch mismatch: expected {expected_current_epoch}, actual {current_epoch}"
            )));
        }
        *guard = Some(Arc::new(committee));
        Ok(())
    }

    // ========================================================================
    // Rate Limiter Management
    // ========================================================================

    fn set_rate_limiter(&self, limiter: RateLimiter) -> GuardianResult<()> {
        info!("Setting rate limiter.");

        self.rate_limiter
            .set(Arc::new(tokio::sync::Mutex::new(limiter)))
            .map_err(|_| InvalidInputs("rate_limiter already initialized".into()))
    }

    /// Timeout for acquiring the limiter lock. If a withdrawal is in progress and
    /// takes longer than this, callers bail rather than wait indefinitely.
    const LIMITER_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

    /// Acquire exclusive access to the limiter, bounded by
    /// `LIMITER_LOCK_TIMEOUT`.
    async fn lock_limiter(&self) -> GuardianResult<OwnedMutexGuard<RateLimiter>> {
        let rate_limiter = self
            .rate_limiter
            .get()
            .ok_or_else(|| InternalError("rate limiter not initialized".into()))?;
        tokio::time::timeout(
            Self::LIMITER_LOCK_TIMEOUT,
            rate_limiter.clone().lock_owned(),
        )
        .await
        .map_err(|_| Unavailable("timed out waiting for rate limiter lock".into()))
    }

    /// Acquire exclusive access to the limiter, consume tokens, and return a guard.
    /// The guard is held through signing and durable logging so no other withdrawal
    /// can start until this one is durably logged or the enclave aborts.
    pub async fn consume_from_limiter(
        &self,
        seq: u64,
        timestamp: u64,
        amount_sats: u64,
    ) -> GuardianResult<OwnedMutexGuard<RateLimiter>> {
        let mut guard = self.lock_limiter().await?;
        guard.consume(seq, timestamp, amount_sats)?;
        Ok(guard)
    }

    /// Return the limiter state for status reporting, or `None` if the limiter
    /// is uninitialized or remains locked through the acquisition deadline.
    pub async fn limiter_state(&self) -> Option<LimiterState> {
        Some(*self.lock_limiter().await.ok()?.state())
    }
}

impl Enclave {
    // ========================================================================
    // Construction
    // ========================================================================

    pub fn new(
        signing_keys: GuardianSignKeyPair,
        encryption_keys: GuardianEncKeyPair,
        mode: EnclaveMode,
    ) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: EnclaveState {
                lifecycle: RwLock::new(match mode {
                    EnclaveMode::Ceremony => CeremonyStage::Uninitialized.into(),
                    EnclaveMode::Withdraw => WithdrawStage::Uninitialized.into(),
                }),
                committee: RwLock::new(None),
                rate_limiter: OnceLock::new(),
            },
            temporary_init_state: RwLock::new(None),
            control_lock: tokio::sync::Mutex::new(()),
        }
    }

    // ========================================================================
    // Task Spawning
    // ========================================================================

    /// Spawn a root-owned Tokio task so caller cancellation only detaches the
    /// waiter and does not cancel accepted work. Use this when the task needs
    /// no serialization or owns a narrower lock for the state it mutates.
    /// E.g., used in `standard_withdrawal` that owns a separate serialization lock inside.
    pub async fn spawn_task<Input, Output, Task, Fut>(
        self: Arc<Self>,
        input: Input,
        task: Task,
    ) -> GuardianResult<Output>
    where
        Input: Send + 'static,
        Output: Send + 'static,
        Task: FnOnce(Arc<Self>, Input) -> Fut + Send + 'static,
        Fut: Future<Output = GuardianResult<Output>> + Send + 'static,
    {
        tokio::spawn(async move { task(self, input).await })
            .await
            .expect("guardian task failed")
    }

    /// Spawn a root-owned Tokio task that holds the control lock while running.
    /// Use this for lifecycle and control-plane transitions whose shared-state
    /// checks and mutations must not interleave with another control task.
    pub async fn spawn_control_task<Input, Output, Task, Fut>(
        self: Arc<Self>,
        input: Input,
        task: Task,
    ) -> GuardianResult<Output>
    where
        Input: Send + 'static,
        Output: Send + 'static,
        Task: FnOnce(Arc<Self>, Input) -> Fut + Send + 'static,
        Fut: Future<Output = GuardianResult<Output>> + Send + 'static,
    {
        self.spawn_task(input, move |enclave, input| async move {
            let task_enclave = enclave.clone();
            let _guard = enclave.control_lock.lock().await;
            task(task_enclave, input).await
        })
        .await
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Which flows this enclave serves (fixed at boot).
    pub fn mode(&self) -> EnclaveMode {
        self.lifecycle().mode()
    }

    pub fn lifecycle(&self) -> EnclaveLifecycle {
        *self
            .state
            .lifecycle
            .read()
            .expect("lifecycle lock poisoned")
    }

    /// Require an exact mode and lifecycle stage, naming the operation in any
    /// resulting error.
    pub fn require_lifecycle(
        &self,
        operation: &str,
        expected: EnclaveLifecycle,
    ) -> GuardianResult<()> {
        let actual = self.lifecycle();
        if actual != expected {
            return Err(LifecycleMismatch {
                operation: operation.into(),
                expected,
                actual,
            });
        }
        Ok(())
    }

    /// Transition after the operation's durable log succeeds. The lifecycle is
    /// the single source of completion state.
    pub fn advance_lifecycle_into(&self, next: EnclaveLifecycle) -> GuardianResult<()> {
        let expected = next
            .predecessor()
            .ok_or_else(|| InvalidInputs(format!("cannot advance lifecycle into {next:?}")))?;
        let mut lifecycle = self
            .state
            .lifecycle
            .write()
            .expect("lifecycle lock poisoned");
        if *lifecycle != expected {
            return Err(LifecycleMismatch {
                operation: "advance_lifecycle_into".into(),
                expected,
                actual: *lifecycle,
            });
        }
        self.assert_state_installed_for(next);
        *lifecycle = next;
        Ok(())
    }

    fn assert_state_installed_for(&self, next: EnclaveLifecycle) {
        let installed = match next {
            EnclaveLifecycle::Ceremony(CeremonyStage::Uninitialized)
            | EnclaveLifecycle::Withdraw(WithdrawStage::Uninitialized) => {
                unreachable!("cannot advance lifecycle into {next:?}")
            }
            EnclaveLifecycle::Ceremony(CeremonyStage::OperatorInitialized) => {
                self.operator_init_state_installed(EnclaveMode::Ceremony)
            }
            EnclaveLifecycle::Withdraw(WithdrawStage::OperatorInitialized) => {
                self.operator_init_state_installed(EnclaveMode::Withdraw)
            }
            // Ceremony handlers advance only after writing their output to S3.
            // The lifecycle itself is the completion state.
            EnclaveLifecycle::Ceremony(CeremonyStage::Completed) => return,
            EnclaveLifecycle::Withdraw(WithdrawStage::ProvisionerInitialized) => {
                self.config.is_enclave_btc_keypair_set() && self.temporary_init_state_is_available()
            }
            EnclaveLifecycle::Withdraw(WithdrawStage::Activated) => {
                self.state.has_committee()
                    && self.state.rate_limiter.get().is_some()
                    && !self.temporary_init_state_is_available()
            }
        };
        assert!(
            installed,
            "cannot advance lifecycle to {next:?}: state is incomplete"
        );
    }

    /// Whether every field operator_init installs is present (mode-aware).
    fn operator_init_state_installed(&self, mode: EnclaveMode) -> bool {
        // Both modes install the S3 logger; a ceremony enclave installs nothing else.
        if self.config.s3_logger.get().is_none() {
            return false;
        }
        match mode {
            EnclaveMode::Ceremony => true,
            // Withdraw enclaves additionally install their stable configuration.
            EnclaveMode::Withdraw => {
                self.config.btc_network.get().is_some()
                    && self.config.pcr_allowlist.get().is_some()
                    && self.config.limiter_config.get().is_some()
                    && self.temporary_init_state_is_available()
                    && self.config.hashi_btc_master_pubkey.get().is_some()
            }
        }
    }

    /// Require the activated withdraw lifecycle, naming the operation in any
    /// resulting error.
    pub fn require_fully_initialized(&self, operation: &str) -> GuardianResult<()> {
        self.require_lifecycle(operation, WithdrawStage::Activated.into())
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

    pub fn sign<T: Serialize + SigningIntent>(&self, data: T) -> GuardianSigned<T> {
        let kp = &self.config.signing_keys;
        let timestamp = now_timestamp_ms();
        GuardianSigned::new(data, kp, timestamp)
    }

    // ========================================================================
    // Enclave Info
    // ========================================================================

    /// Build identity for `GuardianInfo.untrusted_git_revision` / the
    /// `PcrAllowlist` key. A real ceremony enclave is a distinct measured build
    /// (its own PCR0) from the same-commit withdraw enclave, so it reports a
    /// distinct identity — the allowlist forbids two entries per revision, so
    /// otherwise the withdraw enclave and KPs couldn't pin both PCR0s.
    /// `test`/`non-enclave-dev` skip attestation and share one entry, so the
    /// suffix is compiled out (existing mock flow unchanged).
    fn reported_git_revision(&self) -> String {
        // Injected at build time (docker/CI); defaults outside a real build.
        let base = option_env!("GIT_REVISION").unwrap_or("unknown");
        if cfg!(not(any(test, feature = "non-enclave-dev"))) && self.mode() == EnclaveMode::Ceremony
        {
            format!("{base}-ceremony")
        } else {
            base.to_string()
        }
    }

    pub async fn info(&self) -> GuardianInfo {
        let temporary_init_state = self.temporary_init_state().ok();
        GuardianInfo {
            lifecycle: self.lifecycle(),
            secret_sharing_instance: temporary_init_state
                .as_ref()
                .map(|state| state.ceremony_state.secret_sharing_instance.clone()),
            bucket_info: self
                .config
                .s3_logger()
                .ok()
                .map(|l| l.bucket_info().clone()),
            encryption_pubkey: self.encryption_public_key().to_bytes().to_vec(),
            config_hash: temporary_init_state.as_ref().map(|state| state.config_hash),
            genesis_state_hash: temporary_init_state
                .as_ref()
                .and_then(|state| state.genesis_state.as_ref().map(GenesisState::digest)),
            untrusted_git_revision: self.reported_git_revision(),
            enclave_btc_pubkey: self.config.enclave_btc_pubkey().ok(),
            limiter_state: self.state.limiter_state().await,
            limiter_config: self.limiter_config().ok(),
            current_committee_epoch: self.state.get_committee().ok().map(|c| c.epoch()),
            mpc_master_g: self.config.hashi_btc_master_pubkey.get().copied(),
        }
    }

    // ========================================================================
    // S3 Logging
    // ========================================================================

    /// A unique session ID for the current enclave session.
    pub fn s3_session_id(&self) -> SessionID {
        SessionID::from_signing_pubkey(&self.signing_pubkey())
    }

    async fn write_log(&self, message: LogMessage) -> GuardianResult<()> {
        let log = LogRecord::new(self.s3_session_id(), message, &self.config.signing_keys);

        self.config.s3_logger()?.write_log_record(log).await
    }

    async fn write_log_or_abort(&self, message: LogMessage) -> GuardianResult<()> {
        let log = LogRecord::new(self.s3_session_id(), message, &self.config.signing_keys);

        self.config
            .s3_logger()?
            .write_log_record_or_abort(log)
            .await
    }

    /// Only init skips grace-period retries, providing quick fail-stop for basic
    /// S3 write/access issues. The incomplete enclave cannot serve and will restart,
    /// so S3 being ahead after a lost acknowledgement is acceptable.
    pub async fn log_init(&self, msg: InitLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Init(Box::new(msg))).await
    }

    pub async fn log_withdraw(&self, msg: WithdrawalLogMessage) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::Withdrawal(Box::new(msg)))
            .await
    }

    pub async fn log_committee_update(&self, msg: CommitteeUpdateLogMessage) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::CommitteeUpdate(Box::new(msg)))
            .await
    }

    pub async fn log_genesis(&self, msg: GenesisLogMessage) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::Genesis(Box::new(msg)))
            .await
    }

    pub async fn log_heartbeat(&self, msg: HeartbeatLogMessage) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::Heartbeat(msg)).await
    }

    pub async fn log_ceremony(&self, state: CeremonyLogMessage) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::Ceremony(Box::new(state)))
            .await
    }

    /// Persist the current encrypted KP share state to `kp-shares/` for recovery.
    /// `sharing_seq` pairs it with the matching `ceremony/` instance, while
    /// `cert_seq` versions recipient-cert rotations within that instance.
    pub async fn log_kp_share_state(
        &self,
        sharing_seq: u64,
        cert_seq: u64,
        encrypted_shares: KPEncryptedSharesRoster,
    ) -> GuardianResult<()> {
        self.write_log_or_abort(LogMessage::KpShareState(Box::new(
            KpShareStateLogMessage::new(sharing_seq, cert_seq, encrypted_shares),
        )))
        .await
    }

    // ========================================================================
    // Temporary Initialization State
    // ========================================================================

    /// Return an owned initialization snapshot. Activation takes the stored
    /// value, so this capability is unavailable once the enclave is active.
    /// Keep this as the only accessor for `TemporaryInitState`. Its readers are
    /// restricted to provisioner initialization, operator activation, and
    /// status reporting; active request handlers must not depend on it.
    pub fn temporary_init_state(&self) -> GuardianResult<TemporaryInitState> {
        self.temporary_init_state
            .read()
            .expect("temporary initialization lock poisoned")
            .clone()
            .ok_or_else(|| InvalidInputs("Temporary initialization state not set".into()))
    }

    /// Operator initialization is the sole installer of temporary state.
    pub fn set_temporary_init_state(&self, state: TemporaryInitState) -> GuardianResult<()> {
        let mut slot = self
            .temporary_init_state
            .write()
            .expect("temporary initialization lock poisoned");
        if slot.is_some() {
            return Err(InvalidInputs(
                "Temporary initialization state already set".into(),
            ));
        }
        *slot = Some(state);
        Ok(())
    }

    fn temporary_init_state_is_available(&self) -> bool {
        self.temporary_init_state
            .read()
            .expect("temporary initialization lock poisoned")
            .is_some()
    }

    pub fn clear_temporary_init_state(&self) {
        self.temporary_init_state
            .write()
            .expect("temporary initialization lock poisoned")
            .take()
            .expect("temporary initialization state must exist before activation");
    }

    // ========================================================================
    // Enclave Configuration
    // ========================================================================

    /// Construct a verified reader with the enclave's fixed S3 client and PCR
    /// allowlist. Each operation gets a fresh, operation-scoped session cache.
    pub fn new_guardian_reader(&self) -> GuardianResult<GuardianReader> {
        let s3 = self.config.s3_logger()?.clone();
        let pcr_allowlist = self
            .config
            .pcr_allowlist
            .get()
            .cloned()
            .ok_or_else(|| InvalidInputs("PCR allowlist is uninitialized".into()))?;
        Ok(GuardianReader::from_s3_client(s3, pcr_allowlist))
    }

    pub fn limiter_config(&self) -> GuardianResult<LimiterConfig> {
        self.config
            .limiter_config
            .get()
            .copied()
            .ok_or_else(|| InvalidInputs("Limiter config is uninitialized".into()))
    }

    pub fn install_config(
        &self,
        network: Network,
        hashi_btc_master_pubkey: HashiMasterG,
        pcr_allowlist: PcrAllowlist,
        limiter_config: LimiterConfig,
    ) -> GuardianResult<()> {
        self.config
            .btc_network
            .set(network)
            .map_err(|_| InvalidInputs("Network is already initialized".into()))?;
        self.config
            .hashi_btc_master_pubkey
            .set(hashi_btc_master_pubkey)
            .map_err(|_| InvalidInputs("Hashi BTC key is already initialized".into()))?;
        self.config
            .pcr_allowlist
            .set(pcr_allowlist)
            .map_err(|_| InvalidInputs("PCR allowlist is already initialized".into()))?;
        self.config
            .limiter_config
            .set(limiter_config)
            .map_err(|_| InvalidInputs("Limiter config is already initialized".into()))
    }
}
