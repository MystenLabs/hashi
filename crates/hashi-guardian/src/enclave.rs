// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core enclave types: `Enclave` holds all guardian state (immutable config
//! set during operator/provisioner-init, mutable runtime state, and the
//! one-time init scratchpad). Lives in the library so external crates
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
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::*;
use hpke::Serializable;
use serde::Serialize;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use tracing::info;

use crate::s3_client::GuardianS3Client;
use hashi_types::committee::Committee as HashiCommittee;

/// Enclave's config & state
pub struct Enclave {
    /// Immutable config (set once during init)
    pub config: EnclaveConfig,
    /// Mutable state
    pub state: EnclaveState,
    /// Initialization scratchpad
    pub scratchpad: Scratchpad,
    /// Serializes control-plane RPCs (operator_init, update_committee) so
    /// concurrent callers can't race a check-then-set. Held across the handler.
    /// TODO: fold provisioner_init / ceremony serialization in here too, once
    /// their dual-purpose locks (share accumulator / one-shot bool) are untangled.
    pub control_lock: tokio::sync::Mutex<()>,
}

/// Configuration set during initialization (immutable after set)
pub struct EnclaveConfig {
    /// Enclave mode (set on boot).
    mode: EnclaveMode,
    /// Ephemeral keypair (set on boot)
    eph_keys: EphemeralKeyPairs,
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
}

/// Mutable state that changes during operation.
/// Committee + rate limiter are installed during operator_activate.
pub struct EnclaveState {
    /// Current Hashi committee.
    committee: RwLock<Option<Arc<HashiCommittee>>>,
    /// Rate limiter. Set once during operator_activate.
    /// Uses `Arc<tokio::Mutex>` so the guard can be held across `.await`.
    rate_limiter: OnceLock<Arc<tokio::sync::Mutex<RateLimiter>>>,
}

/// Scratchpad used only during initialization. The OnceLock flags retain their
/// state for the life of the enclave.
#[derive(Default)]
pub struct Scratchpad {
    /// Stable withdraw-mode config set by operator_init.
    pub init_config: OnceLock<InitConfig>,
    /// Secret-sharing instance (commitments + N + T) set by operator_init.
    pub secret_sharing_instance: OnceLock<SecretSharingInstance>,
    /// Set once operator_init has successfully written all logs to S3.
    /// This prevents heartbeats from being emitted before operator_init logs.
    pub operator_init_logging_complete: OnceLock<()>,
    /// Set once the provisioner init flow has successfully logged EnclaveFullyInitialized.
    /// operator_activate requires this so activation cannot happen before the PI log is durable.
    pub provisioner_init_logging_complete: OnceLock<()>,
    /// Set once operator_activate has installed live serving state and logged it.
    pub operator_activate_logging_complete: OnceLock<()>,
    /// Guards the single ceremony per enclave: `setup_new_key` (genesis) or
    /// `rotate_kps` (rotation), never both. Each holds this guard across its
    /// flow so the two can't interleave; the `bool` flips true once a ceremony
    /// finalizes, making it one-shot per enclave instance (the operator
    /// restarts to run another).
    pub ceremony_complete: tokio::sync::Mutex<bool>,
    /// Encrypted shares produced by the ceremony (`setup_new_key` or
    /// `rotate_kps`), served to KPs from `get_guardian_info`. Set once.
    pub latest_encrypted_shares: OnceLock<KPEncryptedShares>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: GuardianSignKeyPair,
    pub encryption_keys: GuardianEncKeyPair,
}

impl EnclaveConfig {
    pub fn new(
        signing_keys: GuardianSignKeyPair,
        encryption_keys: GuardianEncKeyPair,
        mode: EnclaveMode,
    ) -> Self {
        EnclaveConfig {
            mode,
            eph_keys: EphemeralKeyPairs {
                signing_keys,
                encryption_keys,
            },
            s3_logger: OnceLock::new(),
            enclave_btc_keypair: OnceLock::new(),
            btc_network: OnceLock::new(),
            hashi_btc_master_pubkey: OnceLock::new(),
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

    pub fn set_bitcoin_network(&self, network: Network) -> GuardianResult<()> {
        self.btc_network
            .set(network)
            .map_err(|_| InvalidInputs("Network is already initialized".into()))
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

    pub fn set_hashi_btc_pk(&self, pk: HashiMasterG) -> GuardianResult<()> {
        self.hashi_btc_master_pubkey
            .set(pk)
            .map_err(|_| InvalidInputs("Hashi BTC key is already set".into()))
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

    pub fn is_enclave_btc_keypair_set(&self) -> bool {
        self.enclave_btc_keypair.get().is_some()
    }
}

impl EnclaveState {
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

    /// Whether the committee is installed, without cloning the `Arc` — used by the
    /// operator_init completeness check, which runs on the heartbeat/withdrawal path.
    fn has_committee(&self) -> bool {
        self.committee
            .read()
            .expect("rwlock should never throw an error")
            .is_some()
    }

    /// Set committee. Called only from `init` (operator_init).
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

    /// Acquire exclusive access to the limiter, consume tokens, and return a guard.
    /// The guard holds the mutex lock — no other withdrawal can start until it is
    /// committed or dropped (which reverts).
    /// Timeout for acquiring the limiter lock. If a withdrawal is in progress and
    /// takes longer than this, we bail rather than queue up requests indefinitely.
    const LIMITER_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

    pub async fn consume_from_limiter(
        &self,
        seq: u64,
        timestamp: u64,
        amount_sats: u64,
    ) -> GuardianResult<LimiterGuard> {
        let rate_limiter = self
            .rate_limiter
            .get()
            .ok_or_else(|| InvalidInputs("rate_limiter not initialized".into()))?;
        let mut guard = tokio::time::timeout(
            Self::LIMITER_LOCK_TIMEOUT,
            rate_limiter.clone().lock_owned(),
        )
        .await
        .map_err(|_| InvalidInputs("timed out waiting for rate limiter lock".into()))?;
        guard.consume(seq, timestamp, amount_sats)?;
        Ok(LimiterGuard::new(guard))
    }

    pub async fn limiter_state(&self) -> Option<LimiterState> {
        let limiter = self.rate_limiter.get()?;
        Some(*limiter.lock().await.state())
    }

    pub async fn limiter_config(&self) -> Option<LimiterConfig> {
        let limiter = self.rate_limiter.get()?;
        Some(*limiter.lock().await.config())
    }
}

/// RAII guard that holds the limiter mutex via an owned guard, returned by
/// [`EnclaveState::consume_from_limiter`]. Reverts on drop unless committed.
pub struct LimiterGuard {
    guard: tokio::sync::OwnedMutexGuard<RateLimiter>,
    committed: bool,
}

impl LimiterGuard {
    pub(crate) fn new(guard: tokio::sync::OwnedMutexGuard<RateLimiter>) -> Self {
        Self {
            guard,
            committed: false,
        }
    }

    /// Mark this withdrawal as successful. Prevents revert on drop.
    pub fn commit(mut self) {
        self.committed = true;
    }

    pub fn state(&self) -> &LimiterState {
        self.guard.state()
    }
}

impl Drop for LimiterGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.guard.revert();
        }
    }
}

impl Enclave {
    // ========================================================================
    // Construction & Initialization Status
    // ========================================================================

    pub fn new(
        signing_keys: GuardianSignKeyPair,
        encryption_keys: GuardianEncKeyPair,
        mode: EnclaveMode,
    ) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys, mode),
            state: EnclaveState {
                committee: RwLock::new(None),
                rate_limiter: OnceLock::new(),
            },
            scratchpad: Scratchpad::default(),
            control_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Which flows this enclave serves (fixed at boot).
    pub fn mode(&self) -> EnclaveMode {
        self.config.mode
    }

    /// Provisioner_init is complete: the reconstructed BTC keypair is set and
    /// its installation has been logged.
    pub fn is_provisioner_init_complete(&self) -> bool {
        let logged = self
            .scratchpad
            .provisioner_init_logging_complete
            .get()
            .is_some();
        assert!(
            !logged
                || (self.config.is_enclave_btc_keypair_set() && self.is_operator_init_complete()),
            "provisioner_init_logging_complete set but provisioner_init state is incomplete"
        );
        logged
    }

    pub fn is_operator_init_complete(&self) -> bool {
        let logged = self
            .scratchpad
            .operator_init_logging_complete
            .get()
            .is_some();
        // commit_operator_init sets this flag last in an all-or-nothing commit, so
        // a set flag implies every installed field is present. This backstop holds
        // in prod too (a violation aborts via `abort_on_panic`) and never fires
        // transiently, since the flag is the last thing set. The converse is NOT
        // checked: a normal commit installs the state before its (slow) S3 logging
        // completes, and a lock-free reader (e.g. the heartbeat) can observe that
        // window with state present but the flag unset.
        assert!(
            !logged || self.operator_init_state_installed(),
            "operator_init_logging_complete set but operator_init state is incomplete"
        );
        logged
    }

    /// Whether every field operator_init installs is present (mode-aware). Only
    /// used to assert the `operator_init_logging_complete` invariant above.
    fn operator_init_state_installed(&self) -> bool {
        // Both modes install the S3 logger; a ceremony enclave installs nothing else.
        if self.config.s3_logger.get().is_none() {
            return false;
        }
        match self.config.mode {
            EnclaveMode::Ceremony => true,
            // Withdraw enclaves additionally install the stable InitConfig.
            EnclaveMode::Withdraw => {
                self.config.btc_network.get().is_some()
                    && self.scratchpad.init_config.get().is_some()
                    && self.scratchpad.secret_sharing_instance.get().is_some()
                    && self.config.hashi_btc_master_pubkey.get().is_some()
            }
        }
    }

    pub fn is_fully_initialized(&self) -> bool {
        self.is_active()
    }

    pub fn is_active(&self) -> bool {
        let logged = self
            .scratchpad
            .operator_activate_logging_complete
            .get()
            .is_some();
        assert!(
            !logged
                || (self.is_provisioner_init_complete()
                    && self.state.has_committee()
                    && self.state.rate_limiter.get().is_some()),
            "operator_activate_logging_complete set but activation state is incomplete"
        );
        logged
    }

    // ========================================================================
    // Ephemeral Keypairs (Encryption & Signing)
    // ========================================================================

    /// Get the enclave's encryption secret key
    pub fn encryption_secret_key(&self) -> &EncSecKey {
        self.config.eph_keys.encryption_keys.secret_key()
    }

    /// Get the enclave's encryption public key
    pub fn encryption_public_key(&self) -> &EncPubKey {
        self.config.eph_keys.encryption_keys.public_key()
    }

    /// Get the enclave's verification key
    pub fn signing_pubkey(&self) -> GuardianPubKey {
        self.config.eph_keys.signing_keys.verification_key()
    }

    pub fn sign<T: Serialize + SigningIntent>(&self, data: T) -> GuardianSigned<T> {
        let kp = &self.config.eph_keys.signing_keys;
        let timestamp = now_timestamp_ms();
        GuardianSigned::new(data, kp, timestamp)
    }

    // ========================================================================
    // Enclave Info
    // ========================================================================

    pub async fn info(&self) -> GuardianInfo {
        GuardianInfo {
            secret_sharing_instance: self.secret_sharing_instance().ok().cloned(),
            bucket_info: self
                .config
                .s3_logger()
                .ok()
                .map(|l| l.bucket_info().clone()),
            encryption_pubkey: self.encryption_public_key().to_bytes().to_vec(),
            config_hash: self.config_hash(),
            // Injected at build time (docker/CI); defaults outside a real build.
            untrusted_git_revision: option_env!("GIT_REVISION").unwrap_or("unknown").to_string(),
            enclave_btc_pubkey: self.config.enclave_btc_pubkey().ok(),
            limiter_state: self.state.limiter_state().await,
            limiter_config: match self.state.limiter_config().await {
                Some(config) => Some(config),
                None => self.init_config().map(|config| *config.limiter_config()),
            },
            current_committee_epoch: self.state.get_committee().ok().map(|c| c.epoch()),
            mpc_master_g: self.config.hashi_btc_master_pubkey.get().cloned(),
        }
    }

    // ========================================================================
    // S3 Logging
    // ========================================================================

    /// A unique session ID for the current enclave session.
    pub fn s3_session_id(&self) -> SessionID {
        session_id_from_signing_pubkey(&self.signing_pubkey())
    }

    async fn write_log(&self, message: LogMessage) -> GuardianResult<()> {
        let log = LogRecord::new(
            self.s3_session_id(),
            message,
            &self.config.eph_keys.signing_keys,
        );

        self.config.s3_logger()?.write_log_record(log).await
    }

    pub async fn log_init(&self, msg: InitLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Init(Box::new(msg))).await
    }

    pub async fn log_withdraw(&self, msg: WithdrawalLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Withdrawal(Box::new(msg))).await
    }

    pub async fn log_committee_update(&self, msg: CommitteeUpdateLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::CommitteeUpdate(Box::new(msg)))
            .await
    }

    pub async fn log_genesis(&self, msg: GenesisLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Genesis(Box::new(msg))).await
    }

    pub async fn log_heartbeat(&self, seq: u64) -> GuardianResult<()> {
        self.write_log(LogMessage::Heartbeat { seq }).await
    }

    pub async fn log_ceremony(&self, state: CeremonyLogMessage) -> GuardianResult<()> {
        self.write_log(LogMessage::Ceremony(Box::new(state))).await
    }

    /// Persist the current encrypted KP share state to `kp-shares/` for recovery.
    /// `sharing_seq` pairs it with the matching `ceremony/` instance, while
    /// `cert_seq` versions recipient-cert rotations within that instance.
    pub async fn log_kp_share_state(
        &self,
        sharing_seq: u64,
        cert_seq: u64,
        encrypted_shares: KPEncryptedShares,
    ) -> GuardianResult<()> {
        self.write_log(LogMessage::KpShareState(Box::new(KpShareState::new(
            sharing_seq,
            cert_seq,
            encrypted_shares,
        ))))
        .await
    }

    // ========================================================================
    // Scratchpad (Initialization-only data)
    // ========================================================================

    pub fn secret_sharing_instance(&self) -> GuardianResult<&SecretSharingInstance> {
        self.scratchpad
            .secret_sharing_instance
            .get()
            .ok_or(InvalidInputs("Secret-sharing instance not set".into()))
    }

    pub fn set_secret_sharing_instance(
        &self,
        instance: SecretSharingInstance,
    ) -> GuardianResult<()> {
        self.scratchpad
            .secret_sharing_instance
            .set(instance)
            .map_err(|_| InvalidInputs("Secret-sharing instance already set".into()))
    }

    /// Stash the ceremony's encrypted shares for KPs to fetch via
    /// `get_guardian_info`. One ceremony per enclave, so this is set once.
    pub fn set_latest_encrypted_shares(&self, shares: KPEncryptedShares) -> GuardianResult<()> {
        self.scratchpad
            .latest_encrypted_shares
            .set(shares)
            .map_err(|_| InvalidInputs("Latest encrypted shares already set".into()))
    }

    /// Encrypted shares from the ceremony, or empty if none has run.
    pub fn latest_encrypted_shares(&self) -> KPEncryptedShares {
        self.scratchpad
            .latest_encrypted_shares
            .get()
            .cloned()
            .unwrap_or_else(|| KPEncryptedShares::new(vec![]).expect("empty share list is valid"))
    }

    pub fn init_config(&self) -> Option<&InitConfig> {
        self.scratchpad.init_config.get()
    }

    pub fn set_init_config(&self, config: InitConfig) -> GuardianResult<()> {
        self.scratchpad
            .init_config
            .set(config)
            .map_err(|_| InvalidInputs("Init config already set".into()))
    }

    pub fn config_hash(&self) -> Option<[u8; 32]> {
        self.init_config().map(InitConfig::digest)
    }
}
