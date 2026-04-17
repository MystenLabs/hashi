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
use hashi_types::guardian::bitcoin_utils::sign_btc_tx;
use hashi_types::guardian::bitcoin_utils::TxUTXOs;
use hashi_types::guardian::crypto::Share;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::*;
use hpke::Serializable;
use serde::Serialize;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use tracing::info;

use crate::s3_logger::S3Logger;
use crate::withdraw::LimiterGuard;
use hashi_types::committee::Committee as HashiCommittee;

/// Enclave's config & state
pub struct Enclave {
    /// Immutable config (set once during init)
    pub config: EnclaveConfig,
    /// Mutable state
    pub state: EnclaveState,
    /// Initialization scratchpad
    pub scratchpad: Scratchpad,
}

/// Configuration set during initialization (immutable after set)
pub struct EnclaveConfig {
    /// Ephemeral keypair (set on boot)
    eph_keys: EphemeralKeyPairs,
    /// S3 client & config (set in operator_init)
    s3_logger: OnceLock<S3Logger>,
    /// Enclave BTC private key (set in provisioner_init)
    pub(crate) enclave_btc_keypair: OnceLock<Keypair>,
    /// BTC network: mainnet, testnet, regtest (set in operator_init)
    btc_network: OnceLock<Network>,
    /// Hashi BTC public key used to derive child keys (set in provisioner_init)
    pub(crate) hashi_btc_master_pubkey: OnceLock<BitcoinPubkey>,
    /// Withdraw related config's (set in provisioner_init)
    withdrawal_config: OnceLock<WithdrawalConfig>,
}

/// Mutable state that changes during operation.
/// Note: State is initialized during provisioner_init.
pub struct EnclaveState {
    /// Current Hashi committee.
    committee: RwLock<Option<Arc<HashiCommittee>>>,
    /// Rate limiter. Set once during provisioner_init.
    /// Uses `Arc<tokio::Mutex>` so the guard can be held across `.await`.
    rate_limiter: OnceLock<Arc<tokio::sync::Mutex<RateLimiter>>>,
    /// LRU cache of signed withdrawal responses keyed by `wid`. Lets the
    /// guardian return the same response for retried requests (leader
    /// restart, leader rotation, lost response) without re-consuming from
    /// the limiter or re-signing. Inserted only after a successful S3 log
    /// commit, so the bucket and the cache never disagree.
    recent_responses:
        std::sync::Mutex<lru::LruCache<u64, GuardianSigned<StandardWithdrawalResponse>>>,
}

/// Scratchpad used only during initialization.
/// Note: We don't clear it post-init because it does not have a lot of data.
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares
    /// TODO: Investigate if it can be moved to std::sync::Mutex
    pub shares: tokio::sync::Mutex<Vec<Share>>,
    /// The share commitments
    pub share_commitments: OnceLock<ShareCommitments>,
    /// Hash of the state in ProvisionerInitRequest
    pub state_hash: OnceLock<[u8; 32]>,
    /// Set once operator_init has successfully written all logs to S3.
    /// This prevents heartbeats from being emitted before operator_init logs.
    pub operator_init_logging_complete: OnceLock<()>,
    /// Set once the provisioner init flow has successfully logged EnclaveFullyInitialized.
    /// This prevents withdrawals from starting before provisioner_init logs.
    pub provisioner_init_logging_complete: OnceLock<()>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: GuardianSignKeyPair,
    pub encryption_keys: GuardianEncKeyPair,
}

impl EnclaveConfig {
    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        EnclaveConfig {
            eph_keys: EphemeralKeyPairs {
                signing_keys,
                encryption_keys,
            },
            s3_logger: OnceLock::new(),
            enclave_btc_keypair: OnceLock::new(),
            btc_network: OnceLock::new(),
            hashi_btc_master_pubkey: OnceLock::new(),
            withdrawal_config: OnceLock::new(),
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

    pub fn set_hashi_btc_pk(&self, pk: BitcoinPubkey) -> GuardianResult<()> {
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
    // Withdrawal Configuration
    // ========================================================================

    pub fn withdrawal_config(&self) -> GuardianResult<&WithdrawalConfig> {
        self.withdrawal_config
            .get()
            .ok_or(InvalidInputs("WithdrawalConfig is not initialized".into()))
    }

    pub fn set_withdrawal_config(&self, config: WithdrawalConfig) -> GuardianResult<()> {
        self.withdrawal_config
            .set(config)
            .map_err(|_| InvalidInputs("WithdrawalConfig already set".into()))
    }

    pub fn committee_threshold(&self) -> GuardianResult<u64> {
        Ok(self.withdrawal_config()?.committee_threshold)
    }

    // ========================================================================
    // S3 Logger
    // ========================================================================

    pub fn s3_logger(&self) -> GuardianResult<&S3Logger> {
        self.s3_logger
            .get()
            .ok_or(InvalidInputs("S3 logger is not initialized".into()))
    }

    pub fn set_s3_logger(&self, logger: S3Logger) -> GuardianResult<()> {
        self.s3_logger
            .set(logger)
            .map_err(|_| InvalidInputs("S3 logger already set".into()))
    }

    // ========================================================================
    // Initialization Status
    // ========================================================================

    /// Check if operator_init configuration is complete (S3 logger and network)
    pub fn is_operator_init_complete(&self) -> bool {
        self.s3_logger.get().is_some() && self.btc_network.get().is_some()
    }

    /// Check if any operator_init configuration has been set
    pub fn is_operator_init_partially_complete(&self) -> bool {
        self.s3_logger.get().is_some() || self.btc_network.get().is_some()
    }

    /// Check if provisioner_init configuration is complete (BTC keys and withdrawal config)
    pub fn is_provisioner_init_complete(&self) -> bool {
        self.enclave_btc_keypair.get().is_some()
            && self.hashi_btc_master_pubkey.get().is_some()
            && self.withdrawal_config.get().is_some()
    }

    /// Check if any provisioner_init configuration has been set
    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        self.enclave_btc_keypair.get().is_some()
            || self.hashi_btc_master_pubkey.get().is_some()
            || self.withdrawal_config.get().is_some()
    }
}

impl EnclaveState {
    pub fn init(&self, incoming_state: ProvisionerInitState) -> GuardianResult<()> {
        let rate_limiter = incoming_state.build_rate_limiter()?;
        let (committee, _, _, _) = incoming_state.into_parts();

        self.set_committee(committee)?;
        self.set_rate_limiter(rate_limiter)?;
        Ok(())
    }

    // ========================================================================
    // Initialization Status
    // ========================================================================

    fn status_check_inner(&self) -> (bool, bool) {
        let committee_init = self
            .committee
            .read()
            .expect("rwlock read should not fail")
            .is_some();

        let limiter_init = self.rate_limiter.get().is_some();

        (committee_init, limiter_init)
    }

    /// Check if state init is complete
    pub fn is_provisioner_init_complete(&self) -> bool {
        let (committee_init, limiter_init) = self.status_check_inner();
        committee_init && limiter_init
    }

    /// Check if any state has been set
    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        let (committee_init, limiter_init) = self.status_check_inner();
        committee_init || limiter_init
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

    /// Set committee. Called only from init(ProvisionerInitState)
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
        wid: u64,
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
        guard.consume(wid, seq, timestamp, amount_sats)?;
        Ok(LimiterGuard::new(guard))
    }

    /// Soft-reserve headroom for `amount_sats` against `wid`. Idempotent:
    /// repeat calls for the same wid return (and refresh) the existing
    /// reservation. Reservations are dropped either by a matching
    /// `consume_from_limiter` call or by a TTL sweep.
    pub async fn soft_reserve(
        &self,
        wid: u64,
        timestamp_secs: u64,
        amount_sats: u64,
        now_unix_secs: u64,
    ) -> GuardianResult<hashi_types::guardian::PendingReserve> {
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
        guard.soft_reserve(wid, timestamp_secs, amount_sats, now_unix_secs)
    }

    /// Drop any soft reservation whose TTL has elapsed. Called periodically
    /// from the guardian's background sweep task.
    pub async fn expire_pending_reserves(&self, now_unix_secs: u64) -> usize {
        let Some(rate_limiter) = self.rate_limiter.get() else {
            return 0;
        };
        // Use a short timeout — if the limiter is held longer than that by
        // an in-flight withdrawal, we'll just try again next tick.
        match tokio::time::timeout(
            Self::LIMITER_LOCK_TIMEOUT,
            rate_limiter.clone().lock_owned(),
        )
        .await
        {
            Ok(mut guard) => guard.expire_pending(now_unix_secs),
            Err(_) => 0,
        }
    }

    /// Snapshot the current rate limiter state, if the limiter has been
    /// initialized. Used by `GetGuardianInfo` so that clients can seed their
    /// local `seq` counter at startup.
    pub async fn limiter_state(&self) -> Option<LimiterState> {
        let limiter = self.rate_limiter.get()?;
        Some(*limiter.lock().await.state())
    }

    // ========================================================================
    // Recent-response cache (wid-keyed idempotency)
    // ========================================================================

    /// Look up a previously signed response by wid. Marks the entry as
    /// most-recently-used on hit.
    pub fn get_cached_response(
        &self,
        wid: u64,
    ) -> Option<GuardianSigned<StandardWithdrawalResponse>> {
        self.recent_responses
            .lock()
            .expect("recent_responses mutex poisoned")
            .get(&wid)
            .cloned()
    }

    /// Insert a signed response into the cache. Called only after the
    /// withdrawal has been logged to S3 and the limiter committed, so the
    /// cache and bucket are always consistent.
    pub fn cache_response(&self, wid: u64, response: GuardianSigned<StandardWithdrawalResponse>) {
        self.recent_responses
            .lock()
            .expect("recent_responses mutex poisoned")
            .put(wid, response);
    }
}

impl Enclave {
    // ========================================================================
    // Construction & Initialization Status
    // ========================================================================

    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: EnclaveState {
                committee: RwLock::new(None),
                rate_limiter: OnceLock::new(),
                recent_responses: std::sync::Mutex::new(lru::LruCache::new(
                    Self::RECENT_RESPONSES_CAPACITY,
                )),
            },
            scratchpad: Scratchpad::default(),
        }
    }

    /// Capacity of the wid-keyed response cache. Each entry is small
    /// (Ed25519 sig + Schnorr sigs for each input), so 1024 is ample for
    /// any realistic withdrawal throughput while bounding memory.
    const RECENT_RESPONSES_CAPACITY: std::num::NonZeroUsize =
        std::num::NonZeroUsize::new(1024).expect("1024 > 0");

    pub fn is_provisioner_init_complete(&self) -> bool {
        self.config.is_provisioner_init_complete()
            && self.state.is_provisioner_init_complete()
            && self
                .scratchpad
                .provisioner_init_logging_complete
                .get()
                .is_some()
    }

    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        self.config.is_provisioner_init_partially_complete()
            || self.state.is_provisioner_init_partially_complete()
    }

    pub fn is_operator_init_complete(&self) -> bool {
        self.config.is_operator_init_complete()
            && self.scratchpad.share_commitments.get().is_some()
            && self
                .scratchpad
                .operator_init_logging_complete
                .get()
                .is_some()
    }

    pub fn is_operator_init_partially_complete(&self) -> bool {
        self.config.is_operator_init_partially_complete()
            || self.scratchpad.share_commitments.get().is_some()
    }

    pub fn is_fully_initialized(&self) -> bool {
        self.is_provisioner_init_complete() && self.is_operator_init_complete()
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

    pub fn info(&self) -> GuardianInfo {
        GuardianInfo {
            share_commitments: self.share_commitments().ok().cloned(),
            bucket_info: self
                .config
                .s3_logger()
                .ok()
                .map(|l| l.bucket_info().clone()),
            encryption_pubkey: self.encryption_public_key().to_bytes().to_vec(),
            // TODO: Change it
            server_version: "v1".to_string(),
        }
    }

    // ========================================================================
    // S3 Logging
    // ========================================================================

    /// A unique session ID for the current enclave session.
    pub fn s3_session_id(&self) -> String {
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

    pub async fn log_heartbeat(&self, seq: u64) -> GuardianResult<()> {
        self.write_log(LogMessage::Heartbeat { seq }).await
    }

    // ========================================================================
    // Scratchpad (Initialization-only data)
    // ========================================================================

    pub fn decrypted_shares(&self) -> &tokio::sync::Mutex<Vec<Share>> {
        &self.scratchpad.shares
    }

    pub fn share_commitments(&self) -> GuardianResult<&ShareCommitments> {
        self.scratchpad
            .share_commitments
            .get()
            .ok_or(InvalidInputs("Share commitments not set".into()))
    }

    pub fn set_share_commitments(&self, commitments: ShareCommitments) -> GuardianResult<()> {
        self.scratchpad
            .share_commitments
            .set(commitments)
            .map_err(|_| InvalidInputs("Share commitments already set".into()))
    }

    pub fn state_hash(&self) -> Option<&[u8; 32]> {
        self.scratchpad.state_hash.get()
    }

    pub fn set_state_hash(&self, hash: [u8; 32]) -> GuardianResult<()> {
        self.scratchpad
            .state_hash
            .set(hash)
            .map_err(|_| InvalidInputs("State hash already set".into()))
    }
}
