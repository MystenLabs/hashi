use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::Amount;
use bitcoin::Network;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use std::time::SystemTime;
use tonic::transport::Server;
use tracing::info;

mod getters;
mod init;
mod rpc;
mod s3_logger;
mod setup;
mod withdraw;

use crate::rpc::GuardianGrpc;
use crate::s3_logger::S3Logger;
use hashi::proto::guardian_service_server::GuardianServiceServer;

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
    pub eph_keys: EphemeralKeyPairs,
    /// S3 client & config (set in operator_init)
    pub s3_logger: OnceLock<S3Logger>,
    /// Enclave BTC private key (set in provisioner_init)
    pub enclave_btc_keypair: OnceLock<Keypair>,
    /// BTC network: mainnet, testnet, regtest (set in operator_init)
    pub btc_network: OnceLock<Network>,
    /// Hashi BTC public key used to derive child keys (set in provisioner_init)
    pub hashi_btc_master_pubkey: OnceLock<BitcoinPubkey>,
    /// Withdraw related config's (set in provisioner_init)
    pub withdrawal_config: OnceLock<WithdrawalConfig>,
}

/// Mutable state that changes during operation
pub struct EnclaveState {
    /// Hashi bls pk's
    /// TODO: Combine rate limiter state into this hashmap?
    pub hashi_committees: RwLock<HashMap<u64, Arc<HashiCommittee>>>,
    /// Withdrawal-related state
    /// Note: We use tokio::sync::Mutex because when mutating the inner counter, guard needs to be held until S3 write succeeds.
    pub withdraw_state: Mutex<WithdrawalState>,
}

impl EnclaveState {
    // ========================================================================
    // Initialization Status
    // ========================================================================

    /// Check if provisioner_init state is complete (committees and withdrawal state initialized)
    pub fn is_provisioner_init_complete(&self) -> bool {
        !self.hashi_committees
            .read()
            .expect("read should not fail").is_empty()
            && self
                .withdraw_state
                .lock()
                .expect("mutex lock should not fail")
                .limiter_len()
                > 0
    }

    /// Check if any provisioner_init state has been set
    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        !self.hashi_committees
            .read()
            .expect("read should not fail").is_empty()
            || self
                .withdraw_state
                .lock()
                .expect("mutex lock should not fail")
                .limiter_len()
                > 0
    }

    // ========================================================================
    // Committee Management
    // ========================================================================

    /// Get the current hashi committee. The read lock is held very briefly only to clone the Arc.
    pub fn get_committee(&self, epoch: u64) -> GuardianResult<Arc<HashiCommittee>> {
        let committee_map = &self
            .hashi_committees
            .read()
            .expect("rwlock should never throw an error");
        // Note: read() or write() return an error if there's a panic while holding the write guard.
        //       we only write in update_committee_map which can never panic.
        match committee_map.get(&epoch) {
            Some(committee) => Ok(Arc::clone(committee)),
            None => Err(InvalidInputs(format!(
                "Requested committee {} not found",
                epoch
            ))),
        }
    }

    /// Adds one committee to committee_map and if needed prunes one from it
    pub fn update_committee_map(&self, new_committee: HashiCommittee) -> GuardianResult<()> {
        let epoch = new_committee.epoch();
        info!("Adding new epoch {} to committee map.", epoch);
        let mut committee_map = self
            .hashi_committees
            .write()
            .expect("rwlock should never throw an error");

        match committee_map.entry(epoch) {
            Entry::Vacant(v) => {
                v.insert(Arc::new(new_committee));
                info!("Epoch {} added to committee map.", epoch);
            }
            Entry::Occupied(_) => {
                return Err(InvalidInputs(format!(
                    "Requested epoch {} already present in committee map",
                    epoch
                )))
            }
        };

        if committee_map.len() > MAX_EPOCHS {
            // Remove the committee with the smallest (oldest) epoch
            let &min_epoch = committee_map
                .keys()
                .min()
                .expect("min is guaranteed to exist since we know MAX_EPOCHS elements exist");
            info!("Pruning old epoch {} from committee map.", min_epoch);
            committee_map.remove(&min_epoch);
        }

        Ok(())
    }

    /// Set committees from ProvisionerInitRequestState
    pub fn set_committees(&self, hashi_committees: HashMap<u64, HashiCommittee>) {
        info!("Setting state with {} committees.", hashi_committees.len());
        // Set committees (validation is done in ProvisionerInitRequestState; so committees.size() <= MAX_EPOCHS)
        let mut committee_map = self
            .hashi_committees
            .write()
            .expect("rwlock should never throw an error");
        for (e, committee) in hashi_committees {
            info!("Adding committee for epoch {}.", e);
            committee_map.insert(e, Arc::new(committee));
        }
    }

    // ========================================================================
    // Withdrawal State Management
    // ========================================================================

    pub fn set_withdrawal_state(&self, state: WithdrawalState) {
        info!("Setting withdrawal state.");
        *self.withdraw_state.lock().expect("should not be poisoned") = state;
    }

    pub fn consume_from_limiter(&self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        info!(
            "Applying rate limits for epoch {}: {} sats.",
            epoch,
            amount.to_sat()
        );
        let result = self
            .withdraw_state
            .lock()
            .expect("mutex should never throw an error")
            .consume_from_limiter(epoch, amount);

        if result.is_ok() {
            info!("Rate limit updated successfully.");
        }

        result
    }

    pub fn add_epoch_to_limiter(&self, epoch: u64) -> GuardianResult<()> {
        self.withdraw_state
            .lock()
            .expect("should not be poisoned")
            .add_epoch_to_limiter(epoch)
    }
}

/// Scratchpad used only during initialization.
/// Note that we don't clear it post-init because it does not have a lot of data.
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares
    pub shares: Mutex<Vec<Share>>,
    /// The share commitments
    pub share_commitments: OnceLock<Vec<ShareCommitment>>,
    /// Hash of the state in ProvisionerInitRequest
    pub state_hash: OnceLock<[u8; 32]>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: GuardianSignKeyPair,
    pub encryption_keys: GuardianEncKeyPair,
}

/// Enclave initialization.
/// SETUP_MODE=true: only get_attestation, operator_init and setup_new_key are enabled.
/// SETUP_MODE=false: all endpoints except setup_new_key are enabled.
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber(true);

    // Check if SETUP_MODE is enabled (defaults to false)
    let setup_mode = std::env::var("SETUP_MODE")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);

    if setup_mode {
        info!("Setup mode: setup_new_key route available, provisioner_init disabled.");
    } else {
        info!("Normal mode: provisioner_init route available, setup_new_key disabled.");
    }

    let signing_keys = GuardianSignKeyPair::new(rand::thread_rng());
    let encryption_keys = GuardianEncKeyPair::random(&mut rand::thread_rng());
    let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys));

    let svc = GuardianGrpc {
        enclave,
        setup_mode,
    };

    let addr = "0.0.0.0:3000".parse()?;
    info!("gRPC server listening on {}.", addr);

    Server::builder()
        .add_service(GuardianServiceServer::new(svc))
        .serve(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
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

    pub fn btc_keypair(&self) -> GuardianResult<&Keypair> {
        self.enclave_btc_keypair
            .get()
            .ok_or(InternalError("Bitcoin key is not initialized".into()))
    }

    pub fn set_btc_keypair(&self, keypair: Keypair) -> GuardianResult<()> {
        self.enclave_btc_keypair
            .set(keypair)
            .map_err(|_| InvalidInputs("Bitcoin key already set".into()))
    }

    pub fn hashi_btc_pk(&self) -> GuardianResult<&BitcoinPubkey> {
        self.hashi_btc_master_pubkey
            .get()
            .ok_or(InternalError("Hashi BTC key is not initialized".into()))
    }

    pub fn set_hashi_btc_pk(&self, pk: BitcoinPubkey) -> GuardianResult<()> {
        self.hashi_btc_master_pubkey
            .set(pk)
            .map_err(|e| InvalidInputs(format!("Hashi BTC key is already set: {}", e)))
    }

    // ========================================================================
    // Withdrawal Configuration
    // ========================================================================

    pub fn withdrawal_config(&self) -> GuardianResult<&WithdrawalConfig> {
        self.withdrawal_config
            .get()
            .ok_or(InternalError("WithdrawalConfig is not initialized".into()))
    }

    pub fn set_withdrawal_config(&self, config: WithdrawalConfig) -> GuardianResult<()> {
        self.withdrawal_config
            .set(config)
            .map_err(|_| InternalError("WithdrawControlsConfig already set".into()))
    }

    pub fn delayed_withdrawals_min_delay(&self) -> GuardianResult<Duration> {
        Ok(self.withdrawal_config()?.delayed_withdrawals_min_delay)
    }

    pub fn delayed_withdrawals_timeout(&self) -> GuardianResult<Duration> {
        Ok(self.withdrawal_config()?.delayed_withdrawals_timeout)
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
            .ok_or(InternalError("S3 logger is not initialized".into()))
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

impl Enclave {
    // ========================================================================
    // Construction & Initialization Status
    // ========================================================================

    pub fn new(signing_keys: GuardianSignKeyPair, encryption_keys: GuardianEncKeyPair) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: EnclaveState {
                hashi_committees: RwLock::new(HashMap::new()),
                withdraw_state: Mutex::new(WithdrawalState::empty()),
            },
            scratchpad: Scratchpad::default(),
        }
    }

    pub fn is_provisioner_init_complete(&self) -> bool {
        self.config.is_provisioner_init_complete() && self.state.is_provisioner_init_complete()
    }

    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        self.config.is_provisioner_init_partially_complete()
            || self.state.is_provisioner_init_partially_complete()
    }

    pub fn is_operator_init_complete(&self) -> bool {
        self.config.is_operator_init_complete() && self.scratchpad.share_commitments.get().is_some()
    }

    pub fn is_operator_init_partially_complete(&self) -> bool {
        self.config.is_operator_init_partially_complete()
            || self.scratchpad.share_commitments.get().is_some()
    }

    /// Is the enclave fully initialized (both operator init and provisioner init)?
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

    /// Get the enclave's signing keypair
    pub fn signing_keypair(&self) -> &GuardianSignKeyPair {
        &self.config.eph_keys.signing_keys
    }

    /// Get the enclave's verification key
    pub fn signing_pubkey(&self) -> GuardianPubKey {
        self.config.eph_keys.signing_keys.verification_key()
    }

    pub fn sign<T: ToBytes + SigningIntent>(&self, data: T) -> GuardianSigned<T> {
        let kp = self.signing_keypair();
        let timestamp = SystemTime::now();
        GuardianSigned::new(data, kp, timestamp)
    }

    // ========================================================================
    // S3 Logging
    // ========================================================================

    /// Sign and log a LogMessage to S3.
    /// Only LogMessage variants can be logged to enforce consistency.
    pub async fn sign_and_log(&self, data: LogMessage) -> GuardianResult<()> {
        let signed = self.sign(data);
        // TODO: Add a session ID (e.g. eph pub key) to every log
        self.config.s3_logger()?.log(signed).await
    }

    /// Log unsigned data to S3 with timestamp.
    /// Only LogMessage variants can be logged to enforce consistency.
    pub async fn timestamp_and_log(&self, data: LogMessage) -> GuardianResult<()> {
        let timestamped = Timestamped {
            data,
            timestamp: SystemTime::now(),
        };
        // TODO: Add a session ID (e.g. eph pub key) to every log
        self.config.s3_logger()?.log(timestamped).await
    }

    // ========================================================================
    // High-level Enclave Operations
    // ========================================================================

    /// Register a new epoch. Adds and (potentially) prunes an entry from limiter and committee map.
    pub fn register_new_epoch(&self, new_committee: HashiCommittee) -> GuardianResult<()> {
        let epoch = new_committee.epoch();
        self.state.update_committee_map(new_committee)?;
        self.state.add_epoch_to_limiter(epoch)
    }

    pub fn set_state(&self, incoming_state: ProvisionerInitRequestState) {
        let (hashi_committees, _, withdrawal_state, _) = incoming_state.into_parts();
        self.state.set_committees(hashi_committees);
        self.state.set_withdrawal_state(withdrawal_state);
    }

    // ========================================================================
    // Scratchpad (Initialization-only data)
    // ========================================================================

    /// Adds a share to the internal list and returns the total number of shares received so far.
    pub fn store_new_share(&self, share: Share) -> GuardianResult<usize> {
        let mut shares = self
            .scratchpad
            .shares
            .lock()
            .expect("Unable to lock shares");
        let share_id = share.id;
        // Check for duplicate share ID (linear search is fine for small share count)
        if shares.iter().any(|s| s.id == share_id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
        shares.push(share);
        let current_share_count = shares.len();
        info!(
            "Total shares received: {}/{}.",
            current_share_count, THRESHOLD
        );
        Ok(current_share_count)
    }

    /// Returns all the shares. Called when we have enough shares.
    pub fn get_all_shares(&self) -> Vec<Share> {
        let shares = self
            .scratchpad
            .shares
            .lock()
            .expect("Unable to lock shares");

        shares.clone()
    }

    pub fn share_commitments(&self) -> GuardianResult<&Vec<ShareCommitment>> {
        self.scratchpad
            .share_commitments
            .get()
            .ok_or(InternalError("Share commitments not set".into()))
    }

    pub fn set_share_commitments(&self, commitments: Vec<ShareCommitment>) -> GuardianResult<()> {
        if commitments.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("Number of commitments does not match".into()));
        }
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
            .map_err(|_| InternalError("State hash already set".into()))
    }
}

#[cfg(test)]
impl Enclave {
    pub fn create_with_random_keys() -> Arc<Self> {
        let signing_keys = GuardianSignKeyPair::new(rand::thread_rng());
        let encryption_keys = GuardianEncKeyPair::random(&mut rand::thread_rng());
        Arc::new(Enclave::new(signing_keys, encryption_keys))
    }

    // Create an enclave post operator_init() but pre provisioner_init()
    pub async fn create_operator_initialized(
        network: Network,
        commitments: &[ShareCommitment],
    ) -> Arc<Self> {
        let enclave = Self::create_with_random_keys();

        // Initialize S3 logger
        let mock_s3_logger = S3Logger::mock_for_testing().await;
        enclave.config.set_s3_logger(mock_s3_logger).unwrap();

        // Set bitcoin network
        enclave.config.set_bitcoin_network(network).unwrap();

        // Set share commitments
        enclave.set_share_commitments(commitments.to_vec()).unwrap();

        assert!(enclave.is_operator_init_complete() && !enclave.is_provisioner_init_complete());

        enclave
    }

    // Create an enclave post operator_init() but pre provisioner_init() for SETUP_MODE
    // Network and share commitments do not matter for setup mode: so we set those to dummy values.
    pub async fn create_operator_initialized_for_setup_mode() -> Arc<Self> {
        let network = Network::Regtest;
        let dummy = ShareCommitment {
            id: std::num::NonZeroU16::new(10).unwrap(),
            digest: vec![],
        };
        Self::create_operator_initialized(network, &vec![dummy; NUM_OF_SHARES]).await
    }
}
