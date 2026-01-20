use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::Amount;
use bitcoin::Network;
use hashi_guardian_shared::bitcoin_utils::construct_signing_messages;
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::bitcoin_utils::TxUTXOs;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
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
use hashi_guardian_shared::epoch_store::ConsecutiveEpochStore;
use hashi_types::committee::Committee as HashiCommittee;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;

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
    enclave_btc_keypair: OnceLock<Keypair>,
    /// BTC network: mainnet, testnet, regtest (set in operator_init)
    btc_network: OnceLock<Network>,
    /// Hashi BTC public key used to derive child keys (set in provisioner_init)
    hashi_btc_master_pubkey: OnceLock<BitcoinPubkey>,
    /// Withdraw related config's (set in provisioner_init)
    withdrawal_config: OnceLock<WithdrawalConfig>,
}

pub type ArcCommitteeStore = ConsecutiveEpochStore<Arc<HashiCommittee>>;

/// Mutable state that changes during operation.
/// Note: State is initialized during provisioner_init.
pub struct EnclaveState {
    /// Hashi committees indexed by epoch.
    hashi_committees: RwLock<Option<ArcCommitteeStore>>,
    /// Withdrawal-related state.
    withdraw_state: Mutex<Option<WithdrawalState>>,
}

/// Scratchpad used only during initialization.
/// Note: We don't clear it post-init because it does not have a lot of data.
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares
    /// TODO: Investigate if it can be moved to std::sync::Mutex
    pub shares: tokio::sync::Mutex<Vec<Share>>,
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

    pub fn set_btc_keypair(&self, keypair: Keypair) -> GuardianResult<()> {
        self.enclave_btc_keypair
            .set(keypair)
            .map_err(|_| InvalidInputs("Bitcoin key already set".into()))
    }

    pub fn set_hashi_btc_pk(&self, pk: BitcoinPubkey) -> GuardianResult<()> {
        self.hashi_btc_master_pubkey
            .set(pk)
            .map_err(|e| InvalidInputs(format!("Hashi BTC key is already set: {}", e)))
    }

    /// Sign a BTC tx. Returns an Err if enclave btc keypair or hashi btc pk is not set.
    pub fn btc_sign(
        &self,
        tx_utxos: &TxUTXOs,
        network: Network,
    ) -> GuardianResult<Vec<BitcoinSignature>> {
        let enclave_keypair = self
            .enclave_btc_keypair
            .get()
            .ok_or(InternalError("Bitcoin key is not initialized".into()))?;
        let hashi_btc_pk = self
            .hashi_btc_master_pubkey
            .get()
            .ok_or(InternalError("Hashi BTC public key not set".into()))?;

        let messages = construct_signing_messages(
            tx_utxos,
            &enclave_keypair.x_only_public_key().0,
            hashi_btc_pk,
            network,
        );
        Ok(sign_btc_tx(&messages, enclave_keypair))
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

impl EnclaveState {
    pub fn init(&self, incoming_state: ProvisionerInitRequestState) -> GuardianResult<()> {
        let (hashi_committees, _, withdrawal_state, _) = incoming_state.into_parts();

        self.set_committees(hashi_committees)?;
        self.set_withdrawal_state(withdrawal_state)?;
        Ok(())
    }

    fn with_committees<R>(&self, f: impl FnOnce(&ArcCommitteeStore) -> R) -> GuardianResult<R> {
        let guard = self
            .hashi_committees
            .read()
            .expect("rwlock should never throw an error");
        let committees = guard
            .as_ref()
            .ok_or_else(|| InvalidInputs("committees not initialized".into()))?;
        Ok(f(committees))
    }

    fn with_committees_mut<R>(
        &self,
        f: impl FnOnce(&mut ArcCommitteeStore) -> GuardianResult<R>,
    ) -> GuardianResult<R> {
        let mut guard = self
            .hashi_committees
            .write()
            .expect("rwlock should never throw an error");
        let committees = guard
            .as_mut()
            .ok_or_else(|| InvalidInputs("committees not initialized".into()))?;
        f(committees)
    }

    fn with_withdraw_state_mut<R>(
        &self,
        f: impl FnOnce(&mut WithdrawalState) -> GuardianResult<R>,
    ) -> GuardianResult<R> {
        let mut guard = self.withdraw_state.lock().expect("should not be poisoned");
        let state = guard
            .as_mut()
            .ok_or_else(|| InvalidInputs("withdraw_state not initialized".into()))?;
        f(state)
    }

    // ========================================================================
    // Initialization Status
    // ========================================================================

    fn status_check_inner(&self) -> (bool, bool) {
        let committees_init = self
            .hashi_committees
            .read()
            .expect("rwlock read should not fail")
            .as_ref()
            .is_some_and(|s| s.is_initialized());

        let withdraw_state_init = self
            .withdraw_state
            .lock()
            .expect("mutex lock should not fail")
            .as_ref()
            .is_some_and(|s| s.is_initialized());

        (committees_init, withdraw_state_init)
    }

    /// Check if state init is complete
    pub fn is_provisioner_init_complete(&self) -> bool {
        let (committees_init, withdraw_state_init) = self.status_check_inner();
        committees_init && withdraw_state_init
    }

    /// Check if any state has been set
    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        let (committees_init, withdraw_state_init) = self.status_check_inner();
        committees_init || withdraw_state_init
    }

    // ========================================================================
    // Committee Management
    // ========================================================================

    /// Get the current hashi committee.
    pub fn get_committee(&self, epoch: u64) -> GuardianResult<Arc<HashiCommittee>> {
        self.with_committees(|committee_map| committee_map.get_checked(epoch).map(Arc::clone))?
    }

    /// Adds one committee and prunes one if needed.
    pub fn add_new_committee(&self, new_committee: HashiCommittee) -> GuardianResult<()> {
        let epoch = new_committee.epoch();
        info!("Adding new epoch {} to committee map.", epoch);

        // TODO: Replace with insert_strict if we are certain store is always pre-initialized
        self.with_committees_mut(|committee_map| {
            committee_map.insert_or_start(epoch, Arc::new(new_committee))
        })
    }

    /// Set committees. Called only from init(ProvisionerInitRequestState)
    fn set_committees(&self, hashi_committees: CommitteeStore) -> GuardianResult<()> {
        info!(
            "Setting state with {} committees.",
            hashi_committees.num_entries()
        );

        // Check if it is already initialized
        let mut guard = self
            .hashi_committees
            .write()
            .expect("rwlock should never throw an error");
        if guard.is_some() {
            return Err(InvalidInputs("committees already initialized".into()));
        }

        // Insert input committee. Iterate and create Arc's.
        let capacity = hashi_committees.capacity();
        let mut new_map = ArcCommitteeStore::empty(capacity);
        for (e, committee) in hashi_committees.into_owned_iter() {
            info!("Adding committee for epoch {}.", e);
            new_map
                .insert_or_start(e, Arc::new(committee))
                .expect("Should not fail because we are reading from a ConsecutiveEpochStore");
        }
        *guard = Some(new_map);
        Ok(())
    }

    // ========================================================================
    // Withdrawal State Management
    // ========================================================================

    fn set_withdrawal_state(&self, state: WithdrawalState) -> GuardianResult<()> {
        info!("Setting withdrawal state.");

        let mut guard = self.withdraw_state.lock().expect("should not be poisoned");
        if guard.is_some() {
            Err(InvalidInputs("withdraw_state already initialized".into()))
        } else {
            *guard = Some(state);
            Ok(())
        }
    }

    pub fn consume_from_limiter(&self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.with_withdraw_state_mut(|st| st.consume_from_limiter(epoch, amount))
    }

    pub fn revert_limiter(&self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.with_withdraw_state_mut(|st| st.revert_limiter(epoch, amount))
    }

    pub fn add_epoch_to_limiter(&self, epoch: u64) -> GuardianResult<()> {
        self.with_withdraw_state_mut(|st| st.add_epoch_to_limiter(epoch))
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
                hashi_committees: RwLock::new(None),
                withdraw_state: Mutex::new(None),
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

    pub fn sign<T: ToBytes + SigningIntent>(&self, data: T) -> GuardianSigned<T> {
        let kp = &self.config.eph_keys.signing_keys;
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
    // Committee Rotation
    // ========================================================================

    /// Register a new epoch. Adds and (potentially) prunes an entry from limiter and committee map.
    pub fn register_new_epoch(&self, new_committee: HashiCommittee) -> GuardianResult<()> {
        let epoch = new_committee.epoch();
        self.state.add_new_committee(new_committee)?;
        self.state.add_epoch_to_limiter(epoch)?;
        Ok(())
    }

    // ========================================================================
    // Scratchpad (Initialization-only data)
    // ========================================================================

    pub fn decrypted_shares(&self) -> &tokio::sync::Mutex<Vec<Share>> {
        &self.scratchpad.shares
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
