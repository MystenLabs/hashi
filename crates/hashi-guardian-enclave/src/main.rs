use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::Network;
use bitcoin::XOnlyPublicKey;
use ed25519_consensus::SigningKey;
use ed25519_consensus::VerificationKey;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tonic::transport::Server;
use tracing::info;

mod getters;
mod init;
mod rpc;
mod s3_logger;
mod setup;

use crate::rpc::GuardianGrpc;
use crate::s3_logger::S3Logger;
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
    /// Ephemeral keypair on boot
    pub eph_keys: EphemeralKeyPairs,
    /// S3 client & config
    pub s3_logger: OnceLock<S3Logger>,
    /// Enclave BTC private key
    pub enclave_btc_keypair: OnceLock<Keypair>,
    /// BTC network (mainnet, testnet, regtest, etc.)
    pub btc_network: OnceLock<Network>,
    /// Hashi BTC public key used to derive child keys
    pub hashi_btc_master_pubkey: OnceLock<XOnlyPublicKey>,
    /// Withdraw related config's
    pub withdrawal_config: OnceLock<WithdrawalConfig>,
    // TODO: Add rate limiter
}

/// Mutable state that changes during operation
pub struct EnclaveState {
    /// Hashi bls pk's
    pub hashi_committee: RwLock<Arc<HashiCommittee>>,
    /// Withdrawal-related state
    pub withdraw_state: Mutex<WithdrawalState>,
}

/// Scratchpad used only during initialization.
/// Note that we don't clear it post-init because it does not have a lot of data.
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares
    pub decrypted_shares: Mutex<Vec<Share>>,
    /// The share commitments
    pub share_commitments: OnceLock<Vec<ShareCommitment>>,
    /// Hash of the state in ProvisionerInitRequest
    pub state_hash: OnceLock<[u8; 32]>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: SigningKey,
    pub encryption_keys: EncKeyPair,
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

    let signing_keys = SigningKey::new(rand::thread_rng());
    let encryption_keys = EncKeyPair::random(&mut rand::thread_rng());
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
    pub fn new(signing_keys: SigningKey, encryption_keys: EncKeyPair) -> Self {
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
}

impl Enclave {
    // ========================================================================
    // Construction & Initialization Status
    // ========================================================================

    pub fn new(signing_keys: SigningKey, encryption_keys: EncKeyPair) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: EnclaveState {
                hashi_committee: RwLock::new(Arc::new(HashiCommittee::new(vec![], 0))),
                withdraw_state: Mutex::new(WithdrawalState::default()),
            },
            scratchpad: Scratchpad::default(),
        }
    }

    pub fn is_provisioner_init_complete(&self) -> bool {
        self.config.enclave_btc_keypair.get().is_some()
            && self.config.hashi_btc_master_pubkey.get().is_some()
    }

    pub fn is_provisioner_init_partially_complete(&self) -> bool {
        self.config.enclave_btc_keypair.get().is_some()
            || self.config.hashi_btc_master_pubkey.get().is_some()
    }

    pub fn is_operator_init_complete(&self) -> bool {
        self.config.s3_logger.get().is_some()
            && self.config.btc_network.get().is_some()
            && self.scratchpad.share_commitments.get().is_some()
    }

    pub fn is_operator_init_partially_complete(&self) -> bool {
        self.config.s3_logger.get().is_some()
            || self.config.btc_network.get().is_some()
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
    pub fn signing_keypair(&self) -> &SigningKey {
        &self.config.eph_keys.signing_keys
    }

    /// Get the enclave's verification key
    pub fn signing_pubkey(&self) -> VerificationKey {
        self.config.eph_keys.signing_keys.verification_key()
    }

    pub fn sign<T: ToBytes + SigningIntent>(&self, data: T) -> GuardianSigned<T> {
        let kp = self.signing_keypair();
        let timestamp = SystemTime::now();
        GuardianSigned::new(data, kp, timestamp)
    }

    // ========================================================================
    // Bitcoin Configuration
    // ========================================================================

    pub fn bitcoin_network(&self) -> GuardianResult<Network> {
        self.config
            .btc_network
            .get()
            .copied()
            .ok_or(InvalidInputs("Network is uninitialized".into()))
    }

    pub fn set_bitcoin_network(&self, network: Network) -> GuardianResult<()> {
        self.config
            .btc_network
            .set(network)
            .map_err(|_| InvalidInputs("Network is already initialized".into()))
    }

    pub fn btc_keypair(&self) -> GuardianResult<&Keypair> {
        self.config
            .enclave_btc_keypair
            .get()
            .ok_or(InternalError("Bitcoin key is not initialized".into()))
    }

    pub fn set_btc_keypair(&self, keypair: Keypair) -> GuardianResult<()> {
        self.config
            .enclave_btc_keypair
            .set(keypair)
            .map_err(|_| InvalidInputs("Bitcoin key already set".into()))
    }

    pub fn hashi_btc_pk(&self) -> GuardianResult<&XOnlyPublicKey> {
        self.config
            .hashi_btc_master_pubkey
            .get()
            .ok_or(InternalError("Hashi BTC key is not initialized".into()))
    }

    pub fn set_hashi_btc_pk(&self, pk: XOnlyPublicKey) -> GuardianResult<()> {
        self.config
            .hashi_btc_master_pubkey
            .set(pk)
            .map_err(|e| InvalidInputs(format!("Hashi BTC key is already set: {}", e)))
    }

    // ========================================================================
    // Withdrawal Configuration
    // ========================================================================

    pub fn withdrawal_config(&self) -> GuardianResult<&WithdrawalConfig> {
        self.config
            .withdrawal_config
            .get()
            .ok_or(InternalError("WithdrawalConfig is not initialized".into()))
    }

    pub fn set_withdrawal_config(&self, config: WithdrawalConfig) -> GuardianResult<()> {
        self.config
            .withdrawal_config
            .set(config)
            .map_err(|_| InternalError("WithdrawControlsConfig already set".into()))
    }

    pub fn delayed_withdrawals_min_delay(&self) -> GuardianResult<Duration> {
        Ok(self.withdrawal_config()?.delayed_withdrawals_min_delay)
    }

    pub fn delayed_withdrawals_timeout(&self) -> GuardianResult<Duration> {
        Ok(self.withdrawal_config()?.delayed_withdrawals_timeout)
    }

    pub fn withdrawal_committee_threshold(&self) -> GuardianResult<u64> {
        Ok(self.withdrawal_config()?.committee_threshold)
    }

    // ========================================================================
    // S3 Logger
    // ========================================================================

    fn s3_logger(&self) -> GuardianResult<&S3Logger> {
        self.config
            .s3_logger
            .get()
            .ok_or(InternalError("S3 logger is not initialized".into()))
    }

    pub fn set_s3_logger(&self, logger: S3Logger) -> GuardianResult<()> {
        self.config
            .s3_logger
            .set(logger)
            .map_err(|_| InvalidInputs("S3 logger already set".into()))
    }

    /// Sign and log a LogMessage to S3.
    /// Only LogMessage variants can be logged to enforce consistency.
    pub async fn sign_and_log(&self, data: LogMessage) -> GuardianResult<()> {
        let signed = self.sign(data);
        self.s3_logger()?.log(signed).await
    }

    /// Log unsigned data to S3 with timestamp.
    /// Only LogMessage variants can be logged to enforce consistency.
    pub async fn timestamp_and_log(&self, data: LogMessage) -> GuardianResult<()> {
        let timestamped = Timestamped {
            data,
            timestamp: SystemTime::now(),
        };
        self.s3_logger()?.log(timestamped).await
    }

    /// Does a prior LogMessage::ImmediateWithdrawal log with the provided counter value exist?
    /// iwlog stands for ImmediateWithdrawal log
    pub async fn iwlog_exists(&self, _counter: u64) -> GuardianResult<bool> {
        todo!()
    }

    // ========================================================================
    // Runtime State
    // ========================================================================

    pub async fn get_withdraw_state(&self) -> MutexGuard<'_, WithdrawalState> {
        self.state.withdraw_state.lock().await
    }

    pub async fn set_state(
        &self,
        committee: HashiCommittee,
        withdrawal_state: WithdrawalState,
    ) -> GuardianResult<()> {
        {
            let mut x = self
                .state
                .hashi_committee
                .write()
                .map_err(|_| InternalError("unable to acquire lock".into()))?;
            *x = Arc::new(committee);
        } // drop the RwLock guard which is not Send before calling await

        {
            let mut y = self.get_withdraw_state().await;
            *y = withdrawal_state;
        }

        Ok(())
    }

    /// Get the current hashi committee. The read lock is held very briefly only to clone the Arc.
    pub fn get_committee(&self) -> Arc<HashiCommittee> {
        let x = &self
            .state
            .hashi_committee
            .read()
            .expect("rwlock should never throw an error");
        // Note: read() or write() return an error if there's a panic while holding the write guard.
        //       we only write in update_committee which can never panic.
        Arc::clone(x)
    }

    /// Update committee. Expected to be called sporadically, e.g., once a day or so.
    pub async fn set_committee(&self, new_committee: HashiCommittee) {
        let mut state = self
            .state
            .hashi_committee
            .write()
            .expect("rwlock should never throw an error");
        *state = Arc::new(new_committee);
    }

    // ========================================================================
    // Scratchpad (Initialization-only data)
    // ========================================================================

    pub fn decrypted_shares(&self) -> &Mutex<Vec<Share>> {
        &self.scratchpad.decrypted_shares
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
        let signing_keys = SigningKey::new(rand::thread_rng());
        let encryption_keys = EncKeyPair::random(&mut rand::thread_rng());
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
        enclave.set_s3_logger(mock_s3_logger).unwrap();

        // Set bitcoin network
        enclave.set_bitcoin_network(network).unwrap();

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
