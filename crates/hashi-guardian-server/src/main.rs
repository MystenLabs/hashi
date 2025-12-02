use anyhow::Result;
use axum::routing::get;
use axum::routing::post;
use axum::Router;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Address;
use bitcoin::Network;
use ed25519_consensus::SigningKey;
use governor::clock::DefaultClock;
use governor::state::InMemoryState;
use governor::state::NotKeyed;
use governor::Quota;
use governor::RateLimiter;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::crypto::ShareID;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::*;
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use nonzero_ext::nonzero;
use std::collections::HashMap;
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tracing::info;

mod attestation;
mod health_check;
mod init;
mod s3_logger;
mod setup;
mod withdraw;

use crate::attestation::get_attestation;
use crate::health_check::health_check;
use crate::s3_logger::S3Logger;
use crate::withdraw::delayed_withdraw;
use crate::withdraw::instant_withdraw;
use init::init_enclave_external;
use init::init_enclave_internal;
use setup::setup_new_key;

/// Enclave's config & state
pub struct Enclave {
    /// Configuration (set once during initialization)
    pub config: EnclaveConfig,
    /// Mutable state
    pub state: Mutex<EnclaveState>,
    /// Initialization scratchpad
    pub scratchpad: Scratchpad,
}

/// Configuration set during initialization (immutable after set)
pub struct EnclaveConfig {
    /// Ephemeral keypair on boot
    pub eph_keys: EphemeralKeyPairs,
    /// S3 client & config
    pub s3_logger: OnceLock<S3Logger>,
    /// Bitcoin private key
    pub bitcoin_key: OnceLock<SecretKey>,
    /// Rate limiter for withdrawals
    pub withdraw_controls_config: OnceLock<WithdrawConfig>,
    /// Bitcoin network (mainnet, testnet, regtest, etc.)
    pub bitcoin_network: Network,
    /// Bitcoin change address for withdrawals
    pub change_address: OnceLock<Address>,
    /// Rate limiter
    pub rate_limiter: MyRateLimiter,
}

pub type MyRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Mutable state that changes during operation
pub struct EnclaveState {
    /// Hashi info, e.g., btc pk, bls pk's, etc.
    pub hashi_committee_info: HashiCommittee,
    /// Withdrawal-related state
    pub withdraw_state: WithdrawalState,
}

/// Scratchpad used only during initialization
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares (stored as a Vec, with IDs tracked in a HashSet for deduplication)
    pub decrypted_shares: Mutex<Vec<Share>>,
    /// Track which share IDs we've received to detect duplicates
    pub received_share_ids: Mutex<HashSet<ShareID>>,
    /// The share commitments
    pub share_commitments: OnceLock<Vec<ShareCommitment>>,
    /// Hash of the state in InitExternalRequest
    pub state_hash: OnceLock<DigestBytes>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: SigningKey,
    pub encryption_keys: EncKeyPair,
}

// 0.1 BTC per hour
const DEFAULT_HOURLY_RATE_LIMIT: u32 = 10_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber(true);

    // Read bitcoin network and max amount withdrawn per hour from environment variable
    let bitcoin_network = std::env::var("BITCOIN_NETWORK")
        .ok()
        .and_then(|s| s.parse::<Network>().ok());
    info!("Bitcoin network: {:?}", bitcoin_network);
    let max_per_hour = std::env::var("MAX_SPEND_PER_HOUR")
        .ok()
        .and_then(|s| s.parse::<NonZeroU32>().ok());
    info!("Max spend per hour: {:?} satoshi's", max_per_hour);

    let signing_keys = SigningKey::new(rand::thread_rng());
    let encryption_keys = EncKeyPair::random(&mut rand::thread_rng());
    let enclave = Arc::new(Enclave::new(
        signing_keys,
        encryption_keys,
        bitcoin_network,
        max_per_hour,
    ));

    let app = Router::new()
        .route("/health_check", get(health_check))
        .route("/get_attestation", get(get_attestation))
        // ------------------------------------------------
        // ---------------- Initialization ----------------
        // TODO: Add a config flag that determines whether setup_new_key is exposed?
        // Setup new BTC key and secret share it with key provisioner (KP)
        .route("/setup_new_key", post(setup_new_key))
        // Init enclave (internal)
        .route("/init_internal", post(init_enclave_internal))
        // Init enclave (external; called by KP's)
        .route("/init_external", post(init_enclave_external))
        // ------------------------------------------------
        // ---------------- Withdraw ----------------------
        // Instant withdraw
        .route("/instant_withdraw", post(instant_withdraw))
        // Delayed withdraw
        .route("/delayed_withdraw", post(delayed_withdraw))
        // TODO: resign, committee rotation
        .with_state(enclave);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server listening on {}", listener.local_addr()?);
    info!("Waiting for S3 configuration from client...");
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

impl EnclaveConfig {
    pub fn new(
        signing_keys: SigningKey,
        encryption_keys: EncKeyPair,
        bitcoin_network: Option<Network>,
        max_per_hour: Option<NonZeroU32>,
    ) -> Self {
        EnclaveConfig {
            eph_keys: EphemeralKeyPairs {
                signing_keys,
                encryption_keys,
            },
            s3_logger: OnceLock::new(),
            bitcoin_key: OnceLock::new(),
            withdraw_controls_config: OnceLock::new(),
            bitcoin_network: bitcoin_network.unwrap_or(Network::Regtest),
            change_address: OnceLock::new(),
            rate_limiter: RateLimiter::direct(Quota::per_hour(
                max_per_hour.unwrap_or(nonzero!(DEFAULT_HOURLY_RATE_LIMIT)),
            )),
        }
    }
}

impl Enclave {
    // ========================================================================
    // Construction & Initialization Status
    // ========================================================================

    /// Create a new Enclave. Setting None to network leads to Regtest
    pub fn new(
        signing_keys: SigningKey,
        encryption_keys: EncKeyPair,
        bitcoin_network: Option<Network>,
        max_per_hour: Option<NonZeroU32>,
    ) -> Self {
        Enclave {
            config: EnclaveConfig::new(
                signing_keys,
                encryption_keys,
                bitcoin_network,
                max_per_hour,
            ),
            state: Mutex::new(EnclaveState {
                hashi_committee_info: HashiCommittee::default(),
                withdraw_state: WithdrawalState::default(),
            }),
            scratchpad: Scratchpad {
                decrypted_shares: Mutex::new(Vec::new()),
                received_share_ids: Mutex::new(HashSet::new()),
                share_commitments: OnceLock::new(),
                state_hash: OnceLock::new(),
            },
        }
    }

    /// Is external init (KP-driven) complete?
    pub fn is_init_external(&self) -> bool {
        self.config.bitcoin_key.get().is_some()
            && self.config.withdraw_controls_config.get().is_some()
            && self.config.change_address.get().is_some()
        // TODO: Add withdraw_state & hashi_committee
    }

    /// Is internal init complete?
    pub fn is_init_internal(&self) -> bool {
        self.config.s3_logger.get().is_some()
    }

    /// Is the enclave fully initialized?
    pub fn is_fully_initialized(&self) -> bool {
        self.is_init_external() && self.is_init_internal()
    }

    // ========================================================================
    // Ephemeral Keypairs (Encryption & Signing)
    // ========================================================================

    /// Get the enclave's encryption secret key
    pub fn encryption_secret_key(&self) -> &hashi_guardian_shared::EncSecKey {
        self.config.eph_keys.encryption_keys.secret_key()
    }

    /// Get the enclave's encryption public key
    pub fn encryption_public_key(&self) -> &hashi_guardian_shared::EncPubKey {
        self.config.eph_keys.encryption_keys.public_key()
    }

    /// Get the enclave's signing keypair
    pub fn signing_keypair(&self) -> &SigningKey {
        &self.config.eph_keys.signing_keys
    }

    // ========================================================================
    // Bitcoin Configuration
    // ========================================================================

    pub fn bitcoin_network(&self) -> Network {
        self.config.bitcoin_network
    }

    pub fn btc_key(&self) -> GuardianResult<&SecretKey> {
        self.config
            .bitcoin_key
            .get()
            .ok_or(InternalError("Bitcoin key is not initialized".into()))
    }

    pub fn set_bitcoin_key(&self, key: SecretKey) -> GuardianResult<()> {
        self.config
            .bitcoin_key
            .set(key)
            .map_err(|_| InternalError("Bitcoin key already set".into()))
    }

    pub fn change_address(&self) -> GuardianResult<Address> {
        Ok(self
            .config
            .change_address
            .get()
            .ok_or(InternalError("Change address is not initialized".into()))?
            .clone())
    }

    pub fn set_change_address(&self, addr_str: &str) -> GuardianResult<()> {
        let network = self.bitcoin_network();
        let address = addr_str
            .parse::<Address<_>>()
            .map_err(|e| InternalError(format!("Invalid change address: {}", e)))?
            .require_network(network)
            .map_err(|e| InternalError(format!("Change address network mismatch: {:?}", e)))?;

        self.config
            .change_address
            .set(address)
            .map_err(|e| InternalError(format!("change_address already set: {}", e)))
    }

    // ========================================================================
    // Withdrawal Configuration
    // ========================================================================

    pub fn rate_limiter(&self) -> &MyRateLimiter {
        &self.config.rate_limiter
    }

    pub fn withdraw_controls_config(&self) -> GuardianResult<&WithdrawConfig> {
        self.config
            .withdraw_controls_config
            .get()
            .ok_or(InternalError(
                "WithdrawControlsConfig is not initialized".into(),
            ))
    }

    pub fn set_withdraw_controls_config(&self, config: WithdrawConfig) -> GuardianResult<()> {
        self.config
            .withdraw_controls_config
            .set(config)
            .map_err(|_| InternalError("WithdrawControlsConfig already set".into()))
    }

    pub fn min_and_max_delay(&self) -> GuardianResult<(Duration, Duration)> {
        let c = self.withdraw_controls_config()?;
        Ok((c.min_delay, c.max_delay))
    }

    // ========================================================================
    // S3 Logger
    // ========================================================================

    pub fn s3_logger(&self) -> GuardianResult<&S3Logger> {
        self.config
            .s3_logger
            .get()
            .ok_or(InternalError("S3 logger is not initialized".into()))
    }

    pub fn set_s3_logger(&self, logger: S3Logger) -> GuardianResult<()> {
        self.config
            .s3_logger
            .set(logger)
            .map_err(|_| InternalError("S3 logger already set".into()))
    }

    // ========================================================================
    // Runtime State
    // ========================================================================

    pub async fn state(&self) -> MutexGuard<'_, EnclaveState> {
        self.state.lock().await
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
        self.scratchpad
            .share_commitments
            .set(commitments)
            .map_err(|_| InternalError("Share commitments already set".into()))
    }

    pub fn state_hash(&self) -> Option<&DigestBytes> {
        self.scratchpad.state_hash.get()
    }

    pub fn set_state_hash(&self, hash: DigestBytes) -> GuardianResult<()> {
        self.scratchpad
            .state_hash
            .set(hash)
            .map_err(|_| InternalError("State hash already set".into()))
    }
}

impl EnclaveState {
    pub fn pending_withdrawals(&self) -> &HashMap<WithdrawID, DelayedWithdrawInfo> {
        &self.withdraw_state.pending_delayed_withdrawals
    }

    pub fn pending_withdrawals_mut(&mut self) -> &mut HashMap<WithdrawID, DelayedWithdrawInfo> {
        &mut self.withdraw_state.pending_delayed_withdrawals
    }
}

#[cfg(test)]
impl Enclave {
    /// Create a test enclave with all necessary initialization
    ///
    /// # Arguments
    /// * `min_delay` - Optional custom min_delay (defaults to 60 seconds)
    pub async fn create_for_test_with_min_delay(min_delay: Option<Duration>) -> Arc<Self> {
        let mut rng = rand::thread_rng();
        let signing_keys = SigningKey::new(rand::thread_rng());
        let encryption_keys = EncKeyPair::random(&mut rng);
        let enclave = Arc::new(Enclave::new(
            signing_keys,
            encryption_keys,
            Some(Network::Regtest),
            None,
        ));

        // Initialize S3 logger
        let mock_s3_logger = S3Logger::mock_for_testing().await;
        enclave.set_s3_logger(mock_s3_logger).unwrap();

        // Set bitcoin key
        let btc_sk = SecretKey::from_slice(&test_utils::TEST_ENCLAVE_SK).unwrap();
        enclave.set_bitcoin_key(btc_sk).unwrap();

        // Set withdraw controls config
        let withdraw_config = WithdrawConfig {
            min_delay: min_delay.unwrap_or(Duration::from_secs(60)),
            max_delay: Duration::from_secs(3600),
        };
        enclave
            .set_withdraw_controls_config(withdraw_config)
            .unwrap();

        // Set change address
        enclave
            .set_change_address(test_utils::DUMMY_REGTEST_ADDRESS)
            .unwrap();

        enclave
    }

    /// Create a test enclave with default 60-second delay
    pub async fn create_for_test() -> Arc<Self> {
        Self::create_for_test_with_min_delay(None).await
    }

    /// Create a bare enclave for testing initialization
    /// Only sets up S3 logger, no bitcoin key or withdraw config
    pub async fn create_bare_for_test() -> Arc<Self> {
        let mut rng = rand::thread_rng();
        let signing_keys = SigningKey::new(rand::thread_rng());
        let encryption_keys = EncKeyPair::random(&mut rng);
        let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys, None, None));

        // Initialize S3 logger only (required for is_init_internal() to pass)
        let mock_s3_logger = S3Logger::mock_for_testing().await;
        enclave.set_s3_logger(mock_s3_logger).unwrap();

        enclave
    }
}
