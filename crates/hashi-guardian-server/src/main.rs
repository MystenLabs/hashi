use anyhow::Result;
use axum::routing::get;
use axum::routing::post;
use axum::Router;
use bitcoin::secp256k1::SecretKey;
use fastcrypto::hash::Digest;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use hashi_guardian_shared::{
    EncKeyPair, GuardianError, GuardianResult, HashiCommittee, MyShare, ShareCommitment,
    WithdrawConfig, WithdrawalState,
};
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::info;

mod attestation;
mod health_check;
mod init;
mod s3_logger;
mod setup;

use crate::attestation::get_attestation;
use crate::health_check::health_check;
use crate::s3_logger::S3Logger;
use init::{init_enclave_external, init_enclave_internal};
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
}

/// Mutable state that changes during operation
pub struct EnclaveState {
    /// Hashi info, e.g., btc pk, bls pk's, etc.
    pub hashi_committee_info: HashiCommittee,
    /// Withdrawal-related state
    pub withdraw_state: WithdrawalState,
}

// Scratchpad used only during initialization
#[derive(Default)]
pub struct Scratchpad {
    /// The received shares
    pub decrypted_shares: Mutex<HashSet<MyShare>>,
    /// The share commitments
    pub share_commitments: OnceLock<Vec<ShareCommitment>>,
    /// Hash of the state in InitExternalRequest
    pub state_hash: OnceLock<Digest<32>>,
}

pub struct EphemeralKeyPairs {
    pub signing_keys: Ed25519KeyPair,
    pub encryption_keys: EncKeyPair,
}

async fn ping() -> &'static str {
    info!("🏓 /ping - Received request");
    "pong"
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber();

    let signing_keys = Ed25519KeyPair::generate(&mut rand::thread_rng());
    let encryption_keys = X25519HkdfSha256::gen_keypair(&mut rand::thread_rng()).into();
    let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys));

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/health_check", get(health_check))
        .route("/get_attestation", get(get_attestation))
        // TODO: Add a config flag that determines whether setup_new_key is exposed
        .route("/setup_new_key", post(setup_new_key))
        .route("/configure_s3", post(init_enclave_internal))
        .route("/init", post(init_enclave_external))
        .with_state(enclave);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server listening on {}", listener.local_addr()?);
    info!("Waiting for S3 configuration from client...");
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

fn init_tracing_subscriber() {
    let subscriber = ::tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_file(true)
        .with_line_number(true)
        .finish();
    ::tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}

impl EnclaveConfig {
    pub fn new(signing_keys: Ed25519KeyPair, encryption_keys: EncKeyPair) -> Self {
        EnclaveConfig {
            eph_keys: EphemeralKeyPairs {
                signing_keys,
                encryption_keys,
            },
            s3_logger: OnceLock::new(),
            bitcoin_key: OnceLock::new(),
            withdraw_controls_config: OnceLock::new(),
        }
    }
}

impl Enclave {
    pub fn new(signing_keys: Ed25519KeyPair, encryption_keys: EncKeyPair) -> Self {
        Enclave {
            config: EnclaveConfig::new(signing_keys, encryption_keys),
            state: Mutex::new(EnclaveState {
                hashi_committee_info: HashiCommittee::default(),
                withdraw_state: WithdrawalState::default(),
            }),
            scratchpad: Scratchpad::default(),
        }
    }
}

impl Enclave {
    pub fn is_init_external(&self) -> bool {
        self.config.bitcoin_key.get().is_some()
            && self.config.withdraw_controls_config.get().is_some()
        // TODO: Add withdraw_state & hashi_committee
    }

    pub fn is_init_internal(&self) -> bool {
        self.config.s3_logger.get().is_some()
    }

    pub fn is_fully_initialized(&self) -> bool {
        self.is_init_external() && self.is_init_internal()
    }
}
