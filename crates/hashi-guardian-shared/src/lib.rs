pub mod bitcoin_utils;
pub mod crypto;
pub mod errors;
pub mod proto_conversions;
pub mod test_utils;

pub use crypto::*;
pub use errors::*;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::GuardianError::*;
pub use bitcoin::secp256k1::Keypair as BitcoinKeypair;
pub use bitcoin::taproot::Signature as BitcoinSignature;
use bitcoin::*;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
pub use ed25519_consensus::Signature as GuardianSignature;
pub use ed25519_consensus::SigningKey as GuardianSigningKeyPair;
pub use ed25519_consensus::VerificationKey as GuardianVerificationKey;
pub use hashi::committee::Committee as HashiCommittee;
pub use hashi::committee::CommitteeMember as HashiCommitteeMember;
pub use hashi::committee::SignedMessage as HashiSigned;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::SystemTime;

use crate::bitcoin_utils::TxUTXOs;
use crate::proto_conversions::provisioner_init_state_to_pb;
use prost::Message;

pub const MAX_HASHI_COMMITTEES: usize = 7;

// ---------------------------------
//     Serialization Abstraction
// ---------------------------------

/// Trait for types that can be converted to bytes for signing, hashing, or logging.
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Blanket implementation for all types that implement Serialize.
/// This allows existing BCS serialization to work through the new trait.
impl<T: Serialize> ToBytes for T {
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("serialization should not fail")
    }
}

// ---------------------------------
//          Intents
// ---------------------------------

/// All possible signing intent types.
/// Using an enum ensures no two types can accidentally share the same intent value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentType {
    /// Intent for all LogMessage's
    LogMessage = 0,
    /// Intent for SetupNewKeyResponse
    SetupNewKeyResponse = 1,
    /// Intent for NormalWithdrawalResponse
    NormalWithdrawalResponse = 2,
}

/// Trait for types that can be signed, providing domain separation via an intent.
pub trait SigningIntent {
    const INTENT: IntentType;
}

// ---------------------------------
//          Envelopes
// ---------------------------------

/// Timestamped wrapper - adds timestamp to any data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Timestamped<T> {
    pub data: T,
    pub timestamp: SystemTime,
}

/// Guardian-signed wrapper - adds timestamp and signature to any data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianSigned<T> {
    pub data: T,
    pub timestamp: SystemTime,
    pub signature: GuardianSignature,
}

// ---------------------------------
//    All requests and responses
// ---------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SetupNewKeyRequest {
    key_provisioner_public_keys: Vec<EncPubKey>,
}

/// `EnclaveSigned<T>`
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetupNewKeyResponse {
    pub encrypted_shares: Vec<EncryptedShare>,
    pub share_commitments: Vec<ShareCommitment>,
}

/// Provides S3 API keys, share commitments and the BTC network to the enclave.
/// To be called by the operator.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorInitRequest {
    s3_config: S3Config,
    share_commitments: Vec<ShareCommitment>,
    network: Network,
}

/// Provides key shares and all other necessary state values to the enclaves.
/// To be called by Key Provisioners (who may be outside entities).
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerInitRequest {
    encrypted_share: EncryptedShare,
    state: ProvisionerInitRequestState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerInitRequestState {
    /// Hashi BLS keys used to sign cert's
    pub hashi_committees: HashMap<u64, HashiCommittee>,
    /// Withdrawal config
    pub withdrawal_config: WithdrawalConfig,
    /// Withdrawal state
    pub withdrawal_state: WithdrawalState,
    /// Hashi BTC master key used to derive child keys for diff inputs
    pub hashi_btc_master_pubkey: XOnlyPublicKey,
}

#[derive(Debug, PartialEq, Clone)]
pub struct GetGuardianInfoResponse {
    /// Attestation document serialized in Hex
    pub attestation: Attestation,
    /// Server version
    /// TODO: Replace with hashi's ServerVersion to include crate SHA and version
    pub server_version: String,
}

/// An "immediate withdrawal" request. `HashiSigned<T>.`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// Hashi-assigned timestamp
    timestamp_secs: WithdrawalTime,
    /// BTC transaction input and output utxos
    all_utxos: TxUTXOs,
    /// Was delayed_withdraw previously called for this withdrawal?
    is_delayed: bool,
}

/// `EnclaveSigned<T>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalWithdrawalResponse {
    pub enclave_signatures: Vec<BitcoinSignature>,
}

// ---------------------------------
//          Log Messages
// ---------------------------------

/// All log messages emitted by the guardian enclave.
/// Uses enum discriminator for automatic domain separation between variants.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessage {
    /// Attestation and signing public key
    OperatorInitAttestationUnsigned {
        attestation: Attestation,
        signing_public_key: GuardianVerificationKey,
    },
    /// Share commitments given in /operator_init
    OperatorInitShareCommitments(Vec<ShareCommitment>),
    /// A successful /setup_new_key call
    SetupNewKeySuccess {
        encrypted_shares: Vec<EncryptedShare>,
        share_commitments: Vec<ShareCommitment>,
    },
    /// A single successful /provisioner_init call (happens N times)
    ProvisionerInitSuccess {
        share_id: ShareID,
        state_hash: [u8; 32],
    },
    /// Threshold reached - enclave fully initialized (happens once)
    EnclaveFullyInitialized,
    /// Immediate withdraw
    NormalWithdrawalSuccess {
        request: NormalWithdrawalRequest,
        response: NormalWithdrawalResponse,
        withdraw_count: u64,
    },
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

// TODO: Align types with hashi
/// Unique identifier for a withdrawal request
pub type WithdrawalID = u64;

/// Sui-assigned timestamp for a withdrawal (seconds since UNIX_EPOCH)
pub type WithdrawalTime = u64;

pub type Attestation = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
}

// TODO: Align types with hashi.
/// All the withdrawal config
#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalConfig {
    /// Committee threshold expressed in terms of weight
    pub committee_threshold: u64,
    /// The min delay after which any withdrawal is approved
    pub delayed_withdrawals_min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub delayed_withdrawals_timeout: Duration,
}

/// Withdrawal state - all that is needed to restart the enclave
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WithdrawalState {
    /// Total number of withdrawals processed till now
    pub num_withdrawals: u64,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl SigningIntent for LogMessage {
    const INTENT: IntentType = IntentType::LogMessage;
}

impl SigningIntent for SetupNewKeyResponse {
    const INTENT: IntentType = IntentType::SetupNewKeyResponse;
}

impl SigningIntent for NormalWithdrawalResponse {
    const INTENT: IntentType = IntentType::NormalWithdrawalResponse;
}

impl SetupNewKeyRequest {
    pub fn new(public_keys: Vec<EncPubKey>) -> GuardianResult<Self> {
        if public_keys.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("provide enough public keys".into()));
        }
        Ok(Self {
            key_provisioner_public_keys: public_keys,
        })
    }

    pub fn public_keys(&self) -> &[EncPubKey] {
        &self.key_provisioner_public_keys
    }
}

impl OperatorInitRequest {
    pub fn new(
        s3_config: S3Config,
        share_commitments: Vec<ShareCommitment>,
        network: Network,
    ) -> GuardianResult<Self> {
        if share_commitments.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("provide enough share commitments".into()));
        }

        let mut x = HashSet::new();
        for c in &share_commitments {
            if !x.insert(c.id) {
                return Err(InvalidInputs("duplicate share id".into()));
            }
        }

        Ok(Self {
            s3_config,
            share_commitments,
            network,
        })
    }

    pub fn s3_config(&self) -> &S3Config {
        &self.s3_config
    }

    pub fn share_commitments(&self) -> &[ShareCommitment] {
        &self.share_commitments
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

impl ToBytes for ProvisionerInitRequestState {
    fn to_bytes(&self) -> Vec<u8> {
        provisioner_init_state_to_pb(self.clone()).encode_to_vec()
    }
}

impl ProvisionerInitRequestState {
    pub fn new(
        hashi_committees: HashMap<u64, HashiCommittee>,
        withdrawal_config: WithdrawalConfig,
        withdrawal_state: WithdrawalState,
        hashi_btc_master_pubkey: XOnlyPublicKey,
    ) -> GuardianResult<Self> {
        // TODO: Add more validation (if any)
        if hashi_committees.len() > MAX_HASHI_COMMITTEES {
            return Err(InvalidInputs("too many committees".into()));
        }

        Ok(Self {
            hashi_committees,
            withdrawal_config,
            withdrawal_state,
            hashi_btc_master_pubkey,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        Blake2b::<U32>::digest(self.to_bytes()).into()
    }
}

impl ProvisionerInitRequest {
    pub fn new(encrypted_share: EncryptedShare, state: ProvisionerInitRequestState) -> Self {
        // TODO: Add validation
        Self {
            encrypted_share,
            state,
        }
    }

    /// Create a new ProvisionerInitRequest by encrypting the share to the enclave's public key.
    /// In addition, it sets the state hash as AAD for the encryption effectively
    /// allowing the enclave to trust that state is indeed coming from the KP.
    pub fn build_from_share_and_state<R: CryptoRng + RngCore>(
        share: &Share,
        enclave_pub_key: &EncPubKey,
        state: ProvisionerInitRequestState,
        rng: &mut R,
    ) -> Self {
        let state_hash = state.digest();
        let encrypted_share = encrypt_share(share, enclave_pub_key, Some(&state_hash), rng);
        ProvisionerInitRequest::new(encrypted_share, state)
    }

    pub fn encrypted_share(&self) -> &EncryptedShare {
        &self.encrypted_share
    }

    pub fn state(&self) -> &ProvisionerInitRequestState {
        &self.state
    }

    pub fn into_state(self) -> ProvisionerInitRequestState {
        self.state
    }
}

impl NormalWithdrawalRequest {
    pub fn wid(&self) -> &WithdrawalID {
        &self.wid
    }

    pub fn all_utxos(&self) -> &TxUTXOs {
        &self.all_utxos
    }

    pub fn timestamp(&self) -> &WithdrawalTime {
        &self.timestamp_secs
    }

    pub fn is_delayed(&self) -> bool {
        self.is_delayed
    }
}

// ---------------------------------
//    Tracing utilities
// ---------------------------------

/// Initialize tracing subscriber with optional file/line number logging
pub fn init_tracing_subscriber(with_file_line: bool) {
    let mut builder = tracing_subscriber::FmtSubscriber::builder().with_env_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
            .from_env_lossy(),
    );

    if with_file_line {
        builder = builder.with_file(true).with_line_number(true);
    }

    let subscriber = builder.finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}
