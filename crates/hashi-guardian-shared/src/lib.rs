pub mod bitcoin_utils;
pub mod crypto;
pub mod errors;
pub mod proto_conversions;

pub use crypto::*;
pub use errors::*;

use crate::GuardianError::*;
use bitcoin::*;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
pub use ed25519_consensus::Signature as GuardianSignature;
use ed25519_consensus::VerificationKey;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::SystemTime;

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GuardianSigned<T> {
    pub data: T,
    pub timestamp: SystemTime,
    pub signature: GuardianSignature,
}

/// Hashi-signed wrapper
/// TODO: Add cert, intent. Align types with hashi.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashiNodeSigned<T> {
    pub data: T,
}

// ---------------------------------
//    All requests and responses
// ---------------------------------

#[derive(Debug)]
pub struct SetupNewKeyRequest {
    key_provisioner_public_keys: Vec<EncPubKey>,
}

/// `EnclaveSigned<T>`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetupNewKeyResponse {
    pub encrypted_shares: Vec<EncryptedShare>,
    pub share_commitments: Vec<ShareCommitment>,
}

/// Provides S3 API keys, share commitments and the BTC network to the enclave.
/// To be called by the operator.
#[derive(Serialize, Deserialize, Debug)]
pub struct OperatorInitRequest {
    config: S3Config,
    share_commitments: Vec<ShareCommitment>,
    network: Network,
}

/// Provides key shares and all other necessary state values to the enclaves.
/// To be called by Key Provisioners (who may be outside entities).
#[derive(Serialize, Deserialize, Debug)]
pub struct ProvisionerInitRequest {
    encrypted_share: EncryptedShare,
    state: ProvisionerInitRequestState,
}

/// Note: Serialize & Deserialize traits are needed here to compute digest
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionerInitRequestState {
    /// Hashi BLS keys used to sign cert's
    pub hashi_committee_info: HashiCommitteeInfo,
    /// Withdrawal config
    pub withdrawal_config: WithdrawalConfig,
    /// Withdrawal state
    pub withdrawal_state: WithdrawalState,
    /// Hashi BTC master key used to derive child keys for diff inputs
    pub hashi_btc_master_pubkey: XOnlyPublicKey,
}

#[derive(Debug)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex
    pub attestation: Attestation,
}

// ---------------------------------
//          Log Messages
// ---------------------------------

/// All log messages emitted by the guardian enclave.
/// Uses enum discriminator for automatic domain separation between variants.
#[derive(Serialize, Deserialize, Debug)]
pub enum LogMessage {
    /// Attestation and signing public key
    OperatorInitAttestationUnsigned {
        attestation: Attestation,
        signing_public_key: VerificationKey,
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
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

pub type Attestation = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
}

/// Hashi public keys used to sign messages sent to guardian
// TODO: Add pub keys, threshold. Align types with hashi.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct HashiCommitteeInfo {}

// TODO: Align types with hashi
/// All the withdrawal config
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawalConfig {
    /// The min delay after which any withdrawal is approved
    pub delayed_withdrawals_min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub delayed_withdrawals_timeout: Duration,
}

/// Withdrawal state - all that is needed to restart the enclave
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
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

impl<T> HashiNodeSigned<T> {
    pub fn verify_cert(self, _committee: &HashiCommitteeInfo) -> GuardianResult<T> {
        // TODO: Validate sig with committee
        Ok(self.data)
    }
}

impl SetupNewKeyRequest {
    /// Serialize and return a SetupNewKeyRequest
    pub fn new(public_keys: Vec<EncPubKey>) -> GuardianResult<Self> {
        if public_keys.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("provide enough public keys".into()));
        }
        Ok(Self {
            key_provisioner_public_keys: public_keys,
        })
    }

    /// Deserialize and return public keys
    pub fn public_keys(&self) -> &[EncPubKey] {
        &self.key_provisioner_public_keys
    }

    /// Generates mock key provisioner keys and SetupNewKeyRequest for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mock_for_testing() -> (Self, Vec<EncSecKey>) {
        use hpke::kem::X25519HkdfSha256;
        use hpke::Kem;

        let mut private_keys = vec![];
        let mut public_keys = vec![];
        for _i in 0..NUM_OF_SHARES {
            let mut rng = rand::thread_rng();
            let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
            private_keys.push(sk);
            public_keys.push(pk);
        }

        (SetupNewKeyRequest::new(public_keys).unwrap(), private_keys)
    }
}

impl OperatorInitRequest {
    pub fn new(
        config: S3Config,
        share_commitments: Vec<ShareCommitment>,
        network: Network,
    ) -> GuardianResult<Self> {
        if share_commitments.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("provide enough share commitments".into()));
        }
        Ok(Self {
            config,
            share_commitments,
            network,
        })
    }

    pub fn validate(&self) -> GuardianResult<()> {
        if self.share_commitments.len() != NUM_OF_SHARES {
            return Err(InvalidInputs("provide enough share commitments".into()));
        }
        Ok(())
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    pub fn share_commitments(&self) -> &[ShareCommitment] {
        &self.share_commitments
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

impl ProvisionerInitRequestState {
    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(self).expect("Failed to serialize");
        Blake2b::<U32>::digest(bytes).into()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn mock_for_testing() -> Self {
        use bitcoin_utils::test_utils::create_keypair;
        use bitcoin_utils::test_utils::TEST_HASHI_SK;

        let kp = create_keypair(&TEST_HASHI_SK);
        ProvisionerInitRequestState {
            withdrawal_config: WithdrawalConfig {
                delayed_withdrawals_min_delay: Duration::from_secs(10),
                delayed_withdrawals_timeout: Duration::from_secs(60),
            },
            withdrawal_state: WithdrawalState::default(),
            hashi_committee_info: HashiCommitteeInfo::default(),
            hashi_btc_master_pubkey: kp.x_only_public_key().0,
        }
    }
}

impl ProvisionerInitRequest {
    /// Create a new ProvisionerInitRequest by encrypting the share to the enclave's public key.
    /// In addition, it sets the state hash as AAD for the encryption effectively
    /// allowing the enclave to trust that state is indeed coming from the KP.
    pub fn new<R: CryptoRng + RngCore>(
        share: &Share,
        enclave_pub_key: &EncPubKey,
        state: ProvisionerInitRequestState,
        rng: &mut R,
    ) -> GuardianResult<Self> {
        let state_hash = state.digest();
        let encrypted_share = encrypt_share(share, enclave_pub_key, Some(&state_hash), rng)?;
        Ok(ProvisionerInitRequest {
            encrypted_share,
            state,
        })
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
