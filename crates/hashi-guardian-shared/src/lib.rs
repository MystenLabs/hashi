pub mod bitcoin_utils;
pub mod crypto;
pub mod errors;

pub use crypto::*;
pub use errors::*;
use std::collections::HashMap;

use crate::bitcoin_utils::{OutputUTXO, TxUTXOs};
use crate::GuardianError::*;
use bitcoin::taproot::Signature as BitcoinSignature;
use bitcoin::*;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
use ed25519_consensus::Signature as GuardianSignature;
use ed25519_consensus::VerificationKey;
use hpke::Deserializable;
use hpke::Serializable;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::time::{Duration, SystemTime};

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
    /// Intent for ImmediateWithdrawalResponse
    ImmediateWithdrawalResponse = 2,
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
/// TODO: Add cert, intent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashiSigned<T> {
    pub data: T,
}

// ---------------------------------
//    All requests and responses
// ---------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupNewKeyRequest {
    key_provisioner_public_keys: Vec<Vec<u8>>,
}

/// EnclaveSigned<T>
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

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex
    pub attestation: Attestation,
}

/// An "immediate withdrawal" request. HashiSigned<T>.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImmediateWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// Hashi-assigned timestamp
    timestamp_secs: HashiTime,
    /// BTC transaction input and output utxos
    all_utxos: TxUTXOs,
    /// Was delayed_withdraw previously called for this withdrawal?
    is_delayed: bool,
}

/// EnclaveSigned<T>
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImmediateWithdrawalResponse {
    pub enclave_signatures: Vec<BitcoinSignature>,
}

/// A "delayed withdrawal" request. HashiSigned<T>.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelayedWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// Hashi-assigned timestamp
    timestamp_secs: HashiTime,
    /// External output utxos
    external_output_utxos: Vec<OutputUTXO>,
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
    /// Delayed withdraw
    DelayedWithdrawal(DelayedWithdrawalRequest),
    /// Immediate withdraw
    ImmediateWithdrawal {
        request: ImmediateWithdrawalRequest,
        response: ImmediateWithdrawalResponse,
        withdraw_count: u64,
    },
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
// TODO: Add pub keys, threshold.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct HashiCommitteeInfo {}

// TODO: Align types with hashi
pub type WithdrawalID = u64;
pub type HashiTime = u64;

/// All the withdrawal config
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawalConfig {
    /// The min delay after which any withdrawal is approved
    pub min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub max_delay: Duration,
}

/// Withdrawal state - all that is needed to restart the enclave
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WithdrawalState {
    /// Total number of withdrawals processed till now
    pub num_withdrawals: u64,
    /// Pending delayed withdrawals
    /// TODO: implement pruning
    pub pending_delayed_withdrawals: HashMap<WithdrawalID, DelayedWithdrawalRequest>,
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

impl SigningIntent for ImmediateWithdrawalResponse {
    const INTENT: IntentType = IntentType::ImmediateWithdrawalResponse;
}

impl<T> HashiSigned<T> {
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
            key_provisioner_public_keys: public_keys
                .into_iter()
                .map(|pk| pk.to_bytes().to_vec())
                .collect(),
        })
    }

    /// Deserialize and return public keys
    pub fn public_keys(&self) -> GuardianResult<Vec<EncPubKey>> {
        self.key_provisioner_public_keys
            .iter()
            .map(|bytes| EncPubKey::from_bytes(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| InvalidInputs(format!("Failed to deserialize public key: {}", e)))
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

    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        self.withdrawal_state.validate(network)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn mock_for_testing() -> Self {
        use bitcoin_utils::test_utils::create_keypair;
        use bitcoin_utils::test_utils::TEST_HASHI_SK;

        let kp = create_keypair(&TEST_HASHI_SK);
        ProvisionerInitRequestState {
            withdrawal_config: WithdrawalConfig {
                min_delay: Duration::from_secs(10),
                max_delay: Duration::from_secs(60),
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

impl DelayedWithdrawalRequest {
    pub fn new(
        wid: WithdrawalID,
        timestamp_secs: HashiTime,
        external_output_utxos: Vec<OutputUTXO>,
    ) -> GuardianResult<Self> {
        if external_output_utxos.is_empty() {
            return Err(InvalidInputs("output utxo list is empty".into()));
        }
        // TODO: Check that all OutputUTXO's are External?
        Ok(Self {
            wid,
            timestamp_secs,
            external_output_utxos,
        })
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    pub fn timestamp(&self) -> HashiTime {
        self.timestamp_secs
    }

    pub fn external_outs(&self) -> &[OutputUTXO] {
        &self.external_output_utxos
    }

    /// Validate the request is valid for the given network.
    /// Called from two places: `delayed_withdraw()` & `provisioner_init()`.
    /// `fresh_withdrawal` is true for calls from `delayed_withdraw()` and false for `provisioner_init()`.
    pub fn validate(&self, network: Network, fresh_withdrawal: bool) -> GuardianResult<()> {
        if fresh_withdrawal {
            // verify timestamp is latest for a delayed_withdraw(); skip for provisioner_init
            validate_time(self.timestamp_secs)?;
        }
        // TODO: if max_delay is pre-configured, we could do some validation for provisioner_init() too
        self.external_output_utxos
            .iter()
            .try_for_each(|utxo| utxo.validate(network))
    }
}

impl ImmediateWithdrawalRequest {
    pub fn new(
        wid: WithdrawalID,
        timestamp_secs: HashiTime,
        tx_utxos: TxUTXOs,
        is_delayed: bool,
    ) -> Self {
        Self {
            wid,
            timestamp_secs,
            all_utxos: tx_utxos,
            is_delayed,
        }
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    pub fn is_delayed(&self) -> bool {
        self.is_delayed
    }

    pub fn all_utxos(&self) -> &TxUTXOs {
        &self.all_utxos
    }

    pub fn timestamp(&self) -> HashiTime {
        self.timestamp_secs
    }

    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        validate_time(self.timestamp_secs)?;
        self.all_utxos.validate(network)
    }
}

fn validate_time(_request_time: HashiTime) -> GuardianResult<()> {
    todo!("impl after understanding what hashi time is")
}

impl WithdrawalState {
    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        self.pending_delayed_withdrawals
            .values()
            .into_iter()
            .try_for_each(|request| request.validate(network, false))
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
