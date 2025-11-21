pub mod crypto;
mod errors;
pub mod test_utils;

pub use crypto::{
    EncKeyPair, EncPubKey, EncSecKey, EncapsulatedKey, K256ShareBase, MyShare, ShareID, ShareValue,
    LIMIT, THRESHOLD,
};
pub use errors::{GuardianError, GuardianResult};

use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use hpke::{Deserializable, HpkeError, Serializable};
use serde::Deserialize;
use serde::Serialize;
use std::time::{Duration, SystemTime};

// ---------------------------------
//      Types and Constants
// ---------------------------------

pub type WithdrawID = String; // TODO: Placeholder

// ---------------------------------
//    All requests and responses
// ---------------------------------

#[derive(Serialize, Deserialize)]
pub struct SetupNewKeyRequest {
    pub key_provisioner_public_keys: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct SetupNewKeyResponse {
    pub encrypted_shares: Vec<EncryptedShare>,
    pub share_commitments: Vec<ShareCommitment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitInternalRequest {
    pub config: S3Config,
    pub share_commitments: Vec<ShareCommitment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitExternalRequest {
    pub encrypted_share: EncryptedShare,
    pub state: InitExternalRequestState,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitExternalRequestState {
    /// Hashi info, e.g., btc pk, bls pk's, etc.
    pub hashi_committee_info: HashiCommittee,
    /// Rate limiter for withdrawals
    pub withdraw_config: WithdrawConfig,
    /// Enclave state
    pub withdraw_state: WithdrawalState,
    /// Cached serialized bytes
    #[serde(skip)]
    pub cached_bytes: std::sync::OnceLock<Vec<u8>>,
}

/// Response for get attestation
#[derive(Serialize, Deserialize, Debug)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex
    pub attestation: String,
}

/// Response for health check
#[derive(Serialize, Deserialize, Debug)]
pub struct HealthCheckResponse {
    /// S3 is configured
    pub s3_configured: bool,
    /// Bitcoin key is set (enclave initialized)
    pub btc_key_configured: bool,
    /// Number of shares received so far
    pub shares_received: usize,
    /// Enclave encryption public key (for non-enclave environments)
    pub enc_public_key: Option<Vec<u8>>,
}

/// A "Delayed Withdraw" request
#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWithdrawRequest {
    /// Details of the withdrawal
    pub info: WithdrawInfo,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

/// An (instantaneous) withdraw request
#[derive(Serialize, Deserialize, Debug)]
pub struct InstantWithdrawRequest {
    /// Details of the withdrawal
    pub info: WithdrawInfo,
    /// Is the request trying to spend a delayed withdrawal
    pub delayed: bool,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WithdrawInfo {
    /// Unique withdraw ID assigned by Hashi
    pub withdraw_id: WithdrawID,
    /// External addresses and corresponding amounts
    pub external_dest: Vec<WithdrawOutput>,
    /// Hashi-assigned timestamp
    pub timestamp: SystemTime,
    /// Transaction fee in Satoshi's
    pub fee_sats: u64,
}

// ---------------------------------
//          Helper structs
// ---------------------------------

/// Transaction output for withdrawal (external parties only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawOutput {
    /// Bitcoin address to withdraw to (external party)
    pub address: String,
    /// Amount in Satoshi's
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HashiCert {} // TODO: Placeholder

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitment {
    pub id: ShareID,
    pub digest: Digest<32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ciphertext {
    pub encapsulated_key: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
}

/// Hashi keys used to sign messages to Guardian (BLS?).
// TODO: Placeholder. Add pub keys, threshold.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct HashiCommittee {}

/// All the rate limiting config's
// TODO: Add rate limiting stuff
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawConfig {
    /// The min delay after which any withdrawal is approved
    pub min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub max_delay: Duration,
}

/// Withdrawal info, e.g., in-flight ones, amount withdrawn in the current slot, etc.
// TODO: Add stuff
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WithdrawalState {
    /// Total number of withdrawals processed till now
    pub counter: u64,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl From<(EncapsulatedKey, Vec<u8>)> for Ciphertext {
    fn from((encapped_key, aes_ciphertext): (EncapsulatedKey, Vec<u8>)) -> Self {
        Ciphertext {
            encapsulated_key: encapped_key.to_bytes().to_vec(),
            aes_ciphertext,
        }
    }
}

impl<'a> TryFrom<&'a Ciphertext> for (EncapsulatedKey, &'a [u8]) {
    type Error = HpkeError;
    fn try_from(value: &'a Ciphertext) -> Result<Self, Self::Error> {
        Ok((
            EncapsulatedKey::from_bytes(&value.encapsulated_key)?,
            &value.aes_ciphertext,
        ))
    }
}

impl ShareCommitment {
    pub fn id(&self) -> &ShareID {
        &self.id
    }

    pub fn digest(&self) -> &Digest<32> {
        &self.digest
    }
}

impl From<(ShareID, Digest<32>)> for ShareCommitment {
    fn from((id, digest): (ShareID, Digest<32>)) -> ShareCommitment {
        ShareCommitment { id, digest }
    }
}

impl EncryptedShare {
    pub fn id(&self) -> &ShareID {
        &self.id
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }
}

impl From<(ShareID, Ciphertext)> for EncryptedShare {
    fn from((id, ciphertext): (ShareID, Ciphertext)) -> EncryptedShare {
        EncryptedShare { id, ciphertext }
    }
}

impl AsRef<[u8]> for InitExternalRequestState {
    fn as_ref(&self) -> &[u8] {
        self.cached_bytes.get_or_init(|| {
            bincode::serialize(self).expect("Failed to serialize InitExternalRequestState")
        })
    }
}

impl Clone for InitExternalRequestState {
    fn clone(&self) -> Self {
        InitExternalRequestState {
            hashi_committee_info: self.hashi_committee_info.clone(),
            withdraw_config: self.withdraw_config.clone(),
            withdraw_state: self.withdraw_state.clone(),
            cached_bytes: std::sync::OnceLock::new(),
        }
    }
}

impl InitExternalRequestState {
    pub fn digest(&self) -> Digest<32> {
        Blake2b256::digest(&self)
    }
}

impl InitExternalRequest {
    /// Create a new InitExternalRequest by encrypting the share with the enclave's public key
    pub fn new(
        share: &crypto::MyShare,
        enclave_pub_key: &EncPubKey,
        state: InitExternalRequestState,
    ) -> Result<Self, crate::errors::GuardianError> {
        let state_hash = state.digest().digest;
        let encrypted_share = crypto::encrypt_share(share, enclave_pub_key, Some(&state_hash))?;
        Ok(InitExternalRequest {
            encrypted_share,
            state,
        })
    }
}

// ---------------------------------
//    Tracing utilities
// ---------------------------------

/// Initialize tracing subscriber with optional file/line number logging
pub fn init_tracing_subscriber(with_file_line: bool) {
    let mut builder = ::tracing_subscriber::FmtSubscriber::builder().with_env_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
            .from_env_lossy(),
    );

    if with_file_line {
        builder = builder.with_file(true).with_line_number(true);
    }

    let subscriber = builder.finish();
    ::tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}
