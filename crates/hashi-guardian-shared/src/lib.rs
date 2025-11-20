use fastcrypto::hash::Digest;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, HpkeError, Kem, Serializable};
use p256::Scalar;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use vsss_rs::{DefaultShare, IdentifierPrimeField};

pub type EncSecKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type EncPubKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub struct EncKeyPair {
    sk: EncSecKey,
    pk: EncPubKey,
}
pub type EncapsulatedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

pub type P256ShareBase = IdentifierPrimeField<Scalar>;
pub type ShareID = P256ShareBase;
pub type ShareValue = P256ShareBase;
pub type MyShare = DefaultShare<ShareID, ShareValue>;

// The threshold and number of key provisioner's
pub const SECRET_SHARING_T: u16 = 3;
pub const SECRET_SHARING_N: u16 = 5;

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

// ---------------------------------
//          Helper structs
// ---------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

/// All the relevant info related to hashi.
/// Note: BTC pub key is currently stored as a const
// TODO: Add sui committee, threshold
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

impl From<Vec<EncPubKey>> for SetupNewKeyRequest {
    fn from(keys: Vec<EncPubKey>) -> Self {
        SetupNewKeyRequest {
            key_provisioner_public_keys: keys.iter().map(|k| k.to_bytes().to_vec()).collect(),
        }
    }
}

impl TryFrom<SetupNewKeyRequest> for Vec<EncPubKey> {
    type Error = HpkeError;
    fn try_from(value: SetupNewKeyRequest) -> Result<Self, Self::Error> {
        value
            .key_provisioner_public_keys
            .into_iter()
            .map(|k| EncPubKey::from_bytes(&k))
            .collect()
    }
}

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

impl EncKeyPair {
    pub fn secret(&self) -> &EncSecKey {
        &self.sk
    }
    pub fn public(&self) -> &EncPubKey {
        &self.pk
    }
}

impl From<(EncSecKey, EncPubKey)> for EncKeyPair {
    fn from((enc_sk, enc_pk): (EncSecKey, EncPubKey)) -> Self {
        EncKeyPair {
            sk: enc_sk,
            pk: enc_pk,
        }
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
