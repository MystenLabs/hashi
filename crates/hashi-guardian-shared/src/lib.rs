use fastcrypto::hash::Digest;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, HpkeError, Kem, Serializable};
use k256::Scalar;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use vsss_rs::{DefaultShare, IdentifierPrimeField};

pub type EncSecKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type EncPubKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub struct EncKeyPair {
    sk: EncSecKey,
    pk: EncPubKey,
}
pub type EncapsulatedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

pub type K256ShareBase = IdentifierPrimeField<Scalar>;
pub type ShareID = K256ShareBase;
pub type ShareValue = K256ShareBase;
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

// ---------------------------------
//          Error types
// ---------------------------------

#[derive(Debug, PartialEq)]
pub enum GuardianError {
    GenericError(String),
    EnclaveAlreadyInitialized,
    Forbidden(String),
}

pub type GuardianResult<T> = Result<T, GuardianError>;

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::GenericError(e) => write!(f, "Error: {}", e),
            GuardianError::EnclaveAlreadyInitialized => write!(f, "Enclave is already initialized"),
            GuardianError::Forbidden(e) => write!(f, "Forbidden: {}", e),
        }
    }
}

impl std::error::Error for GuardianError {}


/// Implement IntoResponse for EnclaveError.
impl IntoResponse for GuardianError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            GuardianError::GenericError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            GuardianError::EnclaveAlreadyInitialized => (
                StatusCode::BAD_REQUEST,
                "Enclave is already initialized!".into(),
            ),
            GuardianError::Forbidden(e) => (StatusCode::FORBIDDEN, e),
        };
        error!("Status: {}, Message: {}", status, error_message);
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}


// ---------------------------------
//    Encryption/Decryption utils
// ---------------------------------

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use serde_json::json;
use tracing::error;

pub fn encrypt(bytes: &[u8], pk: &EncPubKey, aad: Option<&[u8; 32]>) -> GuardianResult<Ciphertext> {
    let mut rng = rand::thread_rng();
    let (encapsulated_key, aes_ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            &pk,
            &[],
            &bytes,
            aad.or(Option::Some(&[0; 32])).expect("REASON"),
            &mut rng,
        )
        .map_err(|e| GuardianError::GenericError(format!("Failed to encrypt: {}", e)))?;

    Ok((encapsulated_key, aes_ciphertext).into())
}

pub fn decrypt(
    ciphertext: &Ciphertext,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Vec<u8>> {
    let (encapsulated_key, aes_ciphertext) = ciphertext
        .try_into()
        .map_err(|e: HpkeError| GuardianError::GenericError(format!("Failed to deserialize ciphertext: {}", e)))?;

    let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        sk,
        &encapsulated_key,
        &[],
        &aes_ciphertext,
        aad.or(Option::Some(&[0; 32])).expect("REASON"),
    )
    .map_err(|e| GuardianError::GenericError(format!("Failed to decrypt: {}", e)))?;

    Ok(decrypted)
}
