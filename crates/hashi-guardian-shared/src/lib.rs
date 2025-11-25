pub mod bitcoin_utils;
pub mod crypto;
mod errors;
pub mod test_utils;

pub use crypto::*;
pub use errors::GuardianError;
pub use errors::GuardianResult;
use std::collections::HashMap;

use crate::bitcoin_utils::TaprootUTXO;
use crate::GuardianError::GenericError;
use bitcoin::address::NetworkUnchecked;
use bitcoin::taproot::Signature;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::TxOut;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;

use hpke::Deserializable;
use hpke::HpkeError;
use hpke::Serializable;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::SystemTime;

pub type WithdrawID = String; // TODO: Placeholder
pub type DigestBytes = [u8; 32];

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
    /// Bitcoin change address for withdrawals
    pub change_address: String,
    /// Cached serialized bytes
    #[serde(skip)]
    pub cached_bytes: std::sync::OnceLock<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex
    pub attestation: String,
}

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

/// A "delayed withdraw" request
#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWithdrawRequest {
    /// Withdrawal details
    pub info: DelayedWithdrawInfo,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

/// An "instantaneous withdraw" request
#[derive(Serialize, Deserialize, Debug)]
pub struct InstantWithdrawRequest {
    /// Withdrawal details
    pub info: FullWithdrawInfo,
    /// Is it a delayed withdrawal?
    pub delayed: bool,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InstantWithdrawResponse {
    pub enclave_sign: Vec<Signature>,
}

// ---------------------------------
//          Helper structs
// ---------------------------------

/// Full withdraw details
/// input utxo's and fee are None for Delayed and Some for Instant
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullWithdrawInfo {
    /// Unique withdraw ID assigned by Hashi
    pub withdraw_id: WithdrawID,
    /// External addresses and corresponding amounts
    pub external_dest: Vec<WithdrawOutput>,
    /// Hashi-assigned timestamp
    pub timestamp: SystemTime,
    /// The input UTXOs owned by hashi + guardian
    pub input_utxos: Vec<TaprootUTXO>,
    /// Transaction fee in Satoshi's
    pub fee_sats: u64,
}

/// Partial withdraw details used for delayed withdrawals
/// input utxo's and fee are None for Delayed and Some for Instant
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelayedWithdrawInfo {
    /// Unique withdraw ID assigned by Hashi
    pub withdraw_id: WithdrawID,
    /// External addresses and corresponding amounts
    pub external_dest: Vec<WithdrawOutput>,
    /// Hashi-assigned timestamp
    pub timestamp: SystemTime,
}

/// Transaction output for withdrawal (external parties only)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WithdrawOutput {
    /// Bitcoin address to withdraw to (external party)
    pub address: Address<NetworkUnchecked>,
    /// Amount in Satoshi's
    pub amount: Amount,
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
    pub digest: DigestBytes,
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
// TODO: Add pub keys, threshold.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct HashiCommittee {}

/// All the rate limiting config's
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawConfig {
    /// The min delay after which any withdrawal is approved
    pub min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub max_delay: Duration,
}

/// Withdrawal info, e.g., in-flight ones, amount withdrawn in the current slot, etc.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WithdrawalState {
    /// Total number of withdrawals processed till now
    pub counter: u64,
    /// Pending delayed withdrawals. We do three types of operations with it:
    /// 1. Insertion (when "delayed_withdraw()" is called)
    /// 2. Lookup (when "instant_withdraw()" is called later)
    /// 3. Prune old records (TODO: To be implemented).
    pub pending_delayed_withdrawals: HashMap<WithdrawID, DelayedWithdrawInfo>,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl From<(EncapsulatedKey, Vec<u8>)> for Ciphertext {
    fn from((encapsulated_key, aes_ciphertext): (EncapsulatedKey, Vec<u8>)) -> Self {
        Ciphertext {
            encapsulated_key: encapsulated_key.to_bytes().to_vec(),
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

    pub fn digest(&self) -> &DigestBytes {
        &self.digest
    }
}

impl From<(ShareID, DigestBytes)> for ShareCommitment {
    fn from((id, digest): (ShareID, DigestBytes)) -> ShareCommitment {
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
            change_address: self.change_address.clone(),
            cached_bytes: std::sync::OnceLock::new(),
        }
    }
}

impl InitExternalRequestState {
    pub fn digest(&self) -> DigestBytes {
        Blake2b::<U32>::digest(self).into()
    }
}

impl InitExternalRequest {
    /// Create a new InitExternalRequest by encrypting the share with the enclave's public key
    pub fn new(
        share: &MyShare,
        enclave_pub_key: &EncPubKey,
        state: InitExternalRequestState,
    ) -> Result<Self, GuardianError> {
        let state_hash = state.digest();
        let encrypted_share = encrypt_share(share, enclave_pub_key, Some(&state_hash))?;
        Ok(InitExternalRequest {
            encrypted_share,
            state,
        })
    }
}

impl FullWithdrawInfo {
    /// The total amount of money being withdrawn
    pub fn withdraw_amount(&self) -> Amount {
        self.external_dest.iter().map(|utxo| utxo.amount).sum()
    }

    pub fn change_amount(&self) -> GuardianResult<Amount> {
        let input_sum: Amount = self.input_utxos.iter().map(|utxo| utxo.amount).sum();
        let output_sum: Amount = self.withdraw_amount();
        if input_sum < output_sum {
            return Err(GenericError(
                "Input sum is smaller than output sum.".to_string(),
            ));
        }
        // TODO: Also add an error for input_sum - output_sum < threshold?
        Ok(input_sum - output_sum)
    }
}

impl WithdrawOutput {
    /// Validates the address against the expected network and returns a checked Address
    pub fn validate_address(&self, expected_network: Network) -> GuardianResult<Address> {
        self.address
            .clone()
            .require_network(expected_network)
            .map_err(|e| GenericError(format!("Invalid address network: {:?}", e)))
    }
}

impl From<&WithdrawOutput> for TxOut {
    /// Converts to TxOut, assuming the address has already been validated
    /// Use validate_address() first to ensure the address is for the correct network
    fn from(output: &WithdrawOutput) -> Self {
        TxOut {
            value: output.amount,
            script_pubkey: output.address.clone().assume_checked().script_pubkey(),
        }
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
