pub mod bitcoin_utils;
pub mod crypto;
pub mod errors;

pub mod test_utils;

pub use crypto::*;
pub use errors::*;

use crate::bitcoin_utils::TaprootUTXO;
use crate::GuardianError::*;
use bitcoin::address::NetworkUnchecked;
use bitcoin::taproot::Signature;
use bitcoin::*;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
use std::collections::HashMap;
use std::num::NonZeroU32;

use hpke::{Deserializable, Kem, Serializable};
use rand_core::{CryptoRng, RngCore};
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::SystemTime;
use hpke::kem::X25519HkdfSha256;
use crate::test_utils::DUMMY_REGTEST_ADDRESS;
// ---------------------------------
//    All requests and responses
// ---------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupNewKeyRequest {
    key_provisioner_public_keys: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupNewKeyResponse {
    pub encrypted_shares: Vec<EncryptedShare>,
    pub share_commitments: Vec<ShareCommitment>,
}

/// Provides S3 API keys and share commitments to the enclave.
/// Returns an error if something goes wrong.
/// To be called by the operator.
#[derive(Serialize, Deserialize, Debug)]
pub struct OperatorInitRequest {
    config: S3Config,
    share_commitments: Vec<ShareCommitment>,
    network: Network
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
    /// Fixed change address for all withdrawals
    pub change_address: Address<NetworkUnchecked>,
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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnclaveInfoResponse {
    /// Enclave encryption public key
    pub enc_public_key: Vec<u8>,
    /// Enclave signing verification key (for validating signatures)
    pub signing_verification_key: Vec<u8>,
    /// Share commitments
    pub share_commitments: Option<Vec<ShareCommitment>>,
}

/// A "delayed withdrawal" request
#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWithdrawalRequest {
    /// Withdrawal details
    pub info: DelayedWithdrawalInfo,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

/// An "immediate withdrawal" request
#[derive(Serialize, Deserialize, Debug)]
pub struct ImmediateWithdrawalRequest {
    /// Withdrawal details
    pub info: ImmediateWithdrawalInfo,
    /// Is it spending a delayed withdrawal?
    pub delayed: bool,
    /// Hashi cert over the request
    pub cert: HashiCert,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImmediateWithdrawalResponse {
    pub enclave_sign: Vec<Signature>,
}

/// Wrapper struct containing the response and signature
#[derive(Serialize, Deserialize, Debug)]
pub struct Signed<T> {
    pub response: T,
    pub timestamp: SystemTime,
    pub signature: String,
}

// ---------------------------------
//          Helper structs
// ---------------------------------

pub type WithdrawalID = String; // TODO: Placeholder

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImmediateWithdrawalInfo {
    /// Unique withdrawal ID assigned by Hashi
    withdrawal_id: WithdrawalID,
    /// External addresses and corresponding amounts
    external_dest: Vec<WithdrawalOutput>,
    /// Hashi-assigned timestamp
    timestamp: SystemTime,
    /// The input UTXOs owned by hashi + guardian
    input_utxos: Vec<TaprootUTXO>,
    /// Transaction fee in Satoshi's
    fee_sats: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DelayedWithdrawalInfo {
    /// Unique withdrawal ID assigned by Hashi
    withdrawal_id: WithdrawalID,
    /// External addresses and corresponding amounts
    external_dest: Vec<WithdrawalOutput>,
    /// Hashi-assigned timestamp
    timestamp: SystemTime,
}

/// Transaction output for withdrawal (external parties only)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WithdrawalOutput {
    /// Bitcoin address to withdraw to (external party)
    pub address: Address<NetworkUnchecked>,
    /// Amount in Satoshi's
    pub amount: Amount,
}

#[derive(Debug, Clone)]
pub struct ValidatedWithdrawalOutput {
    pub address: Address, // checked
    pub amount: Amount,
}

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

// TODO: Add sigs
#[derive(Serialize, Deserialize, Debug)]
pub struct HashiCert {}

/// All the rate limiting config's
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawalConfig {
    /// The hourly rate limit (TODO: Align types with rate limiting impl in hashi)
    pub hourly_rate_limit: NonZeroU32,
    /// The min delay after which any withdrawal is approved
    pub min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub max_delay: Duration,
}

/// Withdrawal related state containing all that is needed to restart the enclave.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WithdrawalState {
    /// Total number of withdrawals processed till now
    pub counter: u64,
    /// Pending delayed withdrawals. We do three types of operations with it:
    /// 1. Insertion (when "delayed_withdraw()" is called)
    /// 2. Lookup (when "immediate_withdraw()" is called later)
    /// 3. Prune old records (once in a while)
    pub pending_delayed_withdrawals: HashMap<WithdrawalID, DelayedWithdrawalInfo>,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

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
    pub fn mock_for_testing() -> (Self, Vec<EncSecKey>) {
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

    pub fn mock_for_testing() -> Self {
        ProvisionerInitRequestState {
            hashi_committee_info: HashiCommitteeInfo::default(),
            withdrawal_config: WithdrawalConfig {
                min_delay: Duration::from_secs(60),
                max_delay: Duration::from_secs(3600),
                // 0.1 BTC per hour
                hourly_rate_limit: NonZeroU32::new(10_000_000).unwrap(),
            },
            withdrawal_state: WithdrawalState::default(),
            change_address: DUMMY_REGTEST_ADDRESS.to_string().parse().unwrap(),
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
}

impl ImmediateWithdrawalInfo {
    pub fn new(
        withdrawal_id: WithdrawalID,
        external_dest: Vec<WithdrawalOutput>,
        timestamp: SystemTime,
        input_utxos: Vec<TaprootUTXO>,
        fee_sats: u64,
    ) -> GuardianResult<Self> {
        // Input Validation
        if input_utxos.is_empty() {
            return Err(InvalidInputs(
                "input utxos must not be empty for immediate withdrawal".into(),
            ));
        }
        if external_dest.is_empty() {
            return Err(InvalidInputs(
                "output utxos must not be empty for immediate withdrawal".into(),
            ));
        }
        let out = Self {
            withdrawal_id,
            external_dest,
            timestamp,
            input_utxos,
            fee_sats,
        };
        let _ = out.change_amount()?; // checks change amount is non negative
                                      // TODO: fee validation? withdrawal ID validation?
        Ok(out)
    }

    pub fn withdrawal_id(&self) -> &WithdrawalID {
        &self.withdrawal_id
    }

    pub fn external_dest(&self) -> &[WithdrawalOutput] {
        &self.external_dest
    }

    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    pub fn input_utxos(&self) -> &[TaprootUTXO] {
        &self.input_utxos
    }

    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// The total amount of money available in the input UTXO's
    pub fn in_amount(&self) -> Amount {
        self.input_utxos.iter().map(|utxo| utxo.amount()).sum()
    }

    /// The total amount of money being spent
    pub fn out_amount(&self) -> Amount {
        self.external_dest.iter().map(|utxo| utxo.amount).sum()
    }

    pub fn change_amount(&self) -> GuardianResult<Amount> {
        let input_sum = self.in_amount();
        let output_sum = self.out_amount() + Amount::from_sat(self.fee_sats);
        if input_sum < output_sum {
            return Err(InvalidInputs("Input sum is smaller than output sum".into()));
        }
        Ok(input_sum - output_sum)
    }
}

impl DelayedWithdrawalInfo {
    pub fn new(
        withdrawal_id: WithdrawalID,
        external_dest: Vec<WithdrawalOutput>,
        timestamp: SystemTime,
    ) -> GuardianResult<Self> {
        if external_dest.is_empty() {
            return Err(InvalidInputs(
                "output utxo must not be empty for delayed withdrawal".into(),
            ));
        }
        Ok(Self {
            withdrawal_id,
            external_dest,
            timestamp,
        })
    }

    pub fn withdrawal_id(&self) -> &WithdrawalID {
        &self.withdrawal_id
    }

    pub fn external_dest(&self) -> &[WithdrawalOutput] {
        &self.external_dest
    }

    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
}

impl WithdrawalOutput {
    /// Validates the address against the expected network and returns a checked Address
    pub fn validate(&self, network: Network) -> GuardianResult<ValidatedWithdrawalOutput> {
        let address = self
            .address
            .clone()
            .require_network(network)
            .map_err(|e| InternalError(format!("Invalid address network: {:?}", e)))?;
        Ok(ValidatedWithdrawalOutput {
            address,
            amount: self.amount,
        })
    }
}

impl From<&ValidatedWithdrawalOutput> for TxOut {
    fn from(output: &ValidatedWithdrawalOutput) -> Self {
        TxOut {
            value: output.amount,
            script_pubkey: output.address.clone().script_pubkey(),
        }
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
