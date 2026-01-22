pub mod bitcoin_utils;
pub mod crypto;
pub mod epoch_store;
pub mod errors;
pub mod proto_conversions;
pub mod s3_logger;
pub mod test_utils;

use crate::bitcoin_utils::InputUTXO;
use crate::bitcoin_utils::OutputUTXO;
use crate::bitcoin_utils::TxUTXOs;
use crate::bitcoin_utils::TxUTXOsWire;
use crate::epoch_store::ConsecutiveEpochStore;
use crate::epoch_store::ConsecutiveEpochStoreRepr;
use crate::epoch_store::EpochWindow;
use crate::GuardianError::*;
pub use bitcoin::secp256k1::Keypair as BitcoinKeypair;
pub use bitcoin::secp256k1::XOnlyPublicKey as BitcoinPubkey;
pub use bitcoin::taproot::Signature as BitcoinSignature;
pub use bitcoin::Address as BitcoinAddress;
use bitcoin::*;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
pub use crypto::*;
pub use ed25519_consensus::Signature as GuardianSignature;
pub use ed25519_consensus::SigningKey as GuardianSignKeyPair;
pub use ed25519_consensus::VerificationKey as GuardianPubKey;
pub use errors::*;
pub use hashi_types::committee::Committee as HashiCommittee;
pub use hashi_types::committee::CommitteeMember as HashiCommitteeMember;
use hashi_types::committee::CommitteeSignature;
pub use hashi_types::committee::SignedMessage as HashiSigned;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
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
    /// Intent for StandardWithdrawalResponse
    StandardWithdrawalResponse = 2,
    /// Intent for GuardianInfo
    GuardianInfo = 3,
}

/// Trait for types that can be signed, providing domain separation via an intent.
pub trait SigningIntent {
    const INTENT: IntentType;
}

// ---------------------------------
//          Time
// ---------------------------------

/// Milliseconds since Unix epoch.
/// Panics if the system clock is before `UNIX_EPOCH`.
pub fn now_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system_time cannot be before Unix epoch")
        .as_millis() as u64
}

// ---------------------------------
//          Envelopes
// ---------------------------------

/// Timestamped wrapper - adds timestamp to any data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Timestamped<T> {
    pub data: T,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

/// Guardian-signed wrapper - adds timestamp and signature to any data
/// TODO: Impl custom ser/deser for GuardianSignature as signatures are displayed as long bytes in S3 logs
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianSigned<T> {
    pub data: T,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: u64,
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
    state: ProvisionerInitState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerInitState {
    /// Hashi BLS keys used to sign cert's
    hashi_committees: CommitteeStore,
    /// Withdrawal config
    withdrawal_config: WithdrawalConfig,
    /// Withdrawal state
    withdrawal_state: WithdrawalState,
    /// Hashi BTC master key used to derive child keys for diff inputs
    hashi_btc_master_pubkey: BitcoinPubkey,
}

#[derive(Debug, PartialEq, Clone)]
pub struct GetGuardianInfoResponse {
    /// AWS Nitro attestation
    pub attestation: Attestation,
    /// Signing pub key of the guardian
    pub signing_pub_key: GuardianPubKey,
    /// Signed guardian info
    pub signed_info: GuardianSigned<GuardianInfo>,
}

/// TODO: Add network?
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    /// Share commitments (if set). Used by KPs to check that right key will be used.
    pub share_commitments: Option<Vec<ShareCommitment>>,
    /// S3 bucket name (if set). Used by KPs to check S3 bucket info.
    pub bucket_info: Option<S3BucketInfo>,
    /// Encryption key. Used by KPs to encrypt their shares.
    pub encryption_pubkey: EncPubKeyBytes,
    /// Server version
    /// TODO: Replace with hashi ServerVersion to include crate SHA and version
    pub server_version: String,
}

/// An "immediate withdrawal" request. `HashiSigned<T>.`
/// Note: Deserialize is not implemented because UTXOs contain validated addresses.
/// StandardWithdrawalRequestWire mocks this type with unverified addresses and Deserialize trait.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StandardWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// BTC transaction input and output utxos
    utxos: TxUTXOs,
}

/// `EnclaveSigned<T>`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardWithdrawalResponse {
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
        signing_public_key: GuardianPubKey,
    },
    /// Share commitments given in /operator_init
    GuardianInfo(GuardianInfo),
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
    /// Immediate withdraw success
    NormalWithdrawalSuccess {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        response: StandardWithdrawalResponse,
    },
    /// Immediate withdraw failure
    /// TODO: Any sensitivity concerns with logging the entire request permanently? (same for others)
    NormalWithdrawalFailure {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

/// Unique identifier for a withdrawal request
/// It is used to correlate events across sui & guardian. And to uniquely identify a delayed withdrawal.
pub type WithdrawalID = u64;

pub type Attestation = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket_info: S3BucketInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3BucketInfo {
    pub bucket: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WithdrawalConfig {
    /// Committee threshold expressed in terms of weight
    pub committee_threshold: u64,
    /// The min delay after which any withdrawal is approved
    pub delayed_withdrawals_min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub delayed_withdrawals_timeout: Duration,
}

/// Rate limiter state: Amount withdrawn in the last N epochs.
/// RateLimiterState and CommitteeStore have the same window & entries size. This is enforced in
/// ProvisionerInitState::new() and Enclave::register_new_epoch().
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateLimiter {
    state: ConsecutiveEpochStore<Amount>,
    max_withdrawable_per_epoch: Amount,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WithdrawalState {
    limiter: RateLimiter,
}

/// A store for last N committees. Needs to be initialized with at least one committee.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitteeStore(ConsecutiveEpochStore<HashiCommittee>);

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl SigningIntent for LogMessage {
    const INTENT: IntentType = IntentType::LogMessage;
}

impl SigningIntent for SetupNewKeyResponse {
    const INTENT: IntentType = IntentType::SetupNewKeyResponse;
}

impl SigningIntent for StandardWithdrawalResponse {
    const INTENT: IntentType = IntentType::StandardWithdrawalResponse;
}

impl SigningIntent for GuardianInfo {
    const INTENT: IntentType = IntentType::GuardianInfo;
}

impl S3Config {
    pub fn bucket_name(&self) -> &str {
        &self.bucket_info.bucket
    }

    pub fn region(&self) -> &str {
        &self.bucket_info.region
    }
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

    pub fn into_parts(self) -> (S3Config, Vec<ShareCommitment>, Network) {
        (self.s3_config, self.share_commitments, self.network)
    }
}

impl ProvisionerInitState {
    pub fn new(
        hashi_committees: CommitteeStore,
        withdrawal_config: WithdrawalConfig,
        withdrawal_state: WithdrawalState,
        hashi_btc_master_pubkey: BitcoinPubkey,
    ) -> GuardianResult<Self> {
        if hashi_committees.epoch_window() != withdrawal_state.limiter.epoch_window() {
            return Err(InvalidInputs("epoch window mismatch".into()));
        }
        if hashi_committees.num_entries() != withdrawal_state.limiter.num_entries() {
            return Err(InvalidInputs(
                "mismatch between number of committees and limiter size".into(),
            ));
        }

        Ok(Self {
            hashi_committees,
            withdrawal_config,
            withdrawal_state,
            hashi_btc_master_pubkey,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        CommitteeStore,
        WithdrawalConfig,
        WithdrawalState,
        BitcoinPubkey,
    ) {
        (
            self.hashi_committees,
            self.withdrawal_config,
            self.withdrawal_state,
            self.hashi_btc_master_pubkey,
        )
    }

    pub fn withdrawal_config(&self) -> &WithdrawalConfig {
        &self.withdrawal_config
    }

    pub fn hashi_btc_master_pubkey(&self) -> BitcoinPubkey {
        self.hashi_btc_master_pubkey
    }

    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(&ProvisionerInitStateRepr::from(self))
            .expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl ProvisionerInitRequest {
    pub fn new(encrypted_share: EncryptedShare, state: ProvisionerInitState) -> Self {
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
        state: ProvisionerInitState,
        rng: &mut R,
    ) -> Self {
        let state_hash = state.digest();
        let encrypted_share = encrypt_share(share, enclave_pub_key, Some(&state_hash), rng);
        ProvisionerInitRequest::new(encrypted_share, state)
    }

    pub fn encrypted_share(&self) -> &EncryptedShare {
        &self.encrypted_share
    }

    pub fn state(&self) -> &ProvisionerInitState {
        &self.state
    }

    pub fn into_state(self) -> ProvisionerInitState {
        self.state
    }
}

impl StandardWithdrawalRequest {
    pub fn new(wid: WithdrawalID, utxos: TxUTXOs) -> Self {
        Self { wid, utxos }
    }

    pub fn wid(&self) -> &WithdrawalID {
        &self.wid
    }

    pub fn utxos(&self) -> &TxUTXOs {
        &self.utxos
    }
}

impl WithdrawalState {
    pub fn new(limiter: RateLimiter) -> Self {
        Self { limiter }
    }

    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Consume amount units from the given epoch's rate limit
    pub fn consume_from_limiter(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.limiter.consume(epoch, amount)
    }

    /// Adds a new epoch and prunes an old epoch
    pub fn add_epoch_to_limiter(&mut self, epoch: u64) -> GuardianResult<()> {
        self.limiter.add_epoch(epoch)
    }

    /// Reverse of consume_from_limiter
    pub fn revert_limiter(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.limiter.revert(epoch, amount)
    }
}

impl RateLimiter {
    pub fn new(
        epoch_window: EpochWindow,
        amounts_withdrawn_per_epoch: Vec<Amount>,
        max_withdrawable_per_epoch: Amount,
    ) -> GuardianResult<Self> {
        // Note: instead of erring out, we could use zero as default
        if amounts_withdrawn_per_epoch.is_empty() {
            return Err(InvalidInputs("amounts empty".into()));
        }
        Ok(Self {
            state: ConsecutiveEpochStore::<Amount>::new(epoch_window, amounts_withdrawn_per_epoch)?,
            max_withdrawable_per_epoch,
        })
    }

    pub fn max_withdrawable_per_epoch(&self) -> Amount {
        self.max_withdrawable_per_epoch
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.state.epoch_window()
    }

    pub fn num_entries(&self) -> usize {
        self.state.num_entries()
    }

    /// Consume amount units from the given epoch's rate limit.
    /// Stored values are the amount withdrawn so far in that epoch.
    pub fn consume(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        let cur_sum = *self.state.get_checked(epoch)?;

        let new_sum = cur_sum
            .checked_add(amount)
            .ok_or(InvalidInputs("Overflow when computing sum".into()))?;

        if new_sum > self.max_withdrawable_per_epoch {
            return Err(InvalidInputs("Rate limit will exceed".into()));
        }

        *self.state.get_mut_checked(epoch)? = new_sum;
        Ok(())
    }

    /// Add back consumed units to the limiter
    pub fn revert(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        let cur_sum = *self.state.get_checked(epoch)?;

        debug_assert!(cur_sum > amount);
        let new_sum = cur_sum
            .checked_sub(amount)
            .ok_or(InternalError("Underflow when computing sub".into()))?; // this should be unreachable

        *self.state.get_mut_checked(epoch)? = new_sum;
        Ok(())
    }

    /// Adds a new epoch (must be the next consecutive epoch). Old epochs are pruned automatically.
    pub fn add_epoch(&mut self, epoch: u64) -> GuardianResult<()> {
        self.state.insert(epoch, Amount::from_sat(0))?;
        Ok(())
    }
}

impl CommitteeStore {
    pub fn new(epoch_window: EpochWindow, committees: Vec<HashiCommittee>) -> GuardianResult<Self> {
        // Err if input has no committees
        if committees.is_empty() {
            return Err(InvalidInputs("No committee set".into()));
        }

        // Match window.epoch() against committee.epoch()
        let mut base_epoch = epoch_window.first_epoch;
        for committee in &committees {
            if committee.epoch() != base_epoch {
                return Err(InvalidInputs("epoch doesn't match".into()));
            }
            base_epoch += 1;
        }

        Ok(Self(ConsecutiveEpochStore::<HashiCommittee>::new(
            epoch_window,
            committees,
        )?))
    }

    pub fn num_entries(&self) -> usize {
        self.0.num_entries()
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.0.epoch_window()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &HashiCommittee)> {
        self.0.iter()
    }

    pub fn into_owned_iter(self) -> impl Iterator<Item = (u64, HashiCommittee)> {
        self.0.into_owned_iter()
    }
}

// ---------------------------------
//    Serialize / Deserialize
// ---------------------------------

/// Mock of StandardWithdrawalRequest with unchecked addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardWithdrawalRequestWire {
    pub wid: WithdrawalID,
    pub utxos: TxUTXOsWire,
}

#[derive(Debug, Clone)]
pub struct CommitteeSignatureWire {
    pub epoch: u64,
    pub signature: Vec<u8>,
    pub bitmap: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignedStandardWithdrawalRequestWire {
    pub data: StandardWithdrawalRequestWire,
    pub signature: CommitteeSignatureWire,
}

#[derive(Serialize)]
struct CommitteeStoreRepr(ConsecutiveEpochStoreRepr<hashi_types::move_types::Committee>);

/// Mock of ProvisionerInitState with Serialize. Used for computing the digest of ProvisionerInitState.
#[derive(Serialize)]
struct ProvisionerInitStateRepr {
    pub hashi_committees: CommitteeStoreRepr,
    pub withdrawal_config: WithdrawalConfig,
    pub withdrawal_state: WithdrawalState,
    pub hashi_btc_master_pubkey: BitcoinPubkey,
}

/// Converter from T -> Self that internally validates addresses
pub trait AddressValidation<T>: Sized {
    fn validate_addr(value: T, network: Network) -> GuardianResult<Self>;
}

impl AddressValidation<SignedStandardWithdrawalRequestWire>
    for HashiSigned<StandardWithdrawalRequest>
{
    fn validate_addr(
        wire_value: SignedStandardWithdrawalRequestWire,
        network: Network,
    ) -> GuardianResult<Self> {
        HashiSigned::<StandardWithdrawalRequest>::new(
            wire_value.signature.epoch,
            StandardWithdrawalRequest::validate_addr(wire_value.data, network)?,
            &wire_value.signature.signature,
            &wire_value.signature.bitmap,
        )
        .map_err(|e| InvalidInputs(format!("{:?}", e)))
    }
}

impl AddressValidation<StandardWithdrawalRequestWire> for StandardWithdrawalRequest {
    fn validate_addr(
        value: StandardWithdrawalRequestWire,
        network: Network,
    ) -> GuardianResult<Self> {
        let utxos = value.utxos;
        let inputs = utxos
            .inputs
            .into_iter()
            .map(|utxo| InputUTXO::from_wire(utxo, network))
            .collect::<Result<Vec<_>, _>>()?;

        let outputs = utxos
            .outputs
            .into_iter()
            .map(|utxo| OutputUTXO::from_wire(utxo, network))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            wid: value.wid,
            utxos: TxUTXOs::new(inputs, outputs)?,
        })
    }
}

impl From<StandardWithdrawalRequest> for StandardWithdrawalRequestWire {
    fn from(m: StandardWithdrawalRequest) -> Self {
        Self {
            wid: m.wid,
            utxos: m.utxos.into(),
        }
    }
}

impl From<CommitteeStore> for CommitteeStoreRepr {
    fn from(store: CommitteeStore) -> Self {
        CommitteeStoreRepr(
            ConsecutiveEpochStoreRepr::<hashi_types::move_types::Committee> {
                window: store.0.epoch_window(),
                entries: store.0.iter().map(|(_, c)| c.into()).collect(),
            },
        )
    }
}

impl From<&ProvisionerInitState> for ProvisionerInitStateRepr {
    fn from(state: &ProvisionerInitState) -> Self {
        let (a, b, c, d) = state.clone().into_parts();

        Self {
            hashi_committees: CommitteeStoreRepr::from(a),
            withdrawal_config: b,
            withdrawal_state: c,
            hashi_btc_master_pubkey: d,
        }
    }
}
