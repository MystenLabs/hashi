pub mod bitcoin_utils;
pub mod crypto;
pub mod epoch_store;
pub mod errors;
pub mod proto_conversions;
pub mod test_utils;

use crate::GuardianError::*;
pub use bitcoin::secp256k1::Keypair as BitcoinKeypair;
pub use bitcoin::secp256k1::XOnlyPublicKey as BitcoinPubkey;
pub use bitcoin::taproot::Signature as BitcoinSignature;
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
pub use hashi_types::committee::SignedMessage as HashiSigned;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::num::NonZeroU16;
use std::time::Duration;
use std::time::SystemTime;

use crate::bitcoin_utils::TxUTXOs;
use crate::epoch_store::ConsecutiveEpochStore;
use crate::epoch_store::ConsecutiveEpochStoreRepr;
use crate::epoch_store::EpochWindow;
use crate::proto_conversions::provisioner_init_state_to_pb;
use hashi_types::committee::CommitteeSignature;
use prost::Message;
use tracing::info;
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
    /// Attestation document serialized in Hex
    pub attestation: Attestation,
    /// Server version
    /// TODO: Replace with hashi's ServerVersion to include crate SHA and version
    pub server_version: String,
}

/// An "immediate withdrawal" request. `HashiSigned<T>.`
/// Note that epoch number is present in the wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// BTC transaction input and output utxos
    utxos: TxUTXOs,
}

/// `EnclaveSigned<T>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalWithdrawalResponse {
    /// Enclave's BTC signatures
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
    /// Immediate withdraw success
    NormalWithdrawalSuccess {
        request_data: NormalWithdrawalRequest,
        request_sign: CommitteeSignature,
        response: NormalWithdrawalResponse,
    },
    /// Immediate withdraw failure
    /// TODO: Any sensitivity concerns with logging the entire request permanently? (same for others)
    NormalWithdrawalFailure {
        request_data: NormalWithdrawalRequest,
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
    pub bucket_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalConfig {
    /// Committee threshold expressed in terms of weight
    pub committee_threshold: u64,
    /// The min delay after which any withdrawal is approved
    pub delayed_withdrawals_min_delay: Duration,
    /// The max delay after which pending withdrawals are cleaned up
    pub delayed_withdrawals_timeout: Duration,
}

/// Rate limiter
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimiter {
    // State: (epoch_number, amount_withdrawn) for the last X epochs
    state: ConsecutiveEpochStore<Amount>,
    // Maximum amount withdrawable per epoch
    max_withdrawable_per_epoch: Amount,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalState {
    limiter: RateLimiter,
}

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

// TODO: Implement custom serializer since proto buf serializer is not deterministic
impl ToBytes for ProvisionerInitRequestState {
    fn to_bytes(&self) -> Vec<u8> {
        provisioner_init_state_to_pb(self.clone()).encode_to_vec()
    }
}

impl ProvisionerInitRequestState {
    pub fn new(
        hashi_committees: CommitteeStore,
        withdrawal_config: WithdrawalConfig,
        withdrawal_state: WithdrawalState,
        hashi_btc_master_pubkey: BitcoinPubkey,
    ) -> GuardianResult<Self> {
        if hashi_committees.epoch_window() != withdrawal_state.limiter.epoch_window() {
            return Err(InvalidInputs("epoch window mismatch".into()));
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
        Blake2b::<U32>::digest(self.to_bytes()).into()
    }
}

impl ProvisionerInitRequest {
    pub fn new(encrypted_share: EncryptedShare, state: ProvisionerInitRequestState) -> Self {
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
    pub fn new(wid: WithdrawalID, utxos: TxUTXOs) -> Self {
        // TODO: Validate that UTXOs belong to the correct network
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

    pub fn empty(max_withdrawable_per_epoch: Amount, num_epochs: NonZeroU16) -> Self {
        Self {
            limiter: RateLimiter::empty(max_withdrawable_per_epoch, num_epochs),
        }
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

    pub fn is_initialized(&self) -> bool {
        self.limiter.is_initialized()
    }
}

impl RateLimiter {
    pub fn new(
        epoch_window: EpochWindow,
        amounts: Vec<Amount>,
        max_withdrawable_per_epoch: Amount,
    ) -> GuardianResult<Self> {
        Self::from_repr(
            ConsecutiveEpochStoreRepr::<Amount> {
                base_epoch: epoch_window.base_epoch,
                entries: amounts,
                capacity: epoch_window.num_epochs,
            },
            max_withdrawable_per_epoch,
        )
    }

    pub fn from_repr(
        wire_input: ConsecutiveEpochStoreRepr<Amount>,
        max_withdrawable: Amount,
    ) -> GuardianResult<Self> {
        Ok(Self {
            state: wire_input.try_into()?,
            max_withdrawable_per_epoch: max_withdrawable,
        })
    }

    /// Construct an empty limiter.
    pub fn empty(max_withdrawable_per_epoch: Amount, num_epochs: NonZeroU16) -> Self {
        Self {
            state: ConsecutiveEpochStore::empty(num_epochs),
            max_withdrawable_per_epoch,
        }
    }

    pub fn max_withdrawable_per_epoch(&self) -> Amount {
        self.max_withdrawable_per_epoch
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.state.epoch_window()
    }

    pub fn is_initialized(&self) -> bool {
        self.state.is_initialized()
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
        info!("Adding epoch {} to rate limiter.", epoch);
        self.state.insert_or_start(epoch, Amount::from_sat(0))?;
        info!("Epoch {} added to rate limiter.", epoch);
        Ok(())
    }
}

impl CommitteeStore {
    pub fn new(epoch_window: EpochWindow, committees: Vec<HashiCommittee>) -> GuardianResult<Self> {
        Self::from_repr(ConsecutiveEpochStoreRepr::<HashiCommittee> {
            base_epoch: epoch_window.base_epoch,
            entries: committees,
            capacity: epoch_window.num_epochs,
        })
    }

    pub fn from_repr(
        wire_input: ConsecutiveEpochStoreRepr<HashiCommittee>,
    ) -> GuardianResult<Self> {
        let mut base_epoch = wire_input.base_epoch;
        for committee in &wire_input.entries {
            if committee.epoch() != base_epoch {
                return Err(InvalidInputs("epoch doesn't match".into()));
            }
            base_epoch += 1;
        }
        Ok(Self(wire_input.try_into()?))
    }

    pub fn num_entries(&self) -> usize {
        self.0.len()
    }

    pub fn capacity(&self) -> NonZeroU16 {
        self.0.capacity()
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.0.epoch_window()
    }

    pub fn insert(&mut self, epoch: u64, committee: HashiCommittee) -> GuardianResult<()> {
        self.0.insert_or_start(epoch, committee)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &HashiCommittee)> {
        self.0.iter()
    }

    pub fn into_owned_iter(self) -> impl Iterator<Item = (u64, HashiCommittee)> {
        self.0.into_owned_iter()
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
