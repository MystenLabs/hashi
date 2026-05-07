// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod bitcoin_utils;
pub mod crypto;
pub mod errors;
pub mod proto_conversions;
pub mod test_utils;
pub mod time_utils;

pub mod limiter;
pub mod s3_utils;

pub use limiter::LimiterConfig;
pub use limiter::LimiterState;
pub use limiter::RateLimiter;
pub use time_utils::UnixMillis;
pub use time_utils::now_timestamp_ms;
pub use time_utils::now_timestamp_secs;
pub use time_utils::unix_millis_to_seconds;

use self::bitcoin_utils::InputUTXO;
use self::bitcoin_utils::OutputUTXO;
use self::bitcoin_utils::TxUTXOs;
use self::bitcoin_utils::TxUTXOsWire;
use self::errors::GuardianError::*;
pub use crate::committee::Committee as HashiCommittee;
pub use crate::committee::CommitteeMember as HashiCommitteeMember;
use crate::committee::CommitteeSignature;
pub use crate::committee::SignedMessage as HashiSigned;
use crate::guardian::s3_utils::S3HourScopedDirectory;
pub use bitcoin::Address as BitcoinAddress;
pub use bitcoin::secp256k1::Keypair as BitcoinKeypair;
pub use bitcoin::secp256k1::XOnlyPublicKey as BitcoinPubkey;
pub use bitcoin::taproot::Signature as BitcoinSignature;
use bitcoin::*;
use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
pub use crypto::*;
pub use ed25519_consensus::Signature as GuardianSignature;
pub use ed25519_consensus::SigningKey as GuardianSignKeyPair;
pub use ed25519_consensus::VerificationKey as GuardianPubKey;
pub use errors::*;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
// ---------------------------------
//          Constants
// ---------------------------------

/// Object lock durations used for S3 log objects.
///
/// These are public so that external verifiers/monitors can apply the same expectations.
pub const S3_OBJECT_LOCK_DURATION_INIT: Duration = Duration::from_secs(5 * 60);
pub const S3_OBJECT_LOCK_DURATION_WITHDRAW: Duration = Duration::from_secs(5 * 60);
pub const S3_OBJECT_LOCK_DURATION_HEARTBEAT: Duration = Duration::from_secs(5 * 60);

/// S3 sub-prefixes used for guardian log streams.
/// See `crates/hashi-guardian/README.md` for canonical key layout.
pub const S3_DIR_INIT: &str = "init";
pub const S3_DIR_WITHDRAW: &str = "withdraw";
pub const S3_DIR_HEARTBEAT: &str = "heartbeat";

/// Canonical guardian session ID derived from the enclave signing public key.
pub fn session_id_from_signing_pubkey(signing_pub_key: &GuardianPubKey) -> String {
    ::hex::encode(signing_pub_key.as_bytes())
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
//          Envelopes
// ---------------------------------

/// Guardian-signed wrapper - adds timestamp and signature to any data
/// TODO: Impl custom ser/deser for GuardianSignature as signatures are displayed as long bytes in S3 logs
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianSigned<T> {
    pub data: T,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: UnixMillis,
    pub signature: GuardianSignature,
}

/// Canonical log record written to S3.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecord {
    pub session_id: String,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
    /// Present for signed logs; omitted for unsigned logs (currently only OIAttestationUnsigned).
    pub signature: Option<GuardianSignature>,
}

/// A verified log record where message authenticity has been checked.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    pub session_id: String,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
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
    pub share_commitments: ShareCommitments,
}

/// Provides S3 API keys, share commitments and the BTC network to the enclave.
/// To be called by the operator.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorInitRequest {
    s3_config: S3Config,
    share_commitments: ShareCommitments,
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
    /// Current Hashi committee
    committee: HashiCommittee,
    /// Withdrawal config (includes limiter config)
    withdrawal_config: WithdrawalConfig,
    /// Limiter state (tokens available, timestamp, seq)
    limiter_state: LimiterState,
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
    /// Current rate limiter state (if initialized).
    pub limiter_state: Option<LimiterState>,
    /// Immutable limiter configuration (if initialized).
    pub limiter_config: Option<LimiterConfig>,
}

/// TODO: Add network?
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    /// Share commitments (if set). Used by KPs to check that right key will be used.
    pub share_commitments: Option<ShareCommitments>,
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
    /// Timestamp in unix seconds (used for rate limiting)
    timestamp_secs: u64,
    /// Monotonic sequence number for ordering
    seq: u64,
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
    Heartbeat { seq: u64 },
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
}

/// OI: operator_init
/// PI: provisioner_init
/// Init messages are expected to be logged in the following order:
/// OIAttestationUnsigned -> OIGuardianInfo -> PISuccess (T times) -> PIEnclaveFullyInitialized.
#[derive(Debug, Serialize, Deserialize)]
pub enum InitLogMessage {
    /// Attestation and signing public key posted in /operator_init
    OIAttestationUnsigned {
        attestation: Attestation,
        signing_public_key: GuardianPubKey,
    },
    /// Share commitments given in /operator_init
    OIGuardianInfo(GuardianInfo),
    /// A successful /setup_new_key call
    SetupNewKeySuccess {
        encrypted_shares: Vec<EncryptedShare>,
        share_commitments: Vec<ShareCommitment>,
    },
    /// A single successful /provisioner_init call (happens N times)
    PISuccess {
        share_id: ShareID,
        state_hash: [u8; 32],
    },
    /// Threshold reached - enclave fully initialized (happens once)
    PIEnclaveFullyInitialized,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WithdrawalLogMessage {
    /// Immediate withdraw success
    Success {
        txid: Txid,
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        response: StandardWithdrawalResponse,
    },
    /// Immediate withdraw failure
    Failure {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

/// 32-byte UID of the on-chain `WithdrawalTransaction` Sui object.
/// Used to correlate events across Sui, hashi nodes, and the guardian.
pub type WithdrawalID = sui_sdk_types::Address;

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

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawalConfig {
    /// Committee threshold expressed in terms of weight
    pub committee_threshold: u64,
    /// Token refill rate in sats per second
    pub refill_rate_sats_per_sec: u64,
    /// Maximum bucket capacity in sats
    pub max_bucket_capacity_sats: u64,
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
        share_commitments: ShareCommitments,
        network: Network,
    ) -> GuardianResult<Self> {
        Ok(Self {
            s3_config,
            share_commitments,
            network,
        })
    }

    pub fn s3_config(&self) -> &S3Config {
        &self.s3_config
    }

    pub fn share_commitments(&self) -> &ShareCommitments {
        &self.share_commitments
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn into_parts(self) -> (S3Config, ShareCommitments, Network) {
        (self.s3_config, self.share_commitments, self.network)
    }
}

impl ProvisionerInitState {
    pub fn new(
        committee: HashiCommittee,
        withdrawal_config: WithdrawalConfig,
        limiter_state: LimiterState,
        hashi_btc_master_pubkey: BitcoinPubkey,
    ) -> GuardianResult<Self> {
        // Validate that limiter state is consistent with config.
        if limiter_state.num_tokens_available > withdrawal_config.max_bucket_capacity_sats {
            return Err(InvalidInputs(
                "limiter num_tokens_available exceeds max_bucket_capacity".into(),
            ));
        }
        Ok(Self {
            committee,
            withdrawal_config,
            limiter_state,
            hashi_btc_master_pubkey,
        })
    }

    /// Build a `RateLimiter` from the config and state in this init state.
    pub fn build_rate_limiter(&self) -> GuardianResult<RateLimiter> {
        RateLimiter::new(self.limiter_config(), self.limiter_state)
    }

    pub fn limiter_config(&self) -> LimiterConfig {
        LimiterConfig {
            refill_rate: self.withdrawal_config.refill_rate_sats_per_sec,
            max_bucket_capacity: self.withdrawal_config.max_bucket_capacity_sats,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        HashiCommittee,
        WithdrawalConfig,
        LimiterState,
        BitcoinPubkey,
    ) {
        (
            self.committee,
            self.withdrawal_config,
            self.limiter_state,
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
    pub fn new(wid: WithdrawalID, utxos: TxUTXOs, timestamp_secs: u64, seq: u64) -> Self {
        Self {
            wid,
            utxos,
            timestamp_secs,
            seq,
        }
    }

    pub fn wid(&self) -> &WithdrawalID {
        &self.wid
    }

    pub fn utxos(&self) -> &TxUTXOs {
        &self.utxos
    }

    pub fn timestamp_secs(&self) -> u64 {
        self.timestamp_secs
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

impl InitLogMessage {
    pub const OI_ATTEST_UNSIGNED: &'static str = "oi-attestation-unsigned";
    pub const OI_GUARDIAN_INFO: &'static str = "oi-guardian-info";
    pub const SETUP_NEW_KEY_SUCCESS: &'static str = "setup-new-key-success";
    pub const PI_SUCCESS: &'static str = "pi-success-share";
    pub const PI_FULLY_INITIALIZED: &'static str = "pi-enclave-fully-initialized";

    pub fn log_name(&self, prefix: &str) -> String {
        let suffix = match self {
            InitLogMessage::OIAttestationUnsigned { .. } => Self::OI_ATTEST_UNSIGNED.to_string(),
            InitLogMessage::OIGuardianInfo(_) => Self::OI_GUARDIAN_INFO.to_string(),
            InitLogMessage::SetupNewKeySuccess { .. } => Self::SETUP_NEW_KEY_SUCCESS.to_string(),
            InitLogMessage::PISuccess { share_id, .. } => {
                format!("{}-{}", Self::PI_SUCCESS, share_id.get())
            }
            InitLogMessage::PIEnclaveFullyInitialized => Self::PI_FULLY_INITIALIZED.to_string(),
        };

        format!("{}-{}.json", prefix, suffix)
    }

    pub fn attestation_object_key(session_id: &str) -> String {
        format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            Self::OI_ATTEST_UNSIGNED
        )
    }

    pub fn guardian_info_object_key(session_id: &str) -> String {
        format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            Self::OI_GUARDIAN_INFO
        )
    }
}

impl WithdrawalLogMessage {
    pub fn log_name(&self, prefix: &str) -> String {
        let random_suffix = rand::random::<u32>();
        let status = match self {
            WithdrawalLogMessage::Success { .. } => "success",
            WithdrawalLogMessage::Failure { .. } => "failure",
        };
        format!(
            "{}-{}-{}-{:08x}.json",
            prefix,
            self.wid(),
            status,
            random_suffix
        )
    }
}

impl LogMessage {
    pub fn is_allowed_unsigned(&self) -> bool {
        if let LogMessage::Init(init_message) = self {
            matches!(**init_message, InitLogMessage::OIAttestationUnsigned { .. })
        } else {
            false
        }
    }

    pub fn must_be_signed(&self) -> bool {
        !self.is_allowed_unsigned()
    }

    /// The directory under which logs are written. Ends with a slash.
    pub fn log_dir(&self, timestamp_ms: UnixMillis) -> String {
        match self {
            LogMessage::Init(_) => format!("{}/", S3_DIR_INIT),
            LogMessage::Heartbeat { .. } => {
                S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, unix_millis_to_seconds(timestamp_ms))
                    .to_string()
            }
            LogMessage::Withdrawal(..) => {
                S3HourScopedDirectory::new(S3_DIR_WITHDRAW, unix_millis_to_seconds(timestamp_ms))
                    .to_string()
            }
        }
    }

    /// The name of the log.
    pub fn log_name(&self, prefix: &str) -> String {
        match self {
            LogMessage::Init(init_message) => init_message.log_name(prefix),
            LogMessage::Heartbeat { seq } => format!("{}-{:020}.json", prefix, seq),
            LogMessage::Withdrawal(withdrawal_message) => withdrawal_message.log_name(prefix),
        }
    }

    pub fn into_init_log(self) -> Option<InitLogMessage> {
        match self {
            LogMessage::Init(init_message) => Some(*init_message),
            _ => None,
        }
    }
}

impl LogRecord {
    pub fn new(session_id: String, message: LogMessage, signing_key: &GuardianSignKeyPair) -> Self {
        let timestamp_ms = now_timestamp_ms();
        if message.is_allowed_unsigned() {
            Self::unsigned(session_id, message, timestamp_ms)
        } else {
            Self::signed(session_id, message, signing_key, timestamp_ms)
        }
    }

    /// Object key format:
    /// - Init: `init/{session_id}-{suffix}.json`
    /// - Heartbeats & Withdrawals: `{prefix}/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{suffix}.json`.
    pub fn object_key(&self) -> String {
        let dir = self.message.log_dir(self.timestamp_ms);
        let log_name = self.message.log_name(&self.session_id);
        format!("{}{}", dir, log_name)
    }

    pub fn object_lock_duration(&self) -> Duration {
        match &self.message {
            LogMessage::Init(..) => S3_OBJECT_LOCK_DURATION_INIT,
            LogMessage::Heartbeat { .. } => S3_OBJECT_LOCK_DURATION_HEARTBEAT,
            LogMessage::Withdrawal(..) => S3_OBJECT_LOCK_DURATION_WITHDRAW,
        }
    }

    fn signed(
        session_id: String,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
    ) -> Self {
        let signed = GuardianSigned::new(message, signing_key, timestamp_ms);
        Self {
            session_id,
            timestamp_ms: signed.timestamp_ms,
            message: signed.data,
            signature: Some(signed.signature),
        }
    }

    fn unsigned(session_id: String, message: LogMessage, timestamp_ms: UnixMillis) -> Self {
        assert!(
            message.is_allowed_unsigned(),
            "message must be Init(OIAttestationUnsigned)"
        );
        Self {
            session_id,
            timestamp_ms,
            message,
            signature: None,
        }
    }

    pub fn verify(self, pub_key: &GuardianPubKey) -> GuardianResult<VerifiedLogRecord> {
        let session_id = self.session_id;
        let timestamp_ms = self.timestamp_ms;
        let message = self.message;

        let message = if message.is_allowed_unsigned() {
            message
        } else {
            let signature = self
                .signature
                .ok_or_else(|| InvalidInputs("missing log signature".into()))?;
            GuardianSigned {
                data: message,
                timestamp_ms,
                signature,
            }
            .verify(pub_key)?
        };

        Ok(VerifiedLogRecord {
            session_id,
            timestamp_ms,
            message,
        })
    }

    pub fn verify_unsigned(self) -> GuardianResult<VerifiedLogRecord> {
        if !self.message.is_allowed_unsigned() {
            return Err(InvalidInputs(
                "expected unsigned log record but message requires a signature".into(),
            ));
        }
        Ok(VerifiedLogRecord {
            session_id: self.session_id,
            timestamp_ms: self.timestamp_ms,
            message: self.message,
        })
    }
}

impl WithdrawalLogMessage {
    pub fn wid(&self) -> WithdrawalID {
        match self {
            WithdrawalLogMessage::Success { request_data, .. } => request_data.wid,
            WithdrawalLogMessage::Failure { request_data, .. } => request_data.wid,
        }
    }
}

pub fn verify_enclave_attestation(_attestation: Attestation) -> GuardianResult<()> {
    // TODO: Implement me
    Ok(())
}

// ---------------------------------
//    Serialize / Deserialize
// ---------------------------------

/// Mock of StandardWithdrawalRequest with unchecked addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardWithdrawalRequestWire {
    pub wid: WithdrawalID,
    pub utxos: TxUTXOsWire,
    pub timestamp_secs: u64,
    pub seq: u64,
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

/// Serializable representation of ProvisionerInitState. Used for computing its digest.
#[derive(Serialize)]
struct ProvisionerInitStateRepr {
    pub committee: crate::move_types::Committee,
    pub withdrawal_config: WithdrawalConfig,
    pub limiter_state: LimiterState,
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
            timestamp_secs: value.timestamp_secs,
            seq: value.seq,
        })
    }
}

impl From<StandardWithdrawalRequest> for StandardWithdrawalRequestWire {
    fn from(m: StandardWithdrawalRequest) -> Self {
        Self {
            wid: m.wid,
            utxos: m.utxos.into(),
            timestamp_secs: m.timestamp_secs,
            seq: m.seq,
        }
    }
}

impl From<&ProvisionerInitState> for ProvisionerInitStateRepr {
    fn from(state: &ProvisionerInitState) -> Self {
        let (committee, config, limiter_state, pubkey) = state.clone().into_parts();
        Self {
            committee: (&committee).into(),
            withdrawal_config: config,
            limiter_state,
            hashi_btc_master_pubkey: pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn set_timestamp(log: &mut LogRecord, timestamp_ms: UnixMillis) {
        log.timestamp_ms = timestamp_ms;
    }

    #[test]
    fn object_key_for_init_attestation_unsigned() {
        let session_id = "session-a".to_string();
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let mut log = LogRecord::new(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: vec![1, 2, 3],
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
        );
        set_timestamp(&mut log, 1_700_000_000_000);

        assert_eq!(
            log.object_key(),
            "init/session-a-oi-attestation-unsigned.json"
        );
    }

    #[test]
    fn object_key_for_heartbeat() {
        let session_id = "session-b".to_string();
        let signing_key = GuardianSignKeyPair::from([8u8; 32]);
        let seq = 42_u64;
        let timestamp_ms = 1_700_000_000_000;

        let mut log = LogRecord::new(
            session_id.clone(),
            LogMessage::Heartbeat { seq },
            &signing_key,
        );
        set_timestamp(&mut log, timestamp_ms);

        assert_eq!(
            log.object_key(),
            "heartbeat/2023/11/14/22/session-b-00000000000000000042.json"
        );
    }

    #[test]
    fn object_key_for_withdrawal_success() {
        let session_id = "session-c".to_string();
        let signing_key = GuardianSignKeyPair::from([9u8; 32]);
        let timestamp_ms = 1_700_000_000_000;
        let wid = WithdrawalID::new([0xcd; 32]);
        let signed_request =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let (request_sign, request_data) = signed_request.into_parts();

        let mut log = LogRecord::new(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid: Txid::from_slice(&[3u8; 32]).expect("valid txid"),
                request_data: request_data.into(),
                request_sign,
                response: GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing().data,
            })),
            &signing_key,
        );
        set_timestamp(&mut log, timestamp_ms);

        let key = log.object_key();
        assert!(key.starts_with(&format!("withdraw/2023/11/14/22/session-c-{wid}-success-")));
        assert!(key.ends_with(".json"));
    }
}
