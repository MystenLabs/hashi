// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The versioned `LogMessage` family the enclave emits and its per-message S3 object-key
//! rules. The `LogRecord` wrapper that carries these to S3 lives in
//! `super::envelope`.
//!
//! Every message type exposes `object_key_pattern()`.
//! Types with deterministic keys also expose `object_key()`, which returns the
//! complete bucket-relative key. Types supporting batch reads may additionally
//! expose `object_key_dir()`, a slash-terminated S3 key prefix.
//!
//! Writers call `LogRecord::new()`, which finalizes the pattern exactly once,
//! stores the resulting key, and uses it for signing and upload.
//! Readers either fetch a deterministic record using `object_key()` or list
//! records in `object_key_dir()`. In both read paths, the S3 client rejects a
//! record unless its signed key matches the actual key returned by S3.

use super::S3_DIR_CEREMONY;
use super::S3_DIR_COMMITTEE_UPDATE;
use super::S3_DIR_GENESIS;
use super::S3_DIR_HEARTBEAT;
use super::S3_DIR_INIT;
use super::S3_DIR_KP_SHARES;
use super::S3_DIR_WITHDRAW;
use crate::bitcoin::BitcoinPubkey;
use crate::committee::CommitteeSignature;
use crate::guardian::GuardianError;
use crate::guardian::GuardianInfo;
use crate::guardian::GuardianPubKey;
use crate::guardian::KPEncryptedShares;
use crate::guardian::KPEncryptedSharesRoster;
use crate::guardian::KPFingerprint;
use crate::guardian::KpSigned;
use crate::guardian::LimiterState;
use crate::guardian::NitroAttestation;
use crate::guardian::SecretSharingInstance;
use crate::guardian::ShareID;
use crate::guardian::SingleProvisionerInitRequest;
use crate::guardian::StandardWithdrawalRequestWire;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
use crate::guardian::WithdrawalID;
use crate::guardian::s3_utils::S3HourScopedDirectory;
use crate::guardian::unix_millis_to_seconds;
use bitcoin::Txid;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The wire message stored in a [`super::LogRecord`]. Its version is serialized
/// as the record's sibling `schema_version` field rather than as an additional
/// JSON enum layer.
#[derive(Debug)]
pub enum VersionedLogMessage {
    V1(LogMessageV1),
    V2(LogMessageV2),
}

impl From<LogMessageV1> for VersionedLogMessage {
    fn from(message: LogMessageV1) -> Self {
        Self::V1(message)
    }
}

impl From<LogMessageV2> for VersionedLogMessage {
    fn from(message: LogMessageV2) -> Self {
        Self::V2(message)
    }
}

impl Serialize for VersionedLogMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::V1(message) => message.serialize(serializer),
            Self::V2(message) => message.serialize(serializer),
        }
    }
}

/// Schema-version-1 log messages. Its legacy KP-share payload is retained so
/// readers can verify signatures over records emitted before KP shares
/// supported multiple certificates.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV1 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessageV1>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// Current log schema emitted by the guardian enclave.
/// Uses an enum discriminator for automatic domain separation between variants.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV2 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessageV2>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// The current normalized log-message shape exposed to writers and verified
/// readers. Wire-version handling remains internal to [`VersionedLogMessage`].
pub type LogMessage = LogMessageV2;

pub(super) enum ObjectKeyPattern {
    Fixed(String),
    /// Complete key prefix before the random suffix; finalize() appends the suffix.
    RandomSuffix(String),
}

pub(super) enum LogType {
    Heartbeat,
    Init,
    Withdrawal,
    Ceremony,
    KpShareState,
    CommitteeUpdate,
    Genesis,
}

trait LogMessageSchema {
    fn is_allowed_unsigned(&self) -> bool;

    fn log_type(&self) -> LogType;

    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern;
}

impl ObjectKeyPattern {
    /// Finalizes the pattern into the complete S3 object key.
    pub(super) fn finalize(self) -> String {
        match self {
            Self::Fixed(key) => key,
            Self::RandomSuffix(prefix) => {
                format!("{prefix}{:08x}.json", rand::random::<u32>())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatLogMessage {
    pub seq: u64,
}

impl HeartbeatLogMessage {
    pub fn new(seq: u64) -> Self {
        Self { seq }
    }

    pub fn object_key(&self, session_id: &str, timestamp_ms: UnixMillis) -> String {
        format!(
            "{}{session_id}-{:020}.json",
            S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, unix_millis_to_seconds(timestamp_ms)),
            self.seq,
        )
    }

    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id, timestamp_ms))
    }
}

/// First-deploy committee and the exact KP-signed PI submissions that authorized
/// it. Written at `genesis/record.json` once PI reaches threshold.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GenesisLogMessage {
    pub committee: crate::move_types::Committee,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<KpSigned<SingleProvisionerInitRequest>>,
}

impl GenesisLogMessage {
    pub fn object_key() -> String {
        format!("{S3_DIR_GENESIS}/record.json")
    }

    fn object_key_pattern(&self) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(Self::object_key())
    }
}

/// Current encrypted KP share state for a secret-sharing instance. The initial
/// ceremony writes `cert_seq = 0`; later individual KP cert rotations can write
/// higher `cert_seq` entries for the same `sharing_seq` without changing the
/// `ceremony/` instance.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KpShareStateLogMessageV2 {
    pub sharing_seq: u64,
    pub cert_seq: u64,
    pub encrypted_shares: KPEncryptedSharesRoster,
}

/// The current normalized KP-share state exposed to writers and verified
/// readers.
pub type KpShareStateLogMessage = KpShareStateLogMessageV2;

/// V1 encrypted share state: exactly one certificate and ciphertext per KP.
/// Kept solely for reading and authenticating existing V1 logs.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KpShareStateLogMessageV1 {
    pub sharing_seq: u64,
    pub cert_seq: u64,
    pub encrypted_shares: KPEncryptedSharesV1,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KPEncryptedShareV1 {
    pub id: ShareID,
    pub recipient_fingerprint: KPFingerprint,
    pub armored_ciphertext: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct KPEncryptedSharesV1(Vec<KPEncryptedShareV1>);

impl KPEncryptedSharesV1 {
    fn new(mut shares: Vec<KPEncryptedShareV1>) -> Result<Self, GuardianError> {
        if shares.len() > crate::guardian::crypto::MAX_NUM_SHARES {
            return Err(GuardianError::InvalidInputs(format!(
                "{} encrypted shares must be at most u16::MAX",
                shares.len()
            )));
        }

        shares.sort_by_key(|share| share.id);
        let ids = shares
            .iter()
            .map(|share| share.id.get())
            .collect::<Vec<_>>();
        let expected = (1..=shares.len() as u16).collect::<Vec<_>>();
        if ids != expected {
            return Err(GuardianError::InvalidInputs(format!(
                "encrypted share ids are not exactly 1..={}: got {ids:?}",
                shares.len()
            )));
        }

        Ok(Self(shares))
    }
}

impl<'de> Deserialize<'de> for KPEncryptedSharesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shares = Vec::<KPEncryptedShareV1>::deserialize(deserializer)?;
        Self::new(shares).map_err(serde::de::Error::custom)
    }
}

impl KpShareStateLogMessageV1 {
    fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(KpShareStateLogMessageV2::object_key(
            session_id,
            self.sharing_seq,
            self.cert_seq,
        ))
    }

    fn into_current(self) -> Result<KpShareStateLogMessageV2, GuardianError> {
        let shares = self
            .encrypted_shares
            .0
            .into_iter()
            .map(|share| KPEncryptedShares {
                id: share.id,
                ciphertexts_by_fingerprint: BTreeMap::from([(
                    share.recipient_fingerprint,
                    share.armored_ciphertext,
                )]),
            })
            .collect();
        Ok(KpShareStateLogMessageV2::new(
            self.sharing_seq,
            self.cert_seq,
            KPEncryptedSharesRoster::new(shares)?,
        ))
    }
}

impl KpShareStateLogMessageV2 {
    pub fn new(sharing_seq: u64, cert_seq: u64, encrypted_shares: KPEncryptedSharesRoster) -> Self {
        Self {
            sharing_seq,
            cert_seq,
            encrypted_shares,
        }
    }

    /// `kp-shares/{sharing_seq:020}/` — the slash-terminated S3 key prefix
    /// containing every cert-state version for one `SecretSharingInstance`.
    pub fn object_key_dir(sharing_seq: u64) -> String {
        format!("{S3_DIR_KP_SHARES}/{sharing_seq:020}/")
    }

    /// `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session_id}.json` — the
    /// object key for one written KP share state.
    pub fn object_key(session_id: &str, sharing_seq: u64, cert_seq: u64) -> String {
        format!(
            "{}{:020}-{session_id}.json",
            Self::object_key_dir(sharing_seq),
            cert_seq
        )
    }

    fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(Self::object_key(
            session_id,
            self.sharing_seq,
            self.cert_seq,
        ))
    }
}

/// The authoritative secret-sharing instance, written to `ceremony/` after each
/// ceremony. Carries the commitments + n/t/seq; encrypted KP shares live in
/// `kp-shares/`. A rotation records the `old_instance` it consumed so the chain
/// is auditable from the log alone.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CeremonyLogMessage {
    /// Initial key setup (`setup_new_key`); `instance` has `sharing_seq` 0.
    NewKey {
        instance: SecretSharingInstance,
        /// The x-only BTC master pubkey this ceremony produced; lets KPs and
        /// monitors cross-check it against the on-chain `guardian_btc_public_key`.
        btc_master_pubkey: BitcoinPubkey,
    },
    /// Key rotation (`rotate_kps`) from `old_instance` to `new_instance`.
    Rotate {
        old_instance: SecretSharingInstance,
        new_instance: SecretSharingInstance,
        /// See [`Self::NewKey`]; invariant across rotations (the same key is re-shared).
        btc_master_pubkey: BitcoinPubkey,
    },
}

impl CeremonyLogMessage {
    /// Consume the ceremony result. `NewKey` yields its initial instance;
    /// `Rotate` yields the new instance after verifying that it advances exactly
    /// one `sharing_seq` from the consumed instance.
    pub fn into_instance_and_pubkey(self) -> (SecretSharingInstance, BitcoinPubkey) {
        match self {
            Self::NewKey {
                instance,
                btc_master_pubkey,
            } => (instance, btc_master_pubkey),
            Self::Rotate {
                old_instance,
                new_instance,
                btc_master_pubkey,
            } => {
                let expected = old_instance
                    .sharing_seq()
                    .checked_add(1)
                    .expect("Rotate old sharing_seq must not be u64::MAX");
                assert_eq!(
                    new_instance.sharing_seq(),
                    expected,
                    "Rotate must advance sharing_seq by exactly one"
                );
                (new_instance, btc_master_pubkey)
            }
        }
    }

    /// The resulting instance's `sharing_seq` — used as the `ceremony/` object key.
    pub fn sharing_seq(&self) -> u64 {
        match self {
            CeremonyLogMessage::NewKey { instance, .. } => instance.sharing_seq(),
            CeremonyLogMessage::Rotate { new_instance, .. } => new_instance.sharing_seq(),
        }
    }

    pub fn object_key(&self, session_id: &str) -> String {
        format!(
            "{S3_DIR_CEREMONY}/{:020}-{session_id}.json",
            self.sharing_seq(),
        )
    }

    fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id))
    }
}

/// OI: operator_init
/// PI: provisioner_init
/// Init messages are expected to be logged in the following order:
/// OIAttestationUnsigned -> OIGuardianInfo -> PIEnclaveFullyInitialized -> OAActivated.
#[derive(Debug, Serialize, Deserialize)]
pub enum InitLogMessage {
    /// Attestation and signing public key posted in /operator_init
    OIAttestationUnsigned {
        attestation: NitroAttestation,
        #[serde(with = "crate::guardian::serde_utils::guardian_pubkey")]
        signing_public_key: GuardianPubKey,
    },
    /// Signed GuardianInfo logged in /operator_init (secret-sharing instance,
    /// config_hash, encryption/BTC pubkeys). Boxed: much larger than the other
    /// variants (`clippy::large_enum_variant`).
    OIGuardianInfo(Box<GuardianInfo>),
    /// Threshold reached — enclave BTC key reconstructed (happens once).
    PIEnclaveFullyInitialized {
        sharing_seq: u64,
        share_ids: Vec<ShareID>,
        enclave_btc_pubkey: BitcoinPubkey,
    },
    /// Operator activation succeeded and installed live serving state.
    OAActivated {
        #[serde(with = "hex::serde")]
        state_hash: [u8; 32],
        #[serde(with = "hex::serde")]
        config_hash: [u8; 32],
        sharing_seq: u64,
        committee_epoch: u64,
        limiter_state: LimiterState,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WithdrawalLogMessage {
    Success {
        txid: Txid,
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        response: StandardWithdrawalResponse,
        /// Limiter state after this withdrawal was consumed. The KP rotating in
        /// the next enclave reads the max-seq Success log and uses its
        /// `post_state` as the new enclave's initial limiter state.
        post_state: LimiterState,
    },
    Failure {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CommitteeUpdateLogMessage {
    /// `from_epoch` is the guardian's current epoch at the time; the
    /// applied epoch is `new_committee.epoch`. Both are recorded because
    /// hashi reconfig is sparse — `new_committee.epoch` is not
    /// necessarily `from_epoch + 1`.
    Success {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
    },
    /// `from_epoch` is the guardian's current epoch at the time;
    /// `new_committee` is what was proposed (and rejected).
    Failure {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

impl InitLogMessage {
    pub const OI_ATTEST_UNSIGNED: &'static str = "01-oi-attestation-unsigned";
    pub const OI_GUARDIAN_INFO: &'static str = "02-oi-guardian-info";
    pub const PI_FULLY_INITIALIZED: &'static str = "03-pi-enclave-fully-initialized";
    pub const OA_ACTIVATED: &'static str = "04-oa-activated";

    pub fn object_key(&self, session_id: &str) -> String {
        let suffix = match self {
            InitLogMessage::OIAttestationUnsigned { .. } => Self::OI_ATTEST_UNSIGNED,
            InitLogMessage::OIGuardianInfo(_) => Self::OI_GUARDIAN_INFO,
            InitLogMessage::PIEnclaveFullyInitialized { .. } => Self::PI_FULLY_INITIALIZED,
            InitLogMessage::OAActivated { .. } => Self::OA_ACTIVATED,
        };

        Self::object_key_for_suffix(session_id, suffix)
    }

    fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id))
    }

    pub fn attestation_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::OI_ATTEST_UNSIGNED)
    }

    pub fn guardian_info_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::OI_GUARDIAN_INFO)
    }

    fn object_key_for_suffix(session_id: &str, suffix: &str) -> String {
        format!("{S3_DIR_INIT}/{session_id}/{suffix}.json")
    }
}

impl WithdrawalLogMessage {
    /// Success keys lead with `success-{seq:020}` so that lexicographic listing
    /// within an hour bucket is also seq-sorted — the last key is the max-seq
    /// log, which the KP reads to recover limiter state. Failures don't have a
    /// meaningful seq (the request's seq may be stale), so they use a random
    /// suffix for dedup.
    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern {
        let directory =
            S3HourScopedDirectory::new(S3_DIR_WITHDRAW, unix_millis_to_seconds(timestamp_ms));
        match self {
            Self::Success { request_data, .. } => ObjectKeyPattern::Fixed(format!(
                "{directory}success-{:020}-{session_id}-wid{}.json",
                request_data.seq, request_data.wid,
            )),
            Self::Failure { request_data, .. } => ObjectKeyPattern::RandomSuffix(format!(
                "{directory}failure-{session_id}-wid{}-",
                request_data.wid,
            )),
        }
    }

    pub fn wid(&self) -> WithdrawalID {
        match self {
            WithdrawalLogMessage::Success { request_data, .. } => request_data.wid,
            WithdrawalLogMessage::Failure { request_data, .. } => request_data.wid,
        }
    }
}

impl CommitteeUpdateLogMessage {
    /// Success keys lead with the new epoch (zero-padded) so a lex listing
    /// is epoch-sorted; failures lead with `failure-` so they sort after
    /// all successes, leaving the lex-last success key as the latest
    /// successfully-applied epoch.
    fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        match self {
            Self::Success { new_committee, .. } => ObjectKeyPattern::Fixed(format!(
                "{S3_DIR_COMMITTEE_UPDATE}/{:020}-{session_id}.json",
                new_committee.epoch,
            )),
            Self::Failure { new_committee, .. } => ObjectKeyPattern::RandomSuffix(format!(
                "{S3_DIR_COMMITTEE_UPDATE}/failure-{:020}-{session_id}-",
                new_committee.epoch,
            )),
        }
    }
}

macro_rules! impl_log_message_schema {
    ($schema:ty) => {
        impl LogMessageSchema for $schema {
            fn is_allowed_unsigned(&self) -> bool {
                matches!(
                    self,
                    Self::Init(init_message)
                        if matches!(
                            **init_message,
                            InitLogMessage::OIAttestationUnsigned { .. }
                        )
                )
            }

            fn log_type(&self) -> LogType {
                match self {
                    Self::Heartbeat(..) => LogType::Heartbeat,
                    Self::Init(..) => LogType::Init,
                    Self::Withdrawal(..) => LogType::Withdrawal,
                    Self::Ceremony(..) => LogType::Ceremony,
                    Self::KpShareState(..) => LogType::KpShareState,
                    Self::CommitteeUpdate(..) => LogType::CommitteeUpdate,
                    Self::Genesis(..) => LogType::Genesis,
                }
            }

            fn object_key_pattern(
                &self,
                session_id: &str,
                timestamp_ms: UnixMillis,
            ) -> ObjectKeyPattern {
                match self {
                    Self::Heartbeat(message) => {
                        message.object_key_pattern(session_id, timestamp_ms)
                    }
                    Self::Init(message) => message.object_key_pattern(session_id),
                    Self::Withdrawal(message) => {
                        message.object_key_pattern(session_id, timestamp_ms)
                    }
                    Self::Ceremony(message) => message.object_key_pattern(session_id),
                    Self::KpShareState(message) => message.object_key_pattern(session_id),
                    Self::CommitteeUpdate(message) => message.object_key_pattern(session_id),
                    Self::Genesis(message) => message.object_key_pattern(),
                }
            }
        }
    };
}

impl_log_message_schema!(LogMessageV1);
impl_log_message_schema!(LogMessageV2);

impl LogMessageV1 {
    fn into_current(self) -> Result<LogMessage, GuardianError> {
        Ok(match self {
            LogMessageV1::Heartbeat(message) => LogMessage::Heartbeat(message),
            LogMessageV1::Init(message) => LogMessage::Init(message),
            LogMessageV1::Withdrawal(message) => LogMessage::Withdrawal(message),
            LogMessageV1::Ceremony(message) => LogMessage::Ceremony(message),
            LogMessageV1::KpShareState(message) => {
                LogMessage::KpShareState(Box::new((*message).into_current()?))
            }
            LogMessageV1::CommitteeUpdate(message) => LogMessage::CommitteeUpdate(message),
            LogMessageV1::Genesis(message) => LogMessage::Genesis(message),
        })
    }
}

impl LogMessageV2 {
    pub fn into_init_log(self) -> Option<InitLogMessage> {
        match self {
            Self::Init(init_message) => Some(*init_message),
            _ => None,
        }
    }
}

impl VersionedLogMessage {
    pub const SCHEMA_VERSION_V1: u64 = 1;
    pub const SCHEMA_VERSION_V2: u64 = 2;

    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => Self::SCHEMA_VERSION_V1,
            Self::V2(_) => Self::SCHEMA_VERSION_V2,
        }
    }

    pub fn is_allowed_unsigned(&self) -> bool {
        match self {
            Self::V1(message) => message.is_allowed_unsigned(),
            Self::V2(message) => message.is_allowed_unsigned(),
        }
    }

    pub fn must_be_signed(&self) -> bool {
        !self.is_allowed_unsigned()
    }

    pub(super) fn log_type(&self) -> LogType {
        match self {
            Self::V1(message) => message.log_type(),
            Self::V2(message) => message.log_type(),
        }
    }

    pub(super) fn object_key_pattern(
        &self,
        session_id: &str,
        timestamp_ms: UnixMillis,
    ) -> ObjectKeyPattern {
        match self {
            Self::V1(message) => message.object_key_pattern(session_id, timestamp_ms),
            Self::V2(message) => message.object_key_pattern(session_id, timestamp_ms),
        }
    }

    pub fn into_current(self) -> Result<LogMessage, GuardianError> {
        match self {
            Self::V1(message) => message.into_current(),
            Self::V2(message) => Ok(message),
        }
    }
}
