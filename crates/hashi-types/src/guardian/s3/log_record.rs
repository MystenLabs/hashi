// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! S3 log-record wire format and validation.
//!
//! A [`LogRecord`] carries a [`VersionedLogMessage`] and its S3 routing
//! context. Signed records carry a Guardian signature over their [`LogEntry`].
//! The one permitted unsigned entry carries the OI attestation that establishes
//! the Guardian signing key and must be authenticated separately. Deserialization
//! enforces self-contained record invariants; checks requiring external context
//! remain explicit reader operations.

use super::config::S3ObjectLockPolicy;
use super::log_layout::ObjectKeyPattern;
use super::log_schema::LogMessage;
use super::log_schema::LogMessageV1;
use super::log_schema::LogType;
use super::log_schema::VersionedLogMessage;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::GuardianSignKeyPair;
use crate::guardian::GuardianSignature;
use crate::guardian::GuardianSigned;
use crate::guardian::SessionID;
use crate::guardian::UnixMillis;
use crate::guardian::now_timestamp_ms;
use serde::Deserialize;
use serde::Serialize;
use serde::de::Error as _;
use serde_json::Value;
use std::time::Duration;
use std::time::SystemTime;

/// Routing context and versioned payload carried by a [`LogRecord`].
///
/// For signed records, field order defines the BCS signing format.
#[derive(Debug, Serialize)]
pub struct LogEntry {
    /// Version of the message's serialized schema.
    schema_version: u64,
    /// Guardian session that wrote the entry.
    session_id: SessionID,
    /// Final S3 destination selected before signing. Readers must compare this
    /// intended key with the actual key returned by S3.
    object_key: String,
    /// Versioned log payload.
    message: VersionedLogMessage,
    /// Entry creation time in milliseconds since the Unix epoch.
    timestamp_ms: UnixMillis,
}

/// A Guardian S3 log record.
///
/// Both variants use the same flat JSON representation. Deserialization checks
/// that signature presence matches the message kind and that the embedded
/// routing context is canonical. The record remains unauthenticated until its
/// applicable signature and attestation checks have been performed.
#[derive(Debug)]
pub enum LogRecord {
    /// An entry carrying a Guardian signature.
    Signed(GuardianSigned<LogEntry>),
    /// The OI-attestation entry, which is authenticated separately.
    Unsigned(LogEntry),
}

#[derive(Deserialize)]
struct LogRecordWire {
    schema_version: u64,
    object_key: String,
    session_id: SessionID,
    timestamp_ms: UnixMillis,
    message: Value,
    #[serde(with = "crate::guardian::serde::option_guardian_signature")]
    signature: Option<GuardianSignature>,
}

#[derive(Serialize)]
struct LogRecordWireRef<'a> {
    schema_version: u64,
    object_key: &'a str,
    session_id: &'a SessionID,
    timestamp_ms: UnixMillis,
    message: &'a VersionedLogMessage,
    #[serde(with = "crate::guardian::serde::option_guardian_signature")]
    signature: Option<GuardianSignature>,
}

impl Serialize for LogRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (data, signature) = match self {
            Self::Signed(signed) => (signed.data_unchecked(), Some(signed.signature)),
            Self::Unsigned(unsigned) => (unsigned, None),
        };

        LogRecordWireRef {
            schema_version: data.schema_version,
            object_key: &data.object_key,
            session_id: &data.session_id,
            timestamp_ms: data.timestamp_ms,
            message: &data.message,
            signature,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LogRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = LogRecordWire::deserialize(deserializer)?;
        Self::try_from_wire(raw).map_err(D::Error::custom)
    }
}

impl LogEntry {
    fn new(
        session_id: SessionID,
        object_key: String,
        message: VersionedLogMessage,
        timestamp_ms: UnixMillis,
    ) -> GuardianResult<Self> {
        let data = Self {
            schema_version: message.schema_version(),
            object_key,
            session_id,
            message,
            timestamp_ms,
        };
        data.validate_object_key()?;
        data.validate_attestation_log_session_id()?;
        Ok(data)
    }

    /// Return the log schema version.
    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }

    /// Return the intended S3 object key.
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// Return the writing Guardian session.
    pub fn session_id(&self) -> &SessionID {
        &self.session_id
    }

    /// Return the entry creation time in milliseconds since the Unix epoch.
    pub fn timestamp_ms(&self) -> UnixMillis {
        self.timestamp_ms
    }

    /// Return the versioned log payload.
    pub fn message(&self) -> &VersionedLogMessage {
        &self.message
    }

    /// Return the log payload type.
    pub fn log_type(&self) -> LogType {
        self.message.log_type()
    }

    /// Consume the entry and return its versioned log payload.
    pub fn into_message(self) -> VersionedLogMessage {
        self.message
    }

    fn validate_object_key(&self) -> GuardianResult<()> {
        match self
            .message
            .object_key_pattern(&self.session_id, self.timestamp_ms)
        {
            ObjectKeyPattern::Fixed(expected) if self.object_key != expected => {
                return Err(InvalidS3Log(format!(
                    "non-canonical S3 object key: got {}, expected {expected}",
                    self.object_key
                )));
            }
            ObjectKeyPattern::RandomSuffix(prefix) if !self.object_key.starts_with(&prefix) => {
                return Err(InvalidS3Log(format!(
                    "non-canonical S3 object key: got {}, expected prefix {prefix}",
                    self.object_key
                )));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_session_id(&self, signing_public_key: &GuardianPubKey) -> GuardianResult<()> {
        let canonical_session_id = SessionID::from_signing_pubkey(signing_public_key);
        if self.session_id != canonical_session_id {
            return Err(InvalidS3Log(format!(
                "session ID mismatch: record contains {}, signing public key derives {canonical_session_id}",
                self.session_id
            )));
        }
        Ok(())
    }

    // The Nitro attestation itself must be authenticated separately.
    fn validate_attestation_log_session_id(&self) -> GuardianResult<()> {
        let Some(attestation_log) = self.message.as_attestation_log() else {
            return Ok(());
        };
        let super::log_messages::InitLogMessage::OIAttestationUnsigned {
            signing_public_key, ..
        } = attestation_log
        else {
            unreachable!("as_attestation_log only returns OIAttestationUnsigned");
        };
        self.validate_session_id(signing_public_key)
    }
}

impl LogRecord {
    /// Construct a current-schema record using the current time.
    ///
    /// The OI-attestation message is emitted unsigned; every other message is
    /// signed by `signing_key`.
    pub fn new(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
    ) -> Self {
        Self::new_at_timestamp(session_id, message, signing_key, now_timestamp_ms())
    }

    /// Construct a current-schema record using an explicit timestamp.
    ///
    /// The OI-attestation message is emitted unsigned; every other message is
    /// signed by `signing_key`.
    pub fn new_at_timestamp(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
    ) -> Self {
        let message = VersionedLogMessage::V1(message);
        let object_key = message
            .object_key_pattern(&session_id, timestamp_ms)
            .finalize();
        let is_unsigned = message.is_unsigned();
        let data = LogEntry::new(session_id, object_key, message, timestamp_ms)
            .expect("writer-constructed log entry must be intrinsically valid");
        if is_unsigned {
            Self::Unsigned(data)
        } else {
            Self::Signed(GuardianSigned::sign(data, signing_key))
        }
    }

    /// Validate and construct a record from its untrusted flat wire format.
    fn try_from_wire(raw: LogRecordWire) -> GuardianResult<Self> {
        let message = match raw.schema_version {
            VersionedLogMessage::SCHEMA_VERSION_V1 => {
                serde_json::from_value::<LogMessageV1>(raw.message)
                    .map(VersionedLogMessage::V1)
                    .map_err(|e| InvalidS3Log(format!("invalid V1 log message: {e}")))?
            }
            version => {
                return Err(InvalidS3Log(format!(
                    "unsupported log schema version: {version}"
                )));
            }
        };

        match (raw.signature.is_some(), message.is_unsigned()) {
            (true, true) => {
                return Err(InvalidS3Log(
                    "unsigned log record must not contain a signature".into(),
                ));
            }
            (false, false) => {
                return Err(InvalidS3Log("missing log signature".into()));
            }
            _ => {}
        }
        let data = LogEntry::new(raw.session_id, raw.object_key, message, raw.timestamp_ms)?;
        Ok(match raw.signature {
            Some(signature) => Self::Signed(GuardianSigned::from_parts(data, signature)),
            None => Self::Unsigned(data),
        })
    }

    /// Return the intended S3 object key.
    pub fn object_key(&self) -> &str {
        &self.data().object_key
    }

    /// Return the writing Guardian session.
    pub fn session_id(&self) -> &SessionID {
        &self.data().session_id
    }

    /// Return the entry creation time in milliseconds since the Unix epoch.
    pub fn timestamp_ms(&self) -> UnixMillis {
        self.data().timestamp_ms
    }

    /// Return the versioned log payload.
    pub fn message(&self) -> &VersionedLogMessage {
        &self.data().message
    }

    /// Return the log payload type.
    pub fn log_type(&self) -> LogType {
        self.data().log_type()
    }

    /// Validate the record against its externally established signing key.
    ///
    /// For a signed record, this binds the session to the caller-supplied key
    /// and verifies the signature. It does not establish that the key belongs
    /// to an attested, approved Guardian; the S3 reader performs that complete
    /// verification. Self-contained record invariants are checked during
    /// deserialization.
    ///
    /// Signed records require `Some(signing_public_key)`; the one permitted
    /// unsigned record kind requires `None`. The caller is responsible for
    /// authenticating the Nitro attestation carried by an unsigned record.
    pub fn validate(&self, signing_public_key: Option<&GuardianPubKey>) -> GuardianResult<()> {
        match (self, signing_public_key) {
            (Self::Signed(signed), Some(signing_public_key)) => {
                signed
                    .data_unchecked()
                    .validate_session_id(signing_public_key)?;
                signed
                    .verify_signature(signing_public_key)
                    .map(|_| ())
                    .map_err(|e| InvalidS3Log(format!("invalid log signature: {e}")))
            }
            (Self::Unsigned(_), None) => Ok(()),
            (Self::Unsigned(_), Some(_)) => Err(InvalidS3Log(
                "expected signed log record but message is unsigned".into(),
            )),
            (Self::Signed(_), None) => Err(InvalidS3Log(
                "expected unsigned log record but message requires a signature".into(),
            )),
        }
    }

    /// Validate the record, then consume it and return its versioned entry.
    pub fn validate_into_entry(
        self,
        signing_public_key: Option<&GuardianPubKey>,
    ) -> GuardianResult<LogEntry> {
        self.validate(signing_public_key)?;
        Ok(self.into_entry_unchecked())
    }

    /// Return the fixed object-lock expiry used for reads and every PUT attempt.
    pub fn object_lock_expiry(&self, policy: S3ObjectLockPolicy) -> SystemTime {
        let record_timestamp = Duration::from_millis(self.timestamp_ms());
        let retention = self.log_type().object_lock_duration(policy);
        SystemTime::UNIX_EPOCH
            .checked_add(record_timestamp)
            .and_then(|timestamp| timestamp.checked_add(retention))
            .expect("object-lock expiry must fit in SystemTime")
    }

    /// Consume the record and extract its entry without validation.
    ///
    /// This bypasses signed-record session binding, Guardian signature
    /// verification, and Nitro attestation authentication.
    pub fn into_entry_unchecked(self) -> LogEntry {
        match self {
            Self::Signed(signed) => signed.into_data_unchecked(),
            Self::Unsigned(unsigned) => unsigned,
        }
    }

    fn data(&self) -> &LogEntry {
        match self {
            Self::Signed(signed) => signed.data_unchecked(),
            Self::Unsigned(unsigned) => unsigned,
        }
    }

    #[cfg(test)]
    fn data_mut(&mut self) -> &mut LogEntry {
        match self {
            Self::Signed(signed) => signed.data_unchecked_mut(),
            Self::Unsigned(unsigned) => unsigned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CeremonyLogMessage;
    use crate::guardian::CeremonyProposalLogMessage;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
    use crate::guardian::GuardianError;
    use crate::guardian::GuardianSigningIntentType;
    use crate::guardian::HeartbeatLogMessage;
    use crate::guardian::InitLogMessage;
    use crate::guardian::KpEncryptedShare;
    use crate::guardian::KpEncryptedShareRoster;
    use crate::guardian::KpShareStateLogMessage;
    use crate::guardian::LimiterState;
    use crate::guardian::MAINNET_S3_OBJECT_LOCK_POLICY;
    use crate::guardian::NitroAttestation;
    use crate::guardian::OperatorInitInfo;
    use crate::guardian::OperatorInitMode;
    use crate::guardian::RotateKpSetResponse;
    use crate::guardian::SecretSharingInstance;
    use crate::guardian::ShareCommitment;
    use crate::guardian::ShareCommitments;
    use crate::guardian::StandardWithdrawalRequest;
    use crate::guardian::StandardWithdrawalRequestWire;
    use crate::guardian::StandardWithdrawalResponse;
    use crate::guardian::TESTNET_S3_OBJECT_LOCK_POLICY;
    use crate::guardian::WithdrawalID;
    use crate::guardian::WithdrawalLogMessage;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;
    use fastcrypto::groups::GroupElement;
    use std::num::NonZeroU16;

    fn heartbeat_session_id() -> SessionID {
        SessionID::from_signing_pubkey(&GuardianSignKeyPair::from([13u8; 32]).verification_key())
    }

    fn signed_heartbeat(timestamp_ms: UnixMillis) -> (String, LogRecord, GuardianSignKeyPair) {
        let signing_key = GuardianSignKeyPair::from([13u8; 32]);
        let record = LogRecord::new_at_timestamp(
            heartbeat_session_id(),
            LogMessage::Heartbeat(HeartbeatLogMessage::new(42)),
            &signing_key,
            timestamp_ms,
        );
        let object_key = record.object_key().to_string();
        (object_key, record, signing_key)
    }

    fn assert_writer_key_is_stable_and_verifies(log: LogRecord, signing_key: &GuardianSignKeyPair) {
        let writer_key = log.object_key().to_string();
        for _ in 0..4 {
            assert_eq!(
                log.object_key(),
                writer_key,
                "a record must keep the same object key after construction"
            );
        }

        let body = serde_json::to_vec(&log).unwrap();
        let record_read_from_s3: LogRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(record_read_from_s3.object_key(), writer_key);
        record_read_from_s3
            .validate(Some(&signing_key.verification_key()))
            .expect("the serialized record must verify at the key used by the writer");
    }

    fn test_sharing_instance(sharing_seq: u64) -> SecretSharingInstance {
        let commitments = ShareCommitments::new(
            (1..=2)
                .map(|id| ShareCommitment {
                    id: NonZeroU16::new(id).unwrap(),
                    digest: vec![id as u8; 33],
                })
                .collect(),
        )
        .unwrap();
        SecretSharingInstance::new(commitments, 2, 2, sharing_seq).unwrap()
    }

    fn dummy_log_messages() -> Vec<LogMessage> {
        let signing_key = fixture_signing_key();
        let btc_master_pubkey = crate::bitcoin::create_btc_keypair_for_test(&[3u8; 32])
            .x_only_public_key()
            .0;
        let instance_0 = test_sharing_instance(0);
        let instance_1 = test_sharing_instance(1);
        let (signed_request, committee_0) =
            StandardWithdrawalRequest::mock_signed_and_committee_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let request_data: StandardWithdrawalRequestWire = request_data.into();
        let response = StandardWithdrawalResponse::mock_for_testing();
        let encrypted_shares = RotateKpSetResponse::mock_for_testing().encrypted_shares;
        let guardian_info = OperatorInitInfo::mock_for_testing();
        let mut ceremony_info = guardian_info.clone();
        ceremony_info.initialization = OperatorInitMode::Ceremony;
        let mut bootstrap_info = guardian_info.clone();
        let OperatorInitMode::Withdraw(withdraw) = &mut bootstrap_info.initialization else {
            unreachable!("withdraw dummy initialization");
        };
        withdraw.genesis_state_hash =
            Some(crate::guardian::GenesisState::mock_for_testing().digest());
        let committee_0: crate::move_types::Committee = (&committee_0).into();
        let mut committee_1 = committee_0.clone();
        committee_1.epoch = 1;

        vec![
            LogMessage::Heartbeat(HeartbeatLogMessage::new(1)),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(
                guardian_info,
            )))),
            LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(
                ceremony_info,
            )))),
            LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(
                bootstrap_info,
            )))),
            LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 0,
                share_ids: vec![NonZeroU16::new(1).unwrap()],
                enclave_btc_pubkey: btc_master_pubkey,
            })),
            LogMessage::Init(Box::new(InitLogMessage::OAActivated {
                state_hash: [1; 32],
                config_hash: [2; 32],
                sharing_seq: 0,
                committee_epoch: 0,
                limiter_state: LimiterState {
                    num_tokens_available: 10,
                    last_updated_at: 20,
                    next_seq: 30,
                },
            })),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid: Txid::from_slice(&[3; 32]).unwrap(),
                request_data: request_data.clone(),
                request_sign: request_sign.clone(),
                response,
                post_state: LimiterState {
                    num_tokens_available: 10,
                    last_updated_at: 20,
                    next_seq: request_data.seq + 1,
                },
            })),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data,
                request_sign: request_sign.clone(),
                error: GuardianError::RateLimitExceeded.to_string(),
            })),
            LogMessage::Ceremony(Box::new(CeremonyLogMessage::NewKey {
                instance: instance_0.clone(),
                btc_master_pubkey,
            })),
            LogMessage::Ceremony(Box::new(CeremonyLogMessage::Rotate {
                old_instance: instance_0.clone(),
                new_instance: instance_1.clone(),
                btc_master_pubkey,
            })),
            LogMessage::CeremonyProposal(Box::new(CeremonyProposalLogMessage::new(
                CeremonyLogMessage::NewKey {
                    instance: instance_0.clone(),
                    btc_master_pubkey,
                },
                encrypted_shares.clone(),
            ))),
            LogMessage::CeremonyProposal(Box::new(CeremonyProposalLogMessage::new(
                CeremonyLogMessage::Rotate {
                    old_instance: instance_0,
                    new_instance: instance_1,
                    btc_master_pubkey,
                },
                encrypted_shares.clone(),
            ))),
            LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                0,
                0,
                encrypted_shares,
            ))),
            LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage::Success {
                from_epoch: 0,
                new_committee: committee_1.clone(),
                request_sign: request_sign.clone(),
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
            })),
            LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage::Failure {
                from_epoch: 0,
                new_committee: committee_1,
                request_sign,
                error: GuardianError::InvalidInputs("test failure".into()).to_string(),
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
            })),
            LogMessage::Genesis(Box::new(GenesisLogMessage {
                committee: committee_0,
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
                mpc_master_g: crate::bitcoin::HashiMasterG::generator(),
            })),
        ]
    }

    /// Keep these matches exhaustive: every new log variant needs dummy data.
    fn fixture_name(message: &LogMessage) -> &'static str {
        match message {
            LogMessage::Heartbeat(_) => "heartbeat/heartbeat",
            LogMessage::Init(message) => match message.as_ref() {
                InitLogMessage::OIAttestationUnsigned { .. } => "init/oi-attestation-unsigned",
                InitLogMessage::OIGuardianInfo(info) => match &info.initialization {
                    OperatorInitMode::Ceremony => "init/oi-ceremony-guardian-info",
                    OperatorInitMode::Withdraw(withdraw) => match withdraw.genesis_state_hash {
                        None => "init/oi-guardian-info",
                        Some(_) => "init/oi-bootstrap-guardian-info",
                    },
                },
                InitLogMessage::PIEnclaveFullyInitialized { .. } => {
                    "init/pi-enclave-fully-initialized"
                }
                InitLogMessage::OAActivated { .. } => "init/oa-activated",
            },
            LogMessage::Withdrawal(message) => match message.as_ref() {
                WithdrawalLogMessage::Success { .. } => "withdrawal/success",
                WithdrawalLogMessage::Failure { .. } => "withdrawal/failure",
            },
            LogMessage::Ceremony(message) => match message.as_ref() {
                CeremonyLogMessage::NewKey { .. } => "ceremony/new-key",
                CeremonyLogMessage::Rotate { .. } => "ceremony/rotate",
            },
            LogMessage::CeremonyProposal(message) => match &message.ceremony {
                CeremonyLogMessage::NewKey { .. } => "ceremony-proposal/new-key",
                CeremonyLogMessage::Rotate { .. } => "ceremony-proposal/rotate",
            },
            LogMessage::KpShareState(_) => "kp-share-state/kp-share-state",
            LogMessage::CommitteeUpdate(message) => match message.as_ref() {
                CommitteeUpdateLogMessage::Success { .. } => "committee-update/success",
                CommitteeUpdateLogMessage::Failure { .. } => "committee-update/failure",
            },
            LogMessage::Genesis(_) => "genesis/genesis",
        }
    }

    fn fixture_signing_key() -> GuardianSignKeyPair {
        GuardianSignKeyPair::from([21u8; 32])
    }

    /// Fix the normally random failure suffix before signing fixture records.
    fn dummy_log_record(message: LogMessage) -> LogRecord {
        let message = VersionedLogMessage::V1(message);
        let signing_key = fixture_signing_key();
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let timestamp_ms = 1_700_000_000_000;
        let object_key = match message.object_key_pattern(&session_id, timestamp_ms) {
            ObjectKeyPattern::Fixed(key) => key,
            ObjectKeyPattern::RandomSuffix(prefix) => format!("{prefix}{:032x}.json", 0),
        };
        let is_unsigned = message.is_unsigned();
        let entry = LogEntry::new(session_id, object_key, message, timestamp_ms).unwrap();
        if is_unsigned {
            LogRecord::Unsigned(entry)
        } else {
            LogRecord::Signed(GuardianSigned::sign(entry, &signing_key))
        }
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/guardian/s3/fixtures/v1")
            .join(format!("{name}.json"))
    }

    #[test]
    #[ignore = "writes dummy fixtures; run explicitly when updating the log schema"]
    fn regenerate_log_fixtures() {
        for message in dummy_log_messages() {
            let name = fixture_name(&message);
            let record = dummy_log_record(message);
            let json = serde_json::to_string_pretty(&record).unwrap();
            let path = fixture_path(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{json}\n")).unwrap();
            println!("{}:\n{json}", path.display());
        }
    }

    #[test]
    fn dummy_log_fixtures_round_trip_and_verify() {
        let signing_key = fixture_signing_key();
        for message in dummy_log_messages() {
            let name = fixture_name(&message);
            let expected = dummy_log_record(message);
            let json = std::fs::read_to_string(fixture_path(name)).unwrap();
            let decoded: LogRecord = serde_json::from_str(&json)
                .unwrap_or_else(|error| panic!("{name} failed to deserialize: {error}"));
            assert_eq!(decoded.data().schema_version(), 1, "{name}");
            assert_eq!(
                serde_json::to_string_pretty(&decoded).unwrap(),
                json.trim_end(),
                "{name}"
            );
            assert_eq!(
                serde_json::to_string_pretty(&expected).unwrap(),
                json.trim_end(),
                "{name} changed its wire format"
            );
            let signing_pubkey =
                (!decoded.message().is_unsigned()).then(|| signing_key.verification_key());
            decoded
                .validate(signing_pubkey.as_ref())
                .unwrap_or_else(|error| panic!("{name} failed validation: {error}"));
        }
    }

    #[test]
    fn every_log_message_json_round_trips_and_verifies() {
        let signing_key = fixture_signing_key();
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        for message in dummy_log_messages() {
            let name = fixture_name(&message);
            let record = LogRecord::new_at_timestamp(
                session_id.clone(),
                message,
                &signing_key,
                1_700_000_000_000,
            );
            let object_key = record.object_key().to_owned();
            let json = serde_json::to_vec(&record).unwrap();
            let decoded: LogRecord = serde_json::from_slice(&json)
                .unwrap_or_else(|error| panic!("{name} failed to deserialize: {error}"));

            assert_eq!(
                serde_json::to_vec(&decoded).unwrap(),
                json,
                "{name} did not reserialize canonically"
            );
            assert_eq!(
                decoded.object_key(),
                object_key,
                "{name} did not preserve its object key"
            );
            if decoded.message().is_unsigned() {
                decoded
                    .validate(None)
                    .unwrap_or_else(|error| panic!("{name} failed validation: {error}"));
            } else {
                decoded
                    .validate(Some(&signing_key.verification_key()))
                    .unwrap_or_else(|error| panic!("{name} failed verification: {error}"));
            }
        }
    }

    #[test]
    fn kp_share_state_uses_scalar_recipient_and_round_trips() {
        let signing_key = GuardianSignKeyPair::from([22u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let encrypted_shares = KpEncryptedShareRoster::new(vec![KpEncryptedShare {
            id: NonZeroU16::new(1).unwrap(),
            recipient_fingerprint: "010AFFD5514AE454CA0D56DAA40FE24388998D2A".into(),
            armored_ciphertext: "ciphertext".into(),
        }])
        .unwrap();
        let record = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                7,
                1,
                encrypted_shares,
            ))),
            &signing_key,
            1_700_000_000_000,
        );
        let json = serde_json::to_value(&record).unwrap();
        let share = &json["message"]["KpShareState"]["encrypted_shares"][0];
        assert_eq!(
            share,
            &serde_json::json!({
                "id": 1,
                "recipient_fingerprint": "010AFFD5514AE454CA0D56DAA40FE24388998D2A",
                "armored_ciphertext": "ciphertext",
            })
        );

        let decoded: LogRecord = serde_json::from_value(json).unwrap();
        assert!(matches!(
            decoded.message(),
            VersionedLogMessage::V1(LogMessageV1::KpShareState(..))
        ));
        decoded
            .validate(Some(&signing_key.verification_key()))
            .unwrap();
    }

    #[test]
    fn kp_share_state_rejects_removed_fingerprint_map() {
        let signing_key = GuardianSignKeyPair::from([23u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let encrypted_shares = KpEncryptedShareRoster::new(vec![KpEncryptedShare {
            id: NonZeroU16::new(1).unwrap(),
            recipient_fingerprint: "010AFFD5514AE454CA0D56DAA40FE24388998D2A".into(),
            armored_ciphertext: "ciphertext".into(),
        }])
        .unwrap();
        let record = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                7,
                1,
                encrypted_shares,
            ))),
            &signing_key,
            1_700_000_000_000,
        );
        let mut json = serde_json::to_value(record).unwrap();
        json["message"]["KpShareState"]["encrypted_shares"][0] = serde_json::json!({
            "id": 1,
            "ciphertexts_by_fingerprint": {
                "010AFFD5514AE454CA0D56DAA40FE24388998D2A": "ciphertext"
            },
        });

        assert!(serde_json::from_value::<LogRecord>(json).is_err());
    }

    #[test]
    fn withdrawal_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([16u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            session_id,
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded.to_string(),
            })),
            &signing_key,
        );
        let json = serde_json::to_value(&log).unwrap();
        assert_eq!(
            json["message"]["Withdrawal"]["Failure"]["error"],
            GuardianError::RateLimitExceeded.to_string()
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn committee_update_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([17u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, _) = signed_request.into_parts();
        let log = LogRecord::new(
            session_id,
            LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage::Failure {
                from_epoch: 6,
                new_committee: crate::move_types::Committee {
                    epoch: 7,
                    members: vec![],
                    total_weight: 0,
                    config: crate::move_types::Config::default(),
                },
                request_sign,
                error: GuardianError::InvalidInputs("test failure".to_string()).to_string(),
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
            })),
            &signing_key,
        );
        let json = serde_json::to_value(&log).unwrap();
        assert_eq!(
            json["message"]["CommitteeUpdate"]["Failure"]["error"],
            GuardianError::InvalidInputs("test failure".to_string()).to_string()
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn signed_log_verifies_at_canonical_object_key() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);

        log.validate(Some(&signing_key.verification_key()))
            .expect("record should verify at its intended S3 key");

        assert_eq!(log.timestamp_ms(), 1_700_000_000_000);
        assert!(matches!(
            log.message(),
            VersionedLogMessage::V1(LogMessageV1::Heartbeat(HeartbeatLogMessage { seq: 42 }))
        ));
    }

    #[test]
    fn object_key_is_signed_and_serialized() {
        let (object_key, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let json = serde_json::to_value(&log).unwrap();
        assert_eq!(json.get("schema_version").unwrap(), 1);
        assert_eq!(json.get("object_key").unwrap(), &object_key);
        let signature = json["signature"].as_str().unwrap();
        assert_eq!(signature.len(), 128);
        assert!(
            signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let mut malformed = json.clone();
        malformed["signature"] = "00".into();
        assert!(serde_json::from_value::<LogRecord>(malformed).is_err());

        let from_s3: LogRecord = serde_json::from_value(json).unwrap();
        from_s3
            .validate(Some(&signing_key.verification_key()))
            .expect("serialized object key should be covered by the signature");
    }

    #[test]
    fn signed_log_uses_expected_signing_preimage() {
        #[derive(Serialize)]
        struct LogSigningPayload<'a> {
            schema_version: u64,
            session_id: &'a SessionID,
            object_key: &'a str,
            message: &'a VersionedLogMessage,
        }

        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let data = log.data();
        let payload = LogSigningPayload {
            schema_version: data.schema_version,
            session_id: &data.session_id,
            object_key: &data.object_key,
            message: &data.message,
        };
        let signed_bytes = bcs::to_bytes(&(
            GuardianSigningIntentType::LogEntry,
            payload,
            data.timestamp_ms,
        ))
        .unwrap();
        let LogRecord::Signed(signed) = log else {
            panic!("heartbeat must be signed");
        };

        assert_eq!(signed.signature, signing_key.sign(&signed_bytes));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        for version in [0, 2, 3] {
            json["schema_version"] = serde_json::json!(version);
            let err = serde_json::from_value::<LogRecord>(json.clone()).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("unsupported log schema version: {version}"))
            );
        }
    }

    #[test]
    fn signed_message_without_signature_is_rejected_during_deserialization() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        json["signature"] = serde_json::Value::Null;

        let err = serde_json::from_value::<LogRecord>(json).unwrap_err();
        assert!(err.to_string().contains("missing log signature"), "{err}");
    }

    #[test]
    fn unsigned_message_with_signature_is_rejected_during_deserialization() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let unsigned = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let (_, signed, _) = signed_heartbeat(1_700_000_000_000);
        let signature = serde_json::to_value(signed).unwrap()["signature"].clone();
        let mut json = serde_json::to_value(unsigned).unwrap();
        json["signature"] = signature;

        let err = serde_json::from_value::<LogRecord>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsigned log record must not contain a signature"),
            "{err}"
        );
    }

    #[test]
    fn signed_log_rejects_tampered_key_derivation_fields() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let mut tampered: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        tampered.data_mut().message = LogMessage::Heartbeat(HeartbeatLogMessage::new(43)).into();
        tampered.data_mut().object_key = format!(
            "heartbeat/2023/11/14/22/{}-00000000000000000043.json",
            heartbeat_session_id()
        );

        let err = tampered
            .validate(Some(&signing_key.verification_key()))
            .expect_err("signature must cover the canonical object key and message");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_rejects_changed_failure_random_suffix_relocation() {
        let signing_key = GuardianSignKeyPair::from([18u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            session_id,
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded.to_string(),
            })),
            &signing_key,
        );
        let original_key = log.object_key();
        let stem = original_key.strip_suffix(".json").unwrap();
        let (prefix, suffix_hex) = stem.rsplit_once('-').unwrap();
        let suffix = u128::from_str_radix(suffix_hex, 16).unwrap();
        let relocated_key = format!("{prefix}-{:032x}.json", suffix ^ 1);

        let mut record_read_from_s3: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        record_read_from_s3.data_mut().object_key = relocated_key;
        let err = record_read_from_s3
            .validate(Some(&signing_key.verification_key()))
            .expect_err("the signature must authenticate the random failure suffix");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_binds_session_even_when_key_does_not_contain_it() {
        let signing_key = GuardianSignKeyPair::from([19u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Genesis(Box::new(GenesisLogMessage {
                committee: crate::move_types::Committee {
                    epoch: 0,
                    members: vec![],
                    total_weight: 0,
                    config: crate::move_types::Config::default(),
                },
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
                mpc_master_g: crate::bitcoin::HashiMasterG::generator(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut aliased: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        aliased.data_mut().session_id = "aliased-session".into();
        aliased.data_mut().object_key = GenesisLogMessage::object_key();

        let err = aliased
            .validate(Some(&signing_key.verification_key()))
            .expect_err("session ID must be part of the signed routing context");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn unsigned_log_rejects_replay_at_another_s3_key_during_deserialization() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        let mut json = serde_json::to_value(log).unwrap();
        json["object_key"] = "init/copied-attestation.json".into();
        let err = serde_json::from_value::<LogRecord>(json)
            .expect_err("unsigned record copied to another S3 key must be rejected");

        assert!(format!("{err:?}").contains("non-canonical S3 object key"));
    }

    #[test]
    fn unsigned_attestation_rejects_session_during_deserialization() {
        let signing_key = GuardianSignKeyPair::from([15u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut json = serde_json::to_value(log).unwrap();
        json["session_id"] = "forged-session".into();
        json["object_key"] = "init/forged-session/01-oi-attestation-unsigned.json".into();
        let err = serde_json::from_value::<LogRecord>(json)
            .expect_err("attestation session ID must come from its signing public key");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn object_key_for_init_attestation_unsigned() {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(
            log.object_key(),
            format!("init/{session_id}/01-oi-attestation-unsigned.json")
        );

        let json = serde_json::to_value(&log).unwrap();
        let message = &json["message"]["Init"]["OIAttestationUnsigned"];
        assert_eq!(message["attestation"], "AQID");
        assert_eq!(
            message["signing_public_key"],
            hex::encode(signing_key.verification_key().as_bytes())
        );
        let from_json: LogRecord = serde_json::from_value(json).unwrap();
        assert_eq!(from_json.object_key(), log.object_key());
    }

    #[test]
    fn operator_activation_json_encodes_hashes_as_hex() {
        let signing_key = GuardianSignKeyPair::from([20u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OAActivated {
                state_hash: [0xab; 32],
                config_hash: [0xcd; 32],
                sharing_seq: 7,
                committee_epoch: 9,
                limiter_state: LimiterState {
                    num_tokens_available: 11,
                    last_updated_at: 12,
                    next_seq: 13,
                },
            })),
            &signing_key,
            1_700_000_000_000,
        );

        let json = serde_json::to_value(&log).unwrap();
        let message = &json["message"]["Init"]["OAActivated"];
        assert_eq!(message["state_hash"], hex::encode([0xab; 32]));
        assert_eq!(message["config_hash"], hex::encode([0xcd; 32]));

        let from_json: LogRecord = serde_json::from_value(json).unwrap();
        from_json
            .validate(Some(&signing_key.verification_key()))
            .unwrap();
    }

    #[test]
    fn object_key_for_heartbeat() {
        let session_id: SessionID = "session-b".into();
        let signing_key = GuardianSignKeyPair::from([8u8; 32]);
        let seq = 42_u64;
        let timestamp_ms = 1_700_000_000_000;

        let log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Heartbeat(HeartbeatLogMessage::new(seq)),
            &signing_key,
            timestamp_ms,
        );

        assert_eq!(
            log.object_key(),
            "heartbeat/2023/11/14/22/session-b-00000000000000000042.json"
        );
    }

    #[test]
    fn object_key_and_lock_for_kp_share_state() {
        let session_id: SessionID = "session-d".into();
        let signing_key = GuardianSignKeyPair::from([10u8; 32]);
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                7,
                3,
                KpEncryptedShareRoster::new(vec![]).unwrap(),
            ))),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(
            log.object_key(),
            "kp-shares/00000000000000000007/00000000000000000003-session-d.json"
        );
        assert_eq!(
            log.object_lock_expiry(TESTNET_S3_OBJECT_LOCK_POLICY),
            SystemTime::UNIX_EPOCH
                + Duration::from_millis(1_700_000_000_000)
                + TESTNET_S3_OBJECT_LOCK_POLICY.short_lived
        );
    }

    #[test]
    fn object_key_and_lock_for_ceremony_proposal() {
        let session_id: SessionID = "session-proposal".into();
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let btc_master_pubkey = crate::bitcoin::create_btc_keypair_for_test(&[4u8; 32])
            .x_only_public_key()
            .0;
        let proposal = CeremonyProposalLogMessage::new(
            CeremonyLogMessage::NewKey {
                instance: test_sharing_instance(0),
                btc_master_pubkey,
            },
            RotateKpSetResponse::mock_for_testing().encrypted_shares,
        );
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::CeremonyProposal(Box::new(proposal)),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(log.object_key(), "kp-shares/proposed/session-proposal.json");
        assert_eq!(
            log.object_lock_expiry(TESTNET_S3_OBJECT_LOCK_POLICY),
            SystemTime::UNIX_EPOCH
                + Duration::from_millis(1_700_000_000_000)
                + TESTNET_S3_OBJECT_LOCK_POLICY.short_lived
        );
    }

    #[test]
    fn object_key_and_lock_for_genesis_is_fixed() {
        let session_id: SessionID = "session-g".into();
        let signing_key = GuardianSignKeyPair::from([12u8; 32]);
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Genesis(Box::new(GenesisLogMessage {
                committee: crate::move_types::Committee {
                    epoch: 0,
                    members: vec![],
                    total_weight: 0,
                    config: crate::move_types::Config::default(),
                },
                hashi_object_id: sui_sdk_types::Address::new([0xAA; 32]),
                mpc_master_g: crate::bitcoin::HashiMasterG::generator(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(log.object_key(), GenesisLogMessage::object_key());
        assert_eq!(log.object_key(), "genesis/record.json");
        assert_eq!(
            log.object_lock_expiry(MAINNET_S3_OBJECT_LOCK_POLICY),
            SystemTime::UNIX_EPOCH
                + Duration::from_millis(1_700_000_000_000)
                + MAINNET_S3_OBJECT_LOCK_POLICY.long_lived
        );
    }

    #[test]
    fn object_key_for_withdrawal_success() {
        let session_id: SessionID = "session-c".into();
        let signing_key = GuardianSignKeyPair::from([9u8; 32]);
        let timestamp_ms = 1_700_000_000_000;
        let wid = WithdrawalID::new([0xcd; 32]);
        let signed_request =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let (request_sign, request_data) = signed_request.into_parts();
        let request_data: StandardWithdrawalRequestWire = request_data.into();
        let seq = request_data.seq;

        let log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid: Txid::from_slice(&[3u8; 32]).expect("valid txid"),
                request_data,
                request_sign,
                response: StandardWithdrawalResponse::mock_for_testing(),
                post_state: LimiterState {
                    num_tokens_available: 0,
                    last_updated_at: 0,
                    next_seq: seq + 1,
                },
            })),
            &signing_key,
            timestamp_ms,
        );

        assert_eq!(
            log.object_key(),
            format!("withdraw/2023/11/14/22/success-{seq:020}-session-c-wid{wid}.json"),
        );
    }
}
