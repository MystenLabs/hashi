// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `LogRecord` envelope written to S3: it wraps a `super::message::LogMessage`
//! with the session id, timestamp, and (for signed logs) the guardian signature.
//! The object key and lock duration are derived from the wrapped message.

use super::S3_OBJECT_LOCK_DURATION_CEREMONY;
use super::S3_OBJECT_LOCK_DURATION_COMMITTEE_UPDATE;
use super::S3_OBJECT_LOCK_DURATION_GENESIS;
use super::S3_OBJECT_LOCK_DURATION_HEARTBEAT;
use super::S3_OBJECT_LOCK_DURATION_INIT;
use super::S3_OBJECT_LOCK_DURATION_KP_SHARES;
use super::S3_OBJECT_LOCK_DURATION_WITHDRAW;
use super::message::LogMessage;
use super::message::LogMessageV1;
use super::message::ObjectKeyPattern;
use crate::guardian::BuildPcrs;
use crate::guardian::GuardianError::InvalidInputs;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::GuardianSignKeyPair;
use crate::guardian::GuardianSignature;
use crate::guardian::IntentType;
use crate::guardian::SessionID;
use crate::guardian::SigningIntent;
use crate::guardian::UnixMillis;
use crate::guardian::now_timestamp_ms;
use crate::guardian::session_id_from_signing_pubkey;
use crate::guardian::signing::sign_intent;
use crate::guardian::signing::verify_intent;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

/// Write: `LogMessage` -> `LogRecord` -> JSON body.
/// Read: actual S3 key + JSON body -> untrusted `LogRecord` -> `VerifiedLogRecord`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "schema_version")]
pub enum LogRecord {
    #[serde(rename = "v1")]
    V1(LogRecordV1),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecordBody<M> {
    /// Final S3 destination selected before signing. Readers must compare this
    /// signed intended key with the actual key returned by S3.
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: M,
    /// Present for signed logs; omitted for unsigned logs (currently only OIAttestationUnsigned).
    pub signature: Option<GuardianSignature>,
}

pub type LogRecordV1 = LogRecordBody<LogMessageV1>;

#[derive(Serialize)]
enum LogSigningPayload<'a> {
    V1(LogSigningPayloadV1<'a>),
}

#[derive(Serialize)]
struct LogSigningPayloadV1<'a> {
    session_id: &'a SessionID,
    object_key: &'a str,
    message: &'a LogMessageV1,
}

impl SigningIntent for LogSigningPayload<'_> {
    const INTENT: IntentType = IntentType::LogMessage;
}

/// A log record whose message signature and writing session's attestation/PCRs
/// have both been verified.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessageV1,
    pub build_pcrs: BuildPcrs,
}

impl VerifiedLogRecord {
    pub fn new(
        object_key: String,
        session_id: SessionID,
        timestamp_ms: UnixMillis,
        message: LogMessageV1,
        build_pcrs: BuildPcrs,
    ) -> Self {
        Self {
            object_key,
            session_id,
            timestamp_ms,
            message,
            build_pcrs,
        }
    }
}

impl LogRecord {
    pub fn new(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
    ) -> Self {
        Self::new_at_timestamp(session_id, message, signing_key, now_timestamp_ms())
    }

    pub fn new_at_timestamp(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
    ) -> Self {
        let object_key = message
            .object_key_pattern(&session_id, timestamp_ms)
            .finalize();
        if message.is_allowed_unsigned() {
            Self::unsigned(session_id, message, timestamp_ms, object_key)
        } else {
            Self::signed(session_id, message, signing_key, timestamp_ms, object_key)
        }
    }

    pub fn object_key(&self) -> &str {
        &self.v1().object_key
    }

    pub fn session_id(&self) -> &SessionID {
        &self.v1().session_id
    }

    pub fn timestamp_ms(&self) -> UnixMillis {
        self.v1().timestamp_ms
    }

    pub fn message(&self) -> &LogMessageV1 {
        &self.v1().message
    }

    pub fn into_message(self) -> LogMessageV1 {
        self.into_v1().message
    }

    pub fn object_lock_duration(&self) -> Duration {
        match self.message() {
            LogMessage::Init(..) => S3_OBJECT_LOCK_DURATION_INIT,
            LogMessage::Heartbeat(..) => S3_OBJECT_LOCK_DURATION_HEARTBEAT,
            LogMessage::Withdrawal(..) => S3_OBJECT_LOCK_DURATION_WITHDRAW,
            LogMessage::Ceremony(..) => S3_OBJECT_LOCK_DURATION_CEREMONY,
            LogMessage::KpShareState(..) => S3_OBJECT_LOCK_DURATION_KP_SHARES,
            LogMessage::CommitteeUpdate(..) => S3_OBJECT_LOCK_DURATION_COMMITTEE_UPDATE,
            LogMessage::Genesis(..) => S3_OBJECT_LOCK_DURATION_GENESIS,
        }
    }

    fn signed(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
        object_key: String,
    ) -> Self {
        let mut record = LogRecordBody {
            object_key,
            session_id,
            timestamp_ms,
            message,
            signature: None,
        };
        record.signature = Some(sign_intent(
            &record.signing_payload(),
            timestamp_ms,
            signing_key,
        ));
        Self::V1(record)
    }

    fn unsigned(
        session_id: SessionID,
        message: LogMessage,
        timestamp_ms: UnixMillis,
        object_key: String,
    ) -> Self {
        assert!(
            message.is_allowed_unsigned(),
            "message must be Init(OIAttestationUnsigned)"
        );
        Self::V1(LogRecordBody {
            object_key,
            session_id,
            timestamp_ms,
            message,
            signature: None,
        })
    }

    pub fn verify(
        self,
        pub_key: &GuardianPubKey,
    ) -> GuardianResult<(SessionID, UnixMillis, LogMessageV1)> {
        match self {
            Self::V1(record) => record.verify(pub_key),
        }
    }

    /// Validates the unsigned OI-attestation record's envelope and canonical
    /// session. The Nitro attestation itself must be authenticated separately.
    pub fn validate_unsigned(self) -> GuardianResult<(SessionID, UnixMillis, LogMessageV1)> {
        match self {
            Self::V1(record) => record.validate_unsigned(),
        }
    }

    /// Rejects a record whose signed intended key differs from the key at which
    /// the S3 reader found it.
    pub fn validate_actual_object_key(&self, actual_object_key: &str) -> GuardianResult<()> {
        self.v1().validate_actual_object_key(actual_object_key)
    }

    fn v1(&self) -> &LogRecordV1 {
        match self {
            Self::V1(record) => record,
        }
    }

    fn into_v1(self) -> LogRecordV1 {
        match self {
            Self::V1(record) => record,
        }
    }

    #[cfg(test)]
    fn v1_mut(&mut self) -> &mut LogRecordV1 {
        match self {
            Self::V1(record) => record,
        }
    }
}

impl LogRecordBody<LogMessageV1> {
    fn verify(
        self,
        pub_key: &GuardianPubKey,
    ) -> GuardianResult<(SessionID, UnixMillis, LogMessageV1)> {
        if self.message.is_allowed_unsigned() {
            return Err(InvalidInputs(
                "expected signed log record but message is unsigned".into(),
            ));
        }
        self.validate_object_key()?;
        self.validate_session_id(pub_key)?;
        let timestamp_ms = self.timestamp_ms;
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| InvalidInputs("missing log signature".into()))?;
        verify_intent(&self.signing_payload(), timestamp_ms, signature, pub_key)?;

        Ok((self.session_id, timestamp_ms, self.message))
    }

    fn validate_unsigned(self) -> GuardianResult<(SessionID, UnixMillis, LogMessageV1)> {
        if !self.message.is_allowed_unsigned() {
            return Err(InvalidInputs(
                "expected unsigned log record but message requires a signature".into(),
            ));
        }
        if self.signature.is_some() {
            return Err(InvalidInputs(
                "unsigned log record must not contain a signature".into(),
            ));
        }
        self.validate_object_key()?;
        let LogMessage::Init(init) = &self.message else {
            unreachable!("is_allowed_unsigned only permits an init message");
        };
        let super::message::InitLogMessage::OIAttestationUnsigned {
            signing_public_key, ..
        } = init.as_ref()
        else {
            unreachable!("is_allowed_unsigned only permits OIAttestationUnsigned");
        };
        self.validate_session_id(signing_public_key)?;
        Ok((self.session_id, self.timestamp_ms, self.message))
    }

    /// Rejects a record whose signed intended key differs from the key at which
    /// the S3 reader found it.
    fn validate_actual_object_key(&self, actual_object_key: &str) -> GuardianResult<()> {
        if self.object_key != actual_object_key {
            return Err(InvalidInputs(format!(
                "S3 object key mismatch: record contains {}, actual key is {actual_object_key}",
                self.object_key
            )));
        }
        Ok(())
    }

    fn validate_object_key(&self) -> GuardianResult<()> {
        match self
            .message
            .object_key_pattern(&self.session_id, self.timestamp_ms)
        {
            ObjectKeyPattern::Fixed(expected) if self.object_key != expected => {
                return Err(InvalidInputs(format!(
                    "non-canonical S3 object key: got {}, expected {expected}",
                    self.object_key
                )));
            }
            ObjectKeyPattern::RandomSuffix(prefix) if !self.object_key.starts_with(&prefix) => {
                return Err(InvalidInputs(format!(
                    "non-canonical S3 object key: got {}, expected prefix {prefix}",
                    self.object_key
                )));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_session_id(&self, signing_public_key: &GuardianPubKey) -> GuardianResult<()> {
        let canonical_session_id = session_id_from_signing_pubkey(signing_public_key);
        if self.session_id != canonical_session_id {
            return Err(InvalidInputs(format!(
                "session ID mismatch: record contains {}, signing public key derives {canonical_session_id}",
                self.session_id
            )));
        }
        Ok(())
    }

    fn signing_payload(&self) -> LogSigningPayload<'_> {
        LogSigningPayload::V1(LogSigningPayloadV1 {
            session_id: &self.session_id,
            object_key: &self.object_key,
            message: &self.message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
    use crate::guardian::GuardianError;
    use crate::guardian::GuardianSigned;
    use crate::guardian::HeartbeatLogMessage;
    use crate::guardian::InitLogMessage;
    use crate::guardian::KPEncryptedShares;
    use crate::guardian::LimiterState;
    use crate::guardian::NitroAttestation;
    use crate::guardian::StandardWithdrawalRequest;
    use crate::guardian::StandardWithdrawalRequestWire;
    use crate::guardian::StandardWithdrawalResponse;
    use crate::guardian::WithdrawalID;
    use crate::guardian::WithdrawalLogMessage;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;

    fn heartbeat_session_id() -> SessionID {
        session_id_from_signing_pubkey(&GuardianSignKeyPair::from([13u8; 32]).verification_key())
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
            .validate_actual_object_key(&writer_key)
            .expect("the serialized key must match the writer's S3 destination");
        record_read_from_s3
            .verify(&signing_key.verification_key())
            .expect("the serialized record must verify at the key used by the writer");
    }

    fn assert_heartbeat_relocation_rejected(relocated_key: String) {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let err = log
            .validate_actual_object_key(&relocated_key)
            .expect_err("relocated record must be rejected");
        assert!(format!("{err:?}").contains("S3 object key mismatch"));
    }

    #[test]
    fn withdrawal_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([16u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            session_id,
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded,
            })),
            &signing_key,
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn committee_update_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([17u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
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
                error: GuardianError::InvalidInputs("test failure".to_string()),
            })),
            &signing_key,
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn signed_log_verifies_at_canonical_object_key() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        assert!(matches!(&log, LogRecord::V1(_)));

        let (_, timestamp_ms, message) = log
            .verify(&signing_key.verification_key())
            .expect("record should verify at its intended S3 key");

        assert_eq!(timestamp_ms, 1_700_000_000_000);
        assert!(matches!(
            message,
            LogMessage::Heartbeat(HeartbeatLogMessage { seq: 42 })
        ));
    }

    #[test]
    fn object_key_is_signed_and_serialized() {
        let (object_key, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let json = serde_json::to_value(&log).unwrap();
        assert_eq!(json.get("schema_version").unwrap(), "v1");
        assert_eq!(json.get("object_key").unwrap(), &object_key);

        let from_s3: LogRecord = serde_json::from_value(json).unwrap();
        from_s3
            .validate_actual_object_key(&object_key)
            .expect("embedded key should match the S3 destination");
        from_s3
            .verify(&signing_key.verification_key())
            .expect("serialized object key should be covered by the signature");
    }

    #[test]
    fn signed_log_rejects_cross_prefix_relocation() {
        assert_heartbeat_relocation_rejected(format!(
            "withdraw/2023/11/14/22/{}-00000000000000000042.json",
            heartbeat_session_id()
        ));
    }

    #[test]
    fn signed_log_rejects_lexicographically_higher_key_relocation() {
        assert_heartbeat_relocation_rejected(format!(
            "heartbeat/2023/11/14/22/{}-00000000000000000043.json",
            heartbeat_session_id()
        ));
    }

    #[test]
    fn signed_log_rejects_future_hour_relocation() {
        assert_heartbeat_relocation_rejected(format!(
            "heartbeat/2023/11/14/23/{}-00000000000000000042.json",
            heartbeat_session_id()
        ));
    }

    #[test]
    fn signed_log_rejects_changed_session_relocation() {
        assert_heartbeat_relocation_rejected(
            "heartbeat/2023/11/14/22/aliased-session-00000000000000000042.json".to_string(),
        );
    }

    #[test]
    fn signed_log_rejects_tampered_key_derivation_fields() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let mut tampered: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        tampered.v1_mut().message = LogMessage::Heartbeat(HeartbeatLogMessage::new(43));
        tampered.v1_mut().object_key = format!(
            "heartbeat/2023/11/14/22/{}-00000000000000000043.json",
            heartbeat_session_id()
        );

        let err = tampered
            .verify(&signing_key.verification_key())
            .expect_err("signature must cover the canonical object key and message");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_rejects_changed_failure_random_suffix_relocation() {
        let signing_key = GuardianSignKeyPair::from([18u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            session_id,
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded,
            })),
            &signing_key,
        );
        let original_key = log.object_key();
        let stem = original_key.strip_suffix(".json").unwrap();
        let (prefix, suffix_hex) = stem.rsplit_once('-').unwrap();
        let suffix = u32::from_str_radix(suffix_hex, 16).unwrap();
        let relocated_key = format!("{prefix}-{:08x}.json", suffix ^ 1);

        let mut record_read_from_s3: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        let err = record_read_from_s3
            .validate_actual_object_key(&relocated_key)
            .expect_err("changing only the random failure suffix must invalidate placement");

        assert!(format!("{err:?}").contains("S3 object key mismatch"));

        record_read_from_s3.v1_mut().object_key = relocated_key;
        let err = record_read_from_s3
            .verify(&signing_key.verification_key())
            .expect_err("the signature must authenticate the random failure suffix");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_binds_session_even_when_key_does_not_contain_it() {
        let signing_key = GuardianSignKeyPair::from([19u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Genesis(Box::new(GenesisLogMessage {
                committee: crate::move_types::Committee {
                    epoch: 0,
                    members: vec![],
                    total_weight: 0,
                    config: crate::move_types::Config::default(),
                },
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut aliased: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        aliased.v1_mut().session_id = "aliased-session".to_string();
        aliased.v1_mut().object_key = GenesisLogMessage::object_key();

        let err = aliased
            .verify(&signing_key.verification_key())
            .expect_err("session ID must be part of the signed routing context");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn log_rejects_unknown_schema_version() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        json["schema_version"] = "v2".into();

        assert!(serde_json::from_value::<LogRecord>(json).is_err());
    }

    #[test]
    fn log_rejects_absent_schema_version() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        json.as_object_mut().unwrap().remove("schema_version");

        assert!(serde_json::from_value::<LogRecord>(json).is_err());
    }

    #[test]
    fn unsigned_log_rejects_replay_at_another_s3_key() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
        let mut log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        log.v1_mut().object_key = "init/copied-attestation.json".to_string();
        log.validate_actual_object_key("init/copied-attestation.json")
            .expect("the operator can edit an unsigned record's embedded key");
        let err = log
            .validate_unsigned()
            .expect_err("unsigned record copied to another S3 key must be rejected");

        assert!(format!("{err:?}").contains("non-canonical S3 object key"));
    }

    #[test]
    fn unsigned_attestation_rejects_session_not_derived_from_signing_key() {
        let signing_key = GuardianSignKeyPair::from([15u8; 32]);
        let log = LogRecord::new_at_timestamp(
            "forged-session".to_string(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let err = log
            .validate_unsigned()
            .expect_err("attestation session ID must come from its signing public key");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn object_key_for_init_attestation_unsigned() {
        let session_id = "session-a".to_string();
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
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
            "init/session-a-oi-attestation-unsigned.json"
        );
    }

    #[test]
    fn object_key_for_heartbeat() {
        let session_id = "session-b".to_string();
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
        use crate::guardian::KpShareStateLogMessage;

        let session_id = "session-d".to_string();
        let signing_key = GuardianSignKeyPair::from([10u8; 32]);
        let log = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                7,
                3,
                KPEncryptedShares::new(vec![]).unwrap(),
            ))),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(
            log.object_key(),
            "kp-shares/00000000000000000007/00000000000000000003-session-d.json"
        );
        assert_eq!(
            log.object_lock_duration(),
            S3_OBJECT_LOCK_DURATION_KP_SHARES
        );
    }

    #[test]
    fn object_key_and_lock_for_genesis_is_fixed() {
        let session_id = "session-g".to_string();
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
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(log.object_key(), GenesisLogMessage::object_key());
        assert_eq!(log.object_key(), "genesis/record.json");
        assert_eq!(log.object_lock_duration(), S3_OBJECT_LOCK_DURATION_GENESIS);
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
        let request_data: StandardWithdrawalRequestWire = request_data.into();
        let seq = request_data.seq;

        let log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid: Txid::from_slice(&[3u8; 32]).expect("valid txid"),
                request_data,
                request_sign,
                response: GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing().data,
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
