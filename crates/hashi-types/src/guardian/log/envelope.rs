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
use super::message::ObjectKeyPattern;
use crate::guardian::BuildPcrs;
use crate::guardian::GuardianError::InvalidInputs;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::GuardianSignKeyPair;
use crate::guardian::GuardianSignature;
use crate::guardian::GuardianSigned;
use crate::guardian::IntentType;
use crate::guardian::SessionID;
use crate::guardian::SigningIntent;
use crate::guardian::UnixMillis;
use crate::guardian::now_timestamp_ms;
use crate::guardian::session_id_from_signing_pubkey;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

pub const LOG_SCHEMA_VERSION: u8 = 1;

/// Write: `LogMessage` -> signed `LogRecord` with a finalized key -> JSON body.
/// Read: S3 key + JSON body -> untrusted `LogRecord` -> `VerifiedLogRecord`.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecord {
    pub schema_version: u8,
    /// Final S3 destination selected before signing. Readers must compare this
    /// in-memory key with the actual key returned by S3. S3 already carries the
    /// key as object metadata, so it is not duplicated in the JSON body.
    #[serde(skip)]
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
    /// Present for signed logs; omitted for unsigned logs (currently only OIAttestationUnsigned).
    pub signature: Option<GuardianSignature>,
}

#[derive(Serialize)]
pub(crate) struct LogSigningPayload {
    schema_version: u8,
    session_id: SessionID,
    object_key: String,
    message: LogMessage,
}

impl SigningIntent for LogSigningPayload {
    const INTENT: IntentType = IntentType::LogMessage;

    fn signing_bytes(&self, timestamp_ms: UnixMillis) -> Vec<u8> {
        bcs::to_bytes(&(
            Self::INTENT,
            self.schema_version,
            &self.session_id,
            timestamp_ms,
            &self.object_key,
            &self.message,
        ))
        .expect("log signing payload serialization should not fail")
    }
}

/// A log record whose message signature and writing session's attestation/PCRs
/// have both been verified.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    pub schema_version: u8,
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
    pub build_pcrs: BuildPcrs,
}

impl VerifiedLogRecord {
    pub fn new(
        schema_version: u8,
        object_key: String,
        session_id: SessionID,
        timestamp_ms: UnixMillis,
        message: LogMessage,
        build_pcrs: BuildPcrs,
    ) -> Self {
        Self {
            schema_version,
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
        &self.object_key
    }

    pub fn object_lock_duration(&self) -> Duration {
        match &self.message {
            LogMessage::Init(..) => S3_OBJECT_LOCK_DURATION_INIT,
            LogMessage::Heartbeat { .. } => S3_OBJECT_LOCK_DURATION_HEARTBEAT,
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
        let signed = GuardianSigned::new(
            LogSigningPayload {
                schema_version: LOG_SCHEMA_VERSION,
                session_id,
                object_key,
                message,
            },
            signing_key,
            timestamp_ms,
        );
        Self {
            schema_version: signed.data.schema_version,
            object_key: signed.data.object_key,
            session_id: signed.data.session_id,
            timestamp_ms: signed.timestamp_ms,
            message: signed.data.message,
            signature: Some(signed.signature),
        }
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
        Self {
            schema_version: LOG_SCHEMA_VERSION,
            object_key,
            session_id,
            timestamp_ms,
            message,
            signature: None,
        }
    }

    pub fn verify(
        self,
        pub_key: &GuardianPubKey,
    ) -> GuardianResult<(u8, SessionID, UnixMillis, LogMessage)> {
        self.validate_object_key()?;
        let object_key = self.object_key.clone();
        let schema_version = self.schema_version;
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
                data: LogSigningPayload {
                    schema_version: self.schema_version,
                    session_id: session_id.clone(),
                    object_key,
                    message,
                },
                timestamp_ms,
                signature,
            }
            .verify(pub_key)?
            .message
        };

        Ok((schema_version, session_id, timestamp_ms, message))
    }

    pub fn verify_unsigned(self) -> GuardianResult<(u8, SessionID, UnixMillis, LogMessage)> {
        if !self.message.is_allowed_unsigned() {
            return Err(InvalidInputs(
                "expected unsigned log record but message requires a signature".into(),
            ));
        }
        self.validate_object_key()?;
        Ok((
            self.schema_version,
            self.session_id,
            self.timestamp_ms,
            self.message,
        ))
    }

    fn validate_object_key(&self) -> GuardianResult<()> {
        if self.schema_version != LOG_SCHEMA_VERSION {
            return Err(InvalidInputs(format!(
                "unsupported log schema version: {}",
                self.schema_version
            )));
        }
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
        if let LogMessage::Init(init) = &self.message
            && let super::message::InitLogMessage::OIAttestationUnsigned {
                signing_public_key, ..
            } = init.as_ref()
        {
            let attested_session_id = session_id_from_signing_pubkey(signing_public_key);
            if self.session_id != attested_session_id {
                return Err(InvalidInputs(format!(
                    "attestation session ID mismatch: record contains {}, signing public key derives {attested_session_id}",
                    self.session_id
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
    use crate::guardian::GuardianError;
    use crate::guardian::GuardianSigned;
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

    fn signed_heartbeat(timestamp_ms: UnixMillis) -> (String, LogRecord, GuardianSignKeyPair) {
        let signing_key = GuardianSignKeyPair::from([13u8; 32]);
        let record = LogRecord::new_at_timestamp(
            "session-key-binding".to_string(),
            LogMessage::Heartbeat { seq: 42 },
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
        let mut record_read_from_s3: LogRecord = serde_json::from_slice(&body).unwrap();
        record_read_from_s3.object_key = writer_key;
        record_read_from_s3
            .verify(&signing_key.verification_key())
            .expect("the serialized record must verify at the key used by the writer");
    }

    fn assert_heartbeat_relocation_rejected(relocated_key: &str) {
        let (_, mut log, signing_key) = signed_heartbeat(1_700_000_000_000);
        log.object_key = relocated_key.to_owned();
        let err = log
            .verify(&signing_key.verification_key())
            .expect_err("relocated record must be rejected");
        assert!(format!("{err:?}").contains("non-canonical S3 object key"));
    }

    #[test]
    fn withdrawal_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([16u8; 32]);
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            "session-withdraw-failure".to_string(),
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
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, _) = signed_request.into_parts();
        let log = LogRecord::new(
            "session-committee-failure".to_string(),
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

        let (schema_version, _, timestamp_ms, message) = log
            .verify(&signing_key.verification_key())
            .expect("record should verify at its intended S3 key");

        assert_eq!(schema_version, LOG_SCHEMA_VERSION);
        assert_eq!(timestamp_ms, 1_700_000_000_000);
        assert!(matches!(message, LogMessage::Heartbeat { seq: 42 }));
    }

    #[test]
    fn object_key_is_supplied_by_s3_not_duplicated_in_json() {
        let (object_key, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let json = serde_json::to_value(&log).unwrap();
        assert!(json.get("object_key").is_none());

        let mut from_s3: LogRecord = serde_json::from_value(json).unwrap();
        assert!(from_s3.object_key().is_empty());
        from_s3.object_key = object_key;
        from_s3
            .verify(&signing_key.verification_key())
            .expect("actual S3 key should restore the signed routing context");
    }

    #[test]
    fn signed_log_rejects_cross_prefix_relocation() {
        assert_heartbeat_relocation_rejected(
            "withdraw/2023/11/14/22/session-key-binding-00000000000000000042.json",
        );
    }

    #[test]
    fn signed_log_rejects_lexicographically_higher_key_relocation() {
        assert_heartbeat_relocation_rejected(
            "heartbeat/2023/11/14/22/session-key-binding-00000000000000000043.json",
        );
    }

    #[test]
    fn signed_log_rejects_future_hour_relocation() {
        assert_heartbeat_relocation_rejected(
            "heartbeat/2023/11/14/23/session-key-binding-00000000000000000042.json",
        );
    }

    #[test]
    fn signed_log_rejects_changed_session_relocation() {
        assert_heartbeat_relocation_rejected(
            "heartbeat/2023/11/14/22/aliased-session-00000000000000000042.json",
        );
    }

    #[test]
    fn signed_log_rejects_tampered_key_derivation_fields() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let mut tampered: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        tampered.message = LogMessage::Heartbeat { seq: 43 };
        let tampered_key = "heartbeat/2023/11/14/22/session-key-binding-00000000000000000043.json";
        tampered.object_key = tampered_key.to_owned();

        let err = tampered
            .verify(&signing_key.verification_key())
            .expect_err("signature must cover the canonical object key and message");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_rejects_changed_failure_nonce_relocation() {
        let signing_key = GuardianSignKeyPair::from([18u8; 32]);
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::new(
            "session-failure-nonce".to_string(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded,
            })),
            &signing_key,
        );
        let original_key = log.object_key();
        let stem = original_key.strip_suffix(".json").unwrap();
        let (prefix, nonce_hex) = stem.rsplit_once('-').unwrap();
        let nonce = u32::from_str_radix(nonce_hex, 16).unwrap();
        let relocated_key = format!("{prefix}-{:08x}.json", nonce ^ 1);

        let mut record_read_from_s3: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        record_read_from_s3.object_key = relocated_key;
        let err = record_read_from_s3
            .verify(&signing_key.verification_key())
            .expect_err("changing only the random failure nonce must invalidate placement");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_binds_session_even_when_key_does_not_contain_it() {
        let signing_key = GuardianSignKeyPair::from([19u8; 32]);
        let log = LogRecord::new_at_timestamp(
            "original-session".to_string(),
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
        aliased.session_id = "aliased-session".to_string();
        aliased.object_key = GenesisLogMessage::object_key();

        let err = aliased
            .verify(&signing_key.verification_key())
            .expect_err("session ID must be part of the signed routing context");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn log_rejects_unknown_schema_version() {
        let (_, mut log, signing_key) = signed_heartbeat(1_700_000_000_000);
        log.schema_version = LOG_SCHEMA_VERSION + 1;

        let err = log
            .verify(&signing_key.verification_key())
            .expect_err("unknown schema versions must be rejected");

        assert!(format!("{err:?}").contains("unsupported log schema version"));
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

        log.object_key = "init/copied-attestation.json".to_string();
        let err = log
            .verify_unsigned()
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
            .verify_unsigned()
            .expect_err("attestation session ID must come from its signing public key");

        assert!(format!("{err:?}").contains("attestation session ID mismatch"));
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
            LogMessage::Heartbeat { seq },
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
