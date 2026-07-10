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
use crate::guardian::BuildPcrs;
use crate::guardian::GuardianError::InvalidInputs;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::GuardianSignKeyPair;
use crate::guardian::GuardianSignature;
use crate::guardian::GuardianSigned;
use crate::guardian::SessionID;
use crate::guardian::UnixMillis;
use crate::guardian::now_timestamp_ms;
use crate::guardian::session_id_from_signing_pubkey;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

/// Canonical log record written to S3.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogRecord {
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
    /// Present for signed logs; omitted for unsigned logs (currently only OIAttestationUnsigned).
    pub signature: Option<GuardianSignature>,
}

/// Canonical payload covered by a signed log record. The object key is supplied
/// by the writer before upload and by the reader from the S3 listing/get, so a
/// valid record cannot be copied to a different key and still verify.
#[derive(Serialize)]
pub(crate) struct LogSigningPayload {
    object_key: String,
    message: LogMessage,
}

/// A log record whose message signature and writing session's attestation/PCRs
/// have both been verified.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
    pub build_pcrs: BuildPcrs,
}

impl VerifiedLogRecord {
    pub fn new(
        object_key: String,
        session_id: SessionID,
        timestamp_ms: UnixMillis,
        message: LogMessage,
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
        let timestamp_ms = now_timestamp_ms();
        if message.is_allowed_unsigned() {
            Self::unsigned(session_id, message, timestamp_ms)
        } else {
            Self::signed(session_id, message, signing_key, timestamp_ms)
        }
    }

    /// Full S3 object key for this log record (directory + file name). See the
    /// `hashi-guardian` README for the canonical per-log-type key layout.
    pub fn object_key(&self) -> String {
        Self::derive_object_key(&self.session_id, self.timestamp_ms, &self.message)
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
    ) -> Self {
        let object_key = Self::derive_object_key(&session_id, timestamp_ms, &message);
        let signed = GuardianSigned::new(
            LogSigningPayload {
                object_key,
                message,
            },
            signing_key,
            timestamp_ms,
        );
        Self {
            session_id,
            timestamp_ms: signed.timestamp_ms,
            message: signed.data.message,
            signature: Some(signed.signature),
        }
    }

    fn unsigned(session_id: SessionID, message: LogMessage, timestamp_ms: UnixMillis) -> Self {
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

    pub fn verify(
        self,
        object_key: &str,
        pub_key: &GuardianPubKey,
    ) -> GuardianResult<(SessionID, UnixMillis, LogMessage)> {
        self.validate_object_key(object_key)?;
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
                    object_key: object_key.to_owned(),
                    message,
                },
                timestamp_ms,
                signature,
            }
            .verify(pub_key)?
            .message
        };

        Ok((session_id, timestamp_ms, message))
    }

    pub fn verify_unsigned(
        self,
        object_key: &str,
    ) -> GuardianResult<(SessionID, UnixMillis, LogMessage)> {
        if !self.message.is_allowed_unsigned() {
            return Err(InvalidInputs(
                "expected unsigned log record but message requires a signature".into(),
            ));
        }
        self.validate_object_key(object_key)?;
        Ok((self.session_id, self.timestamp_ms, self.message))
    }

    fn validate_object_key(&self, actual_key: &str) -> GuardianResult<()> {
        let canonical_key =
            Self::derive_object_key(&self.session_id, self.timestamp_ms, &self.message);
        if actual_key != canonical_key {
            return Err(InvalidInputs(format!(
                "log object key mismatch: expected {canonical_key}, S3 returned {actual_key}"
            )));
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

    fn derive_object_key(
        session_id: &str,
        timestamp_ms: UnixMillis,
        message: &LogMessage,
    ) -> String {
        let dir = message.log_dir(timestamp_ms);
        let log_name = message.log_name(session_id);
        format!("{}{}", dir, log_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
    use crate::guardian::GuardianError;
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

    fn set_timestamp(log: &mut LogRecord, timestamp_ms: UnixMillis) {
        log.timestamp_ms = timestamp_ms;
    }

    fn signed_heartbeat(timestamp_ms: UnixMillis) -> (LogRecord, GuardianSignKeyPair) {
        let signing_key = GuardianSignKeyPair::from([13u8; 32]);
        let log = LogRecord::signed(
            "session-key-binding".to_string(),
            LogMessage::Heartbeat { seq: 42 },
            &signing_key,
            timestamp_ms,
        );
        (log, signing_key)
    }

    fn assert_writer_key_is_stable_and_verifies(log: LogRecord, signing_key: &GuardianSignKeyPair) {
        let writer_key = log.object_key();
        for _ in 0..4 {
            assert_eq!(
                log.object_key(),
                writer_key,
                "a record must keep the same object key after construction"
            );
        }

        let body = serde_json::to_vec(&log).unwrap();
        let record_read_from_s3: LogRecord = serde_json::from_slice(&body).unwrap();
        record_read_from_s3
            .verify(&writer_key, &signing_key.verification_key())
            .expect("the serialized record must verify at the key used by the writer");
    }

    #[test]
    fn withdrawal_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([16u8; 32]);
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let log = LogRecord::signed(
            "session-withdraw-failure".to_string(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                request_data: request_data.into(),
                request_sign,
                error: GuardianError::RateLimitExceeded,
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn committee_update_failure_writer_key_is_stable_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([17u8; 32]);
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, _) = signed_request.into_parts();
        let log = LogRecord::signed(
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
            1_700_000_000_000,
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn signed_log_verifies_at_canonical_object_key() {
        let (log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let object_key = log.object_key().to_string();

        let (_, timestamp_ms, message) = log
            .verify(&object_key, &signing_key.verification_key())
            .expect("record should verify at its intended S3 key");

        assert_eq!(timestamp_ms, 1_700_000_000_000);
        assert!(matches!(message, LogMessage::Heartbeat { seq: 42 }));
    }

    #[test]
    fn signed_log_rejects_replay_at_another_s3_key() {
        let (log, signing_key) = signed_heartbeat(1_700_000_000_000);

        let err = log
            .verify(
                "heartbeat/2023/11/14/22/copied-record.json",
                &signing_key.verification_key(),
            )
            .expect_err("record copied to another S3 key must be rejected");

        assert!(format!("{err:?}").contains("log object key mismatch"));
    }

    #[test]
    fn signed_log_rejects_tampered_key_derivation_fields() {
        let (log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let mut tampered: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        tampered.message = LogMessage::Heartbeat { seq: 43 };
        let tampered_key = tampered.object_key();

        let err = tampered
            .verify(&tampered_key, &signing_key.verification_key())
            .expect_err("signature must cover the canonical object key and message");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn unsigned_log_rejects_replay_at_another_s3_key() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = session_id_from_signing_pubkey(&signing_key.verification_key());
        let log = LogRecord::unsigned(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            1_700_000_000_000,
        );

        let err = log
            .verify_unsigned("init/copied-attestation.json")
            .expect_err("unsigned record copied to another S3 key must be rejected");

        assert!(format!("{err:?}").contains("log object key mismatch"));
    }

    #[test]
    fn unsigned_attestation_rejects_session_not_derived_from_signing_key() {
        let signing_key = GuardianSignKeyPair::from([15u8; 32]);
        let log = LogRecord::unsigned(
            "forged-session".to_string(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            1_700_000_000_000,
        );
        let object_key = log.object_key();

        let err = log
            .verify_unsigned(&object_key)
            .expect_err("attestation session ID must come from its signing public key");

        assert!(format!("{err:?}").contains("attestation session ID mismatch"));
    }

    #[test]
    fn object_key_for_init_attestation_unsigned() {
        let session_id = "session-a".to_string();
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let mut log = LogRecord::new(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
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
    fn object_key_and_lock_for_kp_share_state() {
        use crate::guardian::KpShareState;

        let session_id = "session-d".to_string();
        let signing_key = GuardianSignKeyPair::from([10u8; 32]);
        let mut log = LogRecord::new(
            session_id,
            LogMessage::KpShareState(Box::new(KpShareState::new(
                7,
                3,
                KPEncryptedShares::new(vec![]).unwrap(),
            ))),
            &signing_key,
        );
        set_timestamp(&mut log, 1_700_000_000_000);

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
        let log = LogRecord::new(
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

        let mut log = LogRecord::new(
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
        );
        set_timestamp(&mut log, timestamp_ms);

        assert_eq!(
            log.object_key(),
            format!("withdraw/2023/11/14/22/success-{seq:020}-session-c-wid{wid}.json"),
        );
    }
}
