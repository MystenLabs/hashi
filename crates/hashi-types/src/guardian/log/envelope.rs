// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `LogRecord` envelope written to S3: it wraps a `super::message::LogMessage`
//! with the session id, timestamp, and (for signed logs) the guardian signature,
//! and derives the object key + lock duration from the wrapped message.

use super::S3_OBJECT_LOCK_DURATION_CEREMONY;
use super::S3_OBJECT_LOCK_DURATION_COMMITTEE_UPDATE;
use super::S3_OBJECT_LOCK_DURATION_HEARTBEAT;
use super::S3_OBJECT_LOCK_DURATION_INIT;
use super::S3_OBJECT_LOCK_DURATION_SHARES;
use super::S3_OBJECT_LOCK_DURATION_WITHDRAW;
use super::message::LogMessage;
use crate::guardian::GuardianError::InvalidInputs;
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

/// A verified log record where message authenticity has been checked.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: LogMessage,
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
        let dir = self.message.log_dir(self.timestamp_ms);
        let log_name = self.message.log_name(&self.session_id);
        format!("{}{}", dir, log_name)
    }

    pub fn object_lock_duration(&self) -> Duration {
        match &self.message {
            LogMessage::Init(..) => S3_OBJECT_LOCK_DURATION_INIT,
            LogMessage::Heartbeat { .. } => S3_OBJECT_LOCK_DURATION_HEARTBEAT,
            LogMessage::Withdrawal(..) => S3_OBJECT_LOCK_DURATION_WITHDRAW,
            LogMessage::Ceremony(..) => S3_OBJECT_LOCK_DURATION_CEREMONY,
            LogMessage::Shares(..) => S3_OBJECT_LOCK_DURATION_SHARES,
            LogMessage::CommitteeUpdate(..) => S3_OBJECT_LOCK_DURATION_COMMITTEE_UPDATE,
        }
    }

    fn signed(
        session_id: SessionID,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::InitLogMessage;
    use crate::guardian::LimiterState;
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
    fn object_key_and_lock_for_shares() {
        use crate::guardian::SharesLogMessage;

        let session_id = "session-d".to_string();
        let signing_key = GuardianSignKeyPair::from([10u8; 32]);
        let mut log = LogRecord::new(
            session_id,
            LogMessage::Shares(Box::new(SharesLogMessage {
                sharing_seq: 7,
                encrypted_shares: vec![],
            })),
            &signing_key,
        );
        set_timestamp(&mut log, 1_700_000_000_000);

        assert_eq!(
            log.object_key(),
            "shares/00000000000000000007-session-d.json"
        );
        assert_eq!(log.object_lock_duration(), S3_OBJECT_LOCK_DURATION_SHARES);
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
