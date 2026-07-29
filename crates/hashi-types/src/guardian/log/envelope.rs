// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `LogRecord` envelope written to S3: it wraps a `super::message::LogMessage`
//! with the session id, timestamp, and (for signed logs) the guardian signature.
//! The object key and lock duration are derived from the wrapped message.

use super::S3ObjectLockPolicy;
use super::message::LogMessage;
use super::message::LogMessageV1;
use super::message::ObjectKeyPattern;
use super::message::VersionedLogMessage;
use crate::guardian::BuildPcrs;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::GuardianSignKeyPair;
use crate::guardian::GuardianSignature;
use crate::guardian::IntentType;
use crate::guardian::SessionID;
use crate::guardian::SigningIntent;
use crate::guardian::UnixMillis;
use crate::guardian::now_timestamp_ms;
use crate::guardian::signing::sign_intent;
use crate::guardian::signing::verify_intent;
use serde::Deserialize;
use serde::Serialize;
use serde::de::Error as _;
use serde_json::Value;
use std::time::Duration;

/// Write: `LogMessage` -> `LogRecord` -> JSON body.
/// Read: actual S3 key + JSON body -> untrusted `LogRecord` -> `VerifiedLogRecord`.
#[derive(Debug)]
pub struct LogRecord {
    /// Final S3 destination selected before signing. Readers must compare this
    /// signed intended key with the actual key returned by S3.
    pub object_key: String,
    pub session_id: SessionID,
    pub timestamp_ms: UnixMillis,
    pub message: VersionedLogMessage,
    /// Present for signed logs; omitted for unsigned logs (currently only OIAttestationUnsigned).
    pub signature: Option<GuardianSignature>,
}

#[derive(Serialize)]
struct LogSigningPayload<'a> {
    schema_version: u64,
    session_id: &'a SessionID,
    object_key: &'a str,
    message: &'a VersionedLogMessage,
}

impl Serialize for LogRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct LogRecordWire<'a, M> {
            schema_version: u64,
            object_key: &'a str,
            session_id: &'a SessionID,
            timestamp_ms: UnixMillis,
            message: &'a M,
            #[serde(with = "crate::guardian::serde_utils::option_guardian_signature")]
            signature: &'a Option<GuardianSignature>,
        }

        match &self.message {
            VersionedLogMessage::V1(message) => LogRecordWire {
                schema_version: VersionedLogMessage::SCHEMA_VERSION_V1,
                object_key: &self.object_key,
                session_id: &self.session_id,
                timestamp_ms: self.timestamp_ms,
                message,
                signature: &self.signature,
            }
            .serialize(serializer),
            VersionedLogMessage::V2(message) => LogRecordWire {
                schema_version: VersionedLogMessage::SCHEMA_VERSION_V2,
                object_key: &self.object_key,
                session_id: &self.session_id,
                timestamp_ms: self.timestamp_ms,
                message,
                signature: &self.signature,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LogRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct LogRecordWire {
            schema_version: u64,
            object_key: String,
            session_id: SessionID,
            timestamp_ms: UnixMillis,
            message: Value,
            #[serde(with = "crate::guardian::serde_utils::option_guardian_signature")]
            signature: Option<GuardianSignature>,
        }

        let raw = LogRecordWire::deserialize(deserializer)?;
        let message = match raw.schema_version {
            VersionedLogMessage::SCHEMA_VERSION_V1 => {
                serde_json::from_value::<LogMessageV1>(raw.message)
                    .map(VersionedLogMessage::V1)
                    .map_err(D::Error::custom)?
            }
            VersionedLogMessage::SCHEMA_VERSION_V2 => {
                serde_json::from_value::<LogMessage>(raw.message)
                    .map(VersionedLogMessage::V2)
                    .map_err(D::Error::custom)?
            }
            version => {
                return Err(D::Error::custom(format!(
                    "unsupported log schema version: {version}"
                )));
            }
        };

        Ok(Self {
            object_key: raw.object_key,
            session_id: raw.session_id,
            timestamp_ms: raw.timestamp_ms,
            message,
            signature: raw.signature,
        })
    }
}

impl SigningIntent for LogSigningPayload<'_> {
    const INTENT: IntentType = IntentType::LogMessage;
}

/// A log record whose message signature and writing session's attestation/PCRs
/// have both been verified. Its message is normalized to the current schema.
/// If a future schema cannot be converted losslessly, this type should retain
/// `VersionedLogMessage` and leave version acceptance to callers instead.
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
        Self::new_at_timestamp(session_id, message, signing_key, now_timestamp_ms())
    }

    pub fn new_at_timestamp(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
    ) -> Self {
        let message = VersionedLogMessage::V2(message);
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

    pub fn object_lock_duration(&self, policy: S3ObjectLockPolicy) -> Duration {
        policy.duration_for(self.message.log_type())
    }

    fn signed(
        session_id: SessionID,
        message: VersionedLogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
        object_key: String,
    ) -> Self {
        let mut record = Self {
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
        record
    }

    fn unsigned(
        session_id: SessionID,
        message: VersionedLogMessage,
        timestamp_ms: UnixMillis,
        object_key: String,
    ) -> Self {
        assert!(
            message.is_allowed_unsigned(),
            "message must be Init(OIAttestationUnsigned)"
        );
        Self {
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
    ) -> GuardianResult<(SessionID, UnixMillis, LogMessage)> {
        if self.message.is_allowed_unsigned() {
            return Err(InvalidS3Log(
                "expected signed log record but message is unsigned".into(),
            ));
        }
        self.validate_object_key()?;
        self.validate_session_id(pub_key)?;
        let timestamp_ms = self.timestamp_ms;
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| InvalidS3Log("missing log signature".into()))?;
        verify_intent(&self.signing_payload(), timestamp_ms, signature, pub_key)
            .map_err(|e| InvalidS3Log(format!("invalid log signature: {e}")))?;

        let message = self
            .message
            .into_current()
            .map_err(|e| InvalidS3Log(format!("log schema conversion failed: {e}")))?;
        Ok((self.session_id, timestamp_ms, message))
    }

    /// Validates the unsigned OI-attestation record's envelope and canonical
    /// session. The Nitro attestation itself must be authenticated separately.
    pub fn validate_unsigned(self) -> GuardianResult<(SessionID, UnixMillis, LogMessage)> {
        if !self.message.is_allowed_unsigned() {
            return Err(InvalidS3Log(
                "expected unsigned log record but message requires a signature".into(),
            ));
        }
        if self.signature.is_some() {
            return Err(InvalidS3Log(
                "unsigned log record must not contain a signature".into(),
            ));
        }
        self.validate_object_key()?;
        let init = match &self.message {
            VersionedLogMessage::V1(LogMessageV1::Init(init)) => init,
            VersionedLogMessage::V2(LogMessage::Init(init)) => init,
            _ => unreachable!("is_allowed_unsigned only permits an init message"),
        };
        let super::message::InitLogMessage::OIAttestationUnsigned {
            signing_public_key, ..
        } = init.as_ref()
        else {
            unreachable!("is_allowed_unsigned only permits OIAttestationUnsigned");
        };
        self.validate_session_id(signing_public_key)?;
        let message = self
            .message
            .into_current()
            .map_err(|e| InvalidS3Log(format!("log schema conversion failed: {e}")))?;
        Ok((self.session_id, self.timestamp_ms, message))
    }

    /// Rejects a record whose signed intended key differs from the key at which
    /// the S3 reader found it.
    pub fn validate_actual_object_key(&self, actual_object_key: &str) -> GuardianResult<()> {
        if self.object_key != actual_object_key {
            return Err(InvalidS3Log(format!(
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

    fn signing_payload(&self) -> LogSigningPayload<'_> {
        LogSigningPayload {
            schema_version: self.message.schema_version(),
            session_id: &self.session_id,
            object_key: &self.object_key,
            message: &self.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CeremonyLogMessage;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
    use crate::guardian::GetGuardianInfoResponse;
    use crate::guardian::GuardianError;
    use crate::guardian::GuardianSigned;
    use crate::guardian::HeartbeatLogMessage;
    use crate::guardian::InitLogMessage;
    use crate::guardian::KPEncryptedSharesRoster;
    use crate::guardian::KpShareStateLogMessage;
    use crate::guardian::LimiterState;
    use crate::guardian::LogMessageV2;
    use crate::guardian::MAINNET_S3_OBJECT_LOCK_POLICY;
    use crate::guardian::NitroAttestation;
    use crate::guardian::RotateKpsResponse;
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

    #[test]
    fn every_log_message_json_round_trips_and_verifies() {
        let signing_key = GuardianSignKeyPair::from([21u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let btc_master_pubkey = crate::bitcoin::create_btc_keypair_for_test(&[3u8; 32])
            .x_only_public_key()
            .0;
        let instance_0 = test_sharing_instance(0);
        let instance_1 = test_sharing_instance(1);
        let (signed_request, committee_0) =
            StandardWithdrawalRequest::mock_signed_and_committee_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed_request.into_parts();
        let request_data: StandardWithdrawalRequestWire = request_data.into();
        let response = GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing().data;
        let encrypted_shares = GuardianSigned::<RotateKpsResponse>::mock_for_testing()
            .data
            .encrypted_shares;
        let (guardian_info, _) = GetGuardianInfoResponse::mock_for_testing().into_info_unchecked();
        let committee_0: crate::move_types::Committee = (&committee_0).into();
        let mut committee_1 = committee_0.clone();
        committee_1.epoch = 1;

        let cases = vec![
            (
                "heartbeat",
                LogMessage::Heartbeat(HeartbeatLogMessage::new(1)),
            ),
            (
                "init OI attestation",
                LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                    attestation: NitroAttestation::new(vec![1, 2, 3]),
                    signing_public_key: signing_key.verification_key(),
                })),
            ),
            (
                "init OI guardian info",
                LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(
                    guardian_info,
                )))),
            ),
            (
                "init PI complete",
                LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                    sharing_seq: 0,
                    share_ids: vec![NonZeroU16::new(1).unwrap()],
                    enclave_btc_pubkey: btc_master_pubkey,
                })),
            ),
            (
                "init OA activated",
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
            ),
            (
                "withdrawal success",
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
            ),
            (
                "withdrawal failure",
                LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Failure {
                    request_data,
                    request_sign: request_sign.clone(),
                    error: GuardianError::RateLimitExceeded,
                })),
            ),
            (
                "ceremony new key",
                LogMessage::Ceremony(Box::new(CeremonyLogMessage::NewKey {
                    instance: instance_0.clone(),
                    btc_master_pubkey,
                })),
            ),
            (
                "ceremony rotate",
                LogMessage::Ceremony(Box::new(CeremonyLogMessage::Rotate {
                    old_instance: instance_0,
                    new_instance: instance_1,
                    btc_master_pubkey,
                })),
            ),
            (
                "KP share state",
                LogMessage::KpShareState(Box::new(KpShareStateLogMessage::new(
                    0,
                    0,
                    encrypted_shares,
                ))),
            ),
            (
                "committee update success",
                LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage::Success {
                    from_epoch: 0,
                    new_committee: committee_1.clone(),
                    request_sign: request_sign.clone(),
                })),
            ),
            (
                "committee update failure",
                LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage::Failure {
                    from_epoch: 0,
                    new_committee: committee_1,
                    request_sign,
                    error: GuardianError::InvalidInputs("test failure".into()),
                })),
            ),
            (
                "genesis",
                LogMessage::Genesis(Box::new(GenesisLogMessage {
                    committee: committee_0,
                })),
            ),
        ];

        for (name, message) in cases {
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
            decoded
                .validate_actual_object_key(&object_key)
                .unwrap_or_else(|error| panic!("{name} failed key validation: {error}"));
            if decoded.message.is_allowed_unsigned() {
                decoded
                    .validate_unsigned()
                    .unwrap_or_else(|error| panic!("{name} failed validation: {error}"));
            } else {
                decoded
                    .verify(&signing_key.verification_key())
                    .unwrap_or_else(|error| panic!("{name} failed verification: {error}"));
            }
        }
    }

    #[test]
    fn deployed_v1_kp_share_state_verifies_and_normalizes() {
        let fixture = r#"{"schema_version":1,"object_key":"kp-shares/00000000000000000000/00000000000000000000-916c711a5e81c2b0.json","session_id":"916c711a5e81c2b0","timestamp_ms":1784219535816,"message":{"KpShareState":{"sharing_seq":0,"cert_seq":0,"encrypted_shares":[{"id":1,"recipient_fingerprint":"010AFFD5514AE454CA0D56DAA40FE24388998D2A","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4DT5hsKqzbvdwSAQdACnLThsK4Jq+u0g98VJzmYXrG05xLKgM1ki4FSGrOljkw\ndnHArbGaerEC8lBXZPVNhxMB8rOAfvgqxOUtt7SIMmjGIZMy7tzwfbM1YL45wgac\n0lkBE7TsICEPN/B/EwheDv/Ooid3NTDsoIsUGGuqtzUPCVYJTGPR+LWVY+F2xZxb\nHaLZO65VgrA3pcnyLsUy8iN3giOrIxmiZy/GjQBUwkeSCbVuopTZ2mpxPg==\n=7m3k\n-----END PGP MESSAGE-----\n"},{"id":2,"recipient_fingerprint":"69A798B4CD1FE3F7C827381BC56DF2575EC846C3","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4DIHt6s8jZpqASAQdALWbHtxu0R/ANnNighIV7VtFgkIX3CGJzfW51GkSJkBQw\n7Ec2Y2wBmo4sDM2VGmxqK5ADvGVSYgLvIlByRdRV2NaJ1xkjHUoA39PDTqCvwCOK\n0lkBOZPrJPrBInDax3ceQwDkC/rkJrQXT8oVWGxNjxp244q66jhMdOBZSEc8T/oZ\noAdjEccCcDLYt+S+bEVZeuNhZowDSx14soiALI16hrzbDqJq04e7K9W0uQ==\n=tfbb\n-----END PGP MESSAGE-----\n"},{"id":3,"recipient_fingerprint":"8D798722C24B2A15C15036A1DEFA2C01C4350A31","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4DZcZnV1kFupoSAQdA4X4hRbapAgL8eAouMEM0aRE4frVwmQZVHsXB6aOOxgkw\nsc2w0UU8bLzgt3aCe4HqBA9/v3jlKqK4STYVRFzG6o8fa+tb2qX94g6bCcIE07x4\n0lkBeTRYLlUlg7Jl2s7X9d9Ns60O8A2DQKwSYtQZV1pEwX44UQPz8Od/C9nIPeLP\nQEIA1BYRghu0ePQaqsfKohRXUunOrgVpYSCNFoupOKoVTl0qFgeDz5dw7Q==\n=giUp\n-----END PGP MESSAGE-----\n"},{"id":4,"recipient_fingerprint":"5551B442C80AB4D9CF3C95B90DA471909B35BFE9","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4DJ51dk/19HSASAQdAgq4QrNM43HykXcLxDfRtHHRtd4BdVJBirC2esDoXEjkw\nF7YLVWrMoXUtwOxFqXGkoUhEhfPAzdLG3WyuZQDnOdPBl0r/2qxmlmZIjFFBGXVc\n0lkBLfdxmJ8BOQYcaiEhBODpY7o2xO13agT28X6Uyv3rc5qw5km1WDw5+AlTLKZj\nw7aathIK+Qof15Tj7VxzSzRmo/pIf/Plcz9JoBNOYPgz/ewuzsPzDQ9+Qw==\n=iAGD\n-----END PGP MESSAGE-----\n"},{"id":5,"recipient_fingerprint":"354807E1940BFC2763D15EBB8E7048E384EBBC7A","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4D6mDrwWj9BrASAQdAazktC+Jd2EMtE8Gav7ROlkVmL+Ty1duA3RttbKQ5eAEw\nbKIxkq1Jp9J4ZqcvjfxcBzVOfZPQwdhxXxDv2pOUG7ioZuDTRlGNNbsiyodvmlgy\n0lkB8eaGI0/LBZ++1vbGsZ/uQ7phGVFkPdcZzXm0pyD1poDKhTTyiHpAgDub2yph\nAAWsEIYzjLQWJvuOw0JXzwu1HBy+z5QTY4nK+wKrh6ojcLKjjyRVehhtTw==\n=m9Mm\n-----END PGP MESSAGE-----\n"},{"id":6,"recipient_fingerprint":"CB27C30ABAAC7EEDE92E71C6017C4627E937F5B0","armored_ciphertext":"-----BEGIN PGP MESSAGE-----\n\nwV4DuqwfDzk48aQSAQdAoJevGCVjo+1pD/WVPkWza4qGxBU9tsXbqE/kaSynsGYw\nskjzNOD5oY+/S0CMeH+6xspbLUZ9uZFy98fWOKMi9nbftH1nWXtKRdCNweaaCAPu\n0lkBR4DxLFCydQKfFzENlKRl9qc4m5NkVnjWaGR+cgK1U2UAPf/p82eRggyf6Obp\nNcdOnAfu0aLB70FESJEHtDFj36QCyC0SwTdtZwXUfCOo0AykDph9rTYVpA==\n=DQ4F\n-----END PGP MESSAGE-----\n"}]}},"signature":"2895193893f1feaea65fb6b441c011815c937df33cde136e4721f4173db86c1fe44a2095a6f8753fecbdaa5c99b744a22368f41ab8ca01edff99fafb6710a304"}"#;
        let record: LogRecord = serde_json::from_str(fixture).unwrap();
        assert!(matches!(
            &record.message,
            VersionedLogMessage::V1(LogMessageV1::KpShareState(..))
        ));
        assert_eq!(serde_json::to_string(&record).unwrap(), fixture);
        record
            .validate_actual_object_key(
                "kp-shares/00000000000000000000/00000000000000000000-916c711a5e81c2b0.json",
            )
            .unwrap();

        let signing_pubkey =
            hex::decode("916c711a5e81c2b032f15952b515205a20ef2a16f8a88da504885f392e314dca")
                .unwrap();
        let signing_pubkey = GuardianPubKey::try_from(signing_pubkey.as_slice()).unwrap();
        let (session_id, timestamp_ms, LogMessageV2::KpShareState(message)) = record
            .verify(&signing_pubkey)
            .expect("the deployed V1 signature must verify before normalization")
        else {
            panic!("expected normalized KP share state");
        };
        assert_eq!(session_id.as_str(), "916c711a5e81c2b0");
        assert_eq!(timestamp_ms, 1_784_219_535_816);
        assert_eq!(message.sharing_seq, 0);
        assert_eq!(message.cert_seq, 0);
        assert_eq!(message.encrypted_shares.share_count(), 6);
        let (share, ciphertext) = message
            .encrypted_shares
            .find_by_fingerprint("010AFFD5514AE454CA0D56DAA40FE24388998D2A")
            .expect("legacy ciphertext must be retained");
        assert_eq!(share.id.get(), 1);
        assert!(ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));
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
                error: GuardianError::RateLimitExceeded,
            })),
            &signing_key,
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
                error: GuardianError::InvalidInputs("test failure".to_string()),
            })),
            &signing_key,
        );

        assert_writer_key_is_stable_and_verifies(log, &signing_key);
    }

    #[test]
    fn signed_log_verifies_at_canonical_object_key() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);

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
        assert_eq!(json.get("schema_version").unwrap(), 2);
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
            .validate_actual_object_key(&object_key)
            .expect("embedded key should match the S3 destination");
        from_s3
            .verify(&signing_key.verification_key())
            .expect("serialized object key should be covered by the signature");
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        json["schema_version"] = serde_json::json!(3);

        let err = serde_json::from_value::<LogRecord>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported log schema version: 3")
        );
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
        tampered.message = LogMessage::Heartbeat(HeartbeatLogMessage::new(43)).into();
        tampered.object_key = format!(
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
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
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

        record_read_from_s3.object_key = relocated_key;
        let err = record_read_from_s3
            .verify(&signing_key.verification_key())
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
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut aliased: LogRecord =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        aliased.session_id = "aliased-session".into();
        aliased.object_key = GenesisLogMessage::object_key();

        let err = aliased
            .verify(&signing_key.verification_key())
            .expect_err("session ID must be part of the signed routing context");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn unsigned_log_rejects_replay_at_another_s3_key() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
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
            "forged-session".into(),
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
        let session_id: SessionID = "session-a".into();
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
            "init/session-a/01-oi-attestation-unsigned.json"
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
        from_json.verify(&signing_key.verification_key()).unwrap();
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
                KPEncryptedSharesRoster::new(vec![]).unwrap(),
            ))),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(
            log.object_key(),
            "kp-shares/00000000000000000007/00000000000000000003-session-d.json"
        );
        assert_eq!(
            log.object_lock_duration(TESTNET_S3_OBJECT_LOCK_POLICY),
            TESTNET_S3_OBJECT_LOCK_POLICY.short_lived
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
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(log.object_key(), GenesisLogMessage::object_key());
        assert_eq!(log.object_key(), "genesis/record.json");
        assert_eq!(
            log.object_lock_duration(MAINNET_S3_OBJECT_LOCK_POLICY),
            MAINNET_S3_OBJECT_LOCK_POLICY.long_lived
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
