// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! S3 log-record wire format and validation.
//!
//! Every [`SignedLogEntry`] carries a Guardian signature over its [`LogEntry`].
//! Deserialization checks the wire format and routing context; readers verify
//! the signing key's attestation before validating the signature.

use super::config::S3ObjectLockPolicy;
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

/// Routing context and versioned payload carried by a [`SignedLogEntry`].
///
/// Field order defines the BCS signing format.
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

/// A signed Guardian S3 log record with a flat JSON representation.
/// Readers must authenticate the signing key before trusting the signature.
#[derive(Debug)]
pub struct SignedLogEntry(GuardianSigned<LogEntry>);

#[derive(Deserialize)]
struct SignedLogEntryWire {
    schema_version: u64,
    object_key: String,
    session_id: SessionID,
    timestamp_ms: UnixMillis,
    message: Value,
    #[serde(with = "crate::guardian::serde::guardian_signature")]
    signature: GuardianSignature,
}

#[derive(Serialize)]
struct SignedLogEntryWireRef<'a> {
    schema_version: u64,
    object_key: &'a str,
    session_id: &'a SessionID,
    timestamp_ms: UnixMillis,
    message: &'a VersionedLogMessage,
    #[serde(with = "crate::guardian::serde::guardian_signature")]
    signature: GuardianSignature,
}

impl Serialize for SignedLogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = self.data();

        SignedLogEntryWireRef {
            schema_version: data.schema_version,
            object_key: &data.object_key,
            session_id: &data.session_id,
            timestamp_ms: data.timestamp_ms,
            message: &data.message,
            signature: self.0.signature,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedLogEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = SignedLogEntryWire::deserialize(deserializer)?;
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
        let expected = self
            .message
            .object_key(&self.session_id, self.timestamp_ms)
            .map_err(|e| {
                InvalidS3Log(format!(
                    "invalid log timestamp {}: {e:#}",
                    self.timestamp_ms
                ))
            })?;
        if self.object_key != expected {
            return Err(InvalidS3Log(format!(
                "non-canonical S3 object key: got {}, expected {expected}",
                self.object_key
            )));
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
}

impl SignedLogEntry {
    /// Sign a current-schema record using the current time.
    pub fn new(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
    ) -> Self {
        Self::new_at_timestamp(session_id, message, signing_key, now_timestamp_ms())
    }

    /// Sign a current-schema record using an explicit timestamp.
    pub fn new_at_timestamp(
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
        timestamp_ms: UnixMillis,
    ) -> Self {
        let message = VersionedLogMessage::V1(message);
        let object_key = message
            .object_key(&session_id, timestamp_ms)
            .expect("writer timestamp must be within the supported calendar range");
        let data = LogEntry::new(session_id, object_key, message, timestamp_ms)
            .expect("writer-constructed log entry must be intrinsically valid");
        Self(GuardianSigned::sign(data, signing_key))
    }

    /// Validate and construct a record from its untrusted flat wire format.
    fn try_from_wire(raw: SignedLogEntryWire) -> GuardianResult<Self> {
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

        let data = LogEntry::new(raw.session_id, raw.object_key, message, raw.timestamp_ms)?;
        Ok(Self(GuardianSigned::from_parts(data, raw.signature)))
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

    /// Return the versioned log message without signature verification.
    /// Verify the signing key and signature before you trust the message.
    pub fn message_unchecked(&self) -> &VersionedLogMessage {
        &self.data().message
    }

    /// Return the log payload type.
    pub fn log_type(&self) -> LogType {
        self.data().log_type()
    }

    /// Bind the session and verify the signature under an authenticated signing key.
    /// The reader must first verify the key's Nitro attestation and approved build.
    pub fn validate(&self, signing_public_key: &GuardianPubKey) -> GuardianResult<()> {
        self.data().validate_session_id(signing_public_key)?;
        self.0
            .verify_signature(signing_public_key)
            .map(|_| ())
            .map_err(|e| InvalidS3Log(format!("invalid log signature: {e}")))
    }

    /// Validate the record, then consume it and return its versioned entry.
    pub fn validate_into_entry(
        self,
        signing_public_key: &GuardianPubKey,
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
    /// This skips session binding and signature verification; the caller must
    /// establish trust independently.
    pub fn into_entry_unchecked(self) -> LogEntry {
        self.0.into_data_unchecked()
    }

    fn data(&self) -> &LogEntry {
        self.0.data_unchecked()
    }

    #[cfg(test)]
    fn data_mut(&mut self) -> &mut LogEntry {
        self.0.data_unchecked_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::CeremonyLogMessage;
    use crate::guardian::CeremonyProposalLogMessage;
    use crate::guardian::CommitteeUpdateLogMessage;
    use crate::guardian::GenesisLogMessage;
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

    fn signed_heartbeat(timestamp_ms: UnixMillis) -> (String, SignedLogEntry, GuardianSignKeyPair) {
        let signing_key = GuardianSignKeyPair::from([13u8; 32]);
        let record = SignedLogEntry::new_at_timestamp(
            heartbeat_session_id(),
            LogMessage::Heartbeat(HeartbeatLogMessage::new(42)),
            &signing_key,
            timestamp_ms,
        );
        let object_key = record.object_key().to_string();
        (object_key, record, signing_key)
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
        let btc_master_pubkey =
            crate::bitcoin::BitcoinKeypair::from_seckey_slice(&crate::bitcoin::BTC_LIB, &[3u8; 32])
                .expect("valid test secret key")
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
        ceremony_info.mode = OperatorInitMode::Ceremony;
        let mut bootstrap_info = guardian_info.clone();
        let OperatorInitMode::Withdraw(withdraw) = &mut bootstrap_info.mode else {
            unreachable!("withdraw dummy initialization");
        };
        withdraw.genesis_state_hash =
            Some(crate::guardian::GenesisState::mock_for_testing().digest());
        bootstrap_info.deployment.pcr_allowlist = crate::guardian::PcrAllowlist::new(
            bootstrap_info
                .deployment
                .pcr_allowlist
                .current_build()
                .clone(),
            [crate::guardian::BuildPcrs::mock_for_testing("previous", 1)],
        )
        .unwrap();
        let committee_0: crate::move_types::Committee = (&committee_0).into();
        let mut committee_1 = committee_0.clone();
        committee_1.epoch = 1;

        vec![
            LogMessage::Heartbeat(HeartbeatLogMessage::new(1)),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestation {
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
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage {
                txid: Txid::from_slice(&[3; 32]).unwrap(),
                post_state: LimiterState {
                    num_tokens_available: 10,
                    last_updated_at: 20,
                    next_seq: request_data.seq + 1,
                },
                request_data,
                request_sign: request_sign.clone(),
                response,
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
            LogMessage::CommitteeUpdate(Box::new(CommitteeUpdateLogMessage {
                from_epoch: 0,
                new_committee: committee_1,
                request_sign,
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
                InitLogMessage::OIAttestation { .. } => "init/oi-attestation",
                InitLogMessage::OIGuardianInfo(info) => match &info.mode {
                    OperatorInitMode::Ceremony => "init/oi-guardian-info-ceremony",
                    OperatorInitMode::Withdraw(withdraw) => match withdraw.genesis_state_hash {
                        None => "init/oi-guardian-info-without-genesis",
                        Some(_) => "init/oi-guardian-info-with-genesis",
                    },
                },
                InitLogMessage::PIEnclaveFullyInitialized { .. } => {
                    "init/pi-enclave-fully-initialized"
                }
                InitLogMessage::OAActivated { .. } => "init/oa-activated",
            },
            LogMessage::Withdrawal(_) => "withdrawal/success",
            LogMessage::Ceremony(message) => match message.as_ref() {
                CeremonyLogMessage::NewKey { .. } => "ceremony/new-key",
                CeremonyLogMessage::Rotate { .. } => "ceremony/rotate",
            },
            LogMessage::CeremonyProposal(message) => match &message.ceremony {
                CeremonyLogMessage::NewKey { .. } => "ceremony-proposal/new-key",
                CeremonyLogMessage::Rotate { .. } => "ceremony-proposal/rotate",
            },
            LogMessage::KpShareState(_) => "kp-share-state/kp-share-state",
            LogMessage::CommitteeUpdate(_) => "committee-update/success",
            LogMessage::Genesis(_) => "genesis/genesis",
        }
    }

    fn fixture_signing_key() -> GuardianSignKeyPair {
        GuardianSignKeyPair::from([21u8; 32])
    }

    fn dummy_log_record(message: LogMessage) -> SignedLogEntry {
        let signing_key = fixture_signing_key();
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        SignedLogEntry::new_at_timestamp(session_id, message, &signing_key, 1_700_000_000_000)
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
    fn withdrawal_seq_round_trips_through_its_object_key() {
        for message in dummy_log_messages() {
            let LogMessage::Withdrawal(withdrawal) = &message else {
                continue;
            };
            let seq = withdrawal.request_data.seq;
            let wid = withdrawal.request_data.wid;
            let record = dummy_log_record(message);
            assert_eq!(
                WithdrawalLogMessage::parse_object_key(record.object_key()),
                Some((seq, wid))
            );
        }
    }

    #[test]
    fn hourly_log_deserialization_rejects_out_of_range_timestamps() {
        for message in dummy_log_messages() {
            if !matches!(
                &message,
                LogMessage::Heartbeat(_) | LogMessage::Withdrawal(_)
            ) {
                continue;
            }
            let mut json = serde_json::to_value(dummy_log_record(message)).unwrap();
            json["timestamp_ms"] = serde_json::json!(u64::MAX);
            let error = serde_json::from_value::<SignedLogEntry>(json).unwrap_err();
            assert!(
                error.to_string().contains("invalid log timestamp"),
                "{error}"
            );
        }
    }

    #[test]
    fn dummy_log_fixtures_round_trip_and_verify() {
        let signing_key = fixture_signing_key();
        for message in dummy_log_messages() {
            let name = fixture_name(&message);
            let expected = dummy_log_record(message);
            let json = std::fs::read_to_string(fixture_path(name)).unwrap();
            let decoded: SignedLogEntry = serde_json::from_str(&json)
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
            decoded
                .validate(&signing_key.verification_key())
                .unwrap_or_else(|error| panic!("{name} failed validation: {error}"));
        }
    }

    #[test]
    fn every_log_message_json_round_trips_and_verifies() {
        let signing_key = fixture_signing_key();
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        for message in dummy_log_messages() {
            let name = fixture_name(&message);
            let record = SignedLogEntry::new_at_timestamp(
                session_id.clone(),
                message,
                &signing_key,
                1_700_000_000_000,
            );
            let object_key = record.object_key().to_owned();
            let json = serde_json::to_vec(&record).unwrap();
            let decoded: SignedLogEntry = serde_json::from_slice(&json)
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
            decoded
                .validate(&signing_key.verification_key())
                .unwrap_or_else(|error| panic!("{name} failed verification: {error}"));
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
        let record = SignedLogEntry::new_at_timestamp(
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

        let decoded: SignedLogEntry = serde_json::from_value(json).unwrap();
        assert!(matches!(
            decoded.message_unchecked(),
            VersionedLogMessage::V1(LogMessageV1::KpShareState(..))
        ));
        decoded.validate(&signing_key.verification_key()).unwrap();
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
        let record = SignedLogEntry::new_at_timestamp(
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

        assert!(serde_json::from_value::<SignedLogEntry>(json).is_err());
    }

    #[test]
    fn signed_log_verifies_at_canonical_object_key() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);

        log.validate(&signing_key.verification_key())
            .expect("record should verify at its intended S3 key");

        assert_eq!(log.timestamp_ms(), 1_700_000_000_000);
        assert!(matches!(
            log.message_unchecked(),
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
        assert!(serde_json::from_value::<SignedLogEntry>(malformed).is_err());

        let from_s3: SignedLogEntry = serde_json::from_value(json).unwrap();
        from_s3
            .validate(&signing_key.verification_key())
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
            GuardianSigningIntentType::LogEntry as u8,
            payload,
            data.timestamp_ms,
        ))
        .unwrap();
        assert_eq!(log.0.signature, signing_key.sign(&signed_bytes));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let (_, log, _) = signed_heartbeat(1_700_000_000_000);
        let mut json = serde_json::to_value(log).unwrap();
        for version in [0, 2, 3] {
            json["schema_version"] = serde_json::json!(version);
            let err = serde_json::from_value::<SignedLogEntry>(json.clone()).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("unsupported log schema version: {version}"))
            );
        }
    }

    #[test]
    fn every_message_requires_a_signature_during_deserialization() {
        for message in dummy_log_messages() {
            let json = serde_json::to_value(dummy_log_record(message)).unwrap();
            for missing in [false, true] {
                let mut json = json.clone();
                if missing {
                    json.as_object_mut().unwrap().remove("signature");
                } else {
                    json["signature"] = serde_json::Value::Null;
                }
                assert!(serde_json::from_value::<SignedLogEntry>(json).is_err());
            }
        }
    }

    #[test]
    fn signed_log_rejects_tampered_key_derivation_fields() {
        let (_, log, signing_key) = signed_heartbeat(1_700_000_000_000);
        let mut tampered: SignedLogEntry =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        tampered.data_mut().message = LogMessage::Heartbeat(HeartbeatLogMessage::new(43)).into();
        tampered.data_mut().object_key = format!(
            "heartbeat/2023/11/14/22/{}-00000000000000000043.json",
            heartbeat_session_id()
        );

        let err = tampered
            .validate(&signing_key.verification_key())
            .expect_err("signature must cover the canonical object key and message");

        assert!(format!("{err:?}").contains("signature invalid"));
    }

    #[test]
    fn signed_log_binds_session_even_when_key_does_not_contain_it() {
        let signing_key = GuardianSignKeyPair::from([19u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = SignedLogEntry::new_at_timestamp(
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
        let mut aliased: SignedLogEntry =
            serde_json::from_slice(&serde_json::to_vec(&log).unwrap()).unwrap();
        aliased.data_mut().session_id = "aliased-session".into();
        aliased.data_mut().object_key = GenesisLogMessage::object_key();

        let err = aliased
            .validate(&signing_key.verification_key())
            .expect_err("session ID must be part of the signed routing context");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn attestation_log_rejects_replay_at_another_s3_key_during_deserialization() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = SignedLogEntry::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestation {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        let mut json = serde_json::to_value(log).unwrap();
        json["object_key"] = "init/copied-attestation.json".into();
        let err = serde_json::from_value::<SignedLogEntry>(json)
            .expect_err("attestation record copied to another S3 key must be rejected");

        assert!(format!("{err:?}").contains("non-canonical S3 object key"));
    }

    #[test]
    fn attestation_rejects_forged_session_during_validation() {
        let signing_key = GuardianSignKeyPair::from([15u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = SignedLogEntry::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestation {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut json = serde_json::to_value(log).unwrap();
        json["session_id"] = "forged-session".into();
        json["object_key"] = "init/forged-session/01-oi-attestation.json".into();
        let decoded = serde_json::from_value::<SignedLogEntry>(json).unwrap();
        let err = decoded
            .validate(&signing_key.verification_key())
            .expect_err("attestation session ID must come from its signing public key");

        assert!(format!("{err:?}").contains("session ID mismatch"));
    }

    #[test]
    fn attestation_log_round_trips_with_session_signature() {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = SignedLogEntry::new_at_timestamp(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestation {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );

        assert_eq!(
            log.object_key(),
            format!("init/{session_id}/01-oi-attestation.json")
        );

        let json = serde_json::to_value(&log).unwrap();
        let message = &json["message"]["Init"]["OIAttestation"];
        assert_eq!(message["attestation"], "AQID");
        assert_eq!(
            message["signing_public_key"],
            hex::encode(signing_key.verification_key().as_bytes())
        );
        assert_eq!(json["signature"], hex::encode(log.0.signature.to_bytes()));
        let from_json: SignedLogEntry = serde_json::from_value(json).unwrap();
        assert_eq!(from_json.object_key(), log.object_key());
        from_json.validate(&signing_key.verification_key()).unwrap();

        let mut tampered = serde_json::to_value(&log).unwrap();
        tampered["timestamp_ms"] = serde_json::json!(log.timestamp_ms() + 1);
        let tampered = serde_json::from_value::<SignedLogEntry>(tampered).unwrap();
        let error = tampered
            .validate(&signing_key.verification_key())
            .unwrap_err();
        assert!(
            matches!(error, InvalidS3Log(message) if message.contains("invalid log signature"))
        );
    }

    #[test]
    fn operator_activation_json_encodes_hashes_as_hex() {
        let signing_key = GuardianSignKeyPair::from([20u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let log = SignedLogEntry::new_at_timestamp(
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

        let from_json: SignedLogEntry = serde_json::from_value(json).unwrap();
        from_json.validate(&signing_key.verification_key()).unwrap();
    }

    #[test]
    fn object_key_for_heartbeat() {
        let session_id: SessionID = "session-b".into();
        let signing_key = GuardianSignKeyPair::from([8u8; 32]);
        let seq = 42_u64;
        let timestamp_ms = 1_700_000_000_000;

        let log = SignedLogEntry::new_at_timestamp(
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
        let log = SignedLogEntry::new_at_timestamp(
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
            "kp-shares/00000000000000000007/00000000000000000003.json"
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
        let btc_master_pubkey =
            crate::bitcoin::BitcoinKeypair::from_seckey_slice(&crate::bitcoin::BTC_LIB, &[4u8; 32])
                .expect("valid test secret key")
                .x_only_public_key()
                .0;
        let proposal = CeremonyProposalLogMessage::new(
            CeremonyLogMessage::NewKey {
                instance: test_sharing_instance(0),
                btc_master_pubkey,
            },
            RotateKpSetResponse::mock_for_testing().encrypted_shares,
        );
        let log = SignedLogEntry::new_at_timestamp(
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
        let log = SignedLogEntry::new_at_timestamp(
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

        let log = SignedLogEntry::new_at_timestamp(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage {
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
            format!("withdraw/2023/11/14/22/{seq:020}-wid{wid}.json"),
        );
    }
}
