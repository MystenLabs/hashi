// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::LogType;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;

/// Initialization checkpoint required by or verified for a session.
///
/// Variants are ordered by the durable log prefix each checkpoint proves.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum InitCheckpoint {
    /// OI attestation and info (01-02), verified while initializing VerifiedSessionInfo.
    OperatorInitialized,
    /// The complete withdraw-mode initialization sequence (01-04).
    OperatorActivated,
}

/// A session's attestation-anchored signing key, signed [`GuardianInfo`], build
/// PCRs, and highest verified initialization checkpoint.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    signing_pubkey: GuardianPubKey,
    info: GuardianInfo,
    build_pcrs: BuildPcrs,
    verified_init_checkpoint: InitCheckpoint,
}

/// A log record whose message signature, writing session's attestation/PCRs,
/// and required initialization checkpoint have been verified. The exact
/// versioned entry is retained so callers can choose which schema versions they
/// accept and how to interpret them.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    entry: LogEntry,
    build_pcrs: BuildPcrs,
}

impl InitCheckpoint {
    /// Return the initialization checkpoint required before serving a log.
    /// Withdrawal and committee-update logs require 01-04; heartbeat, ceremony,
    /// and genesis logs require only 01-02. KP-share state is mode-dependent.
    /// Init logs use the dedicated init-log reader and are rejected here.
    fn required_for(log_type: LogType, mode: EnclaveMode) -> GuardianResult<Self> {
        let required = match log_type {
            LogType::Init => {
                return Err(InvalidS3Log(
                    "unexpected init log in non-init-log reader".into(),
                ));
            }
            LogType::Withdrawal | LogType::CommitteeUpdate => Self::OperatorActivated,
            LogType::KpShareState => match mode {
                EnclaveMode::Ceremony => Self::OperatorInitialized,
                EnclaveMode::Withdraw => Self::OperatorActivated,
            },
            LogType::Heartbeat | LogType::Ceremony | LogType::Genesis => Self::OperatorInitialized,
        };
        Ok(required)
    }
}

impl VerifiedSessionInfo {
    #[cfg(test)]
    pub(super) fn new_for_test(signing_pubkey: GuardianPubKey, build_pcrs: BuildPcrs) -> Self {
        Self {
            signing_pubkey,
            info: GuardianInfo::mock_for_testing(),
            build_pcrs,
            verified_init_checkpoint: InitCheckpoint::OperatorInitialized,
        }
    }

    pub(super) async fn read_from_s3(
        s3: &GuardianS3Client,
        session_id: &str,
        allowlist: &PcrAllowlist,
    ) -> GuardianResult<Self> {
        // 1. Attestation (unsigned: authenticated by AWS, not the enclave key) →
        //    the signing pubkey it commits to.
        let att_key = InitLogMessage::attestation_object_key(session_id);
        let attestation_message = Self::read_init_log(s3, &att_key, None).await?;
        let InitLogMessage::OIAttestationUnsigned {
            attestation,
            signing_public_key: signing_pubkey,
        } = *attestation_message
        else {
            return Err(InvalidS3Log(format!(
                "expected OIAttestationUnsigned at key {att_key}"
            )));
        };

        // 2. GuardianInfo, signature-verified under that pubkey → the reported build.
        let info_key = InitLogMessage::guardian_info_object_key(session_id);
        let info_message = Self::read_init_log(s3, &info_key, Some(&signing_pubkey)).await?;
        let InitLogMessage::OIGuardianInfo(info) = *info_message else {
            return Err(InvalidS3Log(format!(
                "expected OIGuardianInfo at key {info_key}"
            )));
        };
        let info = *info;

        // 3. Anchor the pubkey and pin PCR0 to the allowlist entry for the
        //    reported build. This replays a logged attestation whose short-lived
        //    leaf cert has typically expired, so the chain is checked at the
        //    document's own signed timestamp, not now.
        let build_pcrs = allowlist.resolve(&info.untrusted_git_revision)?.clone();
        attestation
            .verify_replay(&signing_pubkey, &build_pcrs)
            .map_err(|e| InvalidS3Log(format!("attestation at key {att_key}: {e}")))?;

        ensure_bucket_info_matches(session_id, info.bucket_info.as_ref(), s3.bucket_info())?;

        Ok(Self {
            signing_pubkey,
            info,
            build_pcrs,
            verified_init_checkpoint: InitCheckpoint::OperatorInitialized,
        })
    }

    /// Verify a record and the initialization checkpoint required to emit it.
    pub(super) async fn verify_record(
        &mut self,
        s3: &GuardianS3Client,
        record: LogRecord,
    ) -> GuardianResult<VerifiedLogRecord> {
        let entry = record.validate_into_entry(Some(&self.signing_pubkey))?;
        let required = InitCheckpoint::required_for(entry.log_type(), self.info.lifecycle.mode())?;
        self.ensure_init_checkpoint(s3, entry.session_id(), required)
            .await?;
        Ok(VerifiedLogRecord {
            entry,
            build_pcrs: self.build_pcrs.clone(),
        })
    }

    async fn ensure_init_checkpoint(
        &mut self,
        s3: &GuardianS3Client,
        session_id: &str,
        required: InitCheckpoint,
    ) -> GuardianResult<()> {
        if self.verified_init_checkpoint >= required {
            return Ok(());
        }

        match required {
            InitCheckpoint::OperatorInitialized => {
                unreachable!("session construction verifies operator initialization")
            }
            InitCheckpoint::OperatorActivated => {
                // Exact S3-key binding plus canonical init keys establishes each variant.
                let pi_key = InitLogMessage::pi_fully_initialized_object_key(session_id);
                Self::read_init_log(s3, &pi_key, Some(&self.signing_pubkey)).await?;

                let oa_key = InitLogMessage::oa_activated_object_key(session_id);
                Self::read_init_log(s3, &oa_key, Some(&self.signing_pubkey)).await?;
            }
        }

        self.verified_init_checkpoint = required;
        Ok(())
    }

    /// Read an init log and validate it with the supplied signing key, if any.
    async fn read_init_log(
        s3: &GuardianS3Client,
        key: &str,
        signing_pubkey: Option<&GuardianPubKey>,
    ) -> GuardianResult<Box<InitLogMessage>> {
        let record = s3.get_log_record(key).await?;
        let entry = record.validate_into_entry(signing_pubkey)?;
        match entry.into_message() {
            V1(LogMessageV1::Init(message)) | V2(LogMessageV2::Init(message)) => Ok(message),
            V1(_) | V2(_) => Err(InvalidS3Log(format!("expected an init log at key {key}"))),
        }
    }

    pub fn signing_pubkey(&self) -> &GuardianPubKey {
        &self.signing_pubkey
    }

    pub fn info(&self) -> &GuardianInfo {
        &self.info
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }
}

fn ensure_bucket_info_matches(
    session_id: &str,
    reported: Option<&S3BucketInfo>,
    expected: &S3BucketInfo,
) -> GuardianResult<()> {
    let reported = reported.ok_or_else(|| {
        InvalidS3Log(format!(
            "session {session_id} GuardianInfo is missing bucket_info"
        ))
    })?;
    if reported != expected {
        return Err(InvalidS3Log(format!(
            "session {session_id} GuardianInfo bucket_info {reported:?} does not match reader bucket_info {expected:?}"
        )));
    }
    Ok(())
}

impl VerifiedLogRecord {
    #[cfg(test)]
    pub(super) fn new_for_test(entry: LogEntry, build_pcrs: BuildPcrs) -> Self {
        Self { entry, build_pcrs }
    }

    pub fn entry(&self) -> &LogEntry {
        &self.entry
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }

    pub fn log_type(&self) -> LogType {
        self.entry.log_type()
    }

    pub fn into_entry(self) -> LogEntry {
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::primitives::DateTime;
    use aws_sdk_s3::types::ObjectLockMode;
    use aws_sdk_s3::types::ObjectVersion;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::ResolvedS3Config;
    use hashi_types::guardian::SessionID;
    use std::time::Duration;
    use std::time::SystemTime;

    fn bucket_info(bucket: &str, region: &str) -> S3BucketInfo {
        S3BucketInfo {
            bucket: bucket.into(),
            region: region.into(),
        }
    }

    #[test]
    fn matching_bucket_info_is_accepted() {
        let expected = bucket_info("guardian-bucket", "us-east-1");
        ensure_bucket_info_matches("session", Some(&expected), &expected).unwrap();
    }

    #[test]
    fn mismatched_bucket_info_is_rejected() {
        let expected = bucket_info("guardian-bucket", "us-east-1");
        let reported = bucket_info("other-bucket", "us-west-2");

        let error = ensure_bucket_info_matches("session", Some(&reported), &expected).unwrap_err();
        assert!(matches!(error, InvalidS3Log(message) if message.contains("does not match")));
    }

    #[test]
    fn missing_bucket_info_is_rejected() {
        let expected = bucket_info("guardian-bucket", "us-east-1");

        let error = ensure_bucket_info_matches("session", None, &expected).unwrap_err();
        assert!(matches!(error, InvalidS3Log(message) if message.contains("missing bucket_info")));
    }

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn listed_record(key: String) -> ListObjectVersionsOutput {
        ListObjectVersionsOutput::builder()
            .versions(ObjectVersion::builder().key(key).is_latest(true).build())
            .build()
    }

    fn locked_record(body: Vec<u8>) -> GetObjectOutput {
        GetObjectOutput::builder()
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(
                SystemTime::now() + Duration::from_secs(60),
            ))
            .body(ByteStream::from(body))
            .build()
    }

    #[test]
    fn required_init_checkpoint_matches_log_type_and_mode() {
        use InitCheckpoint::OperatorActivated;
        use InitCheckpoint::OperatorInitialized;

        for mode in [EnclaveMode::Ceremony, EnclaveMode::Withdraw] {
            assert_eq!(
                InitCheckpoint::required_for(LogType::Withdrawal, mode).unwrap(),
                OperatorActivated
            );
            assert_eq!(
                InitCheckpoint::required_for(LogType::CommitteeUpdate, mode).unwrap(),
                OperatorActivated
            );
            for log_type in [LogType::Heartbeat, LogType::Ceremony, LogType::Genesis] {
                assert_eq!(
                    InitCheckpoint::required_for(log_type, mode).unwrap(),
                    OperatorInitialized
                );
            }
        }

        assert!(InitCheckpoint::required_for(LogType::Init, EnclaveMode::Ceremony).is_err());
        assert_eq!(
            InitCheckpoint::required_for(LogType::KpShareState, EnclaveMode::Ceremony).unwrap(),
            OperatorInitialized
        );
        assert_eq!(
            InitCheckpoint::required_for(LogType::KpShareState, EnclaveMode::Withdraw).unwrap(),
            OperatorActivated
        );
    }

    #[tokio::test]
    async fn operator_activated_checkpoint_is_verified_once_per_session() {
        let signing_key = GuardianSignKeyPair::from([8u8; 32]);
        let signing_pubkey = signing_key.verification_key();
        let session_id = SessionID::from_signing_pubkey(&signing_pubkey);
        let pi_log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 3,
                share_ids: vec![],
                enclave_btc_pubkey: hashi_types::bitcoin::create_btc_keypair_for_test(&[1; 32])
                    .x_only_public_key()
                    .0,
            })),
            &signing_key,
            0,
        );
        let oa_log = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OAActivated {
                state_hash: [1; 32],
                config_hash: [2; 32],
                sharing_seq: 3,
                committee_epoch: 4,
                limiter_state: LimiterState {
                    num_tokens_available: 5,
                    last_updated_at: 6,
                    next_seq: 7,
                },
            })),
            &signing_key,
            0,
        );
        let pi_key = pi_log.object_key().to_string();
        let pi_body = serde_json::to_vec(&pi_log).unwrap();
        let oa_key = oa_log.object_key().to_string();
        let oa_body = serde_json::to_vec(&oa_log).unwrap();

        let list_logs = mock!(Client::list_object_versions)
            .sequence()
            .output(move || listed_record(pi_key.clone()))
            .output(move || listed_record(oa_key.clone()))
            .build();
        let get_logs = mock!(Client::get_object)
            .sequence()
            .output(move || locked_record(pi_body.clone()))
            .output(move || locked_record(oa_body.clone()))
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list_logs, &get_logs]);
        let s3 =
            GuardianS3Client::from_client_for_tests(ResolvedS3Config::mock_for_testing(), client);
        let mut session_info = VerifiedSessionInfo::new_for_test(signing_pubkey, build_pcrs());

        session_info
            .ensure_init_checkpoint(&s3, &session_id, InitCheckpoint::OperatorActivated)
            .await
            .unwrap();
        session_info
            .ensure_init_checkpoint(&s3, &session_id, InitCheckpoint::OperatorActivated)
            .await
            .unwrap();

        assert_eq!(
            session_info.verified_init_checkpoint,
            InitCheckpoint::OperatorActivated
        );
        assert_eq!(list_logs.num_calls(), 2);
        assert_eq!(get_logs.num_calls(), 2);
    }
}
