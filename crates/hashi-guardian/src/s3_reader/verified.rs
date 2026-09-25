// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::DeploymentConfigSummary;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::LogType;
use hashi_types::guardian::OperatorInitInfo;

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

/// A session's attestation-anchored signing key, signed [`OperatorInitInfo`], build
/// PCRs, and highest verified initialization checkpoint.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    signing_pubkey: GuardianPubKey,
    info: OperatorInitInfo,
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
            LogType::Heartbeat
            | LogType::CeremonyCompleted
            | LogType::CeremonyProposal
            | LogType::Genesis => Self::OperatorInitialized,
        };
        Ok(required)
    }
}

impl VerifiedSessionInfo {
    #[cfg(test)]
    pub(super) fn new_for_test(signing_pubkey: GuardianPubKey, build_pcrs: BuildPcrs) -> Self {
        Self {
            signing_pubkey,
            info: OperatorInitInfo::mock_for_testing(),
            build_pcrs,
            verified_init_checkpoint: InitCheckpoint::OperatorInitialized,
        }
    }

    pub(super) async fn read_from_s3(
        s3: &GuardianS3Client,
        session_id: &str,
        expected_deployment: &DeploymentConfig,
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

        // 2. Completed operator initialization, signature-verified under that pubkey → the reported build.
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
        let build_pcrs =
            verify_deployment_info(session_id, &info.deployment_info, expected_deployment)?;
        attestation
            .verify_replay(&signing_pubkey, &build_pcrs)
            .map_err(|e| InvalidS3Log(format!("attestation at key {att_key}: {e}")))?;

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
        let required = InitCheckpoint::required_for(entry.log_type(), self.info.mode())?;
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
                let pi_key = InitLogMessage::pi_fully_initialized_object_key(session_id);
                let pi_message =
                    Self::read_init_log(s3, &pi_key, Some(&self.signing_pubkey)).await?;

                let oa_key = InitLogMessage::oa_activated_object_key(session_id);
                let oa_message =
                    Self::read_init_log(s3, &oa_key, Some(&self.signing_pubkey)).await?;
                InitLogMessage::verify_oi_pi_consistency(&self.info, &pi_message)?;
                InitLogMessage::verify_oi_oa_consistency(&self.info, &oa_message)?;
                InitLogMessage::verify_pi_oa_consistency(&pi_message, &oa_message)?;
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
        entry
            .into_message()
            .into_init()
            .ok_or_else(|| InvalidS3Log(format!("expected an init log at key {key}")))
    }

    pub fn signing_pubkey(&self) -> &GuardianPubKey {
        &self.signing_pubkey
    }

    pub fn info(&self) -> &OperatorInitInfo {
        &self.info
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }
}

/// Authenticate deployment identity separately from build selection: historical
/// sessions may use older allowlisted builds, but must serve the same deployment.
fn verify_deployment_info(
    session_id: &str,
    reported: &DeploymentConfigSummary,
    expected: &DeploymentConfig,
) -> GuardianResult<BuildPcrs> {
    if reported.bucket_info != expected.bucket_info {
        return Err(InvalidS3Log(format!(
            "session {session_id} bucket/region {:?} does not match expected {:?}",
            reported.bucket_info, expected.bucket_info
        )));
    }
    if reported.retention_environment != expected.retention_environment {
        return Err(InvalidS3Log(format!(
            "session {session_id} retention environment {:?} does not match expected {:?}",
            reported.retention_environment, expected.retention_environment
        )));
    }
    if reported.bitcoin_network != expected.bitcoin_network {
        return Err(InvalidS3Log(format!(
            "session {session_id} Bitcoin network {:?} does not match expected {:?}",
            reported.bitcoin_network, expected.bitcoin_network
        )));
    }
    expected
        .pcr_allowlist
        .resolve(&reported.git_revision)
        .cloned()
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
    use hashi_types::guardian::S3BucketInfo;
    use hashi_types::guardian::S3ObjectLockPolicy;
    use hashi_types::guardian::S3RetentionEnvironment;
    use hashi_types::guardian::SessionID;
    use hashi_types::guardian::ShareID;

    #[test]
    fn session_deployment_must_match_all_stable_fields() {
        let expected = DeploymentConfig::mock_for_testing();
        let reported = expected.summary();
        assert_eq!(
            verify_deployment_info("session", &reported, &expected).unwrap(),
            *expected.pcr_allowlist.current_build()
        );
        let mut wrong_bucket = reported.clone();
        wrong_bucket.bucket_info.name.push_str("-other");
        let mut wrong_region = reported.clone();
        wrong_region.bucket_info.region = "us-west-2".into();
        let mut wrong_retention = reported.clone();
        wrong_retention.retention_environment =
            hashi_types::guardian::S3RetentionEnvironment::Devnet;
        let mut wrong_network = reported.clone();
        wrong_network.bitcoin_network = bitcoin::Network::Bitcoin;
        for changed in [wrong_bucket, wrong_region, wrong_retention, wrong_network] {
            assert!(matches!(
                verify_deployment_info("session", &changed, &expected),
                Err(InvalidS3Log(message)) if message.contains("does not match expected")
            ));
        }
    }

    #[test]
    fn historical_sessions_use_the_readers_allowlist() {
        let mut expected = DeploymentConfig::mock_for_testing();
        let previous = BuildPcrs::new("previous", vec![1]);
        expected.pcr_allowlist = hashi_types::guardian::PcrAllowlist::new(
            expected.pcr_allowlist.current_build().clone(),
            [previous.clone()],
        )
        .unwrap();
        let mut reported = expected.summary();
        reported.git_revision = "previous".into();
        let build = verify_deployment_info("session", &reported, &expected).unwrap();
        assert_eq!(build, previous);
        assert!(expected
            .pcr_allowlist
            .require_current_build(&build)
            .is_err());
        reported.git_revision = "not-allowlisted".into();
        assert!(verify_deployment_info("session", &reported, &expected).is_err());
    }

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn session_info_ready_for_activation(signing_pubkey: GuardianPubKey) -> VerifiedSessionInfo {
        VerifiedSessionInfo::new_for_test(signing_pubkey, build_pcrs())
    }

    fn listed_record(key: String) -> ListObjectVersionsOutput {
        ListObjectVersionsOutput::builder()
            .versions(ObjectVersion::builder().key(key).is_latest(true).build())
            .build()
    }

    fn locked_record(record: &LogRecord, policy: S3ObjectLockPolicy) -> GetObjectOutput {
        GetObjectOutput::builder()
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(record.object_lock_expiry(policy)))
            .body(ByteStream::from(serde_json::to_vec(record).unwrap()))
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
            for log_type in [
                LogType::Heartbeat,
                LogType::CeremonyCompleted,
                LogType::CeremonyProposal,
                LogType::Genesis,
            ] {
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
        let pi_log = LogRecord::new(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 0,
                share_ids: (1..=3).map(|id| ShareID::new(id).unwrap()).collect(),
                enclave_btc_pubkey: hashi_types::bitcoin::create_btc_keypair_for_test(&[1; 32])
                    .x_only_public_key()
                    .0,
            })),
            &signing_key,
        );
        let oa_log = LogRecord::new(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::OAActivated {
                state_hash: [1; 32],
                config_hash: [2; 32],
                sharing_seq: 0,
                committee_epoch: 4,
                limiter_state: LimiterState {
                    num_tokens_available: 5,
                    last_updated_at: 6,
                    next_seq: 7,
                },
            })),
            &signing_key,
        );
        let pi_key = pi_log.object_key().to_string();
        let oa_key = oa_log.object_key().to_string();
        let policy = S3ObjectLockPolicy::for_environment(S3RetentionEnvironment::Testnet);

        let list_logs = mock!(Client::list_object_versions)
            .sequence()
            .output(move || listed_record(pi_key.clone()))
            .output(move || listed_record(oa_key.clone()))
            .build();
        let get_logs = mock!(Client::get_object)
            .sequence()
            .output(move || locked_record(&pi_log, policy))
            .output(move || locked_record(&oa_log, policy))
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list_logs, &get_logs]);
        let s3 = GuardianS3Client::from_client_for_tests(
            S3BucketInfo::mock_for_testing(),
            S3RetentionEnvironment::Testnet,
            client,
        );
        let mut session_info = session_info_ready_for_activation(signing_pubkey);

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
