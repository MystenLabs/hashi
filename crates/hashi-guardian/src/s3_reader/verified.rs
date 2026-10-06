// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verify session attestations, log signatures, and required initialization checkpoints.

use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::LogType;
use hashi_types::guardian::OperatorInitInfo;
use hashi_types::guardian::SignedLogEntry;
use tracing::error;
use tracing::info;

/// An initialization checkpoint required for a read or verified for a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitCheckpoint {
    /// Operator initialization logs 01-02: the attestation and session information.
    /// Construction of [`VerifiedSessionInfo`] verifies these logs.
    OperatorInitialized,
    /// Initialization logs 01-04 for withdrawal mode.
    OperatorActivated,
}

/// Verified session information and the highest verified initialization checkpoint.
/// This includes the signing key, signed [`OperatorInitInfo`], and build PCR values.
/// The session attestation verifies the signing key and PCR values.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    signing_pubkey: GuardianPubKey,
    info: OperatorInitInfo,
    build_pcrs: BuildPcrs,
    verified_init_checkpoint: InitCheckpoint,
}

/// A log entry with a verified signature, session attestation, build PCR values, and required initialization checkpoint.
/// This type keeps the original entry and its schema version.
/// The caller selects which schema versions to accept and how to read them.
#[derive(Debug)]
pub struct VerifiedLogEntry {
    entry: LogEntry,
    build_pcrs: BuildPcrs,
}

impl InitCheckpoint {
    /// Return the initialization checkpoint required to read a log.
    /// Withdrawal and committee update logs require initialization logs 01-04.
    /// Heartbeat, ceremony, ceremony proposal, and genesis logs require initialization logs 01-02.
    /// KP-share state logs require logs 01-02 in ceremony mode and logs 01-04 in withdrawal mode.
    /// Reject initialization logs here. Use the initialization log reader for those records.
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
    /// Create session information for tests without attestation or initialization log verification.
    #[cfg(test)]
    pub(super) fn new_for_test(signing_pubkey: GuardianPubKey, build_pcrs: BuildPcrs) -> Self {
        Self {
            signing_pubkey,
            info: OperatorInitInfo::mock_for_testing(),
            build_pcrs,
            verified_init_checkpoint: InitCheckpoint::OperatorInitialized,
        }
    }

    /// Read and verify the session attestation and operator initialization information from S3.
    /// Select the build PCR values from the reader's deployment allowlist.
    /// Verify the attestation before using its signing key to verify the two log signatures.
    pub(super) async fn read_from_s3(
        s3: &GuardianS3Client,
        session_id: &str,
        expected_deployment: &DeploymentConfig,
    ) -> GuardianResult<Self> {
        // Fetch the attestation and claimed signing key without trusting either.
        let att_key = InitLogMessage::attestation_object_key(session_id);
        let attestation_record = s3.get_log_record(&att_key).await?;
        let InitLogMessage::OIAttestation {
            attestation,
            signing_public_key: signing_pubkey,
        } = Self::unverified_init_message(&attestation_record)?
        else {
            return Err(InvalidS3Log(format!(
                "expected OIAttestation at key {att_key}"
            )));
        };

        // The unverified OI info selects a build from the reader's own allowlist.
        let info_key = InitLogMessage::guardian_info_object_key(session_id);
        let info_record = s3.get_log_record(&info_key).await?;
        let InitLogMessage::OIGuardianInfo(info) = Self::unverified_init_message(&info_record)?
        else {
            return Err(InvalidS3Log(format!(
                "expected OIGuardianInfo at key {info_key}"
            )));
        };
        // Replay checks the certificate chain at the attestation's signed timestamp.
        let build_pcrs =
            verify_deployment_and_resolve_build(session_id, &info.deployment, expected_deployment)?;
        attestation
            .verify_replay(signing_pubkey, &build_pcrs)
            .map_err(|e| InvalidS3Log(format!("attestation at key {att_key}: {e}")))?;

        // An embedded key's signature is trusted only after its attestation verifies.
        attestation_record.validate(signing_pubkey)?;
        info_record.validate(signing_pubkey)?;

        info!(
            session_id,
            git_revision = build_pcrs.git_revision(),
            "Verified the session attestation and operator initialization logs"
        );

        Ok(Self {
            signing_pubkey: *signing_pubkey,
            info: info.as_ref().clone(),
            build_pcrs,
            verified_init_checkpoint: InitCheckpoint::OperatorInitialized,
        })
    }

    /// Verify a record and the initialization checkpoint required to write it.
    pub(super) async fn verify_record(
        &mut self,
        s3: &GuardianS3Client,
        record: SignedLogEntry,
    ) -> GuardianResult<VerifiedLogEntry> {
        let entry = record.validate_into_entry(&self.signing_pubkey)?;
        let required = InitCheckpoint::required_for(entry.log_type(), self.info.mode())?;
        self.ensure_init_checkpoint(s3, entry.session_id(), required)
            .await?;
        Ok(VerifiedLogEntry {
            entry,
            build_pcrs: self.build_pcrs.clone(),
        })
    }

    /// Verify the required initialization checkpoint if this session has not reached it.
    /// Keep the current checkpoint if any verification fails.
    /// The `session_id` must identify this session.
    async fn ensure_init_checkpoint(
        &mut self,
        s3: &GuardianS3Client,
        session_id: &str,
        required: InitCheckpoint,
    ) -> GuardianResult<()> {
        match (self.verified_init_checkpoint, required) {
            (_, InitCheckpoint::OperatorInitialized)
            | (InitCheckpoint::OperatorActivated, InitCheckpoint::OperatorActivated) => Ok(()),
            (InitCheckpoint::OperatorInitialized, InitCheckpoint::OperatorActivated) => {
                let pi_key = InitLogMessage::pi_fully_initialized_object_key(session_id);
                let pi_message =
                    Self::read_verified_init_log(s3, &pi_key, &self.signing_pubkey).await?;

                let oa_key = InitLogMessage::oa_activated_object_key(session_id);
                let oa_message =
                    Self::read_verified_init_log(s3, &oa_key, &self.signing_pubkey).await?;
                InitLogMessage::verify_oi_pi_consistency(&self.info, &pi_message)?;
                InitLogMessage::verify_oi_oa_consistency(&self.info, &oa_message)?;
                InitLogMessage::verify_pi_oa_consistency(&pi_message, &oa_message)?;
                self.verified_init_checkpoint = InitCheckpoint::OperatorActivated;
                info!(session_id, "Verified the session activation checkpoint");
                Ok(())
            }
        }
    }

    /// The caller must verify the attestation and log signatures before trusting the message.
    fn unverified_init_message(record: &SignedLogEntry) -> GuardianResult<&InitLogMessage> {
        record.message_unchecked().as_init().ok_or_else(|| {
            InvalidS3Log(format!(
                "expected an init log at key {}",
                record.object_key()
            ))
        })
    }

    /// Read an initialization log and verify it with the authenticated signing key.
    async fn read_verified_init_log(
        s3: &GuardianS3Client,
        key: &str,
        signing_pubkey: &GuardianPubKey,
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

/// Check the reported deployment and return its build from the reader's allowlist.
/// The reported current build must have the same PCR values as the selected build.
/// Log an error if a shared historical revision has different PCR values in the two allowlists.
/// Historical mismatches do not prevent the read.
/// The caller must then verify the Nitro attestation against the selected build's PCR values.
fn verify_deployment_and_resolve_build(
    session_id: &str,
    reported: &DeploymentConfig,
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
    let reported_build = reported.pcr_allowlist.current_build();
    let expected_build = expected
        .pcr_allowlist
        .resolve(reported_build.git_revision())?;
    if reported_build != expected_build {
        return Err(InvalidS3Log(format!(
            "session {session_id} reported PCR values for build '{}' do not match the reader's allowlist",
            reported_build.git_revision()
        )));
    }

    // Historical revisions can be removed from either allowlist.
    // Compare only revisions present in both allowlists.
    // Log an error if their PCR values differ, but continue the read.
    for reported_build in reported.pcr_allowlist.prev_builds() {
        let Ok(expected_build) = expected
            .pcr_allowlist
            .resolve(reported_build.git_revision())
        else {
            continue;
        };
        if reported_build != expected_build {
            error!(
                session_id,
                git_revision = reported_build.git_revision(),
                "Reported historical PCR values do not match the reader's allowlist"
            );
        }
    }

    Ok(expected_build.clone())
}

impl VerifiedLogEntry {
    /// Create a log entry for tests without signature, attestation, or initialization log verification.
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
        let reported = expected.clone();
        assert_eq!(
            verify_deployment_and_resolve_build("session", &reported, &expected).unwrap(),
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
                verify_deployment_and_resolve_build("session", &changed, &expected),
                Err(InvalidS3Log(message)) if message.contains("does not match expected")
            ));
        }
    }

    #[test]
    fn historical_sessions_use_the_readers_allowlist() {
        let mut expected = DeploymentConfig::mock_for_testing();
        let previous = BuildPcrs::mock_for_testing("previous", 2);
        expected.pcr_allowlist = hashi_types::guardian::PcrAllowlist::new(
            expected.pcr_allowlist.current_build().clone(),
            [previous.clone()],
        )
        .unwrap();
        let mut reported = expected.clone();
        reported.pcr_allowlist =
            hashi_types::guardian::PcrAllowlist::new(previous.clone(), []).unwrap();
        let build = verify_deployment_and_resolve_build("session", &reported, &expected).unwrap();
        assert_eq!(build, previous);
        assert!(expected
            .pcr_allowlist
            .require_current_build(&build)
            .is_err());
        reported.pcr_allowlist = hashi_types::guardian::PcrAllowlist::new(
            BuildPcrs::mock_for_testing("not-allowlisted", 9),
            [],
        )
        .unwrap();
        assert!(verify_deployment_and_resolve_build("session", &reported, &expected).is_err());
    }

    #[test]
    fn reported_pcr_pins_must_match_the_readers_allowlist() {
        let mut expected = DeploymentConfig::mock_for_testing();
        let current = expected.pcr_allowlist.current_build().clone();
        let previous = BuildPcrs::mock_for_testing("previous", 2);
        expected.pcr_allowlist =
            hashi_types::guardian::PcrAllowlist::new(current.clone(), [previous.clone()]).unwrap();
        for build in [current, previous] {
            let mut reported = expected.clone();
            reported.pcr_allowlist = hashi_types::guardian::PcrAllowlist::new(
                BuildPcrs::mock_for_testing(build.git_revision(), 9),
                [],
            )
            .unwrap();
            assert!(matches!(
                verify_deployment_and_resolve_build("session", &reported, &expected),
                Err(InvalidS3Log(message))
                    if message.contains("reported PCR values")
                        && message.contains(build.git_revision())
            ));
        }
    }

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::mock_for_testing("current", 1)
    }

    fn session_info_ready_for_activation(signing_pubkey: GuardianPubKey) -> VerifiedSessionInfo {
        VerifiedSessionInfo::new_for_test(signing_pubkey, build_pcrs())
    }

    fn listed_record(key: String) -> ListObjectVersionsOutput {
        ListObjectVersionsOutput::builder()
            .versions(ObjectVersion::builder().key(key).is_latest(true).build())
            .build()
    }

    fn locked_record(record: &SignedLogEntry, policy: S3ObjectLockPolicy) -> GetObjectOutput {
        GetObjectOutput::builder()
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(record.object_lock_expiry(policy)))
            .body(ByteStream::from(serde_json::to_vec(record).unwrap()))
            .build()
    }

    // The non-enclave-dev feature bypasses Nitro verification.
    #[cfg(not(feature = "non-enclave-dev"))]
    #[tokio::test]
    async fn attestation_is_verified_before_log_signatures() {
        // Both cases must fail on attestation, before either signature is checked.
        for tamper_signature in [false, true] {
            let signing_key = GuardianSignKeyPair::from([8u8; 32]);
            let signing_pubkey = signing_key.verification_key();
            let session_id = SessionID::from_signing_pubkey(&signing_pubkey);
            let attestation = hashi_types::guardian::NitroAttestation::new(vec![1, 2, 3]);
            let info = OperatorInitInfo::mock_for_testing();
            let deployment = info.deployment.clone();
            assert!(attestation
                .verify_replay(&signing_pubkey, deployment.pcr_allowlist.current_build())
                .is_err());
            let mut attestation_record = SignedLogEntry::new(
                session_id.clone(),
                LogMessage::Init(Box::new(InitLogMessage::OIAttestation {
                    attestation,
                    signing_public_key: signing_pubkey,
                })),
                &signing_key,
            );
            // The attacker knows this key, so the log signature alone is valid.
            attestation_record.validate(&signing_pubkey).unwrap();
            if tamper_signature {
                let mut json = serde_json::to_value(attestation_record).unwrap();
                json["signature"] = serde_json::json!("00".repeat(64));
                attestation_record = serde_json::from_value(json).unwrap();
                assert!(attestation_record.validate(&signing_pubkey).is_err());
            }
            let info_record = SignedLogEntry::new(
                session_id.clone(),
                LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(info)))),
                &signing_key,
            );
            let att_key = attestation_record.object_key().to_owned();
            let info_key = info_record.object_key().to_owned();
            let policy = S3ObjectLockPolicy::for_environment(deployment.retention_environment);
            let list_logs = mock!(Client::list_object_versions)
                .sequence()
                .output(move || listed_record(att_key.clone()))
                .output(move || listed_record(info_key.clone()))
                .build();
            let get_logs = mock!(Client::get_object)
                .sequence()
                .output(move || locked_record(&attestation_record, policy))
                .output(move || locked_record(&info_record, policy))
                .build();
            let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list_logs, &get_logs]);
            let s3 = GuardianS3Client::from_client(
                deployment.bucket_info.clone(),
                deployment.retention_environment,
                client,
            );
            let error = VerifiedSessionInfo::read_from_s3(&s3, &session_id, &deployment)
                .await
                .unwrap_err();
            assert!(
                matches!(error, InvalidS3Log(message) if message.contains("attestation parse failed"))
            );
            assert_eq!(list_logs.num_calls(), 2);
            assert_eq!(get_logs.num_calls(), 2);
        }
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
        let pi_log = SignedLogEntry::new(
            session_id.clone(),
            LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 0,
                share_ids: (1..=3).map(|id| ShareID::new(id).unwrap()).collect(),
                enclave_btc_pubkey: hashi_types::bitcoin::BitcoinKeypair::from_seckey_slice(
                    &hashi_types::bitcoin::BTC_LIB,
                    &[1; 32],
                )
                .expect("valid test secret key")
                .x_only_public_key()
                .0,
            })),
            &signing_key,
        );
        let oa_log = SignedLogEntry::new(
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
        let s3 = GuardianS3Client::from_client(
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
