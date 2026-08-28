// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified reads from the guardian's S3 logs.
//!
//! [`GuardianReader`] applies each log stream's S3 immutability policy, verifies
//! records with their writing session's attestation-anchored key, and caches the
//! verified session info for reuse.

use crate::s3_client::GuardianS3Client;
use crate::s3_client::ImmutabilityCheck;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::ResolvedS3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
use std::collections::HashSet;
use tracing::info;

mod heartbeat_checks;
mod limiter_recovery;
mod verified;

pub use verified::VerifiedLogRecord;
pub use verified::VerifiedSessionInfo;

/// Internal policy for sharing read implementations that differ only in which
/// attested guardian builds they accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildPolicy {
    /// Require the configured current build.
    Current,
    /// Accept any build represented in the PCR allowlist.
    AnyAllowlisted,
}

impl BuildPolicy {
    fn enforce(self, allowlist: &PcrAllowlist, build_pcrs: &BuildPcrs) -> GuardianResult<()> {
        match self {
            Self::Current => allowlist.require_current_build(build_pcrs),
            Self::AnyAllowlisted => Ok(()),
        }
    }
}

/// Verified reader over the guardian's S3 logs.
///
/// Reads accept any allowlisted build unless the method explicitly requires
/// the current build. Reuse one reader so repeated reads can share cached
/// session attestations and signing keys.
pub struct GuardianReader {
    s3: GuardianS3Client,
    allowlist: PcrAllowlist,
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
    activated_sessions: HashSet<SessionID>,
}

impl GuardianReader {
    /// Create a reader after checking S3 connectivity and object-lock support.
    pub async fn new(config: &ResolvedS3Config, allowlist: PcrAllowlist) -> GuardianResult<Self> {
        let s3 = GuardianS3Client::new_checked(config).await?;
        Ok(Self::from_s3_client(s3, allowlist))
    }

    /// Create a reader from an existing S3 client without another connectivity
    /// check.
    pub fn from_s3_client(s3: GuardianS3Client, allowlist: PcrAllowlist) -> Self {
        Self {
            s3,
            allowlist,
            sessions: HashMap::new(),
            activated_sessions: HashSet::new(),
        }
    }

    /// Load and verify a session's attestation and guardian info on first use,
    /// then return the cached result.
    async fn get_or_load_session_info(
        &mut self,
        session_id: &str,
    ) -> GuardianResult<&VerifiedSessionInfo> {
        if !self.sessions.contains_key(session_id) {
            let session_info =
                VerifiedSessionInfo::read_from_s3(&self.s3, session_id, &self.allowlist).await?;
            self.sessions.insert(session_id.into(), session_info);
        }
        Ok(&self.sessions[session_id])
    }

    /// Verify a record with its session's attestation-anchored signing key.
    async fn verify_record(&mut self, record: LogRecord) -> GuardianResult<VerifiedLogRecord> {
        let session_id = record.session_id().clone();
        let session_info = self.get_or_load_session_info(&session_id).await?;
        let verified_record = session_info.verify_record(record)?;
        if requires_activation_marker(verified_record.entry()) {
            self.ensure_session_activated(&session_id).await?;
        }
        Ok(verified_record)
    }

    /// Verify a session's activation marker once, then cache the result.
    async fn ensure_session_activated(&mut self, session_id: &str) -> GuardianResult<()> {
        if self.activated_sessions.contains(session_id) {
            return Ok(());
        }

        let session_info = self.get_or_load_session_info(session_id).await?.clone();
        let key = InitLogMessage::oa_activated_object_key(session_id);
        let record = self.s3.get_log_record(&key).await?;
        let verified_record = session_info.verify_record(record)?;
        let message = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::Init(message)) | V2(LogMessageV2::Init(message)) => message,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected OAActivated at key {key}")));
            }
        };
        if !matches!(*message, InitLogMessage::OAActivated { .. }) {
            return Err(InvalidS3Log(format!("expected OAActivated at key {key}")));
        }

        self.activated_sessions.insert(session_id.into());
        Ok(())
    }

    /// Read an immutable S3 record and verify it with its session's
    /// attestation-anchored signing key.
    async fn read_verified_record(&mut self, key: &str) -> GuardianResult<VerifiedLogRecord> {
        let record = self.s3.get_log_record(key).await?;
        self.verify_record(record).await
    }

    /// Read and verify every immutable record in an hour-scoped directory.
    ///
    /// Each result retains its writing session's attested build PCRs because a
    /// directory may contain records from more than one build.
    pub async fn read_logs_in_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let prefix = dir.to_string();
        self.read_logs_with_prefix(&prefix).await
    }

    async fn read_logs_with_prefix(
        &mut self,
        prefix: &str,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let all_logs = self.s3.list_all_log_records_with_prefix(prefix).await?;

        let mut out = Vec::with_capacity(all_logs.len());
        for record in all_logs {
            let verified_record = self.verify_record(record).await?;
            out.push(verified_record);
        }
        Ok(out)
    }

    /// Read and verify successful withdrawal records in `dir`.
    ///
    /// This excludes rejected withdrawal requests, which do not represent
    /// Guardian approval events and are not inputs to the monitor state machine.
    pub async fn read_successful_withdrawals_in_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let prefix = format!("{dir}{}", WithdrawalLogMessage::SUCCESS_OBJECT_KEY_PREFIX);
        self.read_logs_with_prefix(&prefix).await
    }

    /// Return verified session info after requiring the attested PCRs to match
    /// the current build.
    pub async fn get_current_session_info(
        &mut self,
        session_id: &str,
    ) -> GuardianResult<VerifiedSessionInfo> {
        let session_info = self.get_or_load_session_info(session_id).await?.clone();
        self.allowlist
            .require_current_build(session_info.build_pcrs())?;
        Ok(session_info)
    }

    /// Read and verify the latest ceremony, or return `None` if none exists.
    ///
    /// Ceremony keys begin with a zero-padded `sharing_seq`, so the
    /// lexicographically greatest key identifies the latest ceremony.
    async fn read_latest_ceremony_log(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<CeremonyLogMessage>> {
        let keys = self
            .s3
            .list_keys(&CeremonyLogMessage::object_key_dir(), true)
            .await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let verified_record = self.read_verified_record(&key).await?;
        build_policy.enforce(&self.allowlist, verified_record.build_pcrs())?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::Ceremony(msg)) | V2(LogMessageV2::Ceremony(msg)) => msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a ceremony log at {key}")));
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(*msg))
    }

    /// Read and verify the latest encrypted KP-share state for `sharing_seq`.
    ///
    /// Keys begin with a zero-padded `cert_seq`, so the lexicographically
    /// greatest key identifies the latest state. KP-share locks are expected to
    /// expire, so this read authenticates the selected record without claiming
    /// S3 immutability.
    async fn read_latest_kp_share_state_log(
        &mut self,
        sharing_seq: u64,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<KpShareStateLogMessage>> {
        let prefix = KpShareStateLogMessage::object_key_dir(sharing_seq);
        let keys = self.s3.list_keys(&prefix, false).await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let msg = self
            .read_kp_share_state_log_at_key(&key, build_policy)
            .await?;
        if msg.sharing_seq != sharing_seq {
            return Err(InvalidS3Log(format!(
                "sharing_seq mismatch: {} != {}",
                msg.sharing_seq, sharing_seq
            )));
        }
        Ok(Some(msg))
    }

    /// Read and verify an exact encrypted KP-share state written by the current
    /// build.
    ///
    /// The object key binds the writing guardian session and the two sequence
    /// numbers. This lets callers verify the snapshot produced by one request
    /// even if a later request has already advanced the latest state.
    pub async fn read_kp_share_state_log_from_current_build(
        &mut self,
        session_id: &SessionID,
        sharing_seq: u64,
        cert_seq: u64,
    ) -> GuardianResult<KpShareStateLogMessage> {
        let key = KpShareStateLogMessage::object_key(session_id, sharing_seq, cert_seq);
        self.read_kp_share_state_log_at_key(&key, BuildPolicy::Current)
            .await
    }

    /// Read and verify one KP-share object under the requested build policy.
    async fn read_kp_share_state_log_at_key(
        &mut self,
        key: &str,
        build_policy: BuildPolicy,
    ) -> GuardianResult<KpShareStateLogMessage> {
        // KP-share locks are expected to expire, so authenticate the record
        // without claiming that S3 still makes it immutable.
        let record = self
            .s3
            .get_log_record_inner(key, ImmutabilityCheck::Skipped)
            .await?;
        let verified_record = self.verify_record(record).await?;
        build_policy.enforce(&self.allowlist, verified_record.build_pcrs())?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::KpShareState(msg)) => (*msg)
                .try_into()
                .map_err(|e| InvalidS3Log(format!("log schema conversion failed: {e}")))?,
            V2(LogMessageV2::KpShareState(msg)) => *msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a kp-shares log at {key}")));
            }
        };
        log_verified_read(key, &session_id);
        Ok(msg)
    }

    /// Read the latest ceremony together with the latest KP-share state for its
    /// `sharing_seq`, accepting any allowlisted build.
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<CeremonyState> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::AnyAllowlisted)
            .await
    }

    /// Read the latest ceremony together with the latest KP-share state for its
    /// `sharing_seq`, requiring both records to come from the current build.
    pub async fn read_latest_ceremony_state_from_current_build(
        &mut self,
    ) -> GuardianResult<CeremonyState> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::Current)
            .await
    }

    /// Once a ceremony is present, its matching KP-share state must also exist
    /// because writers publish `kp-shares/` before `ceremony/`.
    async fn read_latest_ceremony_state_with_build_policy(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<CeremonyState> {
        let ceremony = self
            .read_latest_ceremony_log(build_policy)
            .await?
            .ok_or_else(|| {
                InvalidInputs("no ceremony log found; setup_new_key has not run".into())
            })?;
        let sharing_seq = ceremony.sharing_seq();
        let kp_share_state = self
            .read_latest_kp_share_state_log(sharing_seq, build_policy)
            .await?
            .ok_or_else(|| {
                InvalidS3Log(format!(
                    "no kp-shares log found for latest ceremony sharing_seq {sharing_seq}"
                ))
            })?;
        Ok(CeremonyState::new(ceremony, kp_share_state)
            .expect("ceremony and KP share state must have a consistent shape"))
    }

    /// Read the latest serving committee.
    ///
    /// Prefer the latest successful `committee-update/` record, then fall back
    /// to the KP-authorized `genesis/record.json` bootstrap record. Return
    /// `None` if neither source exists.
    pub async fn read_latest_committee(&mut self) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update().await? {
            return Ok(Some(committee));
        }
        Ok(self
            .read_genesis_log()
            .await?
            .map(|genesis| genesis.committee))
    }

    /// Read and verify the successfully applied committee with the highest
    /// epoch, or return `None` if no successful update exists.
    ///
    /// Success keys begin with a zero-padded epoch, so the lexicographically
    /// greatest non-failure key identifies the latest applied committee.
    async fn read_latest_committee_update(&mut self) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .list_keys(&CommitteeUpdateLogMessage::object_key_dir(), true)
            .await?;
        let Some(key) = keys
            .into_iter()
            .filter(|key| !CommitteeUpdateLogMessage::is_failure_object_key(key))
            .max()
        else {
            return Ok(None);
        };
        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::CommitteeUpdate(msg)) | V2(LogMessageV2::CommitteeUpdate(msg)) => msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!(
                    "expected a committee-update log at {key}"
                )));
            }
        };
        let committee = match *msg {
            CommitteeUpdateLogMessage::Success { new_committee, .. } => new_committee,
            CommitteeUpdateLogMessage::Failure { .. } => {
                unreachable!("a verified non-failure key cannot contain a Failure log")
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(committee))
    }

    /// Read and verify the fixed KP-authorized bootstrap record, or return
    /// `None` if `genesis/record.json` has not been written.
    async fn read_genesis_log(&mut self) -> GuardianResult<Option<GenesisLogMessage>> {
        let key = GenesisLogMessage::object_key();
        let keys = self
            .s3
            .list_keys(&GenesisLogMessage::object_key_dir(), true)
            .await?;
        if keys.is_empty() {
            return Ok(None);
        }
        if keys != [key.clone()] {
            return Err(InvalidS3Log(format!(
                "expected exactly one genesis record at {key}, found {keys:?}"
            )));
        }
        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::Genesis(msg)) | V2(LogMessageV2::Genesis(msg)) => msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a genesis log at {key}")));
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(*msg))
    }
}

fn requires_activation_marker(entry: &LogEntry) -> bool {
    matches!(
        entry.message(),
        V1(LogMessageV1::Withdrawal(_) | LogMessageV1::CommitteeUpdate(_))
            | V2(LogMessageV2::Withdrawal(_) | LogMessageV2::CommitteeUpdate(_))
    )
}

fn log_verified_read(key: &str, session_id: &SessionID) {
    info!("Successfully read {key} from session {session_id}.");
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
    use bitcoin::Network;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use hashi_types::move_types;
    use std::time::Duration;
    use std::time::SystemTime;

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn entry_for(message: LogMessage) -> LogEntry {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        LogRecord::new_at_timestamp(session_id, message, &signing_key, 0).into_entry_unchecked()
    }

    fn withdrawal_failure() -> WithdrawalLogMessage {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        WithdrawalLogMessage::Failure {
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            error: GuardianError::RateLimitExceeded.to_string(),
        }
    }

    fn committee_update_failure() -> CommitteeUpdateLogMessage {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, _) = signed.into_parts();
        CommitteeUpdateLogMessage::Failure {
            from_epoch: 6,
            new_committee: move_types::Committee {
                epoch: 7,
                members: vec![],
                total_weight: 0,
                config: move_types::Config::default(),
            },
            request_sign,
            error: GuardianError::InvalidInputs("test failure".into()).to_string(),
        }
    }

    #[test]
    fn only_post_activation_records_require_activation_marker() {
        let withdrawal = entry_for(LogMessage::Withdrawal(Box::new(withdrawal_failure())));
        let committee_update = entry_for(LogMessage::CommitteeUpdate(Box::new(
            committee_update_failure(),
        )));
        let heartbeat = entry_for(LogMessage::Heartbeat(HeartbeatLogMessage::new(0)));

        assert!(requires_activation_marker(&withdrawal));
        assert!(requires_activation_marker(&committee_update));
        assert!(!requires_activation_marker(&heartbeat));
    }

    #[tokio::test]
    async fn activation_marker_is_verified_once_per_session() {
        let signing_key = GuardianSignKeyPair::from([8u8; 32]);
        let signing_pubkey = signing_key.verification_key();
        let session_id = SessionID::from_signing_pubkey(&signing_pubkey);
        let marker = LogRecord::new_at_timestamp(
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
        let key = marker.object_key().to_string();
        let body = serde_json::to_vec(&marker).unwrap();

        let list_key = key.clone();
        let output_key = key.clone();
        let list_marker = mock!(Client::list_object_versions)
            .match_requests(move |request| request.prefix() == Some(list_key.as_str()))
            .then_output(move || {
                ListObjectVersionsOutput::builder()
                    .versions(
                        ObjectVersion::builder()
                            .key(output_key.clone())
                            .is_latest(true)
                            .build(),
                    )
                    .build()
            });
        let get_key = key.clone();
        let get_marker = mock!(Client::get_object)
            .match_requests(move |request| request.key() == Some(get_key.as_str()))
            .then_output(move || {
                GetObjectOutput::builder()
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from(
                        SystemTime::now() + Duration::from_secs(60),
                    ))
                    .body(ByteStream::from(body.clone()))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list_marker, &get_marker]);
        let s3 =
            GuardianS3Client::from_client_for_tests(ResolvedS3Config::mock_for_testing(), client);
        let allowlist = PcrAllowlist::new(build_pcrs(), []).unwrap();
        let mut reader = GuardianReader::from_s3_client(s3, allowlist);
        reader.sessions.insert(
            session_id.clone(),
            VerifiedSessionInfo::new_for_test(signing_pubkey, build_pcrs()),
        );

        let first = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(withdrawal_failure())),
            &signing_key,
            0,
        );
        let second = LogRecord::new_at_timestamp(
            session_id.clone(),
            LogMessage::Withdrawal(Box::new(withdrawal_failure())),
            &signing_key,
            1,
        );

        reader.verify_record(first).await.unwrap();
        reader.verify_record(second).await.unwrap();

        assert!(reader.activated_sessions.contains(&session_id));
        assert_eq!(list_marker.num_calls(), 1);
        assert_eq!(get_marker.num_calls(), 1);
    }
}
