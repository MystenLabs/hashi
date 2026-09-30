// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified reads from the guardian's S3 logs.
//!
//! [`GuardianReader`] applies each log stream's S3 immutability policy, verifies
//! records with their writing session's attestation-anchored key and required
//! initialization logs, and caches the verified session info for reuse.

use crate::clock::SharedClock;
use crate::clock::SystemClock;
use crate::s3_client::GuardianS3Client;
use crate::s3_client::ImmutabilityCheck;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CeremonyProposalLogMessage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3Credentials;
use hashi_types::guardian::SessionID;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

mod heartbeat_checks;
mod limiter_recovery;
mod verified;

pub use verified::VerifiedLogRecord;
pub use verified::VerifiedSessionInfo;

/// Verified reader over the guardian's S3 logs.
///
/// Reads accept any allowlisted build unless the method explicitly requires
/// the current build. Reuse one reader so repeated reads can share cached
/// session attestations and signing keys. Every writing session must match the
/// expected bucket, region, retention environment, and Bitcoin network.
pub struct GuardianReader {
    s3: GuardianS3Client,
    clock: SharedClock,
    expected_deployment: DeploymentConfig,
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
}

impl GuardianReader {
    /// Create an off-enclave reader using system time, after checking S3 connectivity
    /// and object-lock support. Enclaves reuse their PTP clock via `from_s3_client`.
    pub async fn new(
        expected_deployment: DeploymentConfig,
        credentials: S3Credentials,
    ) -> GuardianResult<Self> {
        let s3 = GuardianS3Client::new(
            &expected_deployment.bucket_info,
            expected_deployment.retention_environment,
            &credentials,
        )
        .await?;
        Ok(Self::from_s3_client(
            s3,
            expected_deployment,
            Arc::new(SystemClock),
        ))
    }

    /// Reuse the enclave's S3 client, constructed from the same deployment
    /// configuration, without another connectivity check.
    pub(crate) fn from_s3_client(
        s3: GuardianS3Client,
        expected_deployment: DeploymentConfig,
        clock: SharedClock,
    ) -> Self {
        Self {
            s3,
            clock,
            expected_deployment,
            sessions: HashMap::new(),
        }
    }

    /// Load and verify a session's attestation and completed operator initialization on first use.
    async fn ensure_session_info_loaded(&mut self, session_id: &str) -> GuardianResult<()> {
        if !self.sessions.contains_key(session_id) {
            let session_info =
                VerifiedSessionInfo::read_from_s3(&self.s3, session_id, &self.expected_deployment)
                    .await?;
            self.sessions.insert(session_id.into(), session_info);
        }
        Ok(())
    }

    /// Verify a record and the initialization checkpoint required to emit it.
    async fn verify_record(&mut self, record: LogRecord) -> GuardianResult<VerifiedLogRecord> {
        self.ensure_session_info_loaded(record.session_id()).await?;
        let session_info = self
            .sessions
            .get_mut(record.session_id())
            .expect("session info was loaded above");
        session_info.verify_record(&self.s3, record).await
    }

    /// Read an immutable S3 record and verify it against its writing session.
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
        dir: &S3HourDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let all_logs = self.s3.list_all_log_records_in_dir(dir).await?;

        let mut out = Vec::with_capacity(all_logs.len());
        for record in all_logs {
            let verified_record = self.verify_record(record).await?;
            out.push(verified_record);
        }
        Ok(out)
    }

    /// Return verified session info after requiring the attested PCRs to match
    /// the current build.
    pub async fn get_current_session_info(
        &mut self,
        session_id: &str,
    ) -> GuardianResult<VerifiedSessionInfo> {
        self.ensure_session_info_loaded(session_id).await?;
        let session_info = self
            .sessions
            .get(session_id)
            .expect("session info was loaded above");
        self.expected_deployment
            .pcr_allowlist
            .require_current_build(session_info.build_pcrs())?;
        Ok(session_info.clone())
    }

    /// Read and verify the latest ceremony, with the session that wrote it,
    /// or return `None` if none exists.
    ///
    /// Ceremony keys begin with a zero-padded `sharing_seq`, so the
    /// lexicographically greatest key identifies the latest ceremony.
    async fn read_latest_ceremony_log(
        &mut self,
        require_current: bool,
    ) -> GuardianResult<Option<(CeremonyLogMessage, SessionID)>> {
        let keys = self
            .s3
            .list_keys(&CeremonyLogMessage::object_key_dir())
            .await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let verified_record = self.read_verified_record(&key).await?;
        if require_current {
            self.expected_deployment
                .pcr_allowlist
                .require_current_build(verified_record.build_pcrs())?;
        }
        let session_id = verified_record.entry().session_id().clone();
        let msg = verified_record
            .into_entry()
            .into_message()
            .into_ceremony()
            .ok_or_else(|| InvalidS3Log(format!("expected a ceremony log at {key}")))?;
        log_verified_read(&key, &session_id);
        Ok(Some((*msg, session_id)))
    }

    /// Choose a sequence above every completed ceremony and occupied share directory.
    /// Shares are published before the ceremony commit, so an interrupted attempt
    /// can occupy a sequence even though no ceremony record exists for it.
    ///
    /// This allocates under the single ceremony-writer assumption; it does not
    /// reserve the sequence. Conditional writes still reject competing records.
    pub(crate) async fn next_sharing_seq(&mut self) -> GuardianResult<u64> {
        let mut highest = self
            .read_latest_ceremony_log(false)
            .await?
            .map(|(ceremony, _)| ceremony.sharing_seq());
        // Count occupied directories even if their records are unreadable or
        // delete-marked: an interrupted ceremony may have left shares here.
        let shares_dir = KpShareStateLogMessage::root_dir();
        let proposals_dir = CeremonyProposalLogMessage::object_key_dir();
        for directory in self.s3.list_common_prefixes(&shares_dir).await? {
            if directory == proposals_dir {
                continue;
            }
            let seq = KpShareStateLogMessage::sharing_seq_from_dir(&directory)
                .map_err(|err| InvalidS3Log(err.to_string()))?;
            highest = Some(highest.map_or(seq, |previous| previous.max(seq)));
        }
        match highest {
            None => Ok(0),
            Some(seq) => seq
                .checked_add(1)
                .ok_or_else(|| InvalidS3Log("sharing_seq exhausted".into())),
        }
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
        require_current: bool,
    ) -> GuardianResult<Option<KpShareStateLogMessage>> {
        let prefix = KpShareStateLogMessage::object_key_dir(sharing_seq);
        let keys = self.s3.list_keys_allowing_mutations(&prefix).await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let msg = self
            .read_kp_share_state_log_at_key(&key, require_current)
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
    /// Read the requested sequence even if a later request has already advanced
    /// the latest state.
    pub async fn read_kp_share_state_log_from_current_build(
        &mut self,
        sharing_seq: u64,
        cert_seq: u64,
    ) -> GuardianResult<KpShareStateLogMessage> {
        let key = KpShareStateLogMessage::object_key(sharing_seq, cert_seq);
        self.read_kp_share_state_log_at_key(&key, true).await
    }

    /// Read and verify the proposal written by one live ceremony session.
    pub async fn read_live_ceremony_proposal(
        &mut self,
        session_id: &SessionID,
    ) -> GuardianResult<CeremonyState> {
        let key = CeremonyProposalLogMessage::object_key(session_id);
        // A live proposal has just been published, so its short-lived Compliance
        // lock must still be active.
        let verified_record = self.read_verified_record(&key).await?;
        self.expected_deployment
            .pcr_allowlist
            .require_current_build(verified_record.build_pcrs())?;
        let writing_session_id = verified_record.entry().session_id().clone();
        let proposal = *verified_record
            .into_entry()
            .into_message()
            .into_ceremony_proposal()
            .ok_or_else(|| InvalidS3Log(format!("expected a ceremony proposal log at {key}")))?;
        let state = CeremonyState::from_proposal(proposal).map_err(|error| {
            InvalidS3Log(format!("invalid ceremony proposal at {key}: {error}"))
        })?;
        log_verified_read(&key, &writing_session_id);
        Ok(state)
    }

    /// Read and verify one KP-share object under the requested build policy.
    async fn read_kp_share_state_log_at_key(
        &mut self,
        key: &str,
        require_current: bool,
    ) -> GuardianResult<KpShareStateLogMessage> {
        // KP-share locks are expected to expire, so authenticate the record
        // without claiming that S3 still makes it immutable.
        let record = self
            .s3
            .get_log_record_inner(key, ImmutabilityCheck::Skipped)
            .await?;
        let verified_record = self.verify_record(record).await?;
        if require_current {
            self.expected_deployment
                .pcr_allowlist
                .require_current_build(verified_record.build_pcrs())?;
        }
        let session_id = verified_record.entry().session_id().clone();
        let msg = *verified_record
            .into_entry()
            .into_message()
            .into_kp_share_state()
            .ok_or_else(|| InvalidS3Log(format!("expected a kp-shares log at {key}")))?;
        log_verified_read(key, &session_id);
        Ok(msg)
    }

    /// Read the latest ceremony together with the latest KP-share state for its
    /// `sharing_seq`, accepting any allowlisted build.
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<CeremonyState> {
        self.read_latest_ceremony_state_with_build_requirement(false)
            .await
            .map(|(state, _dealer)| state)
    }

    /// Read the latest ceremony together with the latest KP-share state for its
    /// `sharing_seq`, requiring both records to come from the current build.
    pub async fn read_latest_ceremony_state_from_current_build(
        &mut self,
    ) -> GuardianResult<CeremonyState> {
        self.read_latest_ceremony_state_with_build_requirement(true)
            .await
            .map(|(state, _dealer)| state)
    }

    /// Like [`Self::read_latest_ceremony_state_from_current_build`], with the
    /// session that dealt the ceremony: the writer of its `ceremony/` record.
    pub async fn read_latest_ceremony_state_with_dealer(
        &mut self,
    ) -> GuardianResult<(CeremonyState, SessionID)> {
        self.read_latest_ceremony_state_with_build_requirement(true)
            .await
    }

    /// Once a ceremony is present, its matching KP-share state must also exist
    /// because writers publish `kp-shares/` before `ceremony/`.
    async fn read_latest_ceremony_state_with_build_requirement(
        &mut self,
        require_current: bool,
    ) -> GuardianResult<(CeremonyState, SessionID)> {
        let (ceremony, dealer) = self
            .read_latest_ceremony_log(require_current)
            .await?
            .ok_or_else(|| {
                InvalidInputs("no ceremony log found; setup_new_key has not run".into())
            })?;
        let sharing_seq = ceremony.sharing_seq();
        let kp_share_state = self
            .read_latest_kp_share_state_log(sharing_seq, require_current)
            .await?
            .ok_or_else(|| {
                InvalidS3Log(format!(
                    "no kp-shares log found for latest ceremony sharing_seq {sharing_seq}"
                ))
            })?;
        let state = CeremonyState::new(ceremony, kp_share_state)
            .expect("ceremony and KP share state must have a consistent shape");
        Ok((state, dealer))
    }

    /// Read the latest serving committee.
    ///
    /// Prefer the latest `committee-update/` record, then fall back
    /// to the KP-authorized `genesis/record.json` bootstrap record. Return
    /// `None` if neither source exists.
    pub async fn read_latest_committee(&mut self) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update().await? {
            return Ok(Some(committee));
        }
        Ok(self.read_genesis().await?.map(|genesis| genesis.committee))
    }

    /// Read and verify the applied committee with the highest epoch, or return
    /// `None` if no update exists.
    ///
    /// Keys begin with a zero-padded epoch, so the lexicographically
    /// greatest key identifies the latest applied committee.
    async fn read_latest_committee_update(&mut self) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .list_keys(&CommitteeUpdateLogMessage::object_key_dir())
            .await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = verified_record
            .into_entry()
            .into_message()
            .into_committee_update()
            .ok_or_else(|| InvalidS3Log(format!("expected a committee-update log at {key}")))?;
        log_verified_read(&key, &session_id);
        Ok(Some(msg.new_committee))
    }

    /// Read and verify the fixed KP-authorized bootstrap record, or return
    /// `None` if `genesis/record.json` has not been written.
    pub async fn read_genesis(&mut self) -> GuardianResult<Option<Box<GenesisLogMessage>>> {
        let key = GenesisLogMessage::object_key();
        let keys = self
            .s3
            .list_keys(&GenesisLogMessage::object_key_dir())
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
        let genesis = verified_record
            .into_entry()
            .into_message()
            .into_genesis()
            .ok_or_else(|| InvalidS3Log(format!("expected a genesis log at {key}")))?;
        log_verified_read(&key, &session_id);
        Ok(Some(genesis))
    }
}

fn log_verified_read(key: &str, session_id: &SessionID) {
    info!("Successfully read {key} from session {session_id}.");
}

#[cfg(test)]
pub(crate) fn reader_with_record_for_test(
    record: Option<LogRecord>,
    signing_pubkey: hashi_types::guardian::GuardianPubKey,
    extra_keys: Vec<String>,
) -> GuardianReader {
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::primitives::DateTime;
    use aws_sdk_s3::types::CommonPrefix;
    use aws_sdk_s3::types::ObjectLockMode;
    use aws_sdk_s3::types::ObjectVersion;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::InitConfig;
    use hashi_types::guardian::S3ObjectLockPolicy;
    use std::sync::Arc;
    use std::sync::Mutex;

    let mut keys = extra_keys;
    if let Some(record) = &record {
        keys.push(record.object_key().to_string());
    }
    let request = Arc::new(Mutex::new((String::new(), false)));
    let captured_request = request.clone();
    let list = mock!(Client::list_object_versions)
        .match_requests(move |req| {
            *captured_request.lock().unwrap() = (
                req.prefix().unwrap_or_default().to_string(),
                req.delimiter() == Some("/"),
            );
            true
        })
        .then_output(move || {
            let (prefix, directories) = &*request.lock().unwrap();
            if *directories {
                let prefixes: std::collections::BTreeSet<_> = keys
                    .iter()
                    .filter_map(|key| {
                        let rest = key.strip_prefix(prefix)?;
                        let slash = rest.find('/')?;
                        Some(format!("{prefix}{}", &rest[..=slash]))
                    })
                    .collect();
                return ListObjectVersionsOutput::builder()
                    .set_common_prefixes(Some(
                        prefixes
                            .into_iter()
                            .map(|prefix| CommonPrefix::builder().prefix(prefix).build())
                            .collect(),
                    ))
                    .build();
            }
            ListObjectVersionsOutput::builder()
                .set_versions(Some(
                    keys.iter()
                        .filter(|key| key.starts_with(prefix.as_str()))
                        .map(|key| ObjectVersion::builder().key(key).is_latest(true).build())
                        .collect(),
                ))
                .build()
        });
    let config = InitConfig::mock_for_testing();
    let policy = S3ObjectLockPolicy::for_environment(config.deployment().retention_environment);
    let record_key = record
        .as_ref()
        .map(|record| record.object_key().to_string());
    let get = mock!(Client::get_object)
        .match_requests(move |req| req.key() == record_key.as_deref())
        .then_output(move || {
            let record = record.as_ref().unwrap();
            GetObjectOutput::builder()
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(DateTime::from(record.object_lock_expiry(policy)))
                .body(ByteStream::from(serde_json::to_vec(record).unwrap()))
                .build()
        });
    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list, &get]);
    let s3 = GuardianS3Client::from_client(
        config.deployment().bucket_info.clone(),
        config.deployment().retention_environment,
        client,
    );
    let mut reader =
        GuardianReader::from_s3_client(s3, config.deployment().clone(), Arc::new(SystemClock));
    // Seed the attestation cache; the records still undergo normal signature,
    // object-key, history, and lock verification.
    reader.sessions.insert(
        SessionID::from_signing_pubkey(&signing_pubkey),
        VerifiedSessionInfo::new_for_test(
            signing_pubkey,
            config.deployment().pcr_allowlist.current_build().clone(),
        ),
    );
    reader
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_logger_with_layout;
    use crate::test_utils::OperatorInitTestArgs;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::SecretSharingInstance;

    async fn next(keys: &[&str]) -> GuardianResult<u64> {
        let s3 = mock_logger_with_layout(keys.iter().map(|key| key.to_string()));
        GuardianReader::from_s3_client(
            s3,
            DeploymentConfig::mock_for_testing(),
            Arc::new(SystemClock),
        )
        .next_sharing_seq()
        .await
    }

    async fn next_after_ceremony(sharing_seq: u64, keys: &[&str]) -> GuardianResult<u64> {
        let state = OperatorInitTestArgs::default().ceremony_state;
        let old_instance = state.secret_sharing_instance;
        let instance = SecretSharingInstance::new(
            old_instance.commitments().clone(),
            old_instance.num_shares(),
            old_instance.threshold(),
            sharing_seq,
        )
        .unwrap();
        let signing_key = GuardianSignKeyPair::from([42; 32]);
        let record = LogRecord::new(
            SessionID::from_signing_pubkey(&signing_key.verification_key()),
            LogMessage::Ceremony(Box::new(CeremonyLogMessage::NewKey {
                instance,
                btc_master_pubkey: state.btc_master_pubkey,
            })),
            &signing_key,
        );
        reader_with_record_for_test(
            Some(record),
            signing_key.verification_key(),
            keys.iter().map(|key| key.to_string()).collect(),
        )
        .next_sharing_seq()
        .await
    }

    #[tokio::test]
    async fn empty_bucket_and_proposals_do_not_consume_sequences() {
        assert_eq!(next(&[]).await.unwrap(), 0);
        assert_eq!(next(&["kp-shares/proposed/session.json"]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn skips_initial_shares_from_abandoned_setup() {
        assert_eq!(
            next(&["kp-shares/00000000000000000000/00000000000000000000.json"])
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn skips_abandoned_rotations_without_reusing_gaps() {
        assert_eq!(
            next_after_ceremony(
                6,
                &[
                    "kp-shares/00000000000000000006/00000000000000000099.json",
                    "kp-shares/00000000000000000007/00000000000000000000.json",
                    "kp-shares/00000000000000000009/00000000000000000000.json",
                ]
            )
            .await
            .unwrap(),
            10
        );
    }

    #[tokio::test]
    async fn completed_ceremony_consumes_sequence_even_after_shares_are_purged() {
        assert_eq!(next_after_ceremony(6, &[]).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn delete_marked_orphan_still_consumes_its_sequence() {
        let s3 = crate::test_utils::mock_logger_with_deleted_layout(
            std::iter::empty(),
            ["kp-shares/00000000000000000007/00000000000000000000.json".to_string()],
        );
        let mut reader = GuardianReader::from_s3_client(
            s3,
            DeploymentConfig::mock_for_testing(),
            Arc::new(SystemClock),
        );
        assert_eq!(reader.next_sharing_seq().await.unwrap(), 8);
    }

    #[tokio::test]
    async fn rejects_malformed_or_exhausted_sequences() {
        assert!(next_after_ceremony(u64::MAX, &[]).await.is_err());
        for key in [
            "kp-shares/9/record.json",
            "kp-shares/bad/record.json",
            "kp-shares/18446744073709551615/record.json",
        ] {
            assert!(next(&[key]).await.is_err(), "{key}");
        }
    }
}
