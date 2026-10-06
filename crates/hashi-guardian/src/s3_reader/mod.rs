// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read and verify Guardian S3 logs.
//!
//! [`GuardianReader`] applies the S3 immutability policy for each log stream.
//! It verifies each record with the signing key of the session that wrote it.
//! It verifies the session attestation and the required initialization logs.
//! It keeps verified session information in a cache for subsequent reads.

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
use hashi_types::guardian::S3Credentials;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::SignedLogEntry;
use hashi_types::guardian::VersionedLogMessage;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
use tracing::info;

mod heartbeat_checks;
mod limiter_recovery;
mod verified;

pub use verified::VerifiedLogEntry;
pub use verified::VerifiedSessionInfo;

/// A reader that verifies Guardian S3 logs.
///
/// Reads accept any build in the allowlist unless the method requires the current build.
/// Reuse one reader to use the verified session information in its cache.
/// Each session must report the expected bucket, region, retention environment, and Bitcoin network.
pub struct GuardianReader {
    s3: GuardianS3Client,
    expected_deployment: DeploymentConfig,
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
}

impl GuardianReader {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Create a reader from an existing S3 client, including the enclave's configured client.
    /// The client must use the same deployment configuration.
    /// This method does not repeat the S3 connection and Object Lock checks.
    pub(crate) fn from_s3_client(
        s3: GuardianS3Client,
        expected_deployment: DeploymentConfig,
    ) -> Self {
        Self {
            s3,
            expected_deployment,
            sessions: HashMap::new(),
        }
    }

    /// Create a reader outside the enclave, using standard networking.
    /// Check the S3 connection and Object Lock support before returning the reader.
    /// Inside the enclave, use `from_s3_client()` with the configured S3 client.
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
        Ok(Self::from_s3_client(s3, expected_deployment))
    }

    // ========================================================================
    // Session information
    // ========================================================================

    /// Read and verify the session attestation and operator initialization logs on first use.
    async fn ensure_session_info_loaded(&mut self, session_id: &str) -> GuardianResult<()> {
        if !self.sessions.contains_key(session_id) {
            let session_info =
                VerifiedSessionInfo::read_from_s3(&self.s3, session_id, &self.expected_deployment)
                    .await?;
            self.sessions.insert(session_id.into(), session_info);
        }
        Ok(())
    }

    /// Return verified session information and require the current build.
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

    // ========================================================================
    // Log verification and directory reads
    // ========================================================================

    async fn verify_record(
        &mut self,
        log: SignedLogEntry,
        require_current: bool,
    ) -> GuardianResult<VerifiedLogEntry> {
        self.ensure_session_info_loaded(log.session_id()).await?;
        let session_info = self
            .sessions
            .get_mut(log.session_id())
            .expect("session info was loaded above");
        let verified_log = session_info.verify_record(&self.s3, log).await?;
        if require_current {
            self.expected_deployment
                .pcr_allowlist
                .require_current_build(verified_log.build_pcrs())?;
        }
        Ok(verified_log)
    }

    async fn read_log(
        &mut self,
        key: &str,
        require_current: bool,
    ) -> GuardianResult<VerifiedLogEntry> {
        let log = self.s3.get_log_record(key).await?;
        let verified_log = self.verify_record(log, require_current).await?;
        info!(
            key,
            session_id = %verified_log.session_id(),
            "Read and verified the S3 log record"
        );
        Ok(verified_log)
    }

    /// Read and verify each immutable record in a directory for one hour.
    ///
    /// A directory can contain records from more than one build.
    /// Each result includes the build PCR values verified by the session attestation.
    pub async fn read_logs_in_dir(
        &mut self,
        dir: &S3HourDirectory,
    ) -> GuardianResult<Vec<VerifiedLogEntry>> {
        let all_logs = self.s3.list_all_log_records_in_dir(dir).await?;

        let mut out = Vec::with_capacity(all_logs.len());
        for log in all_logs {
            let verified_log = self.verify_record(log, false).await?;
            out.push(verified_log);
        }
        info!(
            directory = %dir,
            record_count = out.len(),
            "Read and verified the S3 log directory"
        );
        Ok(out)
    }

    // ========================================================================
    // KP-share reads
    // ========================================================================

    /// Verify the KP-share record without requiring an active S3 lock, because these locks can expire.
    async fn read_kp_share_state_log_at_key(
        &mut self,
        key: &str,
        require_current: bool,
    ) -> GuardianResult<KpShareStateLogMessage> {
        // KP-share locks are expected to expire, so authenticate the record
        // without claiming that S3 still makes it immutable.
        let log = self
            .s3
            .get_log_record_inner(key, ImmutabilityCheck::Skipped)
            .await?;
        let verified_log = self.verify_record(log, require_current).await?;
        info!(
            key,
            session_id = %verified_log.session_id(),
            "Read and verified the S3 log record"
        );
        let msg = verified_log.extract("kp-shares", VersionedLogMessage::into_kp_share_state)?;
        Ok(*msg)
    }

    /// Read and verify the latest encrypted KP-share state for `sharing_seq`.
    ///
    /// Each key starts with a `cert_seq` value padded with leading zeros.
    /// The last key in lexicographic order identifies the latest state.
    /// KP-share locks can expire.
    /// This method verifies the selected record but does not require S3 immutability.
    async fn read_latest_kp_share_state_log(
        &mut self,
        sharing_seq: u64,
        require_current: bool,
    ) -> GuardianResult<Option<KpShareStateLogMessage>> {
        let keys = self
            .s3
            .list_keys_allowing_mutations(&KpShareStateLogMessage::object_key_dir(sharing_seq))
            .await?;
        if keys.is_empty() {
            info!(
                sharing_seq,
                "No KP-share state log found for the sharing sequence"
            );
            return Ok(None);
        }
        let key = KpShareStateLogMessage::latest_key(sharing_seq, keys)?
            .expect("the key list is nonempty");
        let msg = self
            .read_kp_share_state_log_at_key(&key, require_current)
            .await?;
        Ok(Some(msg))
    }

    /// Read the specified record even if a later state exists.
    pub async fn read_kp_share_state_log_from_current_build(
        &mut self,
        sharing_seq: u64,
        cert_seq: u64,
    ) -> GuardianResult<KpShareStateLogMessage> {
        let key = KpShareStateLogMessage::object_key_for_sequences(sharing_seq, cert_seq);
        self.read_kp_share_state_log_at_key(&key, true).await
    }

    // ========================================================================
    // Ceremony reads and sequence selection
    // ========================================================================

    /// Read and verify the latest ceremony log and return it with its session ID.
    /// Return `None` if no ceremony log exists.
    ///
    /// Each ceremony key starts with a `sharing_seq` value padded with leading zeros.
    /// The last key in lexicographic order identifies the latest ceremony.
    async fn read_latest_ceremony_log(
        &mut self,
        require_current: bool,
    ) -> GuardianResult<Option<(CeremonyLogMessage, SessionID)>> {
        let keys = self
            .s3
            .list_keys(&CeremonyLogMessage::object_key_dir())
            .await?;
        if keys.is_empty() {
            info!("No completed ceremony log found");
            return Ok(None);
        }
        let key = CeremonyLogMessage::latest_key(keys)?.expect("the key list is nonempty");
        let verified_log = self.read_log(&key, require_current).await?;
        let session_id = verified_log.session_id().clone();
        let msg = verified_log.extract("ceremony", VersionedLogMessage::into_ceremony)?;
        Ok(Some((*msg, session_id)))
    }

    /// Read the latest ceremony and its KP-share state with the specified build policy.
    /// The matching KP-share state must exist if the ceremony record exists.
    /// Writers publish `kp-shares/` records before `ceremony/` records.
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
        info!(
            sharing_seq,
            dealer_session_id = %dealer,
            require_current_build = require_current,
            "Loaded the latest ceremony and its KP-share state"
        );
        Ok((state, dealer))
    }

    /// Read the latest ceremony and the latest KP-share state for its `sharing_seq`.
    /// Accept any build in the allowlist.
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<CeremonyState> {
        self.read_latest_ceremony_state_with_build_requirement(false)
            .await
            .map(|(state, _dealer)| state)
    }

    /// Read the latest ceremony and its KP-share state. Return the state and dealer session ID.
    /// Both records must come from the current build.
    /// The dealer session wrote the `ceremony/` record.
    pub async fn read_latest_ceremony_state_from_current_build(
        &mut self,
    ) -> GuardianResult<(CeremonyState, SessionID)> {
        self.read_latest_ceremony_state_with_build_requirement(true)
            .await
    }

    /// Require the current build and an active S3 Compliance lock for the proposal.
    pub async fn read_live_ceremony_proposal(
        &mut self,
        session_id: &SessionID,
    ) -> GuardianResult<CeremonyState> {
        let key = CeremonyProposalLogMessage::object_key(session_id);
        // A live proposal has just been published, so its short-lived Compliance
        // lock must still be active.
        let verified_log = self.read_log(&key, true).await?;
        let proposal = verified_log.extract(
            "ceremony proposal",
            VersionedLogMessage::into_ceremony_proposal,
        )?;
        CeremonyState::from_proposal(*proposal)
            .map_err(|error| InvalidS3Log(format!("invalid ceremony proposal at {key}: {error}")))
    }

    /// Return the next unused sharing sequence number.
    /// It must exceed each sequence number used by a completed ceremony or an existing share directory.
    /// Return zero if neither source contains a sequence number.
    /// Note that writers publish shares before they write the ceremony record.
    /// So an interrupted write can leave a share directory without a ceremony record.
    ///
    /// This method assumes that only one writer creates ceremonies.
    /// It does not reserve the sequence number.
    /// Conditional writes reject records that compete for the same key.
    pub(crate) async fn next_sharing_seq(&mut self) -> GuardianResult<u64> {
        let max_ceremony_sharing_seq = self
            .read_latest_ceremony_log(false)
            .await?
            .map(|(ceremony, _)| ceremony.sharing_seq());
        // Count occupied directories even if their records are unreadable or
        // delete-marked: an interrupted ceremony may have left shares here.
        // Directory names are not authenticated. An operator with S3 write access
        // can increase the next sequence or exhaust it by adding a directory.
        let shares_dir = KpShareStateLogMessage::root_dir();
        let proposals_dir = CeremonyProposalLogMessage::object_key_dir();
        let mut max_kp_share_sharing_seq: Option<u64> = None;
        for directory in self.s3.list_common_prefixes(&shares_dir).await? {
            if directory == proposals_dir {
                continue;
            }
            let seq = KpShareStateLogMessage::sharing_seq_from_dir(&directory)
                .map_err(|err| InvalidS3Log(err.to_string()))?;
            max_kp_share_sharing_seq = max_kp_share_sharing_seq.max(Some(seq));
        }
        let highest = max_ceremony_sharing_seq.max(max_kp_share_sharing_seq);
        let next_seq = match highest {
            None => Ok(0),
            Some(seq) => seq
                .checked_add(1)
                .ok_or_else(|| InvalidS3Log("sharing_seq exhausted".into())),
        }?;
        info!(
            max_ceremony_sharing_seq = ?max_ceremony_sharing_seq,
            max_kp_share_sharing_seq = ?max_kp_share_sharing_seq,
            next_sharing_seq = next_seq,
            "Selected the next ceremony sharing sequence"
        );
        Ok(next_seq)
    }

    // ========================================================================
    // Committee and genesis reads
    // ========================================================================

    /// Read and verify the applied committee with the highest epoch.
    /// Return `None` if no committee update exists.
    ///
    /// Each key starts with an epoch value padded with leading zeros.
    /// The last key in lexicographic order identifies the latest applied committee.
    async fn read_latest_committee_update(&mut self) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .list_keys(&CommitteeUpdateLogMessage::object_key_dir())
            .await?;
        if keys.is_empty() {
            return Ok(None);
        }
        let key = CommitteeUpdateLogMessage::latest_key(keys)?.expect("the key list is nonempty");
        let verified_log = self.read_log(&key, false).await?;
        let msg = verified_log.extract(
            "committee-update",
            VersionedLogMessage::into_committee_update,
        )?;
        Ok(Some(msg.new_committee))
    }

    /// Read and verify the bootstrap record at the fixed key `genesis/record.json`.
    /// The KPs authorize this record.
    /// Return `None` if the record does not exist.
    pub async fn read_genesis(&mut self) -> GuardianResult<Option<Box<GenesisLogMessage>>> {
        let key = GenesisLogMessage::object_key();
        let keys = self
            .s3
            .list_keys(&GenesisLogMessage::object_key_dir())
            .await?;
        if keys.is_empty() {
            info!("No genesis record found");
            return Ok(None);
        }
        if keys != [key.clone()] {
            return Err(InvalidS3Log(format!(
                "expected exactly one genesis record at {key}, found {keys:?}"
            )));
        }
        let verified_log = self.read_log(&key, false).await?;
        let genesis = verified_log.extract("genesis", VersionedLogMessage::into_genesis)?;
        Ok(Some(genesis))
    }

    /// Read the latest committee in service.
    ///
    /// Use the latest `committee-update/` record if one exists.
    /// Otherwise, use the bootstrap record at `genesis/record.json`, which the KPs authorize.
    /// Return `None` if neither record exists.
    pub async fn read_latest_committee(&mut self) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update().await? {
            return Ok(Some(committee));
        }
        info!("No committee update log found; checking the genesis record");
        Ok(self.read_genesis().await?.map(|genesis| genesis.committee))
    }
}

/// Create a reader with mock S3 responses for one optional record and additional keys.
/// Add session information to the cache without attestation verification.
/// Reads still verify the record signature and apply the S3 checks required by the read method.
#[cfg(test)]
pub(crate) fn reader_with_record_for_test(
    log: Option<SignedLogEntry>,
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
    if let Some(log) = &log {
        keys.push(log.object_key().to_string());
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
    let log_key = log.as_ref().map(|log| log.object_key().to_string());
    let get = mock!(Client::get_object)
        .match_requests(move |req| req.key() == log_key.as_deref())
        .then_output(move || {
            let log = log.as_ref().unwrap();
            GetObjectOutput::builder()
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(DateTime::from(log.object_lock_expiry(policy)))
                .body(ByteStream::from(serde_json::to_vec(log).unwrap()))
                .build()
        });
    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&list, &get]);
    let s3 = GuardianS3Client::from_client(
        config.deployment().bucket_info.clone(),
        config.deployment().retention_environment,
        client,
    );
    let mut reader = GuardianReader::from_s3_client(s3, config.deployment().clone());
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
        GuardianReader::from_s3_client(s3, DeploymentConfig::mock_for_testing())
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
        let log = SignedLogEntry::new(
            SessionID::from_signing_pubkey(&signing_key.verification_key()),
            LogMessage::Ceremony(Box::new(CeremonyLogMessage::NewKey {
                instance,
                btc_master_pubkey: state.btc_master_pubkey,
            })),
            &signing_key,
        );
        reader_with_record_for_test(
            Some(log),
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
        let mut reader = GuardianReader::from_s3_client(s3, DeploymentConfig::mock_for_testing());
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
