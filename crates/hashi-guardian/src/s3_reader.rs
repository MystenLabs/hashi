// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified reads of the guardian's S3 logs.
//!
//! [`GuardianReader`] applies each log stream's S3 immutability policy, verifies
//! records with their writing session's attestation-anchored key, and caches the
//! verified session info for reuse.

use crate::s3_client::GuardianS3Client;
use crate::s3_client::ImmutabilityCheck;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
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
}

impl GuardianReader {
    /// Create a reader after checking S3 connectivity and object-lock support.
    pub async fn new(config: &S3Config, allowlist: PcrAllowlist) -> GuardianResult<Self> {
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
        let session_info = self.get_or_load_session_info(record.session_id()).await?;
        session_info.verify_record(record)
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
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<Option<CeremonyState>> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::AnyAllowlisted)
            .await
    }

    /// Read the latest ceremony together with the latest KP-share state for its
    /// `sharing_seq`, requiring both records to come from the current build.
    pub async fn read_latest_ceremony_state_from_current_build(
        &mut self,
    ) -> GuardianResult<Option<CeremonyState>> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::Current)
            .await
    }

    /// Return `None` only when no ceremony exists. Once a ceremony is present,
    /// its matching KP-share state must also exist because writers publish
    /// `kp-shares/` before `ceremony/`.
    async fn read_latest_ceremony_state_with_build_policy(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<CeremonyState>> {
        let Some(ceremony) = self.read_latest_ceremony_log(build_policy).await? else {
            return Ok(None);
        };
        let sharing_seq = ceremony.sharing_seq();
        let kp_share_state = self
            .read_latest_kp_share_state_log(sharing_seq, build_policy)
            .await?
            .ok_or_else(|| {
                InvalidS3Log(format!(
                    "no kp-shares log found for latest ceremony sharing_seq {sharing_seq}"
                ))
            })?;
        Ok(Some(CeremonyState::new(ceremony, kp_share_state).expect(
            "ceremony and KP share state must have a consistent shape",
        )))
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

fn log_verified_read(key: &str, session_id: &SessionID) {
    info!("Successfully read {key} from session {session_id}.");
}
