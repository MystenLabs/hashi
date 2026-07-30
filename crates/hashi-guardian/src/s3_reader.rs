// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified read layer over the guardian's S3 logs.
//!
//! The guardian writes its logs via [`GuardianS3Client`]; off-enclave readers
//! (the monitor auditor, KP/operator init tooling) replay them here through a
//! [`GuardianReader`], which owns the S3 client and a per-session info cache
//! that records the build PCRs verified for each session. Streams are
//! hour-partitioned (`withdraw/`/`heartbeat/`);
//! [`withdraw_cursor`]/[`heartbeat_cursor`] open a cursor that the caller
//! advances/retreats and feeds to [`GuardianReader::read_logs_in_dir`].

use crate::s3_client::GuardianS3Client;
use crate::s3_client::HistoryCheck;
use crate::s3_client::LockCheck;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
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
use hashi_types::guardian::S3_DIR_CEREMONY;
use hashi_types::guardian::S3_DIR_COMMITTEE_UPDATE;
use hashi_types::guardian::S3_DIR_GENESIS;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
use tracing::info;

mod heartbeat_checks;
mod limiter_recovery;
mod verified;

pub use verified::VerifiedLogRecord;
pub use verified::VerifiedSessionInfo;

/// Open an hour-scoped cursor at `start` over the `withdraw/` stream. Advance/
/// retreat with [`S3HourScopedDirectory::next_dir`]/`prev_dir`, gate on
/// `write_completion_time`, and read via [`GuardianReader::read_logs_in_dir`].
pub fn withdraw_cursor(start: UnixSeconds) -> S3HourScopedDirectory {
    S3HourScopedDirectory::new(S3_DIR_WITHDRAW, start)
}

/// Like [`withdraw_cursor`], but over the `heartbeat/` stream.
pub fn heartbeat_cursor(start: UnixSeconds) -> S3HourScopedDirectory {
    S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, start)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildPolicy {
    Current,
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

/// Verified reader over the guardian's S3 logs. Verified reads accept any
/// allowlisted build unless the method explicitly requires the current build.
/// Thread a single `&mut GuardianReader` through a run so repeated reads can
/// reuse session info and inspect the attested build.
pub struct GuardianReader {
    s3: GuardianS3Client,
    allowlist: PcrAllowlist,
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
}

impl GuardianReader {
    pub async fn new(config: &S3Config, allowlist: PcrAllowlist) -> GuardianResult<Self> {
        let s3 = GuardianS3Client::new_checked(config).await?;
        Ok(Self::from_s3_client(s3, allowlist))
    }

    pub fn from_s3_client(s3: GuardianS3Client, allowlist: PcrAllowlist) -> Self {
        Self {
            s3,
            allowlist,
            sessions: HashMap::new(),
        }
    }

    /// The session's verified info, resolving and caching it on first use.
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

    /// Fully verify `record` under its session's attested signing key.
    async fn verify_record(&mut self, record: LogRecord) -> GuardianResult<VerifiedLogRecord> {
        let session_id = record.session_id().clone();
        let session_info = self.get_or_load_session_info(&session_id).await?;
        VerifiedLogRecord::new(record, session_info)
    }

    /// Read and verify every record in `dir`, resolving each writing session's
    /// signing pubkey. Batch readers can straddle upgrades, so each returned
    /// record retains its attested build PCRs.
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

    /// The current build's verified guardian info for `session_id`.
    pub async fn get_current_session_info(
        &mut self,
        session_id: &str,
    ) -> GuardianResult<VerifiedSessionInfo> {
        let session_info = self.get_or_load_session_info(session_id).await?.clone();
        self.allowlist
            .require_current_build(session_info.build_pcrs())?;
        Ok(session_info)
    }

    /// The latest ceremony from `ceremony/` — the max-`sharing_seq` (lex-last)
    /// entry, attestation- and signature-verified. `None` if no ceremony has
    /// been logged yet.
    ///
    /// `kp-shares/` is read independently so later KP cert rotations can advance
    /// `cert_seq` without rewriting the `ceremony/` instance.
    async fn read_latest_ceremony_log(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<CeremonyLogMessage>> {
        let keys = self
            .s3
            .validate_prefix_history_and_list_keys(&format!("{}/", S3_DIR_CEREMONY))
            .await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let verified_record = self.verify_record(record).await?;
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

    /// Read + verify the latest encrypted KP share state for `sharing_seq`.
    /// The lex-greatest object under `kp-shares/{sharing_seq:020}/` has the
    /// latest `cert_seq`, so future per-KP cert rotation can advance the share
    /// recipient state without changing the `ceremony/` instance.
    ///
    /// Uses the lock-agnostic read: shares carry only a short lock that is
    /// expected to expire, and their integrity is the enclave signature checked
    /// below — not S3 immutability — so the immutable-log lock assertion in
    /// `get_log_record` doesn't apply.
    async fn read_latest_kp_share_state_log(
        &mut self,
        sharing_seq: u64,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<KpShareStateLogMessage>> {
        let prefix = KpShareStateLogMessage::object_key_dir(sharing_seq);
        let keys = self
            .s3
            .validate_prefix_history_and_list_keys(&prefix)
            .await?;
        let Some(key) = keys.into_iter().max() else {
            return Ok(None);
        };
        // The enclosing prefix's version history was checked while listing the
        // candidate keys above, so the selected key does not need another check.
        let msg = self
            .read_kp_share_state_log_at_key(&key, build_policy, HistoryCheck::AlreadyChecked)
            .await?;
        if msg.sharing_seq != sharing_seq {
            return Err(InvalidS3Log(format!(
                "sharing_seq mismatch: {} != {}",
                msg.sharing_seq, sharing_seq
            )));
        }
        Ok(Some(msg))
    }

    /// Read and verify one exact encrypted KP-share snapshot written by the
    /// current build.
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
        // Unlike the latest-state path, this direct read has not already
        // checked an enclosing prefix, so validate this exact key's history.
        self.read_kp_share_state_log_at_key(&key, BuildPolicy::Current, HistoryCheck::Required)
            .await
    }

    /// Shared verification path for both latest and exact KP-share reads.
    async fn read_kp_share_state_log_at_key(
        &mut self,
        key: &str,
        build_policy: BuildPolicy,
        history_check: HistoryCheck,
    ) -> GuardianResult<KpShareStateLogMessage> {
        // KP-share locks are short-lived and expected to expire. Expiry permits
        // deletion but does not cause it; while an object remains, its contents
        // are authenticatable through the enclave signature verified below.
        let record = self
            .s3
            .get_log_record_inner(key, LockCheck::Skipped, history_check)
            .await?;
        let verified_record = self.verify_record(record).await?;
        build_policy.enforce(&self.allowlist, verified_record.build_pcrs())?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::KpShareState(msg)) => (*msg).try_into()?,
            V2(LogMessageV2::KpShareState(msg)) => *msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a kp-shares log at {key}")));
            }
        };
        log_verified_read(key, &session_id);
        Ok(msg)
    }

    /// Read the latest ceremony together with the latest KP share state for its
    /// `sharing_seq`, accepting any allowlisted build.
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<Option<CeremonyState>> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::AnyAllowlisted)
            .await
    }

    /// Read the latest ceremony together with the latest KP share state for its
    /// `sharing_seq`, requiring both records to come from the current build.
    pub async fn read_latest_ceremony_state_from_current_build(
        &mut self,
    ) -> GuardianResult<Option<CeremonyState>> {
        self.read_latest_ceremony_state_with_build_policy(BuildPolicy::Current)
            .await
    }

    /// `None` means no ceremony has been logged. Once a ceremony exists, its
    /// matching KP share state must also exist: ceremony writers publish
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

    /// Latest serving committee, preferring `committee-update/` and falling back
    /// to the KP-authorized `genesis/record.json` bootstrap record. `None`
    /// means neither source has been written yet.
    pub async fn read_latest_committee(&mut self) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update().await? {
            return Ok(Some(committee));
        }
        Ok(self
            .read_genesis_log()
            .await?
            .map(|genesis| genesis.committee))
    }

    /// The latest applied committee from `committee-update/` — the lex-last
    /// non-`failure-` (i.e. highest-epoch Success) entry, attestation- and
    /// signature-verified. `None` if no committee update has been logged.
    async fn read_latest_committee_update(&mut self) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .validate_prefix_history_and_list_keys(&format!("{}/", S3_DIR_COMMITTEE_UPDATE))
            .await?;
        let Some(key) = keys
            .into_iter()
            .filter(|key| !CommitteeUpdateLogMessage::is_failure_object_key(key))
            .max()
        else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let verified_record = self.verify_record(record).await?;
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

    /// Fixed genesis record from `genesis/record.json`. `None` means the
    /// KP-authorized bootstrap record has not been written yet.
    async fn read_genesis_log(&mut self) -> GuardianResult<Option<GenesisLogMessage>> {
        let key = GenesisLogMessage::object_key();
        let keys = self
            .s3
            .validate_prefix_history_and_list_keys(&format!("{}/", S3_DIR_GENESIS))
            .await?;
        if keys.is_empty() {
            return Ok(None);
        }
        if keys != [key.clone()] {
            return Err(InvalidS3Log(format!(
                "expected exactly one genesis record at {key}, found {keys:?}"
            )));
        }
        let record = self.s3.get_log_record(&key).await?;
        let verified_record = self.verify_record(record).await?;
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
