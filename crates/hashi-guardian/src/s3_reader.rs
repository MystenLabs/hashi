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
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::VerifiedSessionInfo;
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
pub enum BuildPolicy {
    /// Accept only the configured current guardian build.
    Current,
    /// Accept either the configured current build or an explicitly allowlisted
    /// previous build. This is for historical log reads, not live-session checks.
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

/// Verified reader over the guardian's S3 logs. Owns the S3 client and a private
/// session cache. Thread a single `&mut GuardianReader` through a run so repeated
/// reads can reuse session info and inspect the attested build.
pub struct GuardianReader {
    s3: GuardianS3Client,
    cache: GuardianSessionCache,
}

impl GuardianReader {
    pub async fn new(config: &S3Config, allowlist: PcrAllowlist) -> GuardianResult<Self> {
        let s3 = GuardianS3Client::new_checked(config).await?;
        Ok(Self::from_s3_client(s3, allowlist))
    }

    pub fn from_s3_client(s3: GuardianS3Client, allowlist: PcrAllowlist) -> Self {
        Self {
            s3,
            cache: GuardianSessionCache::new(allowlist),
        }
    }

    /// Raw S3 client, for unverified listing/reads (e.g. the limiter's bucket walk).
    pub fn s3(&self) -> &GuardianS3Client {
        &self.s3
    }

    pub fn require_current_build(&self, build_pcrs: &BuildPcrs) -> GuardianResult<()> {
        self.cache.allowlist.require_current_build(build_pcrs)
    }

    fn enforce_build_policy(
        &self,
        build_policy: BuildPolicy,
        build_pcrs: &BuildPcrs,
    ) -> GuardianResult<()> {
        build_policy.enforce(&self.cache.allowlist, build_pcrs)
    }

    /// Read and verify every record in `dir`, resolving each writing session's
    /// signing pubkey via the cache. Batch readers can straddle upgrades, so
    /// callers that need current-only semantics must inspect each returned
    /// record's build PCRs with [`Self::require_current_build`].
    pub async fn read_logs_in_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let all_logs = self.s3.list_all_log_records_in_dir(dir).await?;

        let mut out = Vec::with_capacity(all_logs.len());
        for log in all_logs {
            out.push(self.cache.verify_record(&self.s3, log).await?);
        }
        Ok(out)
    }

    /// The session's verified guardian info. Served from the session cache, which
    /// resolves the attestation + signed info on first touch and records the
    /// verified build PCRs.
    pub async fn get_session_info(
        &mut self,
        session_id: &str,
        build_policy: BuildPolicy,
    ) -> GuardianResult<VerifiedSessionInfo> {
        let session_info = self
            .cache
            .get_or_load_session_info(&self.s3, session_id)
            .await?
            .clone();
        self.enforce_build_policy(build_policy, &session_info.build_pcrs)?;
        Ok(session_info)
    }

    /// The session's verified `GuardianInfo`, discarding the verified build PCRs.
    pub async fn get_info(
        &mut self,
        session_id: &str,
        build_policy: BuildPolicy,
    ) -> GuardianResult<GuardianInfo> {
        Ok(self.get_session_info(session_id, build_policy).await?.info)
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
        let Some(key) = pick_latest_key(keys, S3_DIR_CEREMONY) else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let record = self.cache.verify_record(&self.s3, record).await?;
        let build_pcrs = record.build_pcrs.clone();
        self.enforce_build_policy(build_policy, &build_pcrs)?;
        let session_id = record.session_id;
        let LogMessage::Ceremony(msg) = record.message else {
            return Err(InvalidS3Log(format!("expected a ceremony log at {key}")));
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

    /// Read and verify one exact encrypted KP-share snapshot.
    ///
    /// The object key binds the writing guardian session and the two sequence
    /// numbers. This lets callers verify the snapshot produced by one request
    /// even if a later request has already advanced the latest state.
    pub async fn read_kp_share_state_log(
        &mut self,
        session_id: &SessionID,
        sharing_seq: u64,
        cert_seq: u64,
        build_policy: BuildPolicy,
    ) -> GuardianResult<KpShareStateLogMessage> {
        let key = KpShareStateLogMessage::object_key(session_id, sharing_seq, cert_seq);
        // Unlike the latest-state path, this direct read has not already
        // checked an enclosing prefix, so validate this exact key's history.
        self.read_kp_share_state_log_at_key(&key, build_policy, HistoryCheck::Required)
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
        let record = self.cache.verify_record(&self.s3, record).await?;
        self.enforce_build_policy(build_policy, &record.build_pcrs)?;
        let session_id = record.session_id;
        let LogMessage::KpShareState(msg) = record.message else {
            return Err(InvalidS3Log(format!("expected a kp-shares log at {key}")));
        };
        log_verified_read(key, &session_id);
        Ok(*msg)
    }

    /// Read the latest ceremony together with the latest KP share state for its
    /// `sharing_seq`. `None` means no ceremony has been logged. Once a ceremony
    /// exists, its matching KP share state must also exist: ceremony writers
    /// publish `kp-shares/` before `ceremony/`.
    pub async fn read_latest_ceremony_state(
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
    pub async fn read_latest_committee(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update(build_policy).await? {
            return Ok(Some(committee));
        }
        Ok(self
            .read_genesis_log(build_policy)
            .await?
            .map(|genesis| genesis.committee))
    }

    /// The latest applied committee from `committee-update/` — the lex-last
    /// non-`failure-` (i.e. highest-epoch Success) entry, attestation- and
    /// signature-verified. `None` if no committee update has been logged.
    async fn read_latest_committee_update(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .validate_prefix_history_and_list_keys(&format!("{}/", S3_DIR_COMMITTEE_UPDATE))
            .await?;
        let Some(key) = pick_latest_key(keys, S3_DIR_COMMITTEE_UPDATE) else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let record = self.cache.verify_record(&self.s3, record).await?;
        self.enforce_build_policy(build_policy, &record.build_pcrs)?;
        let session_id = record.session_id;
        let LogMessage::CommitteeUpdate(msg) = record.message else {
            return Err(InvalidS3Log(format!(
                "expected a committee-update log at {key}"
            )));
        };
        let committee = match *msg {
            CommitteeUpdateLogMessage::Success { new_committee, .. } => new_committee,
            CommitteeUpdateLogMessage::Failure { .. } => {
                return Err(InvalidS3Log(format!(
                    "lex-last non-failure key resolved to a Failure log at {key}"
                )));
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(committee))
    }

    /// Fixed genesis record from `genesis/record.json`. `None` means the
    /// KP-authorized bootstrap record has not been written yet.
    async fn read_genesis_log(
        &mut self,
        build_policy: BuildPolicy,
    ) -> GuardianResult<Option<GenesisLogMessage>> {
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
        let record = self.cache.verify_record(&self.s3, record).await?;
        self.enforce_build_policy(build_policy, &record.build_pcrs)?;
        let session_id = record.session_id;
        let LogMessage::Genesis(msg) = record.message else {
            return Err(InvalidS3Log(format!("expected a genesis log at {key}")));
        };
        log_verified_read(&key, &session_id);
        Ok(Some(*msg))
    }
}

fn log_verified_read(key: &str, session_id: &SessionID) {
    info!("Successfully read {key} from session {session_id}.");
}

/// Per-session [`VerifiedSessionInfo`] cache, internal to [`GuardianReader`]. The first
/// touch of a session resolves and verifies its info (attestation + signed
/// info, PCR0 pinned against `allowlist`); later reads reuse it and expose the
/// verified build PCRs to callers.
struct GuardianSessionCache {
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
    allowlist: PcrAllowlist,
}

impl GuardianSessionCache {
    fn new(allowlist: PcrAllowlist) -> Self {
        Self {
            sessions: HashMap::new(),
            allowlist,
        }
    }

    /// The session's verified info, resolving and caching it on first use.
    async fn get_or_load_session_info(
        &mut self,
        s3: &GuardianS3Client,
        session_id: &str,
    ) -> GuardianResult<&VerifiedSessionInfo> {
        if !self.sessions.contains_key(session_id) {
            let session_info = s3
                .get_verified_session_info(session_id, &self.allowlist)
                .await?;
            self.sessions.insert(session_id.into(), session_info);
        }
        Ok(&self.sessions[session_id])
    }

    /// Verify `record`'s signature under its session's trusted pubkey.
    async fn verify_record(
        &mut self,
        s3: &GuardianS3Client,
        record: LogRecord,
    ) -> GuardianResult<VerifiedLogRecord> {
        let object_key = record.object_key.clone();
        let session_id = record.session_id.clone();
        let session_info = self.get_or_load_session_info(s3, &session_id).await?;
        let (session_id, timestamp_ms, message) = record.verify(&session_info.signing_pubkey)?;
        Ok(VerifiedLogRecord::new(
            object_key,
            session_id,
            timestamp_ms,
            message,
            session_info.build_pcrs.clone(),
        ))
    }
}

/// Pick the lex-greatest key, skipping any whose name starts with `<dir>/failure-`.
/// Keys are zero-padded (ceremony `sharing_seq`, committee `epoch`), so the lex-max
/// non-failure key is the latest successful entry.
fn pick_latest_key(keys: Vec<String>, dir: &str) -> Option<String> {
    let failure_prefix = format!("{dir}/failure-");
    keys.into_iter()
        .filter(|k| !k.starts_with(&failure_prefix))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success_key(epoch: u64) -> String {
        format!("{S3_DIR_COMMITTEE_UPDATE}/{epoch:020}-sess.json")
    }
    fn failure_key(epoch: u64) -> String {
        format!("{S3_DIR_COMMITTEE_UPDATE}/failure-{epoch:020}-sess-abcd1234.json")
    }

    #[test]
    fn pick_latest_key_none_when_empty() {
        assert_eq!(pick_latest_key(vec![], S3_DIR_COMMITTEE_UPDATE), None);
    }

    #[test]
    fn pick_latest_key_takes_lex_max() {
        let keys = vec![success_key(3), success_key(7), success_key(5)];
        assert_eq!(
            pick_latest_key(keys, S3_DIR_COMMITTEE_UPDATE),
            Some(success_key(7))
        );
    }

    #[test]
    fn pick_latest_key_skips_higher_failure() {
        // A later-epoch failure (lex-greater than any success) must not win.
        let keys = vec![success_key(5), failure_key(9)];
        assert_eq!(
            pick_latest_key(keys, S3_DIR_COMMITTEE_UPDATE),
            Some(success_key(5))
        );
    }

    #[test]
    fn pick_latest_key_none_when_all_failures() {
        assert_eq!(
            pick_latest_key(vec![failure_key(9)], S3_DIR_COMMITTEE_UPDATE),
            None
        );
    }
}
