// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified read layer over the guardian's S3 logs.
//!
//! The guardian writes its logs via [`GuardianS3Client`]; off-enclave readers
//! (the monitor auditor, KP/operator init tooling) replay them here through a
//! [`GuardianReader`], which owns the S3 client and the trusted-key cache so a
//! session's attestation is verified once across every read. Streams are
//! hour-partitioned (`withdraw/`/`heartbeat/`); [`withdraw_cursor`]/[`heartbeat_cursor`]
//! open a cursor that the caller advances/retreats and feeds to [`GuardianReader::read_dir`].

use crate::s3_client::GuardianS3Client;
use anyhow::Context;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::KPEncryptedShare;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::S3_DIR_CEREMONY;
use hashi_types::guardian::S3_DIR_COMMITTEE_UPDATE;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_SHARES;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::move_types::Committee;
use std::collections::HashMap;

/// Open an hour-scoped cursor at `start` over the `withdraw/` stream. Advance/
/// retreat with [`S3HourScopedDirectory::next_dir`]/`prev_dir`, gate on
/// `write_completion_time`, and read via [`GuardianReader::read_dir`].
pub fn withdraw_cursor(start: UnixSeconds) -> S3HourScopedDirectory {
    S3HourScopedDirectory::new(S3_DIR_WITHDRAW, start)
}

/// Like [`withdraw_cursor`], but over the `heartbeat/` stream.
pub fn heartbeat_cursor(start: UnixSeconds) -> S3HourScopedDirectory {
    S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, start)
}

/// Verified reader over the guardian's S3 logs. Owns the S3 client and a private
/// session-key cache, so each session's (eventually expensive) attestation check
/// happens at most once across every read. Thread a single `&mut GuardianReader`
/// through a run.
pub struct GuardianReader {
    s3: GuardianS3Client,
    pubkey_cache: GuardianSessionKeyCache,
}

impl GuardianReader {
    pub async fn new(config: &S3Config) -> anyhow::Result<Self> {
        let s3 = GuardianS3Client::new_checked(config)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .context("failed to verify guardian S3 connectivity")?;
        Ok(Self::from_s3_client(s3))
    }

    pub fn from_s3_client(s3: GuardianS3Client) -> Self {
        Self {
            s3,
            pubkey_cache: GuardianSessionKeyCache::default(),
        }
    }

    /// Raw S3 client, for unverified listing/reads (e.g. the limiter's bucket walk).
    pub fn s3(&self) -> &GuardianS3Client {
        &self.s3
    }

    /// Read and verify every record in `dir`, resolving each writing session's
    /// signing pubkey via the cache (loaded once per session).
    pub async fn read_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> anyhow::Result<Vec<VerifiedLogRecord>> {
        let all_logs = self
            .s3
            .list_all_objects_in_dir::<LogRecord>(dir)
            .await
            .with_context(|| format!("failed to list guardian logs in {dir}"))?;

        let mut out = Vec::with_capacity(all_logs.len());
        for log in all_logs {
            out.push(self.pubkey_cache.verify_record(&self.s3, log).await?);
        }
        Ok(out)
    }

    /// Read and verify a session's signed `OIGuardianInfo` log (written at
    /// operator-init). Implements check B of IOP-225.
    pub async fn get_info(&mut self, session_id: &str) -> anyhow::Result<GuardianInfo> {
        let key = InitLogMessage::guardian_info_object_key(session_id);
        let record = self.s3.get_log_record(&key).await?;
        self.pubkey_cache
            .verify_record(&self.s3, record)
            .await?
            .message
            .into_init_log()
            .and_then(|x| match x {
                InitLogMessage::OIGuardianInfo(info) => Some(*info),
                _ => None,
            })
            .with_context(|| format!("expected OIGuardianInfo at {key}"))
    }

    /// The latest secret-sharing instance from `ceremony/` — the max-`sharing_seq`
    /// (lex-last) entry, attestation- and signature-verified. `None` if no ceremony
    /// has been logged yet. Written from initial setup onward, so present whenever a
    /// key exists.
    pub async fn read_latest_ceremony_instance(
        &mut self,
    ) -> anyhow::Result<Option<SecretSharingInstance>> {
        Ok(self
            .read_latest_ceremony()
            .await?
            .map(|(_, instance)| instance))
    }

    /// Like [`Self::read_latest_ceremony_instance`], but also returns the writing
    /// session id — needed to locate the matching `shares/` object for recovery.
    pub async fn read_latest_ceremony(
        &mut self,
    ) -> anyhow::Result<Option<(SessionID, SecretSharingInstance)>> {
        let keys = self
            .s3
            .list_all_keys_in_dir(&format!("{}/", S3_DIR_CEREMONY))
            .await?;
        let Some(key) = pick_latest_key(keys, S3_DIR_CEREMONY) else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let record = self.pubkey_cache.verify_record(&self.s3, record).await?;
        let session_id = record.session_id.clone();
        let LogMessage::Ceremony(msg) = record.message else {
            anyhow::bail!("expected a ceremony log at {key}");
        };
        let instance = match *msg {
            CeremonyLogMessage::NewKey { instance, .. } => instance,
            CeremonyLogMessage::Rotate { new_instance, .. } => new_instance,
        };
        Ok(Some((session_id, instance)))
    }

    /// Read + verify the encrypted shares at `shares/{seq}-{session}.json`. Point
    /// read by exact key (recovery anchors on the ceremony instance's seq), so a
    /// purged older `shares/` object never blocks reading the current one.
    ///
    /// Uses the lock-agnostic read: shares carry only a short lock that is
    /// expected to expire, and their integrity is the enclave signature checked
    /// below — not S3 immutability — so the immutable-log lock assertion in
    /// `get_log_record` doesn't apply.
    pub async fn read_shares(
        &mut self,
        session_id: &str,
        sharing_seq: u64,
    ) -> anyhow::Result<Vec<KPEncryptedShare>> {
        let key = format!("{}/{:020}-{}.json", S3_DIR_SHARES, sharing_seq, session_id);
        let record: LogRecord = self.s3.get_object_no_lock(&key).await?;
        let record = self.pubkey_cache.verify_record(&self.s3, record).await?;
        let LogMessage::Shares(msg) = record.message else {
            anyhow::bail!("expected a shares log at {key}");
        };
        Ok(msg.encrypted_shares)
    }

    /// The latest applied committee from `committee-update/` — the lex-last
    /// non-`failure-` (i.e. highest-epoch Success) entry, attestation- and
    /// signature-verified. `None` if no committee update has been logged (e.g. a
    /// fresh deployment whose committee still only exists in the operator's boot
    /// config).
    pub async fn read_latest_committee(&mut self) -> anyhow::Result<Option<Committee>> {
        let keys = self
            .s3
            .list_all_keys_in_dir(&format!("{}/", S3_DIR_COMMITTEE_UPDATE))
            .await?;
        let Some(key) = pick_latest_key(keys, S3_DIR_COMMITTEE_UPDATE) else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let record = self.pubkey_cache.verify_record(&self.s3, record).await?;
        let LogMessage::CommitteeUpdate(msg) = record.message else {
            anyhow::bail!("expected a committee-update log at {key}");
        };
        match *msg {
            CommitteeUpdateLogMessage::Success { new_committee, .. } => Ok(Some(new_committee)),
            CommitteeUpdateLogMessage::Failure { .. } => {
                anyhow::bail!("lex-last non-failure key resolved to a Failure log at {key}")
            }
        }
    }
}

/// Enclave signing pubkeys trusted after their attestation was verified once,
/// keyed by session. Internal to [`GuardianReader`].
///
/// TODO(check C): make this the trust engine — construct it with a trusted
/// `commit -> ExpectedPcrs` map and pin each session's attested PCRs against the
/// entry for its `/info`-reported commit.
#[derive(Default)]
struct GuardianSessionKeyCache {
    keys: HashMap<SessionID, GuardianPubKey>,
}

impl GuardianSessionKeyCache {
    /// The session's signing pubkey, verifying and caching its attestation on first use.
    async fn get_or_load_pubkey(
        &mut self,
        s3: &GuardianS3Client,
        session_id: &str,
    ) -> anyhow::Result<&GuardianPubKey> {
        if !self.keys.contains_key(session_id) {
            let pubkey = s3.get_verified_enclave_pubkey(session_id).await?;
            self.keys.insert(session_id.to_string(), pubkey);
        }
        Ok(&self.keys[session_id])
    }

    /// Verify `record`'s signature under its session's trusted pubkey.
    async fn verify_record(
        &mut self,
        s3: &GuardianS3Client,
        record: LogRecord,
    ) -> anyhow::Result<VerifiedLogRecord> {
        let signing_pubkey = self.get_or_load_pubkey(s3, &record.session_id).await?;
        record
            .verify(signing_pubkey)
            .with_context(|| "failed to verify guardian enclave signature")
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
