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
//! advances/retreats and feeds to [`GuardianReader::read_dir`].

use crate::s3_client::GuardianS3Client;
use anyhow::Context;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KPEncryptedShares;
use hashi_types::guardian::KPFingerprint;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::SharesLogMessage;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::VerifiedSessionInfo;
use hashi_types::guardian::S3_DIR_CEREMONY;
use hashi_types::guardian::S3_DIR_COMMITTEE_UPDATE;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
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
    pub async fn new(config: &S3Config, allowlist: PcrAllowlist) -> anyhow::Result<Self> {
        let s3 = GuardianS3Client::new_checked(config)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .context("failed to verify guardian S3 connectivity")?;
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
        context: &str,
        build_policy: BuildPolicy,
        build_pcrs: &BuildPcrs,
    ) -> anyhow::Result<()> {
        build_policy
            .enforce(&self.cache.allowlist, build_pcrs)
            .map_err(|e| anyhow::anyhow!("{context} PCR check: {e:?}"))
    }

    /// Read and verify every record in `dir`, resolving each writing session's
    /// signing pubkey via the cache. Batch readers can straddle upgrades, so
    /// callers that need current-only semantics must inspect each returned
    /// record's build PCRs with [`Self::require_current_build`].
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
    ) -> anyhow::Result<VerifiedSessionInfo> {
        let session_info = self
            .cache
            .get_or_load_session_info(&self.s3, session_id)
            .await?
            .clone();
        self.enforce_build_policy("session", build_policy, &session_info.build_pcrs)?;
        Ok(session_info)
    }

    /// The session's verified `GuardianInfo`, discarding the verified build PCRs.
    pub async fn get_info(
        &mut self,
        session_id: &str,
        build_policy: BuildPolicy,
    ) -> anyhow::Result<GuardianInfo> {
        Ok(self.get_session_info(session_id, build_policy).await?.info)
    }

    /// The latest secret-sharing instance from `ceremony/` — the max-`sharing_seq`
    /// (lex-last) entry, attestation- and signature-verified. `None` if no ceremony
    /// has been logged yet. Written from initial setup onward, so present whenever a
    /// key exists.
    pub async fn read_latest_ceremony_instance(
        &mut self,
        build_policy: BuildPolicy,
    ) -> anyhow::Result<Option<SecretSharingInstance>> {
        Ok(self
            .read_latest_ceremony(build_policy)
            .await?
            .map(|(_, instance, _, _)| instance))
    }

    /// Like [`Self::read_latest_ceremony_instance`], but also returns the writing
    /// session id, recipient roster, and BTC master pubkey. The session id
    /// locates the matching `shares/` object; the roster is checked against the
    /// agreed KP set.
    pub async fn read_latest_ceremony(
        &mut self,
        build_policy: BuildPolicy,
    ) -> anyhow::Result<
        Option<(
            SessionID,
            SecretSharingInstance,
            Vec<KPFingerprint>,
            BitcoinPubkey,
        )>,
    > {
        let keys = self
            .s3
            .list_all_keys_in_dir(&format!("{}/", S3_DIR_CEREMONY))
            .await?;
        let Some(key) = pick_latest_key(keys, S3_DIR_CEREMONY) else {
            return Ok(None);
        };
        Ok(Some(self.read_ceremony_record(&key, build_policy).await?))
    }

    /// Read + verify the `ceremony/` record at `key`, returning its writing
    /// session, resulting instance, roster, and BTC master pubkey.
    async fn read_ceremony_record(
        &mut self,
        key: &str,
        build_policy: BuildPolicy,
    ) -> anyhow::Result<(
        SessionID,
        SecretSharingInstance,
        Vec<KPFingerprint>,
        BitcoinPubkey,
    )> {
        let record = self.s3.get_log_record(key).await?;
        let record = self.cache.verify_record(&self.s3, record).await?;
        let session_id = record.session_id.clone();
        let build_pcrs = record.build_pcrs.clone();
        self.enforce_build_policy("ceremony log", build_policy, &build_pcrs)?;
        let LogMessage::Ceremony(msg) = record.message else {
            anyhow::bail!("expected a ceremony log at {key}");
        };
        let (instance, roster, btc_master_pubkey) = ceremony_instance_and_roster(*msg, key)?;
        Ok((session_id, instance, roster, btc_master_pubkey))
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
        build_policy: BuildPolicy,
    ) -> anyhow::Result<KPEncryptedShares> {
        let key = SharesLogMessage::object_key(session_id, sharing_seq);
        let record: LogRecord = self.s3.get_object_no_lock(&key).await?;
        if record.session_id != session_id {
            anyhow::bail!(
                "session id mismatch at {key}: expected {session_id}, got {}",
                record.session_id
            );
        }
        let record = self.cache.verify_record(&self.s3, record).await?;
        let build_pcrs = record.build_pcrs.clone();
        self.enforce_build_policy("shares log", build_policy, &build_pcrs)?;
        let LogMessage::Shares(msg) = record.message else {
            anyhow::bail!("expected a shares log at {key}");
        };
        if msg.sharing_seq != sharing_seq {
            anyhow::bail!(
                "sharing_seq mismatch: {} != {}",
                msg.sharing_seq,
                sharing_seq
            );
        }
        Ok(msg.encrypted_shares)
    }

    /// The latest applied committee from `committee-update/` — the lex-last
    /// non-`failure-` (i.e. highest-epoch Success) entry, attestation- and
    /// signature-verified. `None` if no committee update has been logged (e.g. a
    /// fresh deployment whose committee still only exists in the operator's boot
    /// config).
    pub async fn read_latest_committee(
        &mut self,
        build_policy: BuildPolicy,
    ) -> anyhow::Result<Option<Committee>> {
        let keys = self
            .s3
            .list_all_keys_in_dir(&format!("{}/", S3_DIR_COMMITTEE_UPDATE))
            .await?;
        let Some(key) = pick_latest_key(keys, S3_DIR_COMMITTEE_UPDATE) else {
            return Ok(None);
        };
        let record = self.s3.get_log_record(&key).await?;
        let record = self.cache.verify_record(&self.s3, record).await?;
        self.enforce_build_policy("committee-update log", build_policy, &record.build_pcrs)?;
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
    ) -> anyhow::Result<&VerifiedSessionInfo> {
        if !self.sessions.contains_key(session_id) {
            let session_info = s3
                .get_verified_session_info(session_id, &self.allowlist)
                .await?;
            self.sessions.insert(session_id.to_string(), session_info);
        }
        Ok(&self.sessions[session_id])
    }

    /// Verify `record`'s signature under its session's trusted pubkey.
    async fn verify_record(
        &mut self,
        s3: &GuardianS3Client,
        record: LogRecord,
    ) -> anyhow::Result<VerifiedLogRecord> {
        let session_info = self
            .get_or_load_session_info(s3, &record.session_id)
            .await?;
        record
            .verify(&session_info.signing_pubkey)
            .map(|(session_id, timestamp_ms, message)| {
                VerifiedLogRecord::new(
                    session_id,
                    timestamp_ms,
                    message,
                    session_info.build_pcrs.clone(),
                )
            })
            .with_context(|| "failed to verify guardian enclave signature")
    }
}

/// The resulting instance + recipient roster from a ceremony message: `NewKey`
/// yields its instance; `Rotate` yields `new_instance`, asserting the rotation
/// bumps `sharing_seq` by exactly one over the consumed `old_instance`.
fn ceremony_instance_and_roster(
    msg: CeremonyLogMessage,
    key: &str,
) -> anyhow::Result<(SecretSharingInstance, Vec<KPFingerprint>, BitcoinPubkey)> {
    Ok(match msg {
        CeremonyLogMessage::NewKey {
            instance,
            roster,
            btc_master_pubkey,
        } => (instance, roster, btc_master_pubkey),
        CeremonyLogMessage::Rotate {
            old_instance,
            new_instance,
            roster,
            btc_master_pubkey,
        } => {
            let expected = old_instance
                .sharing_seq()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Rotate old sharing_seq is u64::MAX at {key}"))?;
            anyhow::ensure!(
                new_instance.sharing_seq() == expected,
                "Rotate ceremony log at {key} has non-contiguous sharing_seq: old={}, new={}",
                old_instance.sharing_seq(),
                new_instance.sharing_seq()
            );
            (new_instance, roster, btc_master_pubkey)
        }
    })
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
