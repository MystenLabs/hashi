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
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
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
    cache: GuardianSessionKeyCache,
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
            cache: GuardianSessionKeyCache::default(),
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
            out.push(self.cache.verify_record(&self.s3, log).await?);
        }
        Ok(out)
    }

    /// Read and verify a session's signed `OIGuardianInfo` log (written at
    /// operator-init). Implements check B of IOP-225.
    pub async fn get_info(&mut self, session_id: &str) -> anyhow::Result<GuardianInfo> {
        let key = InitLogMessage::guardian_info_object_key(session_id);
        let record: LogRecord = self.s3.get_object(&key).await?;
        self.cache
            .verify_record(&self.s3, record)
            .await?
            .message
            .into_init_log()
            .and_then(|x| match x {
                InitLogMessage::OIGuardianInfo(info) => Some(info),
                _ => None,
            })
            .with_context(|| format!("expected OIGuardianInfo at {key}"))
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
