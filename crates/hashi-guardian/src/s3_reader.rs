// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified, cursored read layer over the guardian's S3 logs.
//!
//! The guardian writes heartbeat/withdraw logs via [`S3Logger`]; off-enclave
//! readers (the monitor auditor, KP/operator init tooling) replay them here.
//! Each record's signature is checked against its session's signing pubkey,
//! which is anchored to a verified Nitro attestation.

use crate::s3_logger::S3Logger;
use anyhow::Context;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::now_timestamp_secs;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::verify_enclave_attestation;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub enum GuardianLogDir {
    Withdraw,
    Heartbeat,
}

impl GuardianLogDir {
    fn as_prefix(self) -> &'static str {
        match self {
            GuardianLogDir::Withdraw => S3_DIR_WITHDRAW,
            GuardianLogDir::Heartbeat => S3_DIR_HEARTBEAT,
        }
    }
}

/// Reusable S3 poller core with attestation and signature checks. Meant to be used for either withdrawal or heartbeat logs.
/// Idea: Since guardian can write out of order and S3 ListObjectVersions only supports lexicographic cursors, we
///       read from an S3 directory only after we are certain that all writes to it finish.
/// E.g., 12-1 PM bucket is read at 1 PM + DIR_WRITES_COMPLETION_DELAY, e.g., 1:10 PM.
pub struct GuardianPollerCore {
    s3_client: S3Logger,
    cursor: S3HourScopedDirectory,
    enclave_pub_keys: HashMap<String, GuardianPubKey>,
}

impl GuardianPollerCore {
    pub async fn new(
        config: &S3Config,
        start: UnixSeconds,
        log_dir: GuardianLogDir,
    ) -> anyhow::Result<Self> {
        let s3_client = S3Logger::new_checked(config)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .context("failed to verify guardian S3 connectivity")?;
        Ok(Self::from_s3_client(s3_client, start, log_dir))
    }

    pub fn from_s3_client(
        s3_client: S3Logger,
        start: UnixSeconds,
        log_dir: GuardianLogDir,
    ) -> Self {
        Self {
            s3_client,
            cursor: S3HourScopedDirectory::new(log_dir.as_prefix(), start),
            enclave_pub_keys: HashMap::new(),
        }
    }

    pub fn writes_completed(&self) -> bool {
        now_timestamp_secs() >= self.cursor.write_completion_time()
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
    }

    pub fn advance_cursor(&mut self) {
        self.cursor = self.cursor.next_dir();
    }

    pub fn retreat_cursor(&mut self) {
        self.cursor = self.cursor.prev_dir();
    }

    /// Read and verify the signatures on all the records in the current directory.
    pub async fn read_cur_dir(&mut self) -> anyhow::Result<Vec<VerifiedLogRecord>> {
        let all_logs = self
            .s3_client
            .list_all_objects_in_dir::<LogRecord>(&self.cursor)
            .await
            .with_context(|| format!("failed to list guardian logs in {}", self.cursor))?;

        let mut out = Vec::with_capacity(all_logs.len());
        for log in all_logs {
            self.ensure_session_loaded(&log.session_id).await?;

            let signing_pubkey = self
                .enclave_pub_keys
                .get(&log.session_id)
                .ok_or_else(|| anyhow::anyhow!("missing session signing pubkey"))?;

            let verified = log
                .verify(signing_pubkey)
                .with_context(|| "failed to verify guardian enclave signature")?;

            out.push(verified);
        }

        Ok(out)
    }

    async fn ensure_session_loaded(&mut self, session_id: &str) -> anyhow::Result<()> {
        if self.enclave_pub_keys.contains_key(session_id) {
            return Ok(());
        }

        let (attestation, signing_pubkey) = self.s3_client.get_attestation(session_id).await?;
        verify_enclave_attestation(attestation)?;

        self.enclave_pub_keys
            .insert(session_id.to_string(), signing_pubkey);
        Ok(())
    }
}
