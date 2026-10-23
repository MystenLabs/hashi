// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian poller: the withdrawal E2 events read from the guardian's
//! S3 logs, one hourly directory at a time.
//!
//! Why it exists: the guardian's signature on a withdrawal is only recorded
//! in its log. The poller reads the log through `GuardianReader`, which
//! verifies each session's attestation against the allowlist and each
//! record's signature.
//!
//! How it works:
//! 1. The cursor is an hourly directory. A directory is read once its write
//!    completion time has passed.
//! 2. Every verified withdrawal log in the directory becomes an E2 event.
//!    A log whose signed time differs from its S3 `LastModified` time by more
//!    than `MAX_EXPECTED_LOG_CLOCK_SKEW` is also a finding.
//! 3. The cursor moves to the next directory.
//!
//! Assumptions:
//! - The bridge keys are read once, before polling, from the genesis and
//!   ceremony records. They never change.
//! - Concurrent guardian sessions are not detected. One way to detect them
//!   is to keep each session's first and last observed timestamp and require
//!   that the ranges do not overlap.

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::keys::HashiBTCKeys;
use crate::rpc::PollCursor;
use crate::time::utc_timestamp;
use anyhow::Context;
use bitcoin::Network;
use hashi_guardian::MAX_EXPECTED_LOG_CLOCK_SKEW;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use sui_sdk_types::Address;
use tracing::debug;

pub struct GuardianWithdrawalsPoller {
    /// Owns the S3 client + the trusted-key cache, so a session's attestation is
    /// verified once for the poller's lifetime.
    reader: GuardianReader,
    cursor: S3HourDirectory,
    /// Set by `read_hashi_btc_keys`. The guardian's internal outputs state a
    /// derivation path, and the keys turn it into the address they pay.
    hashi_btc_keys: Option<HashiBTCKeys>,
}

impl PollCursor for GuardianWithdrawalsPoller {
    type Position = S3HourDirectory;

    /// The next unread directory's start time also marks the end of the read range.
    fn read_until(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
    }

    fn next_item_to_poll(&self) -> Self::Position {
        self.cursor.clone()
    }
}

impl GuardianWithdrawalsPoller {
    /// Fails if S3 cannot be reached.
    pub async fn new(config: &Config, start: S3HourDirectory) -> anyhow::Result<Self> {
        let s3_credentials =
            hashi_guardian::resolve_s3_credentials(config.s3_credentials.as_ref()).await?;
        Ok(Self {
            reader: GuardianReader::new(config.deployment.clone(), s3_credentials).await?,
            cursor: start,
            hashi_btc_keys: None,
        })
    }

    /// The two keys every bridge address derives from, and the Hashi object
    /// id. They never change. The MPC master key and the object id come from
    /// the KP-authorized genesis record and the guardian's Bitcoin key from
    /// the latest ceremony record, both verified against the allowlist.
    pub async fn read_hashi_identity(
        &mut self,
        network: Network,
    ) -> anyhow::Result<(HashiBTCKeys, Address)> {
        let genesis = self
            .reader
            .read_genesis()
            .await
            .context("failed to read the guardian genesis record")?
            .context("the guardian genesis record does not exist")?;
        let ceremony = self
            .reader
            .read_latest_ceremony_state()
            .await
            .context("failed to read the guardian ceremony record")?;
        let keys = HashiBTCKeys::new(ceremony.btc_master_pubkey, genesis.mpc_master_g, network);
        tracing::info!(
            change_script = %keys.script_pubkey(None),
            hashi_object_id = %genesis.hashi_object_id,
            "read the Hashi identity from the guardian records"
        );
        self.hashi_btc_keys = Some(keys.clone());
        Ok((keys, genesis.hashi_object_id))
    }

    /// Poll one hourly Guardian S3 directory and advance to the next directory.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if now_timestamp_secs() < self.cursor.write_completion_time() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let start = self.cursor.to_unix_seconds();
        let next_cursor = self.cursor.next_dir()?;
        let end = next_cursor.to_unix_seconds();
        let verified_logs = self.reader.read_logs_in_dir(&self.cursor).await?;
        // Withdrawal polling may replay historical buckets during an upgrade, so
        // this caller accepts any record whose session build verifies against the
        // configured allowlist. Add a cursor/cutoff policy here if tailing must
        // require the current build after the upgrade window.
        let keys = self
            .hashi_btc_keys
            .as_ref()
            .context("the bridge keys must be read before polling guardian logs")?;
        let mut findings = Vec::new();
        let mut withdrawal_events = Vec::with_capacity(verified_logs.len());
        for log in verified_logs {
            // Each record is one sample of the guardian's clock against AWS
            // time, plus the write latency.
            if log.exceeds_clock_skew(MAX_EXPECTED_LOG_CLOCK_SKEW) {
                findings.push(MonitorFinding::GuardianClockSkew {
                    session_id: log.session_id().clone(),
                    object_key: log.entry().object_key().to_owned(),
                    logged_at_ms: log.entry().timestamp_ms(),
                    stored_at_ms: log.stored_at_ms(),
                });
            }
            let entry = log.into_entry();
            let timestamp_ms = entry.timestamp_ms();
            let withdrawal = entry
                .into_message()
                .into_withdrawal()
                .context("non-withdrawal log in the guardian's withdrawal logs")?;
            match MonitorWithdrawalEvent::from_guardian(&withdrawal, timestamp_ms, keys) {
                Ok(event) => {
                    debug!(wid = %event.wid, txid = %event.btc_txid, "guardian withdrawal log");
                    withdrawal_events.push(MonitorEvent::Withdrawal(event));
                }
                Err(found) => findings.extend(found),
            }
        }

        self.cursor = next_cursor;
        tracing::info!(
            start = %utc_timestamp(start),
            end = %utc_timestamp(end),
            cursor = %utc_timestamp(self.cursor.to_unix_seconds()),
            events = withdrawal_events.len(),
            "completed Guardian event range"
        );
        Ok(PollOutcome::CursorAdvanced {
            events: withdrawal_events,
            findings,
        })
    }
}

#[cfg(test)]
impl GuardianWithdrawalsPoller {
    /// A poller over a mock S3 client, for tests that never poll it.
    pub(crate) fn for_tests(config: &Config, start: UnixSeconds) -> Self {
        Self {
            reader: hashi_guardian::test_utils::mock_reader(config.deployment.clone()),
            cursor: S3HourDirectory::withdraw(start).expect("valid test timestamp"),
            hashi_btc_keys: Some(crate::test_utils::test_hashi_btc_keys()),
        }
    }
}
