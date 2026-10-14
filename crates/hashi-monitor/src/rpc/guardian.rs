// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::domain::HashiBTCKeys;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::utc_timestamp;
use anyhow::Context;
use bitcoin::Network;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_guardian::s3_reader::VerifiedLogEntry;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::unix_millis_to_seconds;
use tracing::debug;

impl TryFrom<VerifiedLogEntry> for MonitorWithdrawalEvent {
    type Error = anyhow::Error;

    fn try_from(log: VerifiedLogEntry) -> Result<Self, Self::Error> {
        let entry = log.into_entry();
        let timestamp_ms = entry.timestamp_ms();
        let withdrawal = entry
            .into_message()
            .into_withdrawal()
            .ok_or_else(|| anyhow::anyhow!("non-withdrawal logs found"))?;

        debug!(
            wid = %withdrawal.request_data.wid,
            txid = %withdrawal.txid,
            "guardian withdrawal log"
        );
        Ok(MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            wid: withdrawal.request_data.wid,
            timestamp_secs: unix_millis_to_seconds(timestamp_ms),
            btc_txid: withdrawal.txid,
        })
    }
}

// Note: current design does not check if multiple concurrent sessions are running.
//       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
pub struct GuardianWithdrawalsPoller {
    /// Owns the S3 client + the trusted-key cache, so a session's attestation is
    /// verified once for the poller's lifetime.
    reader: GuardianReader,
    cursor: S3HourDirectory,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a S3 connectivity issue
    pub async fn new(config: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let s3_credentials =
            hashi_guardian::resolve_s3_credentials(config.s3_credentials.as_ref()).await?;
        Ok(Self {
            reader: GuardianReader::new(config.deployment.clone(), s3_credentials).await?,
            cursor: S3HourDirectory::withdraw(start)?,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
    }

    /// The two keys every bridge address derives from. They never change. The
    /// MPC master key comes from the KP-authorized genesis record and the
    /// guardian's Bitcoin key from the latest ceremony record, both verified
    /// against the allowlist.
    pub async fn read_hashi_btc_keys(&mut self, network: Network) -> anyhow::Result<HashiBTCKeys> {
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
            "read the bridge keys from the guardian records"
        );
        Ok(keys)
    }

    /// Time after which the next unread hourly partition is considered complete.
    pub fn next_partition_ready_at(&self) -> UnixSeconds {
        self.cursor.write_completion_time()
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
        let withdrawal_events = verified_logs
            .into_iter()
            .map(|log| MonitorWithdrawalEvent::try_from(log).map(MonitorEvent::Withdrawal))
            .collect::<anyhow::Result<Vec<_>>>()?;

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
            findings: Vec::new(),
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
        }
    }
}
