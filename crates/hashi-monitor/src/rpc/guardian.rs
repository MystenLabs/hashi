// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::utc_timestamp;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_guardian::s3_reader::VerifiedLogRecord;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::VersionedLogMessage;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::time_utils::now_timestamp_secs;
use hashi_types::guardian::unix_millis_to_seconds;
use tracing::debug;
impl TryFrom<VerifiedLogRecord> for MonitorWithdrawalEvent {
    type Error = anyhow::Error;

    fn try_from(log: VerifiedLogRecord) -> Result<Self, Self::Error> {
        let entry = log.into_entry();
        let timestamp_ms = entry.timestamp_ms();
        let withdrawal_message = match entry.into_message() {
            VersionedLogMessage::V1(LogMessageV1::Withdrawal(message)) => message,
            VersionedLogMessage::V2(LogMessageV2::Withdrawal(message)) => message,
            VersionedLogMessage::V1(_) | VersionedLogMessage::V2(_) => {
                anyhow::bail!("non-withdrawal logs found");
            }
        };

        match *withdrawal_message {
            WithdrawalLogMessage::Success {
                txid, request_data, ..
            } => {
                debug!(
                    wid = %request_data.wid,
                    txid = %txid,
                    "successful guardian withdrawal log"
                );
                Ok(MonitorWithdrawalEvent {
                    event_type: WithdrawalEventType::E2GuardianApproved,
                    wid: request_data.wid,
                    timestamp_secs: unix_millis_to_seconds(timestamp_ms),
                    btc_txid: txid,
                })
            }
            WithdrawalLogMessage::Failure { .. } => {
                anyhow::bail!("failure log found under successful-withdrawal prefix")
            }
        }
    }
}

// Note: current design does not check if multiple concurrent sessions are running.
//       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
pub struct GuardianWithdrawalsPoller {
    /// Owns the S3 client + the trusted-key cache, so a session's attestation is
    /// verified once for the poller's lifetime.
    reader: GuardianReader,
    cursor: S3HourScopedDirectory,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a S3 connectivity issue
    pub async fn new(config: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let guardian_s3 = hashi_guardian::resolve_s3_config(&config.guardian_s3).await?;
        Ok(Self {
            reader: GuardianReader::new(&guardian_s3, config.pcr_allowlist()).await?,
            cursor: S3HourScopedDirectory::withdraw(start),
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
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
        let next_cursor = self.cursor.next_dir();
        let end = next_cursor.to_unix_seconds();
        let verified_logs = self
            .reader
            .read_successful_withdrawals_in_dir(&self.cursor)
            .await?;
        // Withdrawal polling may replay historical buckets during an upgrade, so
        // this caller accepts any record whose session build verifies against the
        // configured allowlist. Add a cursor/cutoff policy here if tailing must
        // require the current build after the upgrade window.
        let withdrawal_events = verified_logs
            .into_iter()
            .map(MonitorWithdrawalEvent::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .map(MonitorEvent::Withdrawal)
            .collect::<Vec<MonitorEvent>>();

        self.cursor = next_cursor;
        tracing::info!(
            start = %utc_timestamp(start),
            end = %utc_timestamp(end),
            cursor = %utc_timestamp(self.cursor.to_unix_seconds()),
            events = withdrawal_events.len(),
            "completed Guardian event range"
        );
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}
