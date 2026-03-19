// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use anyhow::Context;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::guardian::verify_enclave_attestation;
use std::collections::HashMap;
use tracing::debug;
use tracing::info;

#[derive(Debug, Clone, Copy)]
pub enum GuardianLogDir {
    Withdraw,
    Heartbeat,
}

enum VerifiedWithdrawal {
    Success(MonitorWithdrawalEvent),
    Failure,
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

impl TryFrom<VerifiedLogRecord> for VerifiedWithdrawal {
    type Error = anyhow::Error;

    fn try_from(log: VerifiedLogRecord) -> Result<Self, Self::Error> {
        let LogMessage::Withdrawal(withdrawal_message) = log.message else {
            anyhow::bail!("non-withdrawal logs found");
        };

        match *withdrawal_message {
            WithdrawalLogMessage::Success {
                txid, request_data, ..
            } => {
                debug!(
                    wid = request_data.wid,
                    txid = %txid,
                    "successful guardian withdrawal log"
                );
                Ok(VerifiedWithdrawal::Success(MonitorWithdrawalEvent {
                    event_type: WithdrawalEventType::E2GuardianApproved,
                    wid: request_data.wid,
                    timestamp_secs: unix_millis_to_seconds(log.timestamp_ms),
                    btc_txid: txid,
                }))
            }
            failure @ WithdrawalLogMessage::Failure { .. } => {
                info!(?failure, "failed guardian withdrawal log");
                Ok(VerifiedWithdrawal::Failure)
            }
        }
    }
}

impl GuardianLogDir {
    fn as_prefix(self) -> &'static str {
        match self {
            GuardianLogDir::Withdraw => S3_DIR_WITHDRAW,
            GuardianLogDir::Heartbeat => S3_DIR_HEARTBEAT,
        }
    }
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

    pub fn is_readable(&self) -> bool {
        now_unix_seconds() >= self.cursor.write_completion_time()
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
    }

    pub fn advance_cursor(&mut self) {
        self.cursor = self.cursor.next_dir();
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

// Note: current design does not check if multiple concurrent sessions are running.
//       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
pub struct GuardianWithdrawalsPoller(GuardianPollerCore);

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a S3 connectivity issue
    pub async fn new(config: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        Ok(Self(
            GuardianPollerCore::new(&config.guardian, start, GuardianLogDir::Withdraw).await?,
        ))
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.0.cursor_seconds()
    }

    /// Polls the Guardian S3 bucket for one hour worth of events.
    /// A more aggressive fetch, e.g., one day at a time, can also be done if needed.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if !self.0.is_readable() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let verified_logs = self.0.read_cur_dir().await?;
        let withdrawal_events = verified_logs
            .into_iter()
            .map(VerifiedWithdrawal::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|e| match e {
                VerifiedWithdrawal::Success(event) => Some(MonitorEvent::Withdrawal(event)),
                VerifiedWithdrawal::Failure => None,
            })
            .collect::<Vec<MonitorEvent>>();

        self.0.advance_cursor();
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}
