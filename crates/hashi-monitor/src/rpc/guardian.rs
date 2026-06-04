// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use hashi_guardian::s3_reader::GuardianLogDir;
use hashi_guardian::s3_reader::GuardianPollerCore;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use tracing::debug;
use tracing::info;

enum VerifiedWithdrawal {
    Success(MonitorWithdrawalEvent),
    Failure,
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
                    wid = %request_data.wid,
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
        if !self.0.writes_completed() {
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
