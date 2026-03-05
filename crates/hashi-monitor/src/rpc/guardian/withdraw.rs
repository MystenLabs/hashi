use crate::config::Config;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::rpc::guardian::GuardianLogDir;
use crate::rpc::guardian::GuardianPollerCore;
use crate::rpc::guardian::VerifiedWithdrawal;
use hashi_types::guardian::time_utils::UnixSeconds;

// Note: current design does not check if multiple concurrent sessions are running.
//       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
pub struct GuardianWithdrawalsPoller {
    core: GuardianPollerCore,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a connectivity issue with S3
    pub async fn new(config: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        Ok(Self {
            core: GuardianPollerCore::new(&config.guardian, start, GuardianLogDir::Withdraw)
                .await?,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.core.cursor_seconds()
    }

    /// Polls the Guardian S3 bucket for one hour worth of events.
    /// A more aggressive fetch, e.g., one day at a time, can also be done if needed.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if !self.core.is_readable() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let verified_logs = self.core.read_cur_dir().await?;
        let withdrawal_events = verified_logs
            .into_iter()
            .map(VerifiedWithdrawal::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|e| match e {
                VerifiedWithdrawal::Success(event) => Some(event),
                VerifiedWithdrawal::Failure(_) => None,
            })
            .collect::<Vec<MonitorWithdrawalEvent>>();

        self.core.advance_cursor();
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}
