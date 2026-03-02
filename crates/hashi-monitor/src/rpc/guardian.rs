use crate::config::GuardianConfig;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEvent;
use crate::domain::now_unix_seconds;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::guardian::s3_utils::S3Directory;
use hashi_types::guardian::time_utils::UnixSeconds;

/// Idea: Since guardian can write out of order and S3 ListObjectVersions only supports lexicographic cursors, we
///       read from an S3 directory only after we are certain that all writes to it finish.
/// E.g., 12-1 PM bucket is read at 1 PM + DIR_WRITES_COMPLETION_DELAY, e.g., 1:10 PM.
pub struct GuardianWithdrawalsPoller {
    _config: GuardianConfig,
    cursor: S3Cursor,
}

impl GuardianWithdrawalsPoller {
    pub fn new(config: GuardianConfig, start: UnixSeconds) -> Self {
        Self {
            _config: config,
            cursor: S3Cursor::new(start, true),
        }
    }

    /// TODO: Read the current cursor (dir) till the end.
    async fn read(&self) -> anyhow::Result<Vec<WithdrawalEvent>> {
        Ok(Vec::new())
    }

    fn is_readable(&self) -> bool {
        now_unix_seconds() >= self.cursor.write_completion_time()
    }

    fn advance_cursor(&mut self) {
        self.cursor.advance();
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_seconds()
    }

    /// Polls the Guardian S3 bucket for one hour worth of events.
    /// A more aggressive fetch, e.g., one day at a time, can also be done if needed.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if !self.is_readable() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let withdrawal_events = self.read().await?;
        self.advance_cursor();
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}

/// Cursor is simply an S3 directory. The next directory to read from.
struct S3Cursor(S3Directory);

impl S3Cursor {
    /// true => withdraw, false => heartbeat
    fn new(t: UnixSeconds, for_withdrawals: bool) -> Self {
        let prefix = if for_withdrawals {
            S3_DIR_WITHDRAW
        } else {
            S3_DIR_HEARTBEAT
        };
        Self(S3Directory::new(prefix, t))
    }

    fn advance(&mut self) {
        self.0 = self.0.next_dir();
    }

    /// The time at which writes to the current S3 directory finish
    fn write_completion_time(&self) -> UnixSeconds {
        self.0.completion_time()
    }

    fn to_seconds(&self) -> UnixSeconds {
        self.0.to_unix_seconds()
    }
}
