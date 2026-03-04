use crate::config::Config;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use anyhow::Context;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_INIT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::time_utils::unix_millis_to_seconds;
use hashi_types::guardian::verify_enclave_attestation;
use std::collections::HashMap;
use tracing::info;

/// Idea: Since guardian can write out of order and S3 ListObjectVersions only supports lexicographic cursors, we
///       read from an S3 directory only after we are certain that all writes to it finish.
/// E.g., 12-1 PM bucket is read at 1 PM + DIR_WRITES_COMPLETION_DELAY, e.g., 1:10 PM.
pub struct GuardianWithdrawalsPoller {
    /// S3 logger
    s3_client: S3Logger,
    /// cursor
    cursor: S3Cursor,
    /// all the enclave pub keys it has seen: session id -> enclave pub key
    enclave_pub_keys: HashMap<String, GuardianPubKey>,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a connectivity issue with S3
    pub async fn new(cfg: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let poller = Self {
            s3_client: S3Logger::new(&cfg.guardian).await,
            cursor: S3Cursor::new(start, true),
            enclave_pub_keys: HashMap::new(),
        };

        poller
            .s3_client
            .test_s3_connectivity()
            .await
            .context("failed to verify guardian S3 connectivity")?;
        info!("S3 connectivity check complete.");

        Ok(poller)
    }

    // Note: current design does not check if multiple concurrent sessions are running.
    //       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
    async fn read_cur_dir(&mut self) -> anyhow::Result<Vec<WithdrawalEvent>> {
        let all_guardian_logs = self
            .s3_client
            .list_all_objects_in_dir::<LogRecord>(&self.cursor.0)
            .await
            .with_context(|| format!("failed to list guardian logs in {}", self.cursor.0))?;

        self.logs_to_events(all_guardian_logs).await
    }

    async fn logs_to_events(
        &mut self,
        all_guardian_logs: Vec<LogRecord>,
    ) -> anyhow::Result<Vec<WithdrawalEvent>> {
        let mut events = Vec::new();
        for log in all_guardian_logs {
            if !matches!(log.message, LogMessage::Withdrawal(..)) {
                return Err(anyhow::anyhow!("non-withdrawal logs found"));
            }

            self.ensure_session_loaded(&log.session_id)
                .await
                .with_context(|| {
                    format!(
                        "failed to load new session for session_id={}",
                        log.session_id
                    )
                })?;

            let signing_pubkey = self
                .enclave_pub_keys
                .get(&log.session_id)
                .ok_or_else(|| anyhow::anyhow!("missing session signing pubkey"))?;

            let signed_timestamp = log.timestamp_ms;
            let message = log
                .verify(signing_pubkey)
                .with_context(|| "failed to verify guardian log signature")?;

            if let LogMessage::Withdrawal(withdrawal_message) = message
                && let WithdrawalLogMessage::Success {
                    txid, request_data, ..
                } = *withdrawal_message
            {
                events.push(WithdrawalEvent {
                    event_type: WithdrawalEventType::E2GuardianApproved,
                    wid: request_data.wid,
                    timestamp_secs: unix_millis_to_seconds(signed_timestamp),
                    btc_txid: txid,
                })
            }
        }

        Ok(events)
    }

    async fn ensure_session_loaded(&mut self, session_id: &str) -> anyhow::Result<()> {
        if self.enclave_pub_keys.contains_key(session_id) {
            return Ok(());
        }

        let init_key = format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            InitLogMessage::OI_ATTEST_UNSIGNED
        );
        let log = self
            .s3_client
            .get_object::<LogRecord>(&init_key)
            .await
            .with_context(|| format!("failed to fetch init log at key={init_key}"))?;

        let log = log
            .message
            .to_init_log()
            .ok_or_else(|| anyhow::anyhow!("non-init log found"))?;

        let (attestation, signing_pubkey) = log
            .to_attestation_log()
            .ok_or_else(|| anyhow::anyhow!("non-attestation log found"))?;

        verify_enclave_attestation(attestation)?;

        self.enclave_pub_keys
            .insert(session_id.to_string(), signing_pubkey);
        Ok(())
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

        let withdrawal_events = self.read_cur_dir().await?;
        self.advance_cursor();
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}

/// Cursor is simply an S3 directory. The next directory to read from.
struct S3Cursor(S3HourScopedDirectory);

impl S3Cursor {
    /// true => withdraw, false => heartbeat
    fn new(t: UnixSeconds, for_withdrawals: bool) -> Self {
        let prefix = if for_withdrawals {
            S3_DIR_WITHDRAW
        } else {
            S3_DIR_HEARTBEAT
        };
        Self(S3HourScopedDirectory::new(prefix, t))
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
