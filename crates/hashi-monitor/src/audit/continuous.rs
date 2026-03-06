use std::time::Duration;

use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use hashi_types::guardian::time_utils::UnixSeconds;

// TODO: Move to config
// TODO: Consider switching to a streaming API
/// The frequency at which we poll sui, guardian and btc RPC
const POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The frequency at which we do validation checks.
const STATE_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A continuous audit only requires a start time
pub struct ContinuousAuditWindow {
    pub user_start: UnixSeconds,
    pub sui_start: UnixSeconds,
    pub guardian_start: UnixSeconds,
}

/// A continuous auditor that runs indefinitely processing events as they arrive.
/// Constructors accept a start time as input that acts as a starting point for the auditor.
pub struct ContinuousAuditor {
    pub inner: AuditorCore,
    pub window: ContinuousAuditWindow,
}

impl AuditWindow for ContinuousAuditWindow {
    fn in_window(&self, e: &MonitorWithdrawalEvent) -> bool {
        e.timestamp_secs >= self.user_start
    }
}

impl ContinuousAuditWindow {
    pub fn new(cfg: &Config, start: UnixSeconds) -> Self {
        let e1_e2_delay_secs = cfg
            .next_event_delay(WithdrawalEventType::E1HashiApproved)
            .expect("should be Some");
        let sui_start = start.saturating_sub(e1_e2_delay_secs); // guardian_e2@{start} might match sui_e1@{start-e1_e2_delay_secs}
        let guardian_start = start;

        Self {
            user_start: start,
            sui_start,
            guardian_start,
        }
    }
}

impl ContinuousAuditor {
    pub async fn new(cfg: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let cur_time = now_unix_seconds();
        anyhow::ensure!(
            start <= cur_time,
            "start is in the future: start={start} > cur_time={cur_time}"
        );
        let audit_window = ContinuousAuditWindow::new(cfg, start);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };

        Ok(Self {
            inner: AuditorCore::new(cfg, cursors).await?,
            window: audit_window,
        })
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorWithdrawalEvent>) {
        let errors = self.inner.ingest_batch(events);
        log_findings("continuous", "ingest", &errors);
    }

    async fn tick_sui(&mut self) -> anyhow::Result<()> {
        if let PollOutcome::CursorAdvanced(events) = self.inner.poll_sui().await? {
            self.ingest_batch(events);
        }
        Ok(())
    }

    async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        if let PollOutcome::CursorAdvanced(events) = self.inner.poll_guardian().await? {
            self.ingest_batch(events);
        }
        Ok(())
    }

    /// Throws an error if BTC RPC infra fails.
    fn tick_btc(&mut self) -> anyhow::Result<()> {
        let errors = self.inner.fetch_btc_info(&self.window)?;
        log_findings("continuous", "btc", &errors);
        Ok(())
    }

    fn tick_state_checks_and_gc(&mut self) {
        let violations = self.inner.detect_violations(&self.window);
        // TODO: If a violation is detected, we keep logging it on every call to this. Decide if that's the behavior we want.
        log_findings("continuous", "violations", &violations);

        // Garbage collect
        self.inner.garbage_collect(&self.window);
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut sui_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut state_checks_ticker = tokio::time::interval(STATE_TICK_INTERVAL);

        sui_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        guardian_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        btc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        state_checks_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Consume the immediate first tick and then run on a stable cadence.
        sui_ticker.tick().await;
        guardian_ticker.tick().await;
        btc_ticker.tick().await;
        state_checks_ticker.tick().await;

        loop {
            // TODO: Make it multi-threaded?
            tokio::select! {
                _ = sui_ticker.tick() => {
                    if let Err(error) = self.tick_sui().await {
                        tracing::warn!(source = "sui", ?error, "poll failed; continuing");
                    }
                }
                _ = guardian_ticker.tick() => {
                    if let Err(error) = self.tick_guardian().await {
                        tracing::warn!(source = "guardian", ?error, "poll failed; continuing");
                    }
                }
                _ = btc_ticker.tick() => {
                    if let Err(error) = self.tick_btc() {
                        tracing::warn!(source = "btc", ?error, "btc tick failed; continuing");
                    }
                }
                _ = state_checks_ticker.tick() => {
                    self.tick_state_checks_and_gc();
                }
            }
        }
    }
}
