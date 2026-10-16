// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor: a long-running monitor of the live bridge.
//!
//! Why it exists: the deployed monitor must report a late or contradictory
//! event soon after it happens, and alerting reads its metrics.
//!
//! How it works:
//! 1. The start is on the guardian timeline. Without `--start`, it is far
//!    enough back to re-audit a `DEFAULT_RESTART_LOOKBACK` outage and the
//!    checks that were pending when it began. Sui polling starts
//!    `Timing::sui_lookback` before it.
//! 2. At startup, each source catches up once. A source that fails is
//!    logged and retried on its next tick.
//! 3. Then the Sui, guardian and Bitcoin ticks run every `POLL_INTERVAL`,
//!    and the state checks every `STATE_TICK_INTERVAL`: fetch the missing
//!    Sui approvals, report the violations, garbage collect, and log the
//!    progress watermarks.
//! 4. Every finding is logged and recorded in the metrics, and each source's
//!    checked-through time is exported.
//!
//! Assumptions:
//! - A poll failure is transient. The auditor logs it and goes on; only a
//!   failure to start is an error.

use std::sync::Arc;
use std::time::Duration;

use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::metrics::MonitorMetrics;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SUI;
use crate::time::utc_timestamp;
use crate::timing::Timing;
use hashi_types::guardian::s3::MAX_DIR_COMPLETION_LAG;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// How often the Sui, guardian and Bitcoin sources are polled.
const POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How often the state checks run.
const STATE_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The longest monitor outage a restart without `--start` re-audits.
const DEFAULT_RESTART_LOOKBACK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A continuous audit only requires a start time.
pub struct ContinuousAuditWindow {
    pub user_start: UnixSeconds,
    pub sui_start: UnixSeconds,
    pub guardian_start: UnixSeconds,
}

/// A continuous auditor that runs indefinitely and processes events as they
/// arrive. Its start time is on the guardian timeline; Sui polling begins
/// `Timing::sui_lookback` before it.
pub struct ContinuousAuditor {
    pub inner: AuditorCore,
    pub window: ContinuousAuditWindow,
    metrics: Arc<MonitorMetrics>,
}

impl AuditWindow for ContinuousAuditWindow {
    fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
        timestamp_secs >= self.user_start
    }
}

impl ContinuousAuditWindow {
    pub fn new(timing: &Timing, start: UnixSeconds) -> Self {
        let sui_start = start.saturating_sub(timing.sui_lookback());
        let guardian_start = start;

        Self {
            user_start: start,
            sui_start,
            guardian_start,
        }
    }

    /// Covers a `DEFAULT_RESTART_LOOKBACK` outage plus the checks still pending when it
    /// began: the longest next-event delay and clock skew, the lag of the hourly guardian
    /// cursor that judges those deadlines, and one poll and state tick to report.
    pub fn default_start(timing: &Timing, now: UnixSeconds) -> UnixSeconds {
        let pending = timing
            .successor_delays
            .max()
            .saturating_add(timing.predecessor_skews.max())
            .saturating_add(MAX_DIR_COMPLETION_LAG)
            .saturating_add(POLL_INTERVAL.as_secs())
            .saturating_add(STATE_TICK_INTERVAL.as_secs());
        now.saturating_sub(pending.saturating_add(DEFAULT_RESTART_LOOKBACK.as_secs()))
    }
}

impl ContinuousAuditor {
    pub async fn new(
        cfg: &Config,
        start: UnixSeconds,
        metrics: Arc<MonitorMetrics>,
    ) -> anyhow::Result<Self> {
        let cur_time = now_timestamp_secs();
        anyhow::ensure!(
            start <= cur_time,
            "start is in the future: start={} > current_time={}",
            utc_timestamp(start),
            utc_timestamp(cur_time),
        );
        let audit_window = ContinuousAuditWindow::new(&cfg.timing, start);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };

        let inner = AuditorCore::new(cfg, cursors).await?;
        metrics.set_checked_through(SOURCE_SUI, inner.sui_cursor());
        metrics.set_checked_through(SOURCE_GUARDIAN, inner.guardian_cursor());
        Ok(Self {
            inner,
            window: audit_window,
            metrics,
        })
    }

    fn report_findings(&self, phase: &'static str, findings: &[MonitorFinding]) {
        log_findings("continuous", phase, findings);
        self.metrics.record_findings(findings, now_timestamp_secs());
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorEvent>) {
        let findings = self.inner.ingest_batch(events);
        self.report_findings("ingest", &findings);
    }

    /// Log the outcome of one source's initial catch-up. A failure does not
    /// stop the audit: the source's next tick retries it.
    fn log_initial_catch_up(source: &'static str, result: anyhow::Result<()>) {
        match result {
            Ok(()) => tracing::info!(source, "finished initial catch-up"),
            Err(error) => tracing::warn!(source, ?error, "initial catch-up failed; continuing"),
        }
    }

    async fn tick_sui(&mut self) -> anyhow::Result<()> {
        let up_to = now_timestamp_secs();
        while let PollOutcome::CursorAdvanced { events, findings } =
            self.inner.poll_sui(up_to).await?
        {
            self.report_findings("sui", &findings);
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_SUI, self.inner.sui_cursor());
        }
        Ok(())
    }

    async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        while let PollOutcome::CursorAdvanced { events, findings } =
            self.inner.poll_guardian().await?
        {
            self.report_findings("guardian", &findings);
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_GUARDIAN, self.inner.guardian_cursor());
        }
        Ok(())
    }

    /// Fails if the Bitcoin RPC fails.
    fn tick_btc(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.inner.fetch_btc_info(&self.window)?;
        self.report_findings("btc", &findings);
        self.metrics.set_checked_through(SOURCE_BTC, started_at);
        Ok(())
    }

    async fn tick_state_checks_and_gc(&mut self) {
        let lookup_findings = self.inner.fetch_missing_hashi_approvals(&self.window).await;
        self.report_findings("lookup", &lookup_findings);
        let violations = self.inner.detect_violations(&self.window);
        // TODO: If a violation is detected, we keep logging it on every call to this. Decide if that's the behavior we want.
        self.report_findings("violations", &violations);

        // Garbage collect
        self.inner.garbage_collect(&self.window);

        let progress = self.inner.progress_watermarks(&self.window);
        tracing::info!(
            "continuous progress checkpoint:\n  guardian_cursor={}\n  sui_cursor={}\n  verified_up_to_withdrawals={}\n  withdrawal_blockers={}\n  verified_up_to_deposits={}\n  restart_start={}",
            utc_timestamp(self.inner.guardian_cursor()),
            utc_timestamp(self.inner.sui_cursor()),
            utc_timestamp(progress.verified_up_to_withdrawals),
            progress.withdrawal_blockers(),
            utc_timestamp(progress.verified_up_to_deposits),
            utc_timestamp(progress.restart_start),
        );
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tracing::info!(
            "starting continuous audit:\n  requested_start={}\n  sui_start={}\n  guardian_start={}",
            utc_timestamp(self.window.user_start),
            utc_timestamp(self.window.sui_start),
            utc_timestamp(self.window.guardian_start),
        );
        let sui = self.tick_sui().await;
        Self::log_initial_catch_up(SOURCE_SUI, sui);
        let guardian = self.tick_guardian().await;
        Self::log_initial_catch_up(SOURCE_GUARDIAN, guardian);
        let btc = self.tick_btc();
        Self::log_initial_catch_up(SOURCE_BTC, btc);
        self.tick_state_checks_and_gc().await;

        let mut sui_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut state_checks_ticker = tokio::time::interval(STATE_TICK_INTERVAL);

        sui_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        guardian_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        btc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        state_checks_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // The initial catch-up above handled startup; consume each immediate
        // interval tick so the next pass runs one interval later.
        sui_ticker.tick().await;
        guardian_ticker.tick().await;
        btc_ticker.tick().await;
        state_checks_ticker.tick().await;

        loop {
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
                    self.tick_state_checks_and_gc().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::WithdrawalEventType;
    use crate::timing::EventBounds;

    /// Timing with a day's E2 -> E3 delay and the protocol skews.
    fn timing() -> Timing {
        Timing {
            successor_delays: EventBounds::new([
                (WithdrawalEventType::E1HashiApproved, 1_200),
                (WithdrawalEventType::E2GuardianApproved, 86_400),
            ])
            .unwrap(),
            predecessor_skews: EventBounds::new([
                (WithdrawalEventType::E1HashiApproved, 300),
                (WithdrawalEventType::E2GuardianApproved, 7_200),
            ])
            .unwrap(),
            deposit_confirmation_skew: 300,
        }
    }

    #[test]
    fn default_start_covers_a_week_outage_and_the_checks_pending_when_it_began() {
        assert_eq!(
            ContinuousAuditWindow::default_start(&timing(), 1_000_000),
            1_000_000 - 604_800 - 86_400 - 7_200 - 4_200 - 600 - 300,
        );
    }

    #[test]
    fn default_start_precedes_every_deadline_the_guardian_cursor_has_yet_to_judge() {
        let timing = timing();
        let now = 1_000_000;

        // A missing guardian approval is only found once the hourly cursor
        // passes its deadline, so the oldest one still unreported belongs to a
        // withdrawal that started a whole delay before the cursor's own lag.
        let oldest_unjudged_start = now - MAX_DIR_COMPLETION_LAG - timing.successor_delays.max();

        assert!(ContinuousAuditWindow::default_start(&timing, now) <= oldest_unjudged_start);
    }
}
