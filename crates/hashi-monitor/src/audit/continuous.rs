// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::domain::utc_timestamp;
use crate::findings::MonitorFinding;
use crate::metrics::MonitorMetrics;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SUI;
use hashi_types::guardian::s3::MAX_DIR_COMPLETION_LAG;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

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
/// Its start time is on the Guardian timeline; Sui polling begins at the
/// configured predecessor lookback before that boundary.
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
    pub fn new(cfg: &Config, start: UnixSeconds) -> Self {
        let sui_start = start.saturating_sub(cfg.withdrawal_predecessor_lookback);
        let guardian_start = start;

        Self {
            user_start: start,
            sui_start,
            guardian_start,
        }
    }

    /// The earliest start whose checks can still be pending: the longest
    /// next-event delay and clock skew, the lag of the hourly guardian cursor
    /// that judges those deadlines, and one poll and state tick to report.
    pub fn default_start(cfg: &Config, now: UnixSeconds) -> UnixSeconds {
        let lookback = cfg
            .next_event_delays
            .max_delay()
            .saturating_add(cfg.clock_skew)
            .saturating_add(MAX_DIR_COMPLETION_LAG)
            .saturating_add(POLL_INTERVAL.as_secs())
            .saturating_add(STATE_TICK_INTERVAL.as_secs());
        now.saturating_sub(lookback)
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
        let audit_window = ContinuousAuditWindow::new(cfg, start);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };

        let inner = AuditorCore::new(cfg, cursors).await?;
        metrics.set_checked_through(SOURCE_SUI, inner.get_sui_cursor());
        metrics.set_checked_through(SOURCE_GUARDIAN, inner.get_guardian_cursor());
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

    async fn tick_sui(&mut self) -> anyhow::Result<()> {
        let up_to = now_timestamp_secs();
        while let PollOutcome::CursorAdvanced(events) = self.inner.poll_sui(up_to).await? {
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_SUI, self.inner.get_sui_cursor());
        }
        Ok(())
    }

    async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        while let PollOutcome::CursorAdvanced(events) = self.inner.poll_guardian().await? {
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_GUARDIAN, self.inner.get_guardian_cursor());
        }
        Ok(())
    }

    /// Throws an error if BTC RPC infra fails.
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
            utc_timestamp(self.inner.get_guardian_cursor()),
            utc_timestamp(self.inner.get_sui_cursor()),
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
        tracing::info!(
            cursor = %utc_timestamp(self.inner.get_sui_cursor()),
            "starting initial Sui catch-up"
        );
        if let Err(error) = self.tick_sui().await {
            tracing::warn!(
                source = "sui",
                ?error,
                "initial catch-up failed; continuing"
            );
        } else {
            tracing::info!(
                cursor = %utc_timestamp(self.inner.get_sui_cursor()),
                "finished initial Sui catch-up"
            );
        }
        tracing::info!(
            cursor = %utc_timestamp(self.inner.get_guardian_cursor()),
            "starting initial Guardian catch-up"
        );
        if let Err(error) = self.tick_guardian().await {
            tracing::warn!(
                source = "guardian",
                ?error,
                "initial catch-up failed; continuing"
            );
        } else {
            tracing::info!(
                cursor = %utc_timestamp(self.inner.get_guardian_cursor()),
                "finished initial Guardian catch-up"
            );
        }
        tracing::info!("starting initial Bitcoin confirmation lookups");
        if let Err(error) = self.tick_btc() {
            tracing::warn!(
                source = "btc",
                ?error,
                "initial catch-up failed; continuing"
            );
        } else {
            tracing::info!("finished initial Bitcoin confirmation lookups");
        }
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
        // interval tick so the next pass runs on the configured cadence.
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
                    self.tick_state_checks_and_gc().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
next_event_delays:
  - [E1HashiApproved, 1200]
  - [E2GuardianApproved, 86400]
clock_skew: 300
deployment:
  bucket_info:
    name: "bucket"
    region: "us-west-2"
  retention_environment: "testnet"
  bitcoin_network: "signet"
  pcr_allowlist:
    current_build:
      git_revision: "0000000000000000000000000000000000000000"
      pcr0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    prev_builds: []
sui:
  rpc_url: "http://sui"
  package_id: "0x0000000000000000000000000000000000000000000000000000000000000000"
btc:
  rpc_url: "http://btc"
"#;

    #[test]
    fn default_start_covers_the_longest_next_event_delay() {
        let cfg: Config = serde_yaml::from_str(CONFIG).unwrap();

        assert_eq!(
            ContinuousAuditWindow::default_start(&cfg, 1_000_000),
            1_000_000 - 86_400 - 300 - 4_200 - 600 - 300,
        );
    }

    #[test]
    fn default_start_precedes_every_deadline_the_guardian_cursor_has_yet_to_judge() {
        let cfg: Config = serde_yaml::from_str(CONFIG).unwrap();
        let now = 1_000_000;

        // A missing guardian approval is only found once the hourly cursor
        // passes its deadline, so the oldest one still unreported belongs to a
        // withdrawal that started a whole delay before the cursor's own lag.
        let oldest_unjudged_start =
            now - MAX_DIR_COMPLETION_LAG - cfg.next_event_delays.max_delay();

        assert!(ContinuousAuditWindow::default_start(&cfg, now) <= oldest_unjudged_start);
    }
}
