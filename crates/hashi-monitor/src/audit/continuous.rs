// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor: a long-running monitor of the live bridge.
//!
//! Why it exists: the deployed monitor must report a late or contradictory
//! event soon after it happens, and alerting reads its metrics.
//!
//! How it works:
//! 1. The start is on the guardian timeline. A snapshot this deployment
//!    saved sets it to the snapshot's restart start, unless `--start` is
//!    earlier. Without one, it is `--start`, or far enough back to re-audit
//!    a `DEFAULT_RESTART_LOOKBACK` outage and the checks that were pending
//!    when it began. Sui polling starts `Timing::sui_lookback` before it, and
//!    guardian polling `Timing::guardian_lookback` before it.
//! 2. At startup, each source catches up once. A source that fails is
//!    logged and retried on its next tick.
//! 3. Then the Sui, guardian and Bitcoin ticks run every `POLL_INTERVAL`,
//!    and the state checks every `STATE_TICK_INTERVAL`: fetch the missing
//!    Sui approvals, report the violations, retire the complete flows, log
//!    the progress watermarks, and save the snapshot one state check behind.
//!    The UTXO pool is checked against Bitcoin once at startup and then
//!    every `UTXO_CHECK_INTERVAL`.
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
use crate::metrics::SOURCE_UTXO;
use crate::store::Snapshot;
use crate::store::SnapshotStore;
use crate::time::utc_timestamp;
use crate::timing::Timing;
use hashi_types::guardian::s3::MAX_DIR_COMPLETION_LAG;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// How often the Sui, guardian and Bitcoin sources are polled.
const POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How often every UTXO in the pool is checked against Bitcoin. Every
/// tick runs on the one audit task, so this pass delays the polls by the
/// time its batched lookups take.
const UTXO_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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
/// arrive. Its start time is on the guardian timeline; Sui and guardian
/// polling begin their lookbacks before it.
pub struct ContinuousAuditor {
    pub inner: AuditorCore,
    pub window: ContinuousAuditWindow,
    metrics: Arc<MonitorMetrics>,
    /// Where the snapshot is kept between runs. `None` keeps nothing.
    store: Option<SnapshotStore>,
    /// The last state check's restart start, saved by the next one, so a
    /// restart re-reports findings alerting may not have read yet.
    previous_restart_start: UnixSeconds,
}

impl AuditWindow for ContinuousAuditWindow {
    fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
        timestamp_secs >= self.user_start
    }
}

impl ContinuousAuditWindow {
    pub fn new(timing: &Timing, start: UnixSeconds) -> Self {
        let sui_start = start.saturating_sub(timing.sui_lookback());
        let guardian_start = start.saturating_sub(timing.guardian_lookback());

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
    /// `requested_start` is the operator's `--start`, if given. Fails if the
    /// store cannot be read or written.
    pub async fn new(
        cfg: &Config,
        requested_start: Option<UnixSeconds>,
        metrics: Arc<MonitorMetrics>,
        store: Option<SnapshotStore>,
    ) -> anyhow::Result<Self> {
        let cur_time = now_timestamp_secs();
        let snapshot = match &store {
            Some(store) => store.load().await?,
            None => None,
        };
        let snapshot_restart_start = match snapshot {
            Some(snapshot) if snapshot.is_for(cfg) => {
                tracing::info!(
                    restart_start = %utc_timestamp(snapshot.restart_start),
                    "loaded the snapshot"
                );
                Some(snapshot.restart_start)
            }
            Some(snapshot) => {
                tracing::warn!(?snapshot, "ignoring the snapshot of another deployment");
                None
            }
            None => None,
        };
        let start = resume_start(
            requested_start,
            snapshot_restart_start,
            ContinuousAuditWindow::default_start(&cfg.timing, cur_time),
        );
        anyhow::ensure!(
            start <= cur_time,
            "start is in the future: start={} > current_time={}",
            utc_timestamp(start),
            utc_timestamp(cur_time),
        );
        // Fail now on a bucket that is missing or read-only: a missing one
        // loads as empty.
        if let Some(store) = &store {
            store.save(&Snapshot::new(cfg, start)).await?;
        }
        let audit_window = ContinuousAuditWindow::new(&cfg.timing, start);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };

        // No UTXO pool yet: keeping it between runs, and so turning it on,
        // follows in a later change.
        let inner = AuditorCore::new(cfg, cursors, None).await?;
        metrics.set_checked_through(SOURCE_SUI, inner.sui_cursor());
        metrics.set_checked_through(SOURCE_GUARDIAN, inner.guardian_cursor());
        Ok(Self {
            inner,
            window: audit_window,
            metrics,
            store,
            previous_restart_start: start,
        })
    }

    /// Save the snapshot. A failed save is logged and does not stop the
    /// audit; the next state check saves again.
    async fn save_snapshot(&self, restart_start: UnixSeconds) {
        let Some(store) = &self.store else {
            return;
        };
        match store
            .save(&Snapshot::new(&self.inner.cfg, restart_start))
            .await
        {
            Ok(()) => tracing::debug!(
                restart_start = %utc_timestamp(restart_start),
                "saved the snapshot"
            ),
            Err(error) => tracing::warn!(?error, "failed to save the snapshot; continuing"),
        }
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
    async fn tick_utxo_check(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.inner.check_utxo_pool()?;
        self.report_findings(SOURCE_UTXO, &findings);
        self.metrics.set_checked_through(SOURCE_UTXO, started_at);
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
        let pool_findings = self.inner.retire_complete_flows(&self.window);
        self.report_findings("pool", &pool_findings);

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
        let restart_start =
            std::mem::replace(&mut self.previous_restart_start, progress.restart_start);
        self.save_snapshot(restart_start).await;
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
        // After the Bitcoin lookups, so confirmed withdrawals and deposits
        // have moved through the pool first.
        let utxo = self.tick_utxo_check().await;
        Self::log_initial_catch_up(SOURCE_UTXO, utxo);
        self.tick_state_checks_and_gc().await;

        let mut sui_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(POLL_INTERVAL);
        let mut state_checks_ticker = tokio::time::interval(STATE_TICK_INTERVAL);
        let mut utxo_ticker = tokio::time::interval(UTXO_CHECK_INTERVAL);

        sui_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        guardian_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        btc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        state_checks_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        utxo_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // The initial catch-up above handled startup; consume each immediate
        // interval tick so the next pass runs one interval later.
        sui_ticker.tick().await;
        guardian_ticker.tick().await;
        btc_ticker.tick().await;
        state_checks_ticker.tick().await;
        utxo_ticker.tick().await;

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
                _ = utxo_ticker.tick() => {
                    if let Err(error) = self.tick_utxo_check().await {
                        tracing::warn!(source = SOURCE_UTXO, ?error, "UTXO pool check failed; continuing");
                    }
                }
            }
        }
    }
}

/// Where the audit starts: the snapshot's restart start, or the operator's
/// start if that is earlier, since a later one would skip flows the snapshot
/// has yet to verify. Without a snapshot, the operator's start or the default.
fn resume_start(
    requested: Option<UnixSeconds>,
    snapshot_restart_start: Option<UnixSeconds>,
    default: UnixSeconds,
) -> UnixSeconds {
    match (requested, snapshot_restart_start) {
        (Some(requested), Some(resume)) => requested.min(resume),
        (None, Some(resume)) => resume,
        (Some(requested), None) => requested,
        (None, None) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::WithdrawalEventType;
    use crate::rpc::btc::BtcRpcClient;
    use crate::rpc::guardian::GuardianWithdrawalsPoller;
    use crate::rpc::sui::tests::looked_up_approval;
    use crate::rpc::sui::tests::poller_scanned;
    use crate::timing::EventBounds;
    use crate::timing::UTXO_AGE_CRITICAL;
    use crate::timing::UTXO_AGE_WARN;
    use std::collections::HashMap;

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
            deposit_request_watch: 172_800,
            utxo_age_warn: UTXO_AGE_WARN,
            utxo_age_critical: UTXO_AGE_CRITICAL,
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

    #[test]
    fn the_guardian_is_read_early_enough_to_match_every_approval_in_the_window() {
        let timing = timing();
        let start = 1_700_002_800;

        let window = ContinuousAuditWindow::new(&timing, start);

        let earliest_signature = start
            - timing
                .predecessor_skews
                .get(WithdrawalEventType::E1HashiApproved)
                .unwrap();
        assert!(window.guardian_start <= earliest_signature);
    }

    #[tokio::test]
    async fn a_restart_still_audits_an_approval_the_guardian_never_signed() {
        let cfg = Config::for_tests();
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let guardian_cursor = approved_at + 7_200;
        let window = ContinuousAuditWindow::new(&cfg.timing, approved_at - 86_400);
        let mut inner = AuditorCore {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            utxo_pool: None,
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, guardian_cursor),
            sui_poller: poller_scanned(window.sui_start, guardian_cursor + 600).await,
            btc_client: BtcRpcClient::new(&cfg).unwrap(),
        };
        assert!(
            inner
                .ingest_batch(vec![MonitorEvent::Withdrawal(approval)])
                .is_empty()
        );
        assert_eq!(inner.detect_violations(&window).len(), 1);

        let restart = ContinuousAuditWindow::new(
            &cfg.timing,
            inner.progress_watermarks(&window).restart_start,
        );

        assert!(restart.sui_start <= approved_at && restart.in_window(approved_at));
    }

    #[test]
    fn the_snapshot_sets_the_start_unless_the_operator_asks_for_earlier() {
        assert_eq!(resume_start(None, Some(500), 100), 500);
        assert_eq!(resume_start(Some(300), Some(500), 100), 300);
        assert_eq!(resume_start(Some(700), Some(500), 100), 500);
        assert_eq!(resume_start(Some(700), None, 100), 700);
        assert_eq!(resume_start(None, None, 100), 100);
    }

    #[tokio::test]
    async fn a_state_check_saves_the_restart_start_of_the_check_before() {
        let cfg = Config::for_tests();
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let guardian_cursor = approved_at + 7_200;
        let window = ContinuousAuditWindow::new(&cfg.timing, approved_at - 86_400);
        let resumed_from = window.user_start;
        let mut auditor = ContinuousAuditor {
            inner: AuditorCore {
                cfg: cfg.clone(),
                pending_withdrawals: HashMap::new(),
                pending_deposits: HashMap::new(),
                pending_deposit_requests: HashMap::new(),
                utxo_pool: None,
                guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, guardian_cursor),
                sui_poller: poller_scanned(window.sui_start, guardian_cursor + 600).await,
                btc_client: BtcRpcClient::new(&cfg).unwrap(),
            },
            window,
            metrics: Arc::new(MonitorMetrics::new()),
            store: Some(SnapshotStore::in_memory()),
            previous_restart_start: resumed_from,
        };
        auditor.ingest_batch(vec![MonitorEvent::Withdrawal(approval)]);

        auditor.tick_state_checks_and_gc().await;
        let saved = auditor.store.as_ref().unwrap().load().await.unwrap();
        assert_eq!(saved, Some(Snapshot::new(&cfg, resumed_from)));

        // The approval's flow ends before the next check, which still saves a
        // start that reads it again.
        auditor.inner.pending_withdrawals.clear();
        auditor.tick_state_checks_and_gc().await;
        let saved = auditor.store.as_ref().unwrap().load().await.unwrap();
        assert_eq!(saved, Some(Snapshot::new(&cfg, approved_at)));
    }
}
