// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor: a long-running monitor of the live bridge.
//!
//! Why it exists: the deployed monitor must report a late or contradictory
//! event soon after it happens, and alerting reads its metrics.
//!
//! How it works:
//! 1. The start is on the guardian timeline. A snapshot this deployment
//!    saved, with a UTXO pool, sets it to the snapshot's restart start, and
//!    the pool resumes from the snapshot. Without one, this is a first run:
//!    the start is the bridge's genesis, the time the Hashi package was
//!    published on Sui, and the pool is empty. Either way, the monitor fails
//!    to start unless the Sui node still serves the start. Sui polling starts
//!    `Timing::sui_lookback` before the start, and guardian polling
//!    `Timing::guardian_lookback` before it.
//! 2. At startup, each source catches up once. A source that fails is
//!    logged and retried on its next tick.
//! 3. Then the Sui, guardian and Bitcoin ticks run every `POLL_INTERVAL`,
//!    and the state checks every `STATE_TICK_INTERVAL`: fetch the missing
//!    Sui approvals, report the violations, log the progress watermarks,
//!    and save the snapshot one state check behind. The complete flows are
//!    added to the UTXO pool in the Bitcoin tick, right after its lookups,
//!    so the pool takes a withdrawal only once Bitcoin has answered for its
//!    inputs. The pool is checked against Bitcoin once at startup and then
//!    every `UTXO_CHECK_INTERVAL`. A spend that check cannot explain waits
//!    for the Sui cursor to pass the time Bitcoin was asked, then a state
//!    check judges it.
//! 4. Every finding is logged and recorded in the metrics, and each source's
//!    checked-through time is exported.
//!
//! Assumptions:
//! - A poll failure is transient. The auditor logs it and goes on; only a
//!   failure to start is an error.

use std::sync::Arc;
use std::time::Duration;

use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::audit::pool::UtxoPool;
use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::metrics::MonitorMetrics;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SUI;
use crate::metrics::SOURCE_UTXO;
use crate::rpc::sui::package_publish_time;
use crate::store::Snapshot;
use crate::store::SnapshotStore;
use crate::time::utc_timestamp;
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

/// A continuous auditor that runs indefinitely and processes events as they
/// arrive. Its start time is on the guardian timeline; Sui and guardian
/// polling begin their lookbacks before it.
pub struct ContinuousAuditor {
    pub inner: AuditorCore,
    metrics: Arc<MonitorMetrics>,
    /// Where the snapshot is kept between runs.
    store: SnapshotStore,
    /// The last state check's restart start, saved by the next one, so a
    /// restart re-reports findings alerting may not have read yet.
    previous_restart_start: UnixSeconds,
}

impl ContinuousAuditor {
    /// Resume from the snapshot in `store`, or start a first run from the
    /// bridge's genesis. Fails if the store cannot be read or written, or if
    /// the Sui node has pruned the start.
    pub async fn new(
        cfg: &Config,
        metrics: Arc<MonitorMetrics>,
        store: SnapshotStore,
    ) -> anyhow::Result<Self> {
        let cur_time = now_timestamp_secs();
        let (start, pool) = match resume_point(cfg, store.load().await?) {
            Some(resumed) => resumed,
            None => {
                let genesis = package_publish_time(&cfg.sui).await?;
                tracing::info!(
                    genesis = %utc_timestamp(genesis),
                    "first run: starting at the bridge's genesis with an empty UTXO pool"
                );
                (genesis, UtxoPool::default())
            }
        };
        anyhow::ensure!(
            start <= cur_time,
            "start is in the future: start={} > current_time={}",
            utc_timestamp(start),
            utc_timestamp(cur_time),
        );
        // Fail now on a bucket that is missing or read-only: a missing one
        // loads as empty.
        store.save(&Snapshot::new(cfg, start, pool.clone())).await?;

        let mut inner = AuditorCore::new(cfg, start, pool).await?;
        // A pruned start would leave the pool incomplete for good.
        inner.ensure_sui_serves_start().await?;
        metrics.set_checked_through(SOURCE_SUI, inner.sui_cursor());
        metrics.set_checked_through(SOURCE_GUARDIAN, inner.guardian_cursor());
        Ok(Self {
            inner,
            metrics,
            store,
            previous_restart_start: start,
        })
    }

    /// Save the snapshot: `restart_start` and the pool as it is now. A failed
    /// save is logged and does not stop the audit; the next state check
    /// saves again.
    async fn save_snapshot(&self, restart_start: UnixSeconds) {
        let snapshot = Snapshot::new(
            &self.inner.cfg,
            restart_start,
            self.inner.utxo_pool().clone(),
        );
        match self.store.save(&snapshot).await {
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

    /// Fails if the Bitcoin RPC fails. The complete flows are added to the
    /// UTXO pool here, right after the lookups and before any other poll, so
    /// the pool sees a withdrawal's inputs enter before the withdrawal
    /// spends them: Bitcoin confirms a withdrawal only after the deposits
    /// and withdrawals that made its inputs, and one round of lookups
    /// answers them all.
    fn tick_btc(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.inner.fetch_btc_info()?;
        self.report_findings("btc", &findings);
        self.metrics.set_checked_through(SOURCE_BTC, started_at);
        let pool_findings = self.inner.add_to_pool();
        self.report_findings("pool", &pool_findings);
        Ok(())
    }

    async fn tick_state_checks_and_gc(&mut self) {
        let lookup_findings = self.inner.fetch_missing_hashi_approvals().await;
        self.report_findings("lookup", &lookup_findings);
        let violations = self.inner.detect_violations();
        // TODO: If a violation is detected, we keep logging it on every call to this. Decide if that's the behavior we want.
        self.report_findings("violations", &violations);
        let spends = self.inner.judge_suspect_spends();
        self.report_findings(SOURCE_UTXO, &spends);

        let progress = self.inner.progress_watermarks();
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
            "starting continuous audit:\n  start={}\n  sui_start={}\n  guardian_start={}",
            utc_timestamp(self.inner.window_start),
            utc_timestamp(self.inner.sui_cursor()),
            utc_timestamp(self.inner.guardian_cursor()),
        );
        let sui = self.tick_sui().await;
        Self::log_initial_catch_up(SOURCE_SUI, sui);
        let guardian = self.tick_guardian().await;
        Self::log_initial_catch_up(SOURCE_GUARDIAN, guardian);
        let btc = self.tick_btc();
        Self::log_initial_catch_up(SOURCE_BTC, btc);
        // After the Bitcoin tick, which moved the confirmed withdrawals and
        // deposits through the pool.
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

/// The start and pool the snapshot resumes, if it is this deployment's.
/// Otherwise `None`: the audit is a first run.
fn resume_point(cfg: &Config, snapshot: Option<Snapshot>) -> Option<(UnixSeconds, UtxoPool)> {
    let snapshot = match snapshot {
        Some(snapshot) if snapshot.is_for(cfg) => snapshot,
        Some(snapshot) => {
            tracing::warn!(
                guardian_bucket = snapshot.guardian_bucket,
                package_id = snapshot.package_id,
                "ignoring the snapshot of another deployment"
            );
            return None;
        }
        None => {
            tracing::info!("no snapshot");
            return None;
        }
    };
    let Snapshot {
        restart_start,
        pool,
        ..
    } = snapshot;
    tracing::info!(
        restart_start = %utc_timestamp(restart_start),
        utxos_held = pool.len(),
        utxos_spent = pool.spent_len(),
        "loaded the snapshot; resuming with its UTXO pool"
    );
    Some((restart_start, pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::WithdrawalEventType;
    use crate::rpc::btc::BtcRpcClient;
    use crate::rpc::guardian::GuardianWithdrawalsPoller;
    use crate::rpc::sui::tests::looked_up_approval;
    use crate::rpc::sui::tests::poller_scanned;
    use crate::test_utils::txid;
    use crate::timing::EventBounds;
    use crate::timing::Timing;
    use crate::timing::UTXO_AGE_CRITICAL;
    use crate::timing::UTXO_AGE_WARN;
    use bitcoin::ScriptBuf;
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
    fn the_guardian_is_read_early_enough_to_match_every_approval_in_the_window() {
        let timing = timing();
        let start: UnixSeconds = 1_700_002_800;

        let guardian_start = start.saturating_sub(timing.guardian_lookback());

        let earliest_signature = start
            - timing
                .predecessor_skews
                .get(WithdrawalEventType::E1HashiApproved)
                .unwrap();
        assert!(guardian_start <= earliest_signature);
    }

    #[tokio::test]
    async fn a_restart_still_audits_an_approval_the_guardian_never_signed() {
        let cfg = Config::for_tests();
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let guardian_cursor = approved_at + 7_200;
        let window_start = approved_at - 86_400;
        let sui_start = window_start.saturating_sub(cfg.timing.sui_lookback());
        let mut inner = AuditorCore {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            window_start,
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, guardian_cursor),
            sui_poller: poller_scanned(sui_start, guardian_cursor + 600).await,
            btc_client: BtcRpcClient::new(&cfg).unwrap(),
        };
        assert!(
            inner
                .ingest_batch(vec![MonitorEvent::Withdrawal(approval)])
                .is_empty()
        );
        assert_eq!(inner.detect_violations().len(), 1);

        let restart_start = inner.progress_watermarks().restart_start;

        assert!(restart_start.saturating_sub(cfg.timing.sui_lookback()) <= approved_at);
        assert!(approved_at >= restart_start);
    }

    /// An auditor over an in-memory store that holds `utxo_pool`, started a
    /// day before `looked_up_approval` with the guardian two hours past it.
    async fn auditor_with(cfg: &Config, utxo_pool: UtxoPool) -> ContinuousAuditor {
        let approved_at = looked_up_approval().timestamp_secs;
        let guardian_cursor = approved_at + 7_200;
        let window_start = approved_at - 86_400;
        let sui_start = window_start.saturating_sub(cfg.timing.sui_lookback());
        ContinuousAuditor {
            inner: AuditorCore {
                cfg: cfg.clone(),
                pending_withdrawals: HashMap::new(),
                pending_deposits: HashMap::new(),
                pending_deposit_requests: HashMap::new(),
                window_start,
                utxo_pool,
                suspect_spends: HashMap::new(),
                guardian_poller: GuardianWithdrawalsPoller::for_tests(cfg, guardian_cursor),
                sui_poller: poller_scanned(sui_start, guardian_cursor + 600).await,
                btc_client: BtcRpcClient::new(cfg).unwrap(),
            },
            previous_restart_start: window_start,
            metrics: Arc::new(MonitorMetrics::new()),
            store: SnapshotStore::in_memory(),
        }
    }

    #[tokio::test]
    async fn a_state_check_saves_the_restart_start_of_the_check_before() {
        let cfg = Config::for_tests();
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let mut auditor = auditor_with(&cfg, UtxoPool::default()).await;
        let resumed_from = auditor.inner.window_start;
        auditor.ingest_batch(vec![MonitorEvent::Withdrawal(approval)]);

        auditor.tick_state_checks_and_gc().await;
        let saved = auditor.store.load().await.unwrap();
        assert_eq!(
            saved,
            Some(Snapshot::new(&cfg, resumed_from, UtxoPool::default()))
        );

        // The approval's flow ends before the next check, which still saves a
        // start that reads it again.
        auditor.inner.pending_withdrawals.clear();
        auditor.tick_state_checks_and_gc().await;
        let saved = auditor.store.load().await.unwrap();
        assert_eq!(
            saved,
            Some(Snapshot::new(&cfg, approved_at, UtxoPool::default()))
        );
    }

    #[tokio::test]
    async fn a_state_check_saves_the_utxo_pool() {
        let cfg = Config::for_tests();
        let mut pool = UtxoPool::default();
        let deposit = ConfirmedDeposit {
            deposit_id: DepositId::new(txid(1), 0),
            amount: 1_000,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            block_time: 1_700_000_000,
        };
        assert!(pool.add_deposit(&deposit).is_none());
        let mut auditor = auditor_with(&cfg, pool.clone()).await;

        auditor.tick_state_checks_and_gc().await;

        let saved = auditor.store.load().await.unwrap().unwrap();
        assert_eq!(saved.pool, pool);
    }

    #[test]
    fn only_this_deployments_snapshot_is_resumed() {
        let cfg = Config::for_tests();
        let pool = UtxoPool::default();

        assert_eq!(resume_point(&cfg, None), None);

        let mut other = Snapshot::new(&cfg, 500, pool.clone());
        other.package_id = format!("0x{}", "22".repeat(32));
        assert_eq!(resume_point(&cfg, Some(other)), None);

        let ours = Snapshot::new(&cfg, 500, pool.clone());
        assert_eq!(resume_point(&cfg, Some(ours)), Some((500, pool)));
    }
}
