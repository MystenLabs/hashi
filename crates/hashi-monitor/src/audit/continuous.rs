// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor: a long-running monitor of the live bridge.
//!
//! Why it exists: the deployed monitor must report a late or contradictory
//! event soon after it happens, and alerting reads its metrics.
//!
//! How it works:
//! 1. A snapshot this deployment saved gives the start: the open machines,
//!    the suspect spends, the UTXO pool, the time of the last finding of
//!    each category, and the position of each poller. Without one, this is a first run: both
//!    pollers start at the bridge's genesis, the time the Hashi package was
//!    published on Sui, and the pool is empty. Either way, the monitor fails
//!    to start unless the Sui node still serves the start.
//! 2. At startup, each source catches up once. A source that fails is
//!    logged and retried on its next tick.
//! 3. Then the Sui, Bitcoin and guardian ticks run every
//!    `SUI_POLL_INTERVAL`, `BTC_POLL_INTERVAL` and `GUARDIAN_POLL_INTERVAL`,
//!    and the state checks every `STATE_TICK_INTERVAL`: report the
//!    violations, log the progress, and save the snapshot. The complete flows are
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
use crate::metrics::SOURCE_SNAPSHOT;
use crate::metrics::SOURCE_SUI;
use crate::metrics::SOURCE_UTXO;
use crate::store::AuditState;
use crate::store::Snapshot;
use crate::store::SnapshotStore;
use crate::time::utc_timestamp;
use hashi_types::guardian::time::now_timestamp_secs;

/// How often Sui is polled. A deposit approval must reach the monitor
/// early in Move's delay before the mint, ten minutes by default.
const SUI_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// How often Bitcoin is asked about the pending transactions. An approval
/// is reported unbacked at the second empty lookup after it, so with
/// `SUI_POLL_INTERVAL` the alert comes within five minutes of it.
const BTC_POLL_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How often the guardian's log is polled. The withdrawal bounds are hours.
const GUARDIAN_POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How often every UTXO in the pool is checked against Bitcoin. Every
/// tick runs on the one audit task, so this pass delays the polls by the
/// time its batched lookups take.
const UTXO_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the state checks run.
const STATE_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A continuous auditor that runs indefinitely and processes events as they
/// arrive.
pub struct ContinuousAuditor {
    pub inner: AuditorCore,
    metrics: Arc<MonitorMetrics>,
    /// Where the snapshot is kept between runs.
    store: SnapshotStore,
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
        let (state, pool) = match this_deployments(cfg, store.load().await?) {
            Some(snapshot) => {
                tracing::info!(
                    sui_next_checkpoint = snapshot.state.sui_next_checkpoint,
                    guardian_cursor = %utc_timestamp(snapshot.state.guardian_cursor),
                    withdrawals = snapshot.state.withdrawals.len(),
                    deposits = snapshot.state.deposits.len(),
                    suspect_spends = snapshot.state.suspect_spends.len(),
                    utxos_held = snapshot.pool.len(),
                    utxos_spent = snapshot.pool.spent_len(),
                    "loaded the snapshot; resuming where it stopped"
                );
                metrics.restore_last_findings(&snapshot.state.last_findings);
                (Some(snapshot.state), snapshot.pool)
            }
            None => (None, UtxoPool::default()),
        };
        let mut inner = AuditorCore::new(cfg, state, pool).await?;
        // A pruned start would leave the pool incomplete for good.
        inner.ensure_sui_serves_start().await?;
        metrics.set_checked_through(SOURCE_SUI, inner.sui_cursor());
        metrics.set_checked_through(SOURCE_GUARDIAN, inner.guardian_cursor());
        let auditor = Self {
            inner,
            metrics,
            store,
        };
        // Fail now on a bucket that is missing or read-only: a missing one
        // loads as empty.
        auditor
            .store
            .save(
                &auditor.inner.cfg,
                auditor.state(),
                auditor.inner.utxo_pool(),
            )
            .await?;
        auditor
            .metrics
            .set_checked_through(SOURCE_SNAPSHOT, now_timestamp_secs());
        Ok(auditor)
    }

    /// The audit state the snapshot keeps.
    fn state(&self) -> AuditState {
        self.inner.state(self.metrics.last_findings())
    }

    /// Save the snapshot. A failed save is logged and does not stop the
    /// audit; the next state check saves again. Alerting watches the time
    /// of the last good save.
    async fn save_snapshot(&self) {
        let saved = self
            .store
            .save(&self.inner.cfg, self.state(), self.inner.utxo_pool())
            .await;
        match saved {
            Ok(()) => self
                .metrics
                .set_checked_through(SOURCE_SNAPSHOT, now_timestamp_secs()),
            Err(error) => tracing::error!(?error, "failed to save the snapshot; continuing"),
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
        let findings = self.inner.fetch_btc_info(started_at)?;
        self.report_findings("btc", &findings);
        self.metrics.set_checked_through(SOURCE_BTC, started_at);
        let pool_findings = self.inner.add_to_pool_and_gc();
        self.report_findings("pool", &pool_findings);
        Ok(())
    }

    async fn tick_state_checks(&mut self) {
        let violations = self.inner.detect_timing_violations();
        self.report_findings("timing", &violations);
        let spends = self.inner.judge_suspect_spends();
        self.report_findings(SOURCE_UTXO, &spends);

        let (withdrawals, deposits) = self.inner.open_flows();
        tracing::info!(
            "continuous progress checkpoint:\n  guardian_cursor={}\n  sui_cursor={}\n  open_withdrawals={}\n  open_deposits={}\n  oldest_withdrawals={}",
            utc_timestamp(self.inner.guardian_cursor()),
            utc_timestamp(self.inner.sui_cursor()),
            withdrawals,
            deposits,
            self.inner.oldest_open_withdrawals(),
        );
        self.save_snapshot().await;
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tracing::info!(
            "starting continuous audit:\n  sui_start={}\n  guardian_start={}",
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
        self.tick_state_checks().await;

        let mut sui_ticker = tokio::time::interval(SUI_POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(GUARDIAN_POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(BTC_POLL_INTERVAL);
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
                    self.tick_state_checks().await;
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

/// The snapshot, if this deployment saved it. Otherwise `None`: the audit
/// is a first run.
fn this_deployments(cfg: &Config, snapshot: Option<Snapshot>) -> Option<Snapshot> {
    match snapshot {
        Some(snapshot) if snapshot.is_for(cfg) => Some(snapshot),
        Some(snapshot) => {
            tracing::warn!(
                guardian_bucket = snapshot.guardian_bucket,
                package_id = snapshot.package_id,
                "ignoring the snapshot of another deployment"
            );
            None
        }
        None => {
            tracing::info!("no snapshot");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::WithdrawalEventType;
    use crate::rpc::btc::BtcRpcClient;
    use crate::rpc::btc::MAINNET_MIN_CONFIRMATIONS;
    use crate::rpc::guardian::GuardianWithdrawalsPoller;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::rpc::sui::tests::poller_scanned;
    use crate::test_utils::txid;
    use bitcoin::ScriptBuf;
    use std::collections::HashMap;

    /// An auditor over an in-memory store, with both cursors two hours past
    /// `hashi_approval`.
    fn auditor_with(cfg: &Config, metrics: Arc<MonitorMetrics>) -> ContinuousAuditor {
        let cursor = hashi_approval().timestamp_secs + 7_200;
        ContinuousAuditor {
            inner: AuditorCore {
                cfg: cfg.clone(),
                pending_withdrawals: HashMap::new(),
                pending_deposits: HashMap::new(),
                utxo_pool: UtxoPool::default(),
                suspect_spends: HashMap::new(),
                guardian_poller: GuardianWithdrawalsPoller::for_tests(cfg, cursor),
                sui_poller: poller_scanned(cursor, cursor),
                btc_client: BtcRpcClient::new(cfg, MAINNET_MIN_CONFIRMATIONS).unwrap(),
            },
            metrics,
            store: SnapshotStore::in_memory(),
        }
    }

    #[tokio::test]
    async fn a_restart_resumes_the_open_flows_the_pool_and_the_finding_times() {
        let cfg = Config::for_tests();
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        let deposit = ConfirmedDeposit {
            deposit_id: DepositId::new(txid(1), 0),
            amount: 1_000,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            block_time: 1_700_000_000,
        };
        assert!(auditor.inner.utxo_pool.add_deposit(&deposit).is_none());
        // An approval the guardian never signed: its E2 is overdue.
        auditor.ingest_batch(vec![MonitorEvent::Withdrawal(hashi_approval())]);
        auditor.tick_state_checks().await;
        let missing = auditor.inner.detect_timing_violations();
        assert!(matches!(
            missing[..],
            [MonitorFinding::WithdrawalEventMissing {
                event_type: WithdrawalEventType::E2GuardianApproved,
                ..
            }]
        ));

        let snapshot = auditor.store.load().await.unwrap().unwrap();
        assert_eq!(snapshot.pool, *auditor.inner.utxo_pool());
        let metrics = Arc::new(MonitorMetrics::new());
        metrics.restore_last_findings(&snapshot.state.last_findings);
        let mut resumed = auditor_with(&cfg, metrics);
        resumed.inner.restore(snapshot.state);

        assert_eq!(resumed.inner.detect_timing_violations(), missing);
        assert_eq!(
            resumed.metrics.last_findings(),
            auditor.metrics.last_findings()
        );
    }

    #[tokio::test]
    async fn only_this_deployments_snapshot_is_resumed() {
        let cfg = Config::for_tests();
        let auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        let ours = Snapshot::new(&cfg, auditor.state(), UtxoPool::default());

        assert_eq!(this_deployments(&cfg, None), None);

        let mut other = ours.clone();
        other.package_id = format!("0x{}", "22".repeat(32));
        assert_eq!(this_deployments(&cfg, Some(other)), None);

        assert_eq!(this_deployments(&cfg, Some(ours.clone())), Some(ours));
    }
}
