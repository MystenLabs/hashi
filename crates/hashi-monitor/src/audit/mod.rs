// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor monitors bridge events and reports findings.
//!
//! Why it exists:
//! - The monitor checks deposits, withdrawals, and unspent transaction outputs (UTXOs).
//! - Metrics provide findings and source progress for alerts.
//!
//! How it works:
//! 1. Restore the source positions, flow machines, and UTXO pool from a snapshot.
//! 2. Without a snapshot, start at the bridge genesis with an empty pool.
//! 3. Fail at startup if the Sui node has pruned the start checkpoint.
//! 4. Read Sui events and guardian logs into the flow machines.
//! 5. Check Bitcoin confirmations after both withdrawal approvals arrive.
//! 6. Update the pool every `POOL_MAINTENANCE_INTERVAL` and check Bitcoin when the daily check is due.
//! 7. Check Bitcoin at the first maintenance tick. Repeat successful pool checks after `UTXO_CHECK_INTERVAL` seconds.
//! 8. Judge suspect spends after the Sui cursor passes the Bitcoin lookup time.
//! 9. Report timing violations and save snapshots every `STATE_TICK_INTERVAL`.
//! 10. Log a failed source tick. The next tick of that source retries it.
//! 11. At each state tick, report a source or a snapshot save that is behind its limit.
//! 12. After each pool maintenance tick, check that the UTXO pool backs the hBTC supply.
//!
//! Assumptions:
//! - Every tick runs on one task. The first catch-up blocks the state tick,
//!   so a first run reports no stale source while it catches up.

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::utxo_pool::SuspectSpend;
use crate::domain::utxo_pool::UtxoPool;
use crate::findings::MonitorFinding;
use crate::metrics::MonitorMetrics;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SNAPSHOT;
use crate::metrics::SOURCE_SUI;
use crate::metrics::SOURCE_UTXO;
use crate::rpc::PollCursor;
use crate::rpc::sui::package_genesis;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
use crate::store::AuditState;
use crate::store::Snapshot;
use crate::store::SnapshotStore;
use crate::time::utc_timestamp;
use anyhow::Context;
use bitcoin::OutPoint;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use rpc_pollers::RpcPollers;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;

mod hbtc_supply;
mod pool_checks;
mod pool_maintenance;
mod rpc_pollers;

/// How often Sui is polled. A deposit approval must reach the monitor
/// early in Move's delay before the mint, ten minutes by default.
const SUI_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// How often Bitcoin is asked about the pending transactions. An approval
/// is reported unbacked at the second empty lookup after it, so with
/// `SUI_POLL_INTERVAL` the alert comes within five minutes of it.
const BTC_POLL_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How often the guardian's log is polled. The withdrawal bounds are hours.
const GUARDIAN_POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How often pool maintenance runs.
const POOL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How often the state checks run.
const STATE_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How long snapshot saves may fail before a `SnapshotStale` finding, in
/// seconds. A failed save costs only a longer replay at the next restart.
const SNAPSHOT_STALE_LIMIT: u64 = 12 * 60 * 60;

pub fn log_findings(source: &'static str, phase: &'static str, findings: &[MonitorFinding]) {
    for finding in findings.iter() {
        tracing::error!(
            source,
            phase,
            total = findings.len(),
            finding = %finding,
            "monitor finding"
        );
    }
}

pub struct Auditor {
    cfg: Config,
    pending_withdrawals: HashMap<WithdrawalID, WithdrawalStateMachine>,
    /// Deposit requests Bitcoin is still asked about. Keyed by the Sui
    /// request id, so a repeated event is ignored and each request has its
    /// own.
    pending_deposits: HashMap<Address, DepositStateMachine>,
    /// The UTXOs the bridge holds, by Bitcoin's account. See `crate::domain::utxo_pool`. The
    /// snapshot keeps it between runs.
    utxo_pool: UtxoPool,
    /// Spends waiting for the Sui cursor, by outpoint.
    suspect_spends: HashMap<OutPoint, SuspectSpend>,
    rpc_pollers: RpcPollers,
    metrics: Arc<MonitorMetrics>,
    /// Where the snapshot is kept between runs.
    store: SnapshotStore,
    /// When the last successful pool check finished. `None` until one
    /// succeeds in this run.
    last_successful_pool_check: Option<UnixSeconds>,
    /// When the last snapshot save succeeded.
    last_snapshot_save: UnixSeconds,
    /// Since when the hBTC supply has exceeded the pool value, if it does.
    hbtc_supply_above_pool_since: Option<UnixSeconds>,
}

impl Auditor {
    /// Restore the snapshot, or start at the bridge genesis.
    /// Fail if the store cannot be read or written, or Sui has removed the required history.
    pub async fn new(
        cfg: &Config,
        metrics: Arc<MonitorMetrics>,
        store: SnapshotStore,
    ) -> anyhow::Result<Self> {
        let (state, pool) = match this_deployments(cfg, store.load().await?) {
            Some(snapshot) => {
                tracing::info!(
                    sui_next_checkpoint = snapshot.state.sui_next_checkpoint,
                    guardian_cursor = %utc_timestamp(snapshot.state.guardian_cursor.to_unix_seconds()),
                    withdrawals = snapshot.state.withdrawals.len(),
                    deposits = snapshot.state.deposits.len(),
                    suspect_spends = snapshot.state.suspect_spends.len(),
                    utxos_held = snapshot.pool.len(),
                    "loaded the snapshot; resuming where it stopped"
                );
                (Some(snapshot.state), snapshot.pool)
            }
            None => (None, UtxoPool::default()),
        };
        let (guardian_start, sui_start) = match &state {
            Some(state) => (state.guardian_cursor.clone(), state.sui_next_checkpoint),
            None => {
                let genesis = package_genesis(&cfg.sui).await?;
                tracing::info!(
                    genesis = %utc_timestamp(genesis.timestamp),
                    genesis_checkpoint = genesis.checkpoint,
                    "first run: starting at the bridge's genesis with an empty UTXO pool"
                );
                (
                    S3HourDirectory::withdraw(genesis.timestamp)?,
                    genesis.checkpoint,
                )
            }
        };
        let rpc_pollers = RpcPollers::new(cfg, guardian_start, sui_start).await?;
        let mut auditor = Self {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: pool,
            suspect_spends: HashMap::new(),
            rpc_pollers,
            metrics,
            store,
            last_successful_pool_check: None,
            last_snapshot_save: 0,
            hbtc_supply_above_pool_since: None,
        };
        if let Some(state) = state {
            auditor.restore(state);
        }
        // A pruned start leaves the pool incomplete.
        auditor.rpc_pollers.ensure_sui_serves_start().await?;
        // A setup that cannot read the supply fails here, not silently later.
        let supply = auditor
            .read_hbtc_supply()
            .await
            .context("failed to read the hBTC supply")?;
        tracing::info!(hbtc_supply = supply, "read the hBTC supply");
        auditor
            .metrics
            .set_checked_through(SOURCE_SUI, auditor.rpc_pollers.sui_read_until());
        auditor
            .metrics
            .set_checked_through(SOURCE_GUARDIAN, auditor.rpc_pollers.guardian_read_until());
        auditor
            .metrics
            .set_checked_through(SOURCE_BTC, auditor.rpc_pollers.btc_read_until());
        // Check write access at startup. A missing bucket loads as empty.
        auditor
            .store
            .save(&auditor.cfg, auditor.state(), auditor.utxo_pool())
            .await?;
        let now = now_timestamp_secs();
        auditor.last_snapshot_save = now;
        auditor.metrics.set_checked_through(SOURCE_SNAPSHOT, now);
        Ok(auditor)
    }

    /// The pollers' positions, the open machines and the suspect spends, for
    /// the snapshot.
    fn state(&self) -> AuditState {
        AuditState {
            sui_next_checkpoint: self.rpc_pollers.sui_poller.next_item_to_poll(),
            guardian_cursor: self.rpc_pollers.guardian_poller.next_item_to_poll(),
            withdrawals: self.pending_withdrawals.values().cloned().collect(),
            deposits: self.pending_deposits.values().cloned().collect(),
            suspect_spends: self.suspect_spends.clone().into_iter().collect(),
            hbtc_supply_above_pool_since: self.hbtc_supply_above_pool_since,
        }
    }

    /// Hold the machines and the suspect spends a snapshot saved.
    fn restore(&mut self, state: AuditState) {
        for sm in state.withdrawals {
            self.pending_withdrawals.insert(sm.wid(), sm);
        }
        for sm in state.deposits {
            self.pending_deposits.insert(sm.request_id(), sm);
        }
        self.suspect_spends.extend(state.suspect_spends);
        self.hbtc_supply_above_pool_since = state.hbtc_supply_above_pool_since;
    }

    fn ingest(&mut self, event: MonitorEvent) -> Vec<MonitorFinding> {
        match event {
            MonitorEvent::Withdrawal(event) => self.ingest_withdrawal(event),
            MonitorEvent::DepositApproved(event) => self.ingest_deposit_approved(event),
            MonitorEvent::DepositRequested(event) => self.ingest_deposit_request(event),
        }
    }

    fn ingest_deposit_request(&mut self, event: SuiDepositRequestedEvent) -> Vec<MonitorFinding> {
        match self.pending_deposits.entry(event.request_id) {
            Entry::Occupied(entry) => entry.get().add_sui_request(&event).into_iter().collect(),
            Entry::Vacant(entry) => {
                entry.insert(DepositStateMachine::new(event));
                Vec::new()
            }
        }
    }

    fn ingest_withdrawal(&mut self, event: MonitorWithdrawalEvent) -> Vec<MonitorFinding> {
        let wid = event.wid;
        match self.pending_withdrawals.entry(wid) {
            Entry::Occupied(mut entry) => entry.get_mut().add_event(event, &self.cfg.timing),
            Entry::Vacant(entry) => {
                entry.insert(WithdrawalStateMachine::new(event, &self.cfg.timing));
                Vec::new()
            }
        }
    }

    /// The Sui `DepositApproved`. Move approves only a request it holds, so
    /// the request came first. While its machine is open, the machine keeps
    /// the approval. Once it closed, the pool has its answer.
    fn ingest_deposit_approved(&mut self, event: SuiDepositApprovedEvent) -> Vec<MonitorFinding> {
        match self.pending_deposits.get_mut(&event.request_id) {
            Some(sm) => sm.add_sui_approval(event, &self.cfg.timing),
            None => self
                .utxo_pool
                .check_sui_approval(&event, self.cfg.timing.deposit_approval_skew),
        }
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorEvent>) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for event in events {
            findings.extend(self.ingest(event));
        }
        self.report_findings("ingest", &findings);
        findings
    }

    fn detect_timing_violations(&self) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values() {
            findings.extend(sm.timing_violations(&self.rpc_pollers.cursors()));
        }
        findings
    }

    /// The open withdrawals whose first event is the earliest, for the
    /// progress log. An operator sees what the audit still waits for.
    fn oldest_open_withdrawals(&self) -> String {
        let earliest = self
            .pending_withdrawals
            .values()
            .map(WithdrawalStateMachine::earliest_event_at)
            .min();
        let oldest = self
            .pending_withdrawals
            .values()
            .filter(|sm| Some(sm.earliest_event_at()) == earliest)
            .map(|sm| {
                format!(
                    "wid={}, btc_txid={}, earliest_event_at={}, waiting_for={:?}",
                    sm.wid(),
                    sm.btc_txid(),
                    utc_timestamp(sm.earliest_event_at()),
                    sm.expected_event_types(),
                )
            })
            .collect::<Vec<_>>();
        if oldest.is_empty() {
            "none".to_string()
        } else {
            oldest.join("; ")
        }
    }

    /// Return the deposits with the earliest request timestamp for the progress log.
    fn oldest_open_deposits(&self) -> String {
        let earliest = self
            .pending_deposits
            .values()
            .map(DepositStateMachine::requested_at)
            .min();
        let oldest = self
            .pending_deposits
            .values()
            .filter(|sm| Some(sm.requested_at()) == earliest)
            .map(|sm| {
                format!(
                    "request_id={}, deposit_id={}, requested_at={}",
                    sm.request_id(),
                    sm.deposit_id(),
                    utc_timestamp(sm.requested_at()),
                )
            })
            .collect::<Vec<_>>();
        if oldest.is_empty() {
            "none".to_string()
        } else {
            oldest.join("; ")
        }
    }

    /// The number of open withdrawal and deposit machines.
    fn open_flows(&self) -> (usize, usize) {
        (self.pending_withdrawals.len(), self.pending_deposits.len())
    }

    pub fn utxo_pool(&self) -> &UtxoPool {
        &self.utxo_pool
    }

    /// Save the snapshot. A failed save is logged and does not stop the
    /// audit; the next state check saves again. Alerting watches the time
    /// of the last good save.
    async fn save_snapshot(&mut self) {
        let saved = self
            .store
            .save(&self.cfg, self.state(), self.utxo_pool())
            .await;
        match saved {
            Ok(()) => {
                self.last_snapshot_save = now_timestamp_secs();
                self.metrics
                    .set_checked_through(SOURCE_SNAPSHOT, self.last_snapshot_save);
            }
            Err(error) => tracing::error!(?error, "failed to save the snapshot; continuing"),
        }
    }

    /// A `SnapshotStale` finding if no save has succeeded within the limit.
    fn stale_snapshot(&self, now: UnixSeconds) -> Option<MonitorFinding> {
        (now.saturating_sub(self.last_snapshot_save) > SNAPSHOT_STALE_LIMIT).then_some(
            MonitorFinding::SnapshotStale {
                last_saved: self.last_snapshot_save,
                limit_secs: SNAPSHOT_STALE_LIMIT,
            },
        )
    }

    fn report_findings(&self, phase: &'static str, findings: &[MonitorFinding]) {
        log_findings("continuous", phase, findings);
        self.metrics.record_findings(findings, now_timestamp_secs());
    }

    /// Log the outcome of one source's initial catch-up. A failure does not
    /// stop the audit: the source's next tick retries it.
    fn log_initial_catch_up(source: &'static str, result: anyhow::Result<()>) {
        match result {
            Ok(()) => tracing::info!(source, "finished initial catch-up"),
            Err(error) => tracing::warn!(source, ?error, "initial catch-up failed; continuing"),
        }
    }

    async fn tick_state_checks(&mut self) {
        let violations = self.detect_timing_violations();
        self.report_findings("timing", &violations);
        let spends = self.judge_suspect_spends();
        self.report_findings(SOURCE_UTXO, &spends);

        let (withdrawals, deposits) = self.open_flows();
        tracing::info!(
            "continuous progress checkpoint:\n  guardian_cursor={}\n  sui_cursor={}\n  open_withdrawals={}\n  open_deposits={}\n  oldest_withdrawals={}\n  oldest_deposits={}",
            utc_timestamp(self.rpc_pollers.guardian_read_until()),
            utc_timestamp(self.rpc_pollers.sui_read_until()),
            withdrawals,
            deposits,
            self.oldest_open_withdrawals(),
            self.oldest_open_deposits(),
        );
        let stale = self.rpc_pollers.stale_sources(now_timestamp_secs());
        self.report_findings("progress", &stale);

        self.save_snapshot().await;
        // After the save, so a save that succeeds now is not reported.
        let stale = self.stale_snapshot(now_timestamp_secs());
        self.report_findings("progress", stale.as_slice());
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tracing::info!(
            "starting continuous audit:\n  sui_start={}\n  guardian_start={}",
            utc_timestamp(self.rpc_pollers.sui_read_until()),
            utc_timestamp(self.rpc_pollers.guardian_read_until()),
        );
        let sui = self.tick_sui().await;
        Self::log_initial_catch_up(SOURCE_SUI, sui);
        let guardian = self.tick_guardian().await;
        Self::log_initial_catch_up(SOURCE_GUARDIAN, guardian);
        let btc = self.tick_btc();
        Self::log_initial_catch_up(SOURCE_BTC, btc);

        let mut sui_ticker = tokio::time::interval(SUI_POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(GUARDIAN_POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(BTC_POLL_INTERVAL);
        let mut pool_maintenance_ticker = tokio::time::interval(POOL_MAINTENANCE_INTERVAL);
        let mut state_checks_ticker = tokio::time::interval(STATE_TICK_INTERVAL);

        sui_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        guardian_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        btc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        pool_maintenance_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        state_checks_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Consume each immediate tick so scheduled work starts after its interval.
        sui_ticker.tick().await;
        guardian_ticker.tick().await;
        btc_ticker.tick().await;
        pool_maintenance_ticker.tick().await;
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
                _ = pool_maintenance_ticker.tick() => {
                    if let Err(error) = self.tick_pool_maintenance() {
                        tracing::warn!(source = SOURCE_UTXO, ?error, "pool maintenance failed; retrying at the next tick");
                    }
                    self.check_hbtc_supply().await;
                }
                _ = state_checks_ticker.tick() => {
                    self.tick_state_checks().await;
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
    use crate::domain::BtcConfirmation;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::WithdrawalEventType;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;
    use crate::test_utils::withdrawal_tx;
    use crate::timing::Timing;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::TxOut;
    use std::collections::HashMap;

    #[tokio::test]
    async fn a_repeated_deposit_request_is_ingested_once() {
        let approval = hashi_approval();
        let mut auditor = auditor_with_pool().await;
        let request = SuiDepositRequestedEvent {
            timestamp_secs: approval.timestamp_secs,
            deposit_id: DepositId::new(approval.btc_txid, 0),
            ..deposit_request()
        };

        assert!(
            auditor
                .ingest(MonitorEvent::DepositRequested(request.clone()))
                .is_empty()
        );
        assert!(
            auditor
                .ingest(MonitorEvent::DepositRequested(request.clone()))
                .is_empty()
        );
        assert_eq!(auditor.pending_deposits.len(), 1);

        // The same request id with other contents is a contradiction.
        let contradiction = SuiDepositRequestedEvent {
            amount: request.amount + 1,
            ..request.clone()
        };
        assert!(matches!(
            &auditor.ingest(MonitorEvent::DepositRequested(contradiction))[..],
            [MonitorFinding::InvalidEventAdded(_)]
        ));
        assert_eq!(auditor.pending_deposits.len(), 1);

        // Another request for the same UTXO has its own machine.
        let again = SuiDepositRequestedEvent {
            request_id: Address::new([0x62; 32]),
            ..request
        };
        assert!(
            auditor
                .ingest(MonitorEvent::DepositRequested(again))
                .is_empty()
        );
        assert_eq!(auditor.pending_deposits.len(), 2);
    }

    /// An auditor with an empty UTXO pool and no flows.
    pub async fn auditor_with_pool() -> Auditor {
        let cfg = Config::for_tests();
        let approved_at = hashi_approval().timestamp_secs;
        Auditor {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            rpc_pollers: RpcPollers::for_tests(&cfg, approved_at),
            cfg,
            metrics: Arc::new(MonitorMetrics::new()),
            store: SnapshotStore::in_memory(),
            last_successful_pool_check: None,
            last_snapshot_save: approved_at,
            hbtc_supply_above_pool_since: None,
        }
    }

    /// A deposit request for `txid(9):1` of `amount` to `p2wpkh(0x54)`, and
    /// its Sui approval at time 200.
    fn deposit_request_and_approval(
        amount: u64,
    ) -> (SuiDepositRequestedEvent, SuiDepositApprovedEvent) {
        let request = SuiDepositRequestedEvent {
            amount,
            ..deposit_request()
        };
        let approval = approval_of(&request, 200);
        (request, approval)
    }

    #[tokio::test]
    async fn a_sui_approval_after_its_request_closed_is_checked_against_the_pool() {
        let mut auditor = auditor_with_pool().await;
        let (_, sui) = deposit_request_and_approval(50_000);
        let unbacked = auditor.ingest(MonitorEvent::DepositApproved(sui.clone()));
        assert!(matches!(
            &unbacked[..],
            [MonitorFinding::DepositUnbacked { sui: unbacked }] if *unbacked == sui
        ));

        assert!(
            auditor
                .utxo_pool
                .add_deposit(&ConfirmedDeposit {
                    deposit_id: sui.deposit_id,
                    amount: 50_000,
                    script_pubkey: sui.script_pubkey.clone(),
                    block_time: 150,
                })
                .is_none()
        );
        assert!(
            auditor
                .ingest(MonitorEvent::DepositApproved(sui))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_open_request_keeps_its_sui_approval_until_bitcoin_answers() {
        let mut auditor = auditor_with_pool().await;
        // The request claims more than Bitcoin pays, and Hashi approves it.
        let (request, sui) = deposit_request_and_approval(60_000);
        let request_id = request.request_id;
        assert!(
            auditor
                .ingest_batch(vec![
                    MonitorEvent::DepositRequested(request),
                    MonitorEvent::DepositApproved(sui.clone()),
                ])
                .is_empty()
        );
        assert!(auditor.add_to_pool_and_gc().is_empty());

        // Bitcoin answers: the machine judges the held approval.
        let findings = auditor
            .pending_deposits
            .get_mut(&request_id)
            .unwrap()
            .record_lookup(
                &Timing::for_tests(),
                0,
                Some(&crate::test_utils::confirmation(50_000, p2wpkh(0x54))),
            );
        assert!(
            matches!(&findings[..], [MonitorFinding::DepositMismatch { sui: claimed, btc }] if *claimed == sui && btc.amount == 50_000)
        );

        assert!(auditor.add_to_pool_and_gc().is_empty());
        assert!(auditor.pending_deposits.is_empty());
        assert_eq!(auditor.utxo_pool.len(), 1);
    }

    #[tokio::test]
    async fn a_sui_approval_of_a_request_bitcoin_did_not_back_is_unbacked() {
        let mut auditor = auditor_with_pool().await;
        let (request, sui) = deposit_request_and_approval(50_000);
        let request_id = request.request_id;
        auditor.ingest_batch(vec![
            MonitorEvent::DepositRequested(request),
            MonitorEvent::DepositApproved(sui.clone()),
        ]);

        // The output pays another script.
        let findings = auditor
            .pending_deposits
            .get_mut(&request_id)
            .unwrap()
            .record_lookup(
                &Timing::for_tests(),
                0,
                Some(&crate::test_utils::confirmation(50_000, p2wpkh(0x55))),
            );

        assert!(matches!(
            &findings[..],
            [MonitorFinding::DepositUnbacked { sui: unbacked }] if *unbacked == sui
        ));
        assert!(auditor.add_to_pool_and_gc().is_empty());
        assert!(auditor.utxo_pool.is_empty());
    }

    /// A complete withdrawal `txid(fill)` for `wid_seed`, spending `inputs`,
    /// with one user payout and one change output at vout 1.
    pub fn complete_withdrawal(
        wid_seed: u8,
        fill: u8,
        inputs: Vec<OutPoint>,
        timing: &Timing,
    ) -> WithdrawalStateMachine {
        let approval = MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E1HashiApproved,
            wid: WithdrawalID::new([wid_seed; 32]),
            timestamp_secs: 1_000,
            btc_txid: txid(fill),
            tx: withdrawal_tx(vec![0x55; 20]),
        };
        let confirmation = BtcConfirmation {
            block_time: 1_120,
            confirmed_time: 1_180,
            inputs,
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: p2wpkh(0x53),
                },
                TxOut {
                    value: Amount::from_sat(19_000),
                    script_pubkey: p2wpkh(0x55),
                },
            ],
        };
        WithdrawalStateMachine::complete_for_tests(approval, confirmation, timing)
    }

    /// An auditor over an in-memory store, with both cursors two hours past
    /// `hashi_approval`.
    pub fn auditor_with(cfg: &Config, metrics: Arc<MonitorMetrics>) -> Auditor {
        let cursor = hashi_approval().timestamp_secs + 7_200;
        Auditor {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            rpc_pollers: RpcPollers::for_tests(cfg, cursor),
            metrics,
            store: SnapshotStore::in_memory(),
            last_successful_pool_check: None,
            last_snapshot_save: cursor,
            hbtc_supply_above_pool_since: None,
        }
    }

    #[tokio::test]
    async fn a_restart_resumes_the_open_flows_and_the_pool() {
        let cfg = Config::for_tests();
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        let deposit = ConfirmedDeposit {
            deposit_id: DepositId::new(txid(1), 0),
            amount: 1_000,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            block_time: 1_700_000_000,
        };
        assert!(auditor.utxo_pool.add_deposit(&deposit).is_none());
        // An approval the guardian never signed: its E2 is overdue.
        auditor.ingest_batch(vec![MonitorEvent::Withdrawal(hashi_approval())]);
        auditor.tick_state_checks().await;
        let missing = auditor.detect_timing_violations();
        assert!(matches!(
            missing[..],
            [MonitorFinding::WithdrawalEventMissing {
                event_type: WithdrawalEventType::E2GuardianApproved,
                ..
            }]
        ));

        let snapshot = auditor.store.load().await.unwrap().unwrap();
        assert_eq!(snapshot.pool, *auditor.utxo_pool());
        let mut resumed = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        resumed.restore(snapshot.state);

        assert_eq!(resumed.detect_timing_violations(), missing);
    }

    #[tokio::test]
    async fn a_snapshot_not_saved_within_its_limit_is_stale() {
        let mut auditor = auditor_with(&Config::for_tests(), Arc::new(MonitorMetrics::new()));
        auditor.last_snapshot_save = 1_000;

        assert_eq!(auditor.stale_snapshot(1_000 + SNAPSHOT_STALE_LIMIT), None);
        assert_eq!(
            auditor.stale_snapshot(1_000 + SNAPSHOT_STALE_LIMIT + 1),
            Some(MonitorFinding::SnapshotStale {
                last_saved: 1_000,
                limit_secs: SNAPSHOT_STALE_LIMIT,
            })
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
