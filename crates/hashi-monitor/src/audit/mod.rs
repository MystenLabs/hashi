// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor monitors bridge events and reports findings.
//!
//! Why it exists:
//! - The monitor checks deposits, withdrawals, and unspent transaction outputs (UTXOs).
//! - Metrics provide findings and source progress for alerts.
//!
//! How it works:
//! 1. Restore the source positions, flow machines, UTXO pool, and finding times from a snapshot.
//! 2. Without a snapshot, start at the bridge genesis with an empty pool.
//! 3. Read Sui events and guardian logs into the flow machines.
//! 4. Check Bitcoin confirmations, then add completed flows to the pool before the next source poll.
//! 5. Check the pool at startup and `UTXO_CHECK_INTERVAL` seconds after the last successful check.
//! 6. Judge suspect spends after the Sui cursor passes the Bitcoin lookup time.
//! 7. Report timing violations and save snapshots every `STATE_TICK_INTERVAL`.
//!
//! Assumptions:
//! - Sui must retain the required history at startup.
//! - Source failures are temporary. The next source tick retries the operation.

use crate::config::Config;
use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::WithdrawalEventType;
use crate::findings::FindingCategory;
use crate::findings::MonitorFinding;
use crate::metrics::MonitorMetrics;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SNAPSHOT;
use crate::metrics::SOURCE_SUI;
use crate::metrics::SOURCE_UTXO;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::btc::checked_confirmation_threshold;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiEventsPoller;
use crate::rpc::sui::package_genesis;
use crate::rpc::sui::read_confirmation_threshold;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
use crate::store::AuditState;
use crate::store::Snapshot;
use crate::store::SnapshotStore;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use bitcoin::OutPoint;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use pool::SuspectSpend;
use pool::UtxoPool;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;

pub mod pool;

/// How often Sui is polled. A deposit approval must reach the monitor
/// early in Move's delay before the mint, ten minutes by default.
const SUI_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// How often Bitcoin is asked about the pending transactions. An approval
/// is reported unbacked at the second empty lookup after it, so with
/// `SUI_POLL_INTERVAL` the alert comes within five minutes of it.
const BTC_POLL_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How often the guardian's log is polled. The withdrawal bounds are hours.
const GUARDIAN_POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long after a successful pool check the next one is due, in seconds.
/// Every tick runs on the one audit task, so a check delays the polls by
/// the time its batched lookups take.
const UTXO_CHECK_INTERVAL: u64 = 24 * 60 * 60;

/// How often the state checks run.
const STATE_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The UTXOs held longest that the daily check logs, for a look at the
/// pool's age without the findings.
const OLDEST_UTXOS_LOGGED: usize = 20;

pub fn log_findings(source: &'static str, phase: &'static str, findings: &[MonitorFinding]) {
    for finding in findings.iter() {
        let category = finding.category();
        match category {
            FindingCategory::Safety => tracing::error!(
                source,
                phase,
                %category,
                total = findings.len(),
                finding = %finding,
                "monitor finding"
            ),
            FindingCategory::Liveness => tracing::warn!(
                source,
                phase,
                %category,
                total = findings.len(),
                finding = %finding,
                "monitor finding"
            ),
        }
    }
}

pub struct Auditor {
    cfg: Config,
    pending_withdrawals: HashMap<WithdrawalID, WithdrawalStateMachine>,
    /// Deposit requests Bitcoin is still asked about. Keyed by the Sui
    /// request id, so a repeated event is ignored and each request has its
    /// own.
    pending_deposits: HashMap<Address, DepositStateMachine>,
    /// The UTXOs the bridge holds, by Bitcoin's account. See `pool`. The
    /// snapshot keeps it between runs.
    utxo_pool: UtxoPool,
    /// Spends waiting for the Sui cursor, by outpoint.
    suspect_spends: HashMap<OutPoint, SuspectSpend>,
    guardian_poller: GuardianWithdrawalsPoller,
    sui_poller: SuiEventsPoller,
    btc_client: BtcRpcClient,
    metrics: Arc<MonitorMetrics>,
    /// Where the snapshot is kept between runs.
    store: SnapshotStore,
    /// When the last successful pool check started. `None` until one
    /// succeeds in this run.
    last_pool_check: Option<UnixSeconds>,
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
        let (guardian_start, sui_start) = match &state {
            Some(state) => (state.guardian_cursor, state.sui_next_checkpoint),
            None => {
                let genesis = package_genesis(&cfg.sui).await?;
                tracing::info!(
                    genesis = %utc_timestamp(genesis.timestamp),
                    genesis_checkpoint = genesis.checkpoint,
                    "first run: starting at the bridge's genesis with an empty UTXO pool"
                );
                (genesis.timestamp, genesis.checkpoint)
            }
        };
        let mut guardian_poller = GuardianWithdrawalsPoller::new(cfg, guardian_start).await?;
        let (hashi_btc_keys, hashi_object_id) = guardian_poller
            .read_hashi_identity(cfg.deployment.bitcoin_network)
            .await?;
        let confirmations = checked_confirmation_threshold(
            read_confirmation_threshold(&cfg.sui, hashi_object_id).await?,
            cfg.deployment.bitcoin_network,
        )?;
        tracing::info!(confirmations, "read Hashi's Bitcoin confirmation threshold");
        let sui_poller = SuiEventsPoller::new(&cfg.sui, hashi_btc_keys, sui_start)?;
        let mut auditor = Self {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: pool,
            suspect_spends: HashMap::new(),
            guardian_poller,
            sui_poller,
            btc_client: BtcRpcClient::new(cfg, confirmations)?,
            metrics,
            store,
            last_pool_check: None,
        };
        if let Some(state) = state {
            auditor.restore(state);
        }
        // A pruned start leaves the pool incomplete.
        auditor.ensure_sui_serves_start().await?;
        auditor
            .metrics
            .set_checked_through(SOURCE_SUI, auditor.sui_cursor());
        auditor
            .metrics
            .set_checked_through(SOURCE_GUARDIAN, auditor.guardian_cursor());
        // Check write access at startup. A missing bucket loads as empty.
        auditor
            .store
            .save(&auditor.cfg, auditor.state(), auditor.utxo_pool())
            .await?;
        auditor
            .metrics
            .set_checked_through(SOURCE_SNAPSHOT, now_timestamp_secs());
        Ok(auditor)
    }

    /// The pollers' positions, the open machines and the suspect spends, for
    /// the snapshot.
    fn state(&self) -> AuditState {
        AuditState {
            sui_next_checkpoint: self.sui_poller.next_checkpoint(),
            guardian_cursor: self.guardian_cursor(),
            withdrawals: self.pending_withdrawals.values().cloned().collect(),
            deposits: self.pending_deposits.values().cloned().collect(),
            suspect_spends: self.suspect_spends.clone().into_iter().collect(),
            last_findings: self.metrics.last_findings(),
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
    }

    /// The inputs of every withdrawal the monitor follows. It spends them
    /// on Bitcoin before its flow completes, so a spend of one is explained.
    fn pending_inputs(&self) -> HashSet<OutPoint> {
        self.pending_withdrawals
            .values()
            .flat_map(|sm| sm.tx().inputs.iter())
            .map(|input| OutPoint {
                txid: Txid::from(input.id.txid),
                vout: input.id.vout,
            })
            .collect()
    }

    /// Ask Bitcoin about every UTXO held in the UTXO pool and return the
    /// findings. The spends the pool cannot explain are kept as suspects
    /// for `judge_suspect_spends`.
    pub fn check_utxo_pool(&mut self) -> anyhow::Result<Vec<MonitorFinding>> {
        self.btc_client.ensure_synced()?;
        let pool = &self.utxo_pool;
        let outpoints = pool.outpoints();
        tracing::info!(utxos = outpoints.len(), "starting UTXO pool check");
        // Before the lookups, so a withdrawal committed during them still
        // waits for the Sui cursor.
        let now = now_timestamp_secs();
        let oldest = pool.oldest(OLDEST_UTXOS_LOGGED);
        let oldest_lines = oldest
            .iter()
            .map(|(outpoint, utxo)| {
                format!(
                    "\n  age={:.1}d first_seen={} amount={} origin={:?} outpoint={}",
                    now.saturating_sub(utxo.first_seen) as f64 / 86_400.0,
                    utc_timestamp(utxo.first_seen),
                    utxo.amount,
                    utxo.origin,
                    outpoint,
                )
            })
            .collect::<String>();
        tracing::info!(
            listed = oldest.len(),
            held = pool.len(),
            "the UTXOs held longest, by block time:{oldest_lines}"
        );
        let states = self.btc_client.lookup_outpoint_states(&outpoints)?;
        let (findings, suspects) = pool.check(&states, now, &self.cfg.timing);
        tracing::info!(
            utxos = outpoints.len(),
            findings = findings.len(),
            suspects = suspects.len(),
            "finished UTXO pool check"
        );
        // A suspect already waiting keeps its earlier time.
        for (outpoint, suspect) in suspects {
            self.suspect_spends.entry(outpoint).or_insert(suspect);
        }
        Ok(findings)
    }

    /// Judge the spends the pool check saw. One is unexpected once the Sui
    /// cursor is past the time Bitcoin was asked and still no withdrawal
    /// explains it: every withdrawal committed before that time is known
    /// by then. A withdrawal explains a spend when it names the UTXO as an
    /// input, or when the pool took it and recorded the UTXO spent since.
    /// Until the cursor is past, the suspect waits.
    pub fn judge_suspect_spends(&mut self) -> Vec<MonitorFinding> {
        let named = self.pending_inputs();
        let taken = |outpoint: &OutPoint| self.utxo_pool.is_spent(outpoint);
        let sui_cursor = self.sui_cursor();
        let mut findings = Vec::new();
        let mut judged = Vec::new();
        for (outpoint, suspect) in &self.suspect_spends {
            if sui_cursor <= suspect.asked_at {
                continue;
            }
            judged.push(*outpoint);
            if named.contains(outpoint) || taken(outpoint) {
                tracing::info!(%outpoint, "a withdrawal explains the spend the pool check saw");
            } else {
                findings.push(MonitorFinding::UtxoUnexpectedSpend {
                    outpoint: *outpoint,
                    amount: suspect.amount,
                });
            }
        }
        for outpoint in judged {
            self.suspect_spends.remove(&outpoint);
        }
        findings
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

    /// Pings Bitcoin RPC for all relevant withdrawals & deposits.
    /// Returns domain findings and bubbles up infra errors. `started_at` is
    /// taken before the lookups, so the machines record it as their check time.
    pub fn fetch_btc_info(
        &mut self,
        started_at: UnixSeconds,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        self.btc_client.ensure_synced()?;
        // A "not confirmed yet" answer goes stale. A confirmed one is kept
        // until no flow names its txid.
        self.btc_client.forget_unconfirmed();
        let withdrawal_count = self
            .pending_withdrawals
            .values()
            .filter(|sm| sm.expects(WithdrawalEventType::E3BtcConfirmed))
            .count();
        let deposit_count = self
            .pending_deposits
            .values()
            .filter(|sm| sm.expects_btc())
            .count();
        let unique_txids = self
            .pending_withdrawals
            .values()
            .filter(|sm| sm.expects(WithdrawalEventType::E3BtcConfirmed))
            .map(WithdrawalStateMachine::btc_txid)
            .chain(
                self.pending_deposits
                    .values()
                    .filter(|sm| sm.expects_btc())
                    .map(DepositStateMachine::btc_txid),
            )
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        tracing::info!(
            withdrawal_count,
            deposit_count,
            unique_txids = unique_txids.len(),
            "starting bitcoin confirmation lookups"
        );
        self.btc_client.prefetch_confirmations(&unique_txids)?;
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values_mut() {
            findings.extend(sm.try_fetch_btc_tx(&self.cfg.timing, &self.btc_client, started_at)?);
        }

        for sm in self.pending_deposits.values_mut() {
            findings.extend(sm.try_fetch_btc_tx(&self.cfg.timing, &self.btc_client, started_at)?);
        }

        Ok(findings)
    }

    /// Remove the deposit machines that closed since the last call. Returns
    /// the deposits Bitcoin confirmed, for the pool.
    fn take_closed_deposits(&mut self) -> Vec<ConfirmedDeposit> {
        let closed = self
            .pending_deposits
            .iter()
            .filter(|(_, sm)| sm.is_ready_for_gc())
            .map(|(request_id, _)| *request_id)
            .collect::<Vec<_>>();
        let mut deposits = Vec::new();
        for request_id in closed {
            let sm = self
                .pending_deposits
                .remove(&request_id)
                .expect("closed request is pending");
            let deposit_id = sm.deposit_id();
            let deposit = sm.into_confirmed();
            match &deposit {
                Some(deposit) => tracing::info!(
                    deposit_id = %deposit.deposit_id,
                    amount = deposit.amount,
                    block_time = %utc_timestamp(deposit.block_time),
                    "deposit request confirmed on Bitcoin at a bridge address"
                ),
                // Bitcoin answered without a UTXO, or the request lapsed.
                None => tracing::debug!(
                    %request_id,
                    %deposit_id,
                    "deposit request closed without a UTXO"
                ),
            }
            deposits.extend(deposit);
        }
        deposits
    }

    /// The complete withdrawals: the ones the UTXO pool takes.
    fn complete_withdrawals(&self) -> Vec<ConfirmedWithdrawal> {
        self.pending_withdrawals
            .values()
            .filter(|sm| sm.is_ready_for_gc())
            .filter_map(|sm| sm.confirmed().cloned())
            .collect()
    }

    pub fn detect_timing_violations(&self) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values() {
            findings.extend(sm.timing_violations(&self.cursors()));
        }
        findings
    }

    /// Add every complete flow to the UTXO pool, then drop it:
    /// the pool takes the UTXOs the flow moved. A closed deposit machine is
    /// dropped too; it judged its `DepositApproved` when it closed. The pool
    /// takes
    /// every deposit before any withdrawal, and a withdrawal's change before
    /// its inputs, so the order the flows completed in does not matter.
    /// Call it right after the Bitcoin lookups and before any other poll:
    /// Bitcoin confirms a withdrawal only after the flows that made its
    /// inputs, and one round of lookups answers them all, so the inputs
    /// enter the pool before the withdrawal spends them. Sui and the
    /// guardian order the flows the same way: Move lets a withdrawal lock
    /// only a UTXO an earlier event brought in, and the leader has the
    /// guardian sign withdrawals one at a time, oldest first. A withdrawal that
    /// never completes never reaches the pool: its inputs stay held, and
    /// the daily check reports them once they are too old, on top of the
    /// finding for its missing event.
    pub fn add_to_pool_and_gc(&mut self) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        let confirmed_deposits = self.take_closed_deposits();
        let confirmed_withdrawals = self.complete_withdrawals();
        for deposit in &confirmed_deposits {
            findings.extend(self.utxo_pool.add_deposit(deposit));
        }
        findings.extend(self.utxo_pool.add_withdrawals(&confirmed_withdrawals));

        self.pending_withdrawals.retain(|wid, sm| {
            if !sm.is_ready_for_gc() {
                return true;
            }
            let e1 = sm
                .get(WithdrawalEventType::E1HashiApproved)
                .expect("completed withdrawal has E1");
            let e2 = sm
                .get(WithdrawalEventType::E2GuardianApproved)
                .expect("completed withdrawal has E2");
            let e3 = sm
                .get(WithdrawalEventType::E3BtcConfirmed)
                .expect("completed withdrawal has E3");
            tracing::info!(
                %wid,
                e1_at = %utc_timestamp(e1.timestamp_secs),
                e2_at = %utc_timestamp(e2.timestamp_secs),
                e3_at = %utc_timestamp(e3.timestamp_secs),
                e1_to_e2 = %human_timestamp_delta(e2.timestamp_secs, e1.timestamp_secs),
                e2_to_e3 = %human_timestamp_delta(e3.timestamp_secs, e2.timestamp_secs),
                "withdrawal flow is complete"
            );
            false
        });

        findings
    }

    /// The open withdrawals whose first event is the earliest, for the
    /// progress log. An operator sees what the audit still waits for.
    pub fn oldest_open_withdrawals(&self) -> String {
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

    /// The number of open withdrawal and deposit machines.
    pub fn open_flows(&self) -> (usize, usize) {
        (self.pending_withdrawals.len(), self.pending_deposits.len())
    }

    /// Advance the Guardian cursor by one hourly S3 directory. Callers may loop
    /// to catch up multiple directories in one tick.
    pub async fn poll_guardian(&mut self) -> anyhow::Result<PollOutcome> {
        self.guardian_poller.poll_one_hour().await
    }

    /// The newest checkpoint the Sui node serves.
    pub async fn latest_sui_checkpoint(&mut self) -> anyhow::Result<u64> {
        self.sui_poller.latest_checkpoint().await
    }

    /// Scan Sui up to checkpoint `up_to`, inclusive, one bounded range at a time.
    /// Callers may loop to catch up.
    pub async fn poll_sui(&mut self, up_to: u64) -> anyhow::Result<PollOutcome> {
        self.sui_poller.poll(up_to).await
    }

    /// Fail unless the Sui node still serves the start. See
    /// `SuiEventsPoller::ensure_start_is_served`.
    pub async fn ensure_sui_serves_start(&mut self) -> anyhow::Result<()> {
        self.sui_poller.ensure_start_is_served().await
    }

    pub fn utxo_pool(&self) -> &UtxoPool {
        &self.utxo_pool
    }

    fn cursors(&self) -> Cursors {
        Cursors {
            sui: self.sui_cursor(),
            guardian: self.guardian_cursor(),
        }
    }

    fn sui_cursor(&self) -> UnixSeconds {
        self.sui_poller.cursor_seconds()
    }

    fn guardian_cursor(&self) -> UnixSeconds {
        self.guardian_poller.cursor_seconds()
    }

    /// Save the snapshot. A failed save is logged and does not stop the
    /// audit; the next state check saves again. Alerting watches the time
    /// of the last good save.
    async fn save_snapshot(&self) {
        let saved = self
            .store
            .save(&self.cfg, self.state(), self.utxo_pool())
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

    /// Log the outcome of one source's initial catch-up. A failure does not
    /// stop the audit: the source's next tick retries it.
    fn log_initial_catch_up(source: &'static str, result: anyhow::Result<()>) {
        match result {
            Ok(()) => tracing::info!(source, "finished initial catch-up"),
            Err(error) => tracing::warn!(source, ?error, "initial catch-up failed; continuing"),
        }
    }

    async fn tick_sui(&mut self) -> anyhow::Result<()> {
        // The head at the tick's start bounds the tick, so it ends.
        let up_to = self.latest_sui_checkpoint().await?;
        while let PollOutcome::CursorAdvanced { events, findings } = self.poll_sui(up_to).await? {
            self.report_findings("sui", &findings);
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_SUI, self.sui_cursor());
        }
        Ok(())
    }

    async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        while let PollOutcome::CursorAdvanced { events, findings } = self.poll_guardian().await? {
            self.report_findings("guardian", &findings);
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_GUARDIAN, self.guardian_cursor());
        }
        Ok(())
    }

    /// Fails if the Bitcoin RPC fails.
    fn tick_utxo_check(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.check_utxo_pool()?;
        self.report_findings(SOURCE_UTXO, &findings);
        self.metrics.set_checked_through(SOURCE_UTXO, started_at);
        self.last_pool_check = Some(started_at);
        Ok(())
    }

    /// Whether a pool check is due at `now`: none has succeeded in this run,
    /// or the last one started `UTXO_CHECK_INTERVAL` ago or more.
    fn pool_check_due(&self, now: UnixSeconds) -> bool {
        self.last_pool_check
            .is_none_or(|last| now.saturating_sub(last) >= UTXO_CHECK_INTERVAL)
    }

    /// Fails if the Bitcoin RPC fails. The complete flows are added to the
    /// UTXO pool here, right after the lookups and before any other poll, so
    /// the pool sees a withdrawal's inputs enter before the withdrawal
    /// spends them: Bitcoin confirms a withdrawal only after the deposits
    /// and withdrawals that made its inputs, and one round of lookups
    /// answers them all.
    fn tick_btc(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.fetch_btc_info(started_at)?;
        self.report_findings("btc", &findings);
        self.metrics.set_checked_through(SOURCE_BTC, started_at);
        let pool_findings = self.add_to_pool_and_gc();
        self.report_findings("pool", &pool_findings);
        // After the pool update, so the check sees the flows that completed.
        if self.pool_check_due(started_at)
            && let Err(error) = self.tick_utxo_check()
        {
            tracing::warn!(
                source = SOURCE_UTXO,
                ?error,
                "UTXO pool check failed; retrying at the next Bitcoin tick"
            );
        }
        Ok(())
    }

    async fn tick_state_checks(&mut self) {
        let violations = self.detect_timing_violations();
        self.report_findings("timing", &violations);
        let spends = self.judge_suspect_spends();
        self.report_findings(SOURCE_UTXO, &spends);

        let (withdrawals, deposits) = self.open_flows();
        tracing::info!(
            "continuous progress checkpoint:\n  guardian_cursor={}\n  sui_cursor={}\n  open_withdrawals={}\n  open_deposits={}\n  oldest_withdrawals={}",
            utc_timestamp(self.guardian_cursor()),
            utc_timestamp(self.sui_cursor()),
            withdrawals,
            deposits,
            self.oldest_open_withdrawals(),
        );
        self.save_snapshot().await;
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tracing::info!(
            "starting continuous audit:\n  sui_start={}\n  guardian_start={}",
            utc_timestamp(self.sui_cursor()),
            utc_timestamp(self.guardian_cursor()),
        );
        let sui = self.tick_sui().await;
        Self::log_initial_catch_up(SOURCE_SUI, sui);
        let guardian = self.tick_guardian().await;
        Self::log_initial_catch_up(SOURCE_GUARDIAN, guardian);
        // The first Bitcoin tick also runs the first pool check.
        let btc = self.tick_btc();
        Self::log_initial_catch_up(SOURCE_BTC, btc);
        self.tick_state_checks().await;

        let mut sui_ticker = tokio::time::interval(SUI_POLL_INTERVAL);
        let mut guardian_ticker = tokio::time::interval(GUARDIAN_POLL_INTERVAL);
        let mut btc_ticker = tokio::time::interval(BTC_POLL_INTERVAL);
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
    use crate::rpc::btc::BtcRpcClient;
    use crate::rpc::btc::MAINNET_MIN_CONFIRMATIONS;
    use crate::rpc::guardian::GuardianWithdrawalsPoller;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::rpc::sui::tests::poller_scanned;
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
    async fn auditor_with_pool() -> Auditor {
        let cfg = Config::for_tests();
        let approved_at = hashi_approval().timestamp_secs;
        Auditor {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, approved_at),
            sui_poller: poller_scanned(approved_at),
            btc_client: BtcRpcClient::new(&cfg, MAINNET_MIN_CONFIRMATIONS).unwrap(),
            cfg,
            metrics: Arc::new(MonitorMetrics::new()),
            store: SnapshotStore::in_memory(),
            last_pool_check: None,
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
    fn complete_withdrawal(
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

    #[tokio::test]
    async fn a_complete_withdrawal_spending_an_input_no_flow_names_is_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let unknown = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![unknown], &timing),
        );

        let findings = auditor.add_to_pool_and_gc();

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: unknown,
                txid: txid(7),
            }]
        );
        assert!(auditor.pending_withdrawals.is_empty());
    }

    #[tokio::test]
    async fn a_suspect_spend_waits_while_the_sui_cursor_is_not_past_its_time() {
        let mut auditor = auditor_with_pool().await;
        let cursor = auditor.sui_cursor();
        let outpoint = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                asked_at: cursor,
                amount: 5_000,
            },
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.contains_key(&outpoint));
    }

    #[tokio::test]
    async fn a_suspect_spend_is_unexpected_once_the_sui_cursor_is_past_its_time() {
        let mut auditor = auditor_with_pool().await;
        let cursor = auditor.sui_cursor();
        let outpoint = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                asked_at: cursor - 1,
                amount: 5_000,
            },
        );

        let findings = auditor.judge_suspect_spends();

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnexpectedSpend {
                outpoint,
                amount: 5_000,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_suspect_spend_a_withdrawal_names_is_cleared_without_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let cursor = auditor.sui_cursor();
        // `withdrawal_tx` spends `txid(0x51):1`.
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                asked_at: cursor - 1,
                amount: 5_000,
            },
        );
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![outpoint], &timing),
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_suspect_spend_the_pool_took_a_withdrawal_for_is_cleared_without_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let cursor = auditor.sui_cursor();
        // `withdrawal_tx` spends `txid(0x51):1`.
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                asked_at: cursor - 1,
                amount: 5_000,
            },
        );
        // The withdrawal completed after the check: the pool took it, and
        // the auditor no longer follows it.
        let withdrawal = complete_withdrawal(7, 7, vec![outpoint], &timing);
        let pool = &mut auditor.utxo_pool;
        assert!(
            pool.add_deposit(&ConfirmedDeposit {
                deposit_id: DepositId::new(txid(0x51), 1),
                amount: 5_000,
                script_pubkey: p2wpkh(0x55),
                block_time: 900,
            })
            .is_none()
        );
        assert!(
            pool.add_withdrawals(&[withdrawal.confirmed().cloned().unwrap()])
                .is_empty()
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.is_empty());
    }

    /// An auditor over an in-memory store, with both cursors two hours past
    /// `hashi_approval`.
    fn auditor_with(cfg: &Config, metrics: Arc<MonitorMetrics>) -> Auditor {
        let cursor = hashi_approval().timestamp_secs + 7_200;
        Auditor {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::for_tests(cfg, cursor),
            sui_poller: poller_scanned(cursor),
            btc_client: BtcRpcClient::new(cfg, MAINNET_MIN_CONFIRMATIONS).unwrap(),
            metrics,
            store: SnapshotStore::in_memory(),
            last_pool_check: None,
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
        let metrics = Arc::new(MonitorMetrics::new());
        metrics.restore_last_findings(&snapshot.state.last_findings);
        let mut resumed = auditor_with(&cfg, metrics);
        resumed.restore(snapshot.state);

        assert_eq!(resumed.detect_timing_violations(), missing);
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

    #[tokio::test]
    async fn a_pool_check_is_due_until_one_succeeds_and_a_day_after() {
        let cfg = Config::for_tests();
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        assert!(auditor.pool_check_due(1_000));

        auditor.last_pool_check = Some(1_000);
        assert!(!auditor.pool_check_due(1_000 + UTXO_CHECK_INTERVAL - 1));
        assert!(auditor.pool_check_due(1_000 + UTXO_CHECK_INTERVAL));
    }
}
