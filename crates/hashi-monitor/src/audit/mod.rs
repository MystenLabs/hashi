// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor core, shared by the batch and continuous auditors.
//!
//! Why it exists: both auditors read the same sources and judge the same
//! flows. They differ only in when they poll and when they stop. The core
//! holds one state machine per pending withdrawal and per pending deposit,
//! and the auditors drive it.
//!
//! How it works:
//! 1. The Sui and guardian pollers return events, and the core ingests each
//!    one into its withdrawal's or deposit's state machine. A contradictory
//!    event is reported and dropped.
//! 2. Each tick, the core looks up on Bitcoin every machine that expects a
//!    Bitcoin event, and ingests the confirmations it finds.
//! 3. A Sui approval still missing after its deadline is fetched by its
//!    withdrawal id, since the Sui scan may have started after it.
//! 4. Each tick, the core reports the violations of every machine in the
//!    audit window: the expected events whose deadline a cursor has passed.
//! 5. Complete flows retire: the UTXO pool takes the UTXOs they moved, then
//!    they are dropped.
//! 6. The progress watermarks give the time through which every flow is
//!    verified, which is where a restart starts.
//!
//! Assumptions:
//! - The user's window is on the guardian timeline. A withdrawal is in the
//!   window if any of its events is, so an orphan E1 in the window is
//!   reported too.
//! - Deposits are checked over the Sui range the window derives, not gated
//!   by the window.

use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::Cursors;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::WithdrawalEventType;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;

pub mod batch;
pub mod continuous;
pub mod pool;

use crate::config::Config;
use crate::findings::FindingCategory;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiEventsPoller;
use crate::rpc::sui::approval::HashiApproval;
use crate::state_machine::BtcFetchOutcome;
use crate::state_machine::DepositRequestStateMachine;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
pub use batch::BatchAuditor;
use bitcoin::OutPoint;
use bitcoin::Txid;
pub use continuous::ContinuousAuditor;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use pool::UtxoPool;
use std::fmt;
use sui_sdk_types::Address;

/// The UTXOs held longest that the daily check logs, for a look at the
/// pool's age without the findings.
const OLDEST_UTXOS_LOGGED: usize = 20;

pub trait AuditWindow {
    fn in_window(&self, timestamp_secs: UnixSeconds) -> bool;
}

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

#[derive(Clone, Debug)]
pub struct ProgressWatermarks {
    pub verified_up_to_withdrawals: UnixSeconds,
    pub verified_up_to_deposits: UnixSeconds,
    /// Where a restart starts. It is at or before both cursors and every
    /// pending flow in the window, so a restart reads each one again.
    pub restart_start: UnixSeconds,
    withdrawal_blockers: WithdrawalProgressBlockers,
}

impl ProgressWatermarks {
    pub fn withdrawal_blockers(&self) -> &WithdrawalProgressBlockers {
        &self.withdrawal_blockers
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalProgressBlockers(Vec<WithdrawalProgressBlocker>);

impl fmt::Display for WithdrawalProgressBlockers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((first, rest)) = self.0.split_first() else {
            return f.write_str("none");
        };

        write!(f, "{first}")?;
        for blocker in rest {
            write!(f, "; {blocker}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct WithdrawalProgressBlocker {
    wid: WithdrawalID,
    btc_txid: Txid,
    earliest_event_at: UnixSeconds,
    waiting_for: Vec<WithdrawalEventType>,
}

impl fmt::Display for WithdrawalProgressBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wid={}, btc_txid={}, earliest_event_at={}, waiting_for={:?}",
            self.wid,
            self.btc_txid,
            utc_timestamp(self.earliest_event_at),
            self.waiting_for,
        )
    }
}

pub struct AuditorCore {
    // immutable
    cfg: Config,
    // mutable
    pending_withdrawals: HashMap<WithdrawalID, WithdrawalStateMachine>,
    pending_deposits: HashMap<DepositId, DepositStateMachine>,
    /// Deposit requests Bitcoin is still asked about. Keyed by the Sui
    /// request id, so a replayed event is ignored and each request has its
    /// own.
    pending_deposit_requests: HashMap<Address, DepositRequestStateMachine>,
    /// The UTXOs the bridge holds, by Bitcoin's account. See `pool`. `None`
    /// keeps no pool: batch mode has none, and continuous mode keeps one in
    /// its snapshot.
    utxo_pool: Option<UtxoPool>,
    guardian_poller: GuardianWithdrawalsPoller,
    sui_poller: SuiEventsPoller,
    btc_client: BtcRpcClient,
}

impl AuditorCore {
    /// `utxo_pool` is the pool to keep, or `None` to keep none.
    pub async fn new(
        cfg: &Config,
        cursors: Cursors,
        utxo_pool: Option<UtxoPool>,
    ) -> anyhow::Result<Self> {
        let mut guardian_poller = GuardianWithdrawalsPoller::new(cfg, cursors.guardian).await?;
        let hashi_btc_keys = guardian_poller
            .read_hashi_btc_keys(cfg.deployment.bitcoin_network)
            .await?;
        Ok(Self {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            utxo_pool,
            guardian_poller,
            sui_poller: SuiEventsPoller::new(&cfg.sui, hashi_btc_keys, cursors.sui)?,
            btc_client: BtcRpcClient::new(cfg)?,
        })
    }

    /// Ask Bitcoin about every coin held in the UTXO pool and return the
    /// findings. Nothing when no pool is kept.
    pub fn check_utxo_pool(&self) -> anyhow::Result<Vec<MonitorFinding>> {
        let Some(pool) = &self.utxo_pool else {
            return Ok(Vec::new());
        };
        self.btc_client.ensure_synced()?;
        // A withdrawal the monitor follows spends its inputs on Bitcoin
        // before the flow completes, so those are not checked.
        let pending_inputs = self
            .pending_withdrawals
            .values()
            .flat_map(|sm| sm.tx().inputs.iter())
            .map(|input| OutPoint {
                txid: Txid::from(input.id.txid),
                vout: input.id.vout,
            })
            .collect::<HashSet<_>>();
        let outpoints = pool
            .outpoints()
            .into_iter()
            .filter(|outpoint| !pending_inputs.contains(outpoint))
            .collect::<Vec<_>>();
        tracing::info!(utxos = outpoints.len(), "starting UTXO pool check");
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
        let findings = pool.check(&states, &pending_inputs, now, &self.cfg.timing);
        tracing::info!(
            utxos = outpoints.len(),
            findings = findings.len(),
            "finished UTXO pool check"
        );
        Ok(findings)
    }

    fn ingest(&mut self, event: MonitorEvent) -> Vec<MonitorFinding> {
        match event {
            MonitorEvent::Withdrawal(event) => self.ingest_withdrawal(event),
            MonitorEvent::Deposit(event) => self.ingest_deposit(event),
            MonitorEvent::DepositRequested(event) => {
                self.ingest_deposit_request(event);
                Vec::new()
            }
        }
    }

    fn ingest_deposit_request(&mut self, event: SuiDepositRequestedEvent) {
        self.pending_deposit_requests
            .entry(event.request_id)
            .or_insert_with(|| DepositRequestStateMachine::new(event, &self.cfg.timing));
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

    fn ingest_deposit(&mut self, event: MonitorDepositEvent) -> Vec<MonitorFinding> {
        let deposit_id = event.deposit_id;
        match self.pending_deposits.entry(deposit_id) {
            Entry::Occupied(entry) => {
                if entry.get().sui_event() != &event {
                    return vec![MonitorFinding::InvalidEventAdded(
                        "duplicate deposit event for same outpoint with different contents"
                            .to_string(),
                    )];
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(DepositStateMachine::new(event, &self.cfg.timing));
            }
        }
        Vec::new()
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorEvent>) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for event in events {
            findings.extend(self.ingest(event));
        }
        findings
    }

    /// Pings Bitcoin RPC for all relevant withdrawals & deposits.
    /// Returns domain findings and bubbles up infra errors.
    pub fn fetch_btc_info(
        &mut self,
        window: &impl AuditWindow,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        self.btc_client.ensure_synced()?;
        // The cache dedupes lookups inside one pass. It is cleared because a
        // "not confirmed yet" answer goes stale.
        // TODO: keep confirmed answers across passes, and evict an entry at
        // GC once no machine names its txid. A deposit's transaction is then
        // looked up once, not once for the request and once for the
        // confirmation.
        self.btc_client.clear_confirmation_cache();
        let withdrawal_count = self
            .pending_withdrawals
            .values()
            .filter(|sm| {
                sm.is_in_audit_window(window) && sm.expects(WithdrawalEventType::E3BtcConfirmed)
            })
            .count();
        let deposit_count = self
            .pending_deposits
            .values()
            .filter(|sm| sm.is_expecting_events())
            .count();
        let deposit_request_count = self
            .pending_deposit_requests
            .values()
            .filter(|sm| sm.is_expecting_events())
            .count();
        let unique_txids = self
            .pending_withdrawals
            .values()
            .filter(|sm| {
                sm.is_in_audit_window(window) && sm.expects(WithdrawalEventType::E3BtcConfirmed)
            })
            .map(WithdrawalStateMachine::btc_txid)
            .chain(
                self.pending_deposits
                    .values()
                    .filter(|sm| sm.is_expecting_events())
                    .map(DepositStateMachine::btc_txid),
            )
            .chain(
                self.pending_deposit_requests
                    .values()
                    .filter(|sm| sm.is_expecting_events())
                    .map(DepositRequestStateMachine::btc_txid),
            )
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        tracing::info!(
            withdrawal_count,
            deposit_count,
            deposit_request_count,
            unique_txids = unique_txids.len(),
            "starting bitcoin confirmation lookups"
        );
        self.btc_client.prefetch_confirmations(&unique_txids)?;
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values_mut() {
            if !sm.is_in_audit_window(window) {
                continue;
            }

            // Fetch BTC info for expecting withdrawals
            if sm.expects(WithdrawalEventType::E3BtcConfirmed)
                && let BtcFetchOutcome::Confirmed(new_findings) =
                    sm.try_fetch_btc_tx(&self.cfg.timing, &self.btc_client)?
            {
                findings.extend(new_findings);
            }
        }

        for sm in self.pending_deposits.values_mut() {
            if sm.is_expecting_events()
                && let BtcFetchOutcome::Confirmed(new_findings) =
                    sm.try_fetch_btc_tx(&self.btc_client)?
            {
                findings.extend(new_findings);
            }
        }

        for sm in self.pending_deposit_requests.values_mut() {
            if sm.is_expecting_events() {
                sm.try_fetch_btc_tx(&self.btc_client)?;
            }
        }

        Ok(findings)
    }

    /// The deposits Bitcoin confirmed for deposit requests since the last
    /// call. Each is removed from the pending requests.
    fn take_confirmed_deposits(&mut self) -> Vec<ConfirmedDeposit> {
        let confirmed = self
            .pending_deposit_requests
            .iter()
            .filter(|(_, sm)| sm.confirmed().is_some())
            .map(|(request_id, _)| *request_id)
            .collect::<Vec<_>>();
        let deposits = confirmed
            .into_iter()
            .filter_map(|request_id| self.pending_deposit_requests.remove(&request_id))
            .filter_map(DepositRequestStateMachine::into_confirmed)
            .collect::<Vec<_>>();
        for deposit in &deposits {
            tracing::info!(
                deposit_id = %deposit.deposit_id,
                amount = deposit.amount,
                block_time = %utc_timestamp(deposit.block_time),
                "deposit request confirmed on Bitcoin at a bridge address"
            );
        }
        deposits
    }

    /// The complete withdrawals in the window the UTXO pool can take now,
    /// by wid. One waits while an input is in flight: the outpoint of a
    /// deposit request Bitcoin has not answered, or an output of a
    /// withdrawal that is not complete or that waits itself. Its inputs are
    /// not in the pool yet, and a spend of them would be a false finding.
    /// The next state check tries again. The wait is bounded: a request
    /// lapses on its own, and a withdrawal past a deadline, one with a
    /// missing-event finding, blocks nothing. Its spends then go through,
    /// and each one of its change is a finding, as a spend of an unknown
    /// UTXO.
    fn ready_withdrawals(
        &self,
        window: &impl AuditWindow,
    ) -> HashMap<WithdrawalID, ConfirmedWithdrawal> {
        let requested = self
            .pending_deposit_requests
            .values()
            .filter(|sm| sm.is_expecting_events())
            .map(|sm| OutPoint::from(sm.deposit_id()))
            .collect::<HashSet<_>>();
        let cursors = self.cursors();
        let mut blocked_txids = HashSet::new();
        let mut ready = Vec::new();
        for sm in self.pending_withdrawals.values() {
            if sm.is_expecting_events() {
                if !sm.is_in_audit_window(window) || sm.violations(&cursors).is_empty() {
                    blocked_txids.insert(sm.btc_txid());
                }
            } else if sm.is_in_audit_window(window) {
                ready.push(sm);
            }
        }
        // A withdrawal that waits blocks the withdrawals spending its change,
        // so the rounds repeat until none moves. Each round moves at least
        // one, and a chain of spends is short.
        loop {
            let (still_ready, now_waiting): (Vec<_>, Vec<_>) = ready.into_iter().partition(|sm| {
                sm.confirmed()
                    .map(|withdrawal| withdrawal.confirmation.inputs.as_slice())
                    .unwrap_or_default()
                    .iter()
                    .all(|input| !requested.contains(input) && !blocked_txids.contains(&input.txid))
            });
            ready = still_ready;
            if now_waiting.is_empty() {
                break;
            }
            blocked_txids.extend(now_waiting.iter().map(|sm| sm.btc_txid()));
        }
        ready
            .into_iter()
            .filter_map(|sm| Some((sm.wid(), sm.confirmed()?.clone())))
            .collect()
    }

    /// Fetches each overdue Hashi approval from Sui. One for the guardian's txid inside the
    /// scanned range is also a `SuiScanMissedEvent`; one whose lookup fails stays missing.
    pub async fn fetch_missing_hashi_approvals(
        &mut self,
        window: &impl AuditWindow,
    ) -> Vec<MonitorFinding> {
        let cursors = self.cursors();
        let missing = self
            .pending_withdrawals
            .values()
            .filter(|sm| sm.is_in_audit_window(window) && sm.is_missing_hashi_approval(&cursors))
            .map(|sm| (sm.wid(), sm.btc_txid()))
            .collect::<Vec<_>>();
        let mut findings = Vec::new();
        let mut approvals = Vec::new();
        for (wid, btc_txid) in missing {
            match self.sui_poller.fetch_withdrawal_approval(wid).await {
                Ok(Some(HashiApproval::Rejected(rejection))) => findings.extend(rejection),
                Ok(Some(HashiApproval::Valid(approval))) => {
                    // A contradiction, not a scan miss: the state machine rejects even a scanned one.
                    if approval.btc_txid != btc_txid {
                        findings.push(MonitorFinding::InvalidEventAdded(
                            "invalid btc_txid".to_string(),
                        ));
                        continue;
                    }
                    if self.sui_poller.has_scanned(approval.timestamp_secs) {
                        findings.push(MonitorFinding::SuiScanMissedEvent {
                            event: MonitorEvent::Withdrawal(approval.clone()),
                            cursor: cursors.sui,
                        });
                    } else {
                        tracing::info!(
                            %wid,
                            approved_at = %utc_timestamp(approval.timestamp_secs),
                            "fetched Hashi approval missing from the Sui event scan"
                        );
                    }
                    approvals.push(MonitorEvent::Withdrawal(approval));
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    source = "sui",
                    %wid,
                    ?error,
                    "Hashi approval lookup failed; reporting it missing"
                ),
            }
        }
        findings.extend(self.ingest_batch(approvals));
        findings
    }

    pub fn detect_violations(&self, window: &impl AuditWindow) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values() {
            if !sm.is_in_audit_window(window) {
                continue;
            }

            findings.extend(sm.violations(&self.cursors()));
        }
        for sm in self.pending_deposits.values() {
            findings.extend(sm.violations());
        }
        findings
    }

    /// Retire every complete flow in the window: the UTXO pool takes the
    /// UTXOs it moved, then the flow is dropped and logged. The pool takes
    /// every deposit before any withdrawal, and a withdrawal's change before
    /// its inputs, so the order the flows completed in does not matter. A
    /// complete withdrawal with an input still in flight waits, see
    /// `ready_withdrawals`. A withdrawal that never completes never reaches
    /// the pool: its inputs stay held, and the daily check reports them, on
    /// top of the finding for its missing event.
    pub fn retire_complete_flows(&mut self, window: &impl AuditWindow) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        let confirmed_deposits = self.take_confirmed_deposits();
        let ready = self.ready_withdrawals(window);
        let confirmed_withdrawals = ready.values().cloned().collect::<Vec<_>>();
        if let Some(pool) = &mut self.utxo_pool {
            for deposit in &confirmed_deposits {
                findings.extend(pool.add_deposit(deposit));
            }
            findings.extend(pool.add_withdrawals(&confirmed_withdrawals));
        }

        let waiting = self
            .pending_withdrawals
            .values()
            .filter(|sm| sm.is_in_audit_window(window) && !sm.is_expecting_events())
            .filter(|sm| !ready.contains_key(&sm.wid()))
            .count();
        if waiting > 0 {
            tracing::info!(
                waiting,
                "complete withdrawals wait for the flows that bring in their inputs"
            );
        }

        self.pending_withdrawals.retain(|wid, sm| {
            if !ready.contains_key(wid) {
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

        self.pending_deposits.retain(|deposit_id, sm| {
            if sm.is_expecting_events() {
                return true;
            }
            tracing::debug!(%deposit_id, "deposit flow is complete");
            false
        });

        // A request Bitcoin answered without a UTXO, or that lapsed. One
        // with a UTXO was taken above.
        self.pending_deposit_requests.retain(|request_id, sm| {
            if sm.is_expecting_events() {
                return true;
            }
            tracing::debug!(
                %request_id,
                deposit_id = %sm.deposit_id(),
                "deposit request closed without a UTXO"
            );
            false
        });
        findings
    }

    pub fn progress_watermarks(&self, window: &impl AuditWindow) -> ProgressWatermarks {
        let mut verified_up_to_withdrawals = self.guardian_cursor();
        let mut withdrawal_blockers = Vec::new();
        for sm in self.pending_withdrawals.values() {
            if !sm.is_in_audit_window(window) || !sm.is_expecting_events() {
                continue;
            }

            let earliest_event_at = sm.earliest_event_at();
            if earliest_event_at < verified_up_to_withdrawals {
                verified_up_to_withdrawals = earliest_event_at;
                withdrawal_blockers.clear();
            }
            if earliest_event_at == verified_up_to_withdrawals {
                withdrawal_blockers.push(WithdrawalProgressBlocker {
                    wid: sm.wid(),
                    btc_txid: sm.btc_txid(),
                    earliest_event_at,
                    waiting_for: sm.expected_event_types(),
                });
            }
        }

        // A deposit request still asked about pins the floor too, so a
        // restart replays it and its UTXO is not lost.
        let unresolved_deposit_floor = self
            .pending_deposits
            .values()
            .filter(|sm| sm.is_expecting_events())
            .map(|sm| sm.sui_event().timestamp_secs)
            .chain(
                self.pending_deposit_requests
                    .values()
                    .filter(|sm| sm.is_expecting_events())
                    .map(DepositRequestStateMachine::requested_at),
            )
            .min()
            .unwrap_or(u64::MAX);

        let verified_up_to_deposits = self.sui_cursor().min(unresolved_deposit_floor);

        ProgressWatermarks {
            verified_up_to_withdrawals,
            verified_up_to_deposits,
            restart_start: verified_up_to_withdrawals.min(verified_up_to_deposits),
            withdrawal_blockers: WithdrawalProgressBlockers(withdrawal_blockers),
        }
    }

    /// Advance the Guardian cursor by one hourly S3 directory. Callers may loop
    /// to catch up multiple directories in one tick.
    pub async fn poll_guardian(&mut self) -> anyhow::Result<PollOutcome> {
        self.guardian_poller.poll_one_hour().await
    }

    pub async fn poll_sui(&mut self, up_to: UnixSeconds) -> anyhow::Result<PollOutcome> {
        self.sui_poller.poll(up_to).await
    }

    /// Fail unless the Sui node still serves the start. See
    /// `SuiEventsPoller::ensure_start_is_served`.
    pub async fn ensure_sui_serves_start(&mut self) -> anyhow::Result<()> {
        self.sui_poller.ensure_start_is_served().await
    }

    /// The UTXO pool, if one is kept.
    pub fn utxo_pool(&self) -> Option<&UtxoPool> {
        self.utxo_pool.as_ref()
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

    fn sui_scan_start(&self) -> UnixSeconds {
        self.sui_poller.start_seconds()
    }

    fn guardian_cursor(&self) -> UnixSeconds {
        self.guardian_poller.cursor_seconds()
    }

    fn guardian_next_partition_ready_at(&self) -> UnixSeconds {
        self.guardian_poller.next_partition_ready_at()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::BtcConfirmation;
    use crate::rpc::sui::approval::tests::with_wrong_txid;
    use crate::rpc::sui::approval::tests::withdrawal_transaction;
    use crate::rpc::sui::tests::looked_up_approval;
    use crate::rpc::sui::tests::poller_scanned;
    use crate::rpc::sui::tests::poller_scanned_with;
    use crate::test_utils::confirmation;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;
    use crate::test_utils::withdrawal_tx;
    use crate::timing::Timing;
    use bitcoin::Amount;
    use bitcoin::TxOut;
    use bitcoin::hashes::Hash as _;

    struct AllTime;

    impl AuditWindow for AllTime {
        fn in_window(&self, _: UnixSeconds) -> bool {
            true
        }
    }

    /// An auditor holding a guardian approval for `btc_txid` of `looked_up_approval`'s
    /// withdrawal, whose Sui scan covered `[start, cursor)` without its E1.
    async fn auditor_missing_approval(
        start: UnixSeconds,
        cursor: UnixSeconds,
        btc_txid: Txid,
    ) -> AuditorCore {
        let cfg = Config::for_tests();
        let mut auditor = AuditorCore {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            utxo_pool: None,
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, 0),
            sui_poller: poller_scanned(start, cursor).await,
            btc_client: BtcRpcClient::new(&cfg).unwrap(),
            cfg,
        };
        let approval = looked_up_approval();
        let findings = auditor.ingest(MonitorEvent::Withdrawal(MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            timestamp_secs: approval.timestamp_secs + 7,
            btc_txid,
            ..approval
        }));
        assert!(findings.is_empty());
        auditor
    }

    #[tokio::test]
    async fn a_replayed_deposit_request_is_ingested_once() {
        let approval = looked_up_approval();
        let mut auditor = auditor_missing_approval(
            approval.timestamp_secs,
            approval.timestamp_secs,
            approval.btc_txid,
        )
        .await;
        let request = SuiDepositRequestedEvent {
            request_id: Address::new([0x61; 32]),
            timestamp_secs: approval.timestamp_secs,
            deposit_id: DepositId::new(approval.btc_txid, 0),
            amount: 1,
            script_pubkey: bitcoin::ScriptBuf::new(),
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
        assert_eq!(auditor.pending_deposit_requests.len(), 1);

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
        assert_eq!(auditor.pending_deposit_requests.len(), 2);
    }

    #[tokio::test]
    async fn an_approval_inside_the_scanned_range_is_a_scan_miss() {
        let approval = looked_up_approval();
        let cursor = approval.timestamp_secs + 3_600;
        let mut auditor =
            auditor_missing_approval(approval.timestamp_secs - 3_600, cursor, approval.btc_txid)
                .await;

        let findings = auditor.fetch_missing_hashi_approvals(&AllTime).await;

        assert_eq!(
            findings,
            vec![MonitorFinding::SuiScanMissedEvent {
                event: MonitorEvent::Withdrawal(approval),
                cursor,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        // The approval is ingested, so it is not also reported missing.
        assert!(auditor.detect_violations(&AllTime).is_empty());
    }

    #[tokio::test]
    async fn an_approval_from_before_the_scan_is_ingested_without_a_finding() {
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let mut auditor =
            auditor_missing_approval(approved_at + 1, approved_at + 3_600, approval.btc_txid).await;

        assert!(
            auditor
                .fetch_missing_hashi_approvals(&AllTime)
                .await
                .is_empty()
        );
        assert!(auditor.detect_violations(&AllTime).is_empty());
    }

    #[tokio::test]
    async fn a_looked_up_approval_with_a_wrong_txid_is_rejected() {
        let approval = looked_up_approval();
        let cursor = approval.timestamp_secs + 3_600;
        let mut auditor =
            auditor_missing_approval(approval.timestamp_secs - 3_600, cursor, approval.btc_txid)
                .await;
        let txn = with_wrong_txid(withdrawal_transaction(approval.wid));
        auditor.sui_poller =
            poller_scanned_with(txn.clone(), approval.timestamp_secs - 3_600, cursor).await;

        let findings = auditor.fetch_missing_hashi_approvals(&AllTime).await;

        assert_eq!(
            findings,
            vec![MonitorFinding::WithdrawalTxidMismatch {
                wid: approval.wid,
                claimed: txn.txid.into(),
                computed: approval.btc_txid,
            }]
        );
        // The rejected approval is not ingested, so the E1 stays missing.
        assert!(matches!(
            auditor.detect_violations(&AllTime)[..],
            [MonitorFinding::ExpectedEventMissing { .. }]
        ));
    }

    #[tokio::test]
    async fn an_approval_contradicting_the_guardian_txid_is_not_a_scan_miss() {
        let approved_at = looked_up_approval().timestamp_secs;
        let guardian_txid = Txid::from_byte_array([9; 32]);
        let mut auditor =
            auditor_missing_approval(approved_at - 3_600, approved_at + 3_600, guardian_txid).await;

        let findings = auditor.fetch_missing_hashi_approvals(&AllTime).await;

        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string()
            )]
        );
        assert!(matches!(
            auditor.detect_violations(&AllTime)[..],
            [MonitorFinding::ExpectedEventMissing { .. }]
        ));
    }

    #[tokio::test]
    async fn an_open_withdrawal_holds_the_restart_start_at_its_earliest_event() {
        let cfg = Config::for_tests();
        let approval = looked_up_approval();
        let approved_at = approval.timestamp_secs;
        let signature = MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            timestamp_secs: approved_at + 60,
            ..approval.clone()
        };
        let mut auditor = AuditorCore {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            utxo_pool: None,
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, approved_at + 7_200),
            sui_poller: poller_scanned(approved_at - 3_600, approved_at + 7_200).await,
            btc_client: BtcRpcClient::new(&cfg).unwrap(),
            cfg,
        };
        assert!(
            auditor
                .ingest_batch(vec![
                    MonitorEvent::Withdrawal(signature),
                    MonitorEvent::Withdrawal(approval),
                ])
                .is_empty()
        );

        let progress = auditor.progress_watermarks(&AllTime);

        assert_eq!(progress.restart_start, approved_at);
        assert!(matches!(
            &progress.withdrawal_blockers.0[..],
            [blocker] if blocker.earliest_event_at == approved_at
        ));
    }

    /// An auditor with an empty UTXO pool and no flows.
    async fn auditor_with_pool() -> AuditorCore {
        let cfg = Config::for_tests();
        let approved_at = looked_up_approval().timestamp_secs;
        AuditorCore {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            pending_deposit_requests: HashMap::new(),
            utxo_pool: Some(UtxoPool::default()),
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, approved_at),
            sui_poller: poller_scanned(approved_at - 3_600, approved_at).await,
            btc_client: BtcRpcClient::new(&cfg).unwrap(),
            cfg,
        }
    }

    /// The bridge script every test deposit pays.
    fn bridge_script() -> bitcoin::ScriptBuf {
        p2wpkh(0x54)
    }

    /// A pending request for the deposit at `txid(fill)` vout 1.
    fn deposit_request(fill: u8) -> SuiDepositRequestedEvent {
        SuiDepositRequestedEvent {
            request_id: Address::new([fill; 32]),
            timestamp_secs: 100,
            deposit_id: DepositId::new(txid(fill), 1),
            amount: 50_000,
            script_pubkey: bridge_script(),
        }
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

    fn change_of(fill: u8) -> OutPoint {
        OutPoint {
            txid: txid(fill),
            vout: 1,
        }
    }

    #[tokio::test]
    async fn a_complete_withdrawal_waits_for_the_deposit_request_it_spends() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let request = deposit_request(9);
        let deposit = OutPoint::from(request.deposit_id);
        auditor.ingest_deposit_request(request.clone());
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![deposit], &timing),
        );

        // Bitcoin has not answered the request: the withdrawal waits.
        assert!(auditor.retire_complete_flows(&AllTime).is_empty());
        assert_eq!(auditor.pending_withdrawals.len(), 1);
        assert!(auditor.utxo_pool.as_ref().unwrap().is_empty());

        // The answer brings the deposit in, and the withdrawal spends it.
        auditor
            .pending_deposit_requests
            .get_mut(&request.request_id)
            .unwrap()
            .record_confirmation(&confirmation(50_000, bridge_script()));
        assert!(auditor.retire_complete_flows(&AllTime).is_empty());
        assert!(auditor.pending_withdrawals.is_empty());
        assert!(auditor.pending_deposit_requests.is_empty());
        let pool = auditor.utxo_pool.as_ref().unwrap();
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
        assert_eq!(
            pool.get_spent(&deposit).map(|spent| spent.spent_by),
            Some(txid(7))
        );
    }

    #[tokio::test]
    async fn a_complete_withdrawal_waits_for_the_withdrawal_whose_change_it_spends() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let request = deposit_request(9);
        let deposit = OutPoint::from(request.deposit_id);
        auditor.ingest_deposit_request(request.clone());
        // The parent waits for the request, and the child spends its change.
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![deposit], &timing),
        );
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([8; 32]),
            complete_withdrawal(8, 8, vec![change_of(7)], &timing),
        );

        assert!(auditor.retire_complete_flows(&AllTime).is_empty());
        assert_eq!(auditor.pending_withdrawals.len(), 2);

        auditor
            .pending_deposit_requests
            .get_mut(&request.request_id)
            .unwrap()
            .record_confirmation(&confirmation(50_000, bridge_script()));
        assert!(auditor.retire_complete_flows(&AllTime).is_empty());
        assert!(auditor.pending_withdrawals.is_empty());
        let pool = auditor.utxo_pool.as_ref().unwrap();
        assert_eq!(pool.outpoints(), vec![change_of(8)]);
        assert_eq!(
            pool.get_spent(&change_of(7)).map(|spent| spent.spent_by),
            Some(txid(8))
        );
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

        let findings = auditor.retire_complete_flows(&AllTime);

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
    async fn a_complete_withdrawal_waits_for_an_open_parent_until_its_deadline() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let cursor = looked_up_approval().timestamp_secs;
        // The parent has only its guardian approval, and its E1 is not due
        // yet at the Sui cursor.
        let parent_approval = |at: UnixSeconds| MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            wid: WithdrawalID::new([7; 32]),
            timestamp_secs: at,
            btc_txid: txid(7),
            tx: withdrawal_tx(vec![0x55; 20]),
        };
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            WithdrawalStateMachine::new(parent_approval(cursor), &timing),
        );
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([8; 32]),
            complete_withdrawal(8, 8, vec![change_of(7)], &timing),
        );

        assert!(auditor.retire_complete_flows(&AllTime).is_empty());
        assert_eq!(auditor.pending_withdrawals.len(), 2);

        // The parent's E1 is overdue: it blocks nothing, and the child's
        // spend of its change is a finding.
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            WithdrawalStateMachine::new(parent_approval(cursor - 100), &timing),
        );
        let findings = auditor.retire_complete_flows(&AllTime);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: change_of(7),
                txid: txid(8),
            }]
        );
        assert_eq!(auditor.pending_withdrawals.len(), 1);
        assert_eq!(
            auditor.utxo_pool.as_ref().unwrap().outpoints(),
            vec![change_of(8)]
        );
    }
}
