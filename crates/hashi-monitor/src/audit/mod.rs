// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor core, driven by the continuous auditor.
//!
//! Why it exists: the continuous auditor decides when to poll. The core
//! reads the sources and judges the flows. It holds one state machine per
//! pending withdrawal and per pending deposit request.
//!
//! How it works:
//! 1. The Sui and guardian pollers return events, and the core ingests each
//!    one into its withdrawal's or deposit's state machine. A contradictory
//!    event is reported and dropped. A `DepositApproved` whose request has
//!    no open machine is checked against the UTXO pool at once.
//! 2. Each tick, the core looks up on Bitcoin every machine that expects a
//!    Bitcoin event, and ingests the confirmations it finds.
//! 3. Each tick, the core reports the timing violations of every
//!    withdrawal machine: the expected events whose deadline a cursor has
//!    passed. A deposit machine reports its own findings at its Bitcoin
//!    lookups.
//! 4. Complete flows are added to the UTXO pool: it takes the UTXOs they
//!    moved, and the flows are dropped. Closed deposit machines are
//!    dropped too.
//! 5. The UTXO pool check asks Bitcoin about every held UTXO. A spend no
//!    followed withdrawal explains is a suspect, judged at a later state
//!    check once the Sui cursor is past the time Bitcoin was asked.
//! 6. `state` gives the pollers' positions and the open machines for the
//!    snapshot. A restart builds the core again from that state.
//!
//! Assumptions:
//! - The first run starts at the bridge's genesis, so no flow began before
//!   the pollers' start.

use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::WithdrawalEventType;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;

pub mod continuous;
pub mod pool;

use crate::config::Config;
use crate::findings::FindingCategory;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::btc::checked_confirmation_threshold;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiEventsPoller;
use crate::rpc::sui::package_genesis;
use crate::rpc::sui::read_confirmation_threshold;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
use crate::store::AuditState;
use bitcoin::OutPoint;
use bitcoin::Txid;
pub use continuous::ContinuousAuditor;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use pool::SuspectSpend;
use pool::UtxoPool;
use sui_sdk_types::Address;

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

pub struct AuditorCore {
    // immutable
    cfg: Config,
    // mutable
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
}

impl AuditorCore {
    /// Resume from a snapshot's `state`, or start a first run at the
    /// bridge's genesis: the transaction that published the Hashi package.
    pub async fn new(
        cfg: &Config,
        state: Option<AuditState>,
        utxo_pool: UtxoPool,
    ) -> anyhow::Result<Self> {
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
        let mut core = Self {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool,
            suspect_spends: HashMap::new(),
            guardian_poller,
            sui_poller,
            btc_client: BtcRpcClient::new(cfg, confirmations)?,
        };
        if let Some(state) = state {
            core.restore(state);
        }
        Ok(core)
    }

    /// The pollers' positions, the open machines and the suspect spends, for
    /// the snapshot.
    pub fn state(&self, last_findings: BTreeMap<String, UnixSeconds>) -> AuditState {
        AuditState {
            sui_next_checkpoint: self.sui_poller.next_checkpoint(),
            guardian_cursor: self.guardian_cursor(),
            withdrawals: self.pending_withdrawals.values().cloned().collect(),
            deposits: self.pending_deposits.values().cloned().collect(),
            suspect_spends: self.suspect_spends.clone().into_iter().collect(),
            last_findings,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::BtcConfirmation;
    use crate::domain::DepositId;
    use crate::rpc::btc::MAINNET_MIN_CONFIRMATIONS;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::rpc::sui::tests::poller_scanned;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;
    use crate::test_utils::withdrawal_tx;
    use crate::timing::Timing;
    use bitcoin::Amount;
    use bitcoin::TxOut;

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
    async fn auditor_with_pool() -> AuditorCore {
        let cfg = Config::for_tests();
        let approved_at = hashi_approval().timestamp_secs;
        AuditorCore {
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            utxo_pool: UtxoPool::default(),
            suspect_spends: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::for_tests(&cfg, approved_at),
            sui_poller: poller_scanned(approved_at),
            btc_client: BtcRpcClient::new(&cfg, MAINNET_MIN_CONFIRMATIONS).unwrap(),
            cfg,
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
}
