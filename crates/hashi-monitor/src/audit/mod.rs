// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Auditor implementations.
//! Goal: Attempt to match all withdrawals with a guardian event inside the input time window,
//!       even if some corresponding events for that withdrawal occur outside the window.
//! Core workflow:
//!     - User inputs a window (either just start or both start & end).
//!     - Guardian window is authoritative; Sui uses relaxed bounds for predecessor checks.
//!     - At a desired frequency, auditors do:
//!         - advance cursors
//!         - call `if wsm.is_in_audit_window() { wsm.violations(&cursors) }` to identify errors.
//!     - Currently we also report orphan E1 findings when they fall in the user window.
//!
//! Deposits are checked over the derived Sui polling range rather than gated by
//! the withdrawal audit window.

use crate::domain::Cursors;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::human_timestamp_delta;
use crate::domain::utc_timestamp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;

pub mod batch;
pub mod continuous;

use crate::config::Config;
use crate::findings::FindingCategory;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiEventsPoller;
use crate::state_machine::BtcFetchOutcome;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
pub use batch::BatchAuditor;
use bitcoin::Txid;
pub use continuous::ContinuousAuditor;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use std::fmt;

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
    guardian_approved_at: UnixSeconds,
    waiting_for: Vec<WithdrawalEventType>,
}

impl fmt::Display for WithdrawalProgressBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wid={}, btc_txid={}, guardian_approved_at={}, waiting_for={:?}",
            self.wid,
            self.btc_txid,
            utc_timestamp(self.guardian_approved_at),
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
    guardian_poller: GuardianWithdrawalsPoller,
    sui_poller: SuiEventsPoller,
    btc_client: BtcRpcClient,
}

impl AuditorCore {
    pub async fn new(cfg: &Config, cursors: Cursors) -> anyhow::Result<Self> {
        Ok(Self {
            cfg: cfg.clone(),
            pending_withdrawals: HashMap::new(),
            pending_deposits: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::new(cfg, cursors.guardian).await?,
            sui_poller: SuiEventsPoller::new(&cfg.sui, cursors.sui)?,
            btc_client: BtcRpcClient::new(cfg)?,
        })
    }

    pub fn ingest(&mut self, event: MonitorEvent) -> Vec<MonitorFinding> {
        match event {
            MonitorEvent::Withdrawal(event) => self.ingest_withdrawal(event),
            MonitorEvent::Deposit(event) => self.ingest_deposit(event),
        }
    }

    fn ingest_withdrawal(&mut self, event: MonitorWithdrawalEvent) -> Vec<MonitorFinding> {
        let wid = event.wid;
        match self.pending_withdrawals.entry(wid) {
            Entry::Occupied(mut entry) => entry.get_mut().add_event(event, &self.cfg),
            Entry::Vacant(entry) => {
                entry.insert(WithdrawalStateMachine::new(event, &self.cfg));
                Vec::new()
            }
        }
    }

    fn ingest_deposit(&mut self, event: MonitorDepositEvent) -> Vec<MonitorFinding> {
        let deposit_id = event.deposit_id;
        match self.pending_deposits.entry(deposit_id) {
            Entry::Occupied(entry) => {
                if entry.get().hashi_deposit_event() != &event {
                    return vec![MonitorFinding::InvalidEventAdded(
                        "duplicate deposit event for same outpoint with different contents"
                            .to_string(),
                    )];
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(DepositStateMachine::new(event, &self.cfg));
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
            if !sm.is_in_audit_window(window) {
                continue;
            }

            // Fetch BTC info for expecting withdrawals
            if sm.expects(WithdrawalEventType::E3BtcConfirmed)
                && let BtcFetchOutcome::Confirmed(new_findings) =
                    sm.try_fetch_btc_tx(&self.cfg, &self.btc_client)?
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

        Ok(findings)
    }

    pub fn detect_violations(&self, window: &impl AuditWindow) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values() {
            if !sm.is_in_audit_window(window) {
                continue;
            }

            // Gather all violations so far
            let violations = sm.violations(&self.get_cursors());
            if !violations.is_empty() {
                findings.extend(violations);
            }
        }
        for sm in self.pending_deposits.values() {
            let violations = sm.violations();
            if !violations.is_empty() {
                findings.extend(violations);
            }
        }
        findings
    }

    pub fn garbage_collect(&mut self, window: &impl AuditWindow) {
        let mut completed_withdrawals = Vec::new();
        for (wid, sm) in &mut self.pending_withdrawals {
            if !sm.is_in_audit_window(window) {
                continue;
            }
            if !sm.is_expecting_events() {
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
                completed_withdrawals.push(*wid);
            }
        }
        // Garbage collect
        for wid in completed_withdrawals {
            self.pending_withdrawals.remove(&wid);
        }

        let mut completed_deposits = Vec::new();
        for (deposit_id, sm) in &mut self.pending_deposits {
            if !sm.is_expecting_events() {
                tracing::debug!(%deposit_id, "deposit flow is complete");
                completed_deposits.push(*deposit_id);
            }
        }

        for deposit_id in completed_deposits {
            self.pending_deposits.remove(&deposit_id);
        }
    }

    pub fn progress_watermarks(&self, window: &impl AuditWindow) -> ProgressWatermarks {
        let mut verified_up_to_withdrawals = self.get_guardian_cursor();
        let mut withdrawal_blockers = Vec::new();
        for sm in self.pending_withdrawals.values() {
            if !sm.is_in_audit_window(window) || !sm.is_expecting_events() {
                continue;
            }

            if let Some(e2) = sm.get(WithdrawalEventType::E2GuardianApproved) {
                if e2.timestamp_secs < verified_up_to_withdrawals {
                    verified_up_to_withdrawals = e2.timestamp_secs;
                    withdrawal_blockers.clear();
                }
                if e2.timestamp_secs == verified_up_to_withdrawals {
                    withdrawal_blockers.push(WithdrawalProgressBlocker {
                        wid: sm.wid(),
                        btc_txid: sm.btc_txid(),
                        guardian_approved_at: e2.timestamp_secs,
                        waiting_for: sm.expected_event_types(),
                    });
                }
            } else {
                tracing::debug!(
                    wid = %sm.wid(),
                    "in-window withdrawal missing guardian anchor; skipping in verified_up_to computation"
                );
            }
        }

        let unresolved_deposit_floor = self
            .pending_deposits
            .values()
            .filter(|sm| sm.is_expecting_events())
            .map(|sm| sm.hashi_deposit_event().timestamp_secs)
            .min()
            .unwrap_or(u64::MAX);

        let verified_up_to_deposits = self.get_sui_cursor().min(unresolved_deposit_floor);

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

    fn get_cursors(&self) -> Cursors {
        Cursors {
            sui: self.get_sui_cursor(),
            guardian: self.get_guardian_cursor(),
        }
    }
    fn get_sui_cursor(&self) -> UnixSeconds {
        self.sui_poller.cursor_seconds()
    }

    fn get_guardian_cursor(&self) -> UnixSeconds {
        self.guardian_poller.cursor_seconds()
    }

    fn get_guardian_next_partition_ready_at(&self) -> UnixSeconds {
        self.guardian_poller.next_partition_ready_at()
    }
}
