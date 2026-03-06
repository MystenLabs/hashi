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

use crate::domain::Cursors;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub mod batch;
pub mod continuous;

use crate::config::Config;
use crate::errors::MonitorError;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::state_machine::BtcFetchOutcome;
use crate::state_machine::WithdrawalStateMachine;
pub use batch::BatchAuditor;
pub use continuous::ContinuousAuditor;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time_utils::UnixSeconds;

pub trait AuditWindow {
    fn in_window(&self, e: &MonitorWithdrawalEvent) -> bool;
}

pub fn log_findings(source: &'static str, phase: &'static str, findings: &[MonitorError]) {
    for finding in findings.iter() {
        tracing::error!(
            source,
            phase,
            total = findings.len(),
            ?finding,
            "monitor finding"
        );
    }
}

pub struct AuditorCore {
    // immutable
    cfg: Config,
    // mutable
    pending: HashMap<WithdrawalID, WithdrawalStateMachine>,
    guardian_poller: GuardianWithdrawalsPoller,
    btc_client: BtcRpcClient,
    // placeholder until we implement sui rpc
    sui_cursor: UnixSeconds,
}

impl AuditorCore {
    pub async fn new(cfg: &Config, cursors: Cursors) -> anyhow::Result<Self> {
        Ok(Self {
            cfg: cfg.clone(),
            pending: HashMap::new(),
            guardian_poller: GuardianWithdrawalsPoller::new(cfg, cursors.guardian).await?,
            btc_client: BtcRpcClient::new(cfg)?,
            sui_cursor: cursors.sui,
        })
    }

    pub fn ingest(&mut self, event: MonitorWithdrawalEvent) -> Option<MonitorError> {
        let wid = event.wid;
        match self.pending.entry(wid) {
            Entry::Occupied(mut entry) => {
                if let Err(e) = entry.get_mut().add_event(event, &self.cfg) {
                    return Some(e);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(WithdrawalStateMachine::new(event, &self.cfg));
            }
        }
        None
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorWithdrawalEvent>) -> Vec<MonitorError> {
        let mut errors = Vec::new();
        for event in events {
            if let Some(e) = self.ingest(event) {
                errors.push(e);
            }
        }
        errors
    }

    /// Pings Bitcoin RPC for all relevant withdrawals.
    /// Returns domain findings and bubbles up infra errors.
    pub fn fetch_btc_info(
        &mut self,
        window: &impl AuditWindow,
    ) -> anyhow::Result<Vec<MonitorError>> {
        let mut errors = Vec::new();
        for sm in self.pending.values_mut() {
            if !sm.is_in_audit_window(window) {
                continue;
            }

            // Fetch BTC info for expecting withdrawals
            if sm.expects(WithdrawalEventType::E3BtcConfirmed)
                && let BtcFetchOutcome::Confirmed(Some(e)) =
                    sm.try_fetch_btc_tx(&self.cfg, &self.btc_client)?
            {
                errors.push(e);
            }
        }

        Ok(errors)
    }

    pub fn detect_violations(&self, window: &impl AuditWindow) -> Vec<MonitorError> {
        let mut errors = Vec::new();
        for sm in self.pending.values() {
            if !sm.is_in_audit_window(window) {
                continue;
            }

            // Gather all violations so far
            let violations = sm.violations(&self.get_cursors());
            if !violations.is_empty() {
                errors.extend(violations);
            }
        }
        errors
    }

    pub fn garbage_collect(&mut self, window: &impl AuditWindow) {
        let mut completed = Vec::new();
        for (wid, sm) in &mut self.pending {
            if !sm.is_in_audit_window(window) {
                continue;
            }
            if sm.is_valid() {
                tracing::info!("withdrawal {} is valid", wid);
                completed.push(*wid);
            }
        }
        // Garbage collect
        for wid in completed {
            self.pending.remove(&wid);
        }
    }

    /// Polls one hour worth of guardian events
    /// TODO: Provide an option to poll more aggressively if we are lagging behind
    pub async fn poll_guardian(&mut self) -> anyhow::Result<PollOutcome> {
        self.guardian_poller.poll_one_hour().await
    }

    pub async fn poll_sui(&mut self) -> anyhow::Result<PollOutcome> {
        // TODO: Implement me
        Ok(PollOutcome::CursorUnmoved)
    }

    fn get_cursors(&self) -> Cursors {
        Cursors {
            sui: self.get_sui_cursor(),
            guardian: self.get_guardian_cursor(),
        }
    }
    fn get_sui_cursor(&self) -> UnixSeconds {
        self.sui_cursor
    }

    fn get_guardian_cursor(&self) -> UnixSeconds {
        self.guardian_poller.cursor_seconds()
    }
}
