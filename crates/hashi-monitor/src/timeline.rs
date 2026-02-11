use bitcoin::Txid;

use crate::audit::AuditWindow;
use crate::config::BtcConfig;
use crate::config::Config;
use crate::domain::E1SuiInit;
use crate::domain::E2GuardianApproved;
use crate::domain::E3SuiApproved;
use crate::domain::Finding;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

/// Per-withdrawal timeline.
#[derive(Clone, Debug, Default)]
pub struct Timeline {
    e1: Option<E1SuiInit>,
    e2: Option<E2GuardianApproved>,
    e3: Option<E3SuiApproved>,
}

/// Mental model: events in [t1, t2] start obligations.
///      - Safety checks are always done.
///      - Liveness checks are only done if the successor happens before the horizon.
impl Timeline {
    /// Build a timeline from events and run audit checks.
    pub fn new_audit(
        events: Vec<WithdrawalEvent>,
        window: &AuditWindow,
        cfg: &Config,
    ) -> Vec<Finding> {
        let mut timeline = Self::default();
        let mut findings = Vec::new();
        for ev in events {
            if let Some(f) = timeline.push(ev) {
                findings.push(f);
            }
        }
        findings.extend(timeline.e1_checks(window, cfg));
        findings.extend(timeline.e2_checks(window, cfg));
        findings.extend(timeline.e3_checks(window, cfg));
        findings
    }

    fn push(&mut self, ev: WithdrawalEvent) -> Option<Finding> {
        match ev {
            WithdrawalEvent::SuiInit(e1) => {
                if let Some(old) = &self.e1 {
                    return Some(duplicate_finding(
                        WithdrawalEvent::SuiInit(e1),
                        WithdrawalEvent::SuiInit(old.clone()),
                    ));
                }
                self.e1 = Some(e1);
            }
            WithdrawalEvent::GuardianApproved(e2) => {
                if let Some(old) = &self.e2 {
                    return Some(duplicate_finding(
                        WithdrawalEvent::GuardianApproved(e2),
                        WithdrawalEvent::GuardianApproved(old.clone()),
                    ));
                }
                self.e2 = Some(e2);
            }
            WithdrawalEvent::SuiApproved(e3) => {
                if let Some(old) = &self.e3 {
                    return Some(duplicate_finding(
                        WithdrawalEvent::SuiApproved(e3),
                        WithdrawalEvent::SuiApproved(old.clone()),
                    ));
                }
                self.e3 = Some(e3);
            }
        }
        None
    }

    fn e1_checks(&self, window: &AuditWindow, cfg: &Config) -> Vec<Finding> {
        let Some(e1) = &self.e1 else { return vec![] };
        if !window.contains(e1.timestamp) {
            return vec![];
        }
        let mut out = Vec::new();
        // Liveness: E1 -> E2
        let deadline = e1.timestamp.saturating_add(cfg.e1_e2_delay_secs);
        if deadline <= window.guardian_horizon && !self.has_e2_by(deadline) {
            out.push(Finding::LivenessMissingSuccessor(WithdrawalEvent::SuiInit(
                e1.clone(),
            )));
        }
        out
    }

    fn e2_checks(&self, window: &AuditWindow, cfg: &Config) -> Vec<Finding> {
        let Some(e2) = &self.e2 else { return vec![] };
        if !window.contains(e2.timestamp) {
            return vec![];
        }
        let mut out = Vec::new();
        // Safety: E2 requires E1 predecessor
        if self.e1.is_none() {
            out.push(Finding::SafetyMissingPredecessor(
                WithdrawalEvent::GuardianApproved(e2.clone()),
            ));
        }
        // Liveness: E2 -> E3
        let deadline = e2.timestamp.saturating_add(cfg.e2_e3_delay_secs);
        if deadline <= window.sui_horizon && !self.has_e3_with_txid_by(e2.btc_txid, deadline) {
            out.push(Finding::LivenessMissingSuccessor(
                WithdrawalEvent::GuardianApproved(e2.clone()),
            ));
        }
        out
    }

    fn e3_checks(&self, window: &AuditWindow, cfg: &Config) -> Vec<Finding> {
        let Some(e3) = &self.e3 else { return vec![] };
        if !window.contains(e3.timestamp) {
            return vec![];
        }
        let observed = WithdrawalEvent::SuiApproved(e3.clone());
        let mut out = Vec::new();
        // Safety: E3 requires E2 predecessor
        if self.e2.is_none() {
            out.push(Finding::SafetyMissingPredecessor(observed));
            return out;
        }
        // Safety: E3.txid must match E2.txid
        if let Some(e2) = &self.e2
            && e2.btc_txid != e3.btc_txid
        {
            out.push(Finding::InternalError {
                observed,
                other: WithdrawalEvent::GuardianApproved(e2.clone()),
                details: format!("txid mismatch for wid: e3_txid={}", e3.btc_txid),
            });
        }
        // Liveness: E3 -> BTC broadcast
        let deadline = e3.timestamp.saturating_add(cfg.e3_e4_delay_secs);
        if deadline <= window.btc_horizon && !check_if_btc_txid_exists(&e3.btc_txid, &cfg.btc) {
            out.push(Finding::LivenessMissingSuccessor(
                WithdrawalEvent::SuiApproved(e3.clone()),
            ));
        }
        out
    }

    fn has_e2_by(&self, deadline: UnixSeconds) -> bool {
        self.e2.as_ref().is_some_and(|e2| e2.timestamp <= deadline)
    }

    fn has_e3_with_txid_by(&self, txid: Txid, deadline: UnixSeconds) -> bool {
        self.e3
            .as_ref()
            .is_some_and(|e3| e3.btc_txid == txid && e3.timestamp <= deadline)
    }
}

fn duplicate_finding(observed: WithdrawalEvent, other: WithdrawalEvent) -> Finding {
    Finding::InternalError {
        observed,
        other,
        details: "duplicate event for same wid".to_string(),
    }
}

fn check_if_btc_txid_exists(_txid: &Txid, _cfg: &BtcConfig) -> bool {
    // TODO: query BTC RPC to check if txid exists (panic upon error)
    true
}
