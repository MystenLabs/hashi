use crate::domain::E2GuardianApproved;
use crate::domain::E3SuiApproved;
use crate::domain::Finding;
use crate::domain::WithdrawalEvent;
use crate::store::Store;

/// Correlate all currently-unprocessed safety-relevant events.
///
/// Note: In a real deployment, you may wish to wait for a short grace period before evaluation to
/// tolerate ingestion lag across sources.
///
/// If a finding is detected, we return it as an error.
pub fn correlate_pending_safety_events(store: &dyn Store, limit: usize) -> anyhow::Result<()> {
    // (E3) => (E2)
    for e3 in store.list_unprocessed_e3(limit) {
        if let Some(finding) = check_safety_for_e3(store, &e3) {
            return Err(anyhow::anyhow!(finding));
        }
        store.mark_e3_processed(&e3);
    }

    // (E2) => (E1)
    for e2 in store.list_unprocessed_e2(limit) {
        if let Some(finding) = check_safety_for_e2(store, &e2) {
            return Err(anyhow::anyhow!(finding));
        }
        store.mark_e2_processed(&e2);
    }

    Ok(())
}

fn check_safety_for_e3(store: &dyn Store, e3: &E3SuiApproved) -> Option<Finding> {
    // Safety: if we observe Sui approval (E3), we should have seen Guardian approval (E2).
    let Some(e2) = store.get_e2_by_wid(e3.wid) else {
        return Some(Finding::SafetyMissingPredecessor(
            WithdrawalEvent::SuiApproved(e3.clone()),
        ));
    };

    // Link consistency: E2 and E3 must agree on btc_txid.
    if e2.btc_txid != e3.btc_txid {
        return Some(Finding::InternalError {
            observed: WithdrawalEvent::SuiApproved(e3.clone()),
            other: WithdrawalEvent::GuardianApproved(e2.clone()),
            details: format!("txid mismatch {} {}", e2.btc_txid, e3.btc_txid),
        });
    }

    None
}

fn check_safety_for_e2(store: &dyn Store, e2: &E2GuardianApproved) -> Option<Finding> {
    // Safety: if we observe Guardian approval (E2), we should have seen Sui init (E1).
    if store.get_e1_by_wid(e2.wid).is_none() {
        return Some(Finding::SafetyMissingPredecessor(
            WithdrawalEvent::GuardianApproved(e2.clone()),
        ));
    }

    None
}
