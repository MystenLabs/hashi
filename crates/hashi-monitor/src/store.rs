use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::sync::Mutex;
use std::sync::MutexGuard;

use crate::domain::E1SuiInit;
use crate::domain::E2GuardianApproved;
use crate::domain::E3SuiApproved;
use crate::domain::E4BtcSpendFromHashi;
use crate::domain::WithdrawalEvent;
use anyhow::anyhow;
use bitcoin::Txid;
use hashi_guardian_shared::WithdrawalID;
use tracing::info;

/// A minimal storage abstraction.
///
/// This is intentionally small so we can implement a persistent backend later (fjall / sqlite / etc.)
/// with minimal churn.
///
/// Ingestor flow (TODO: unimplemented):
///     - Read BTC/Sui/S3 cursor
///     - Fetch and insert events
///     - New events are marked unprocessed
///
/// Correlator flow (correlate.rs):
///     - For each unprocessed event, perform all checks and mark it processed.
pub trait Store: Send + Sync {
    // ========================================================================
    // Ingestor Functions
    // ========================================================================

    /// Get a named cursor value (raw). A cursor represents where we left off reading from some upstream source (BTC/Sui/S3/etc.).
    fn get_cursor_raw(&self, name: &str) -> Option<String>;

    /// Set a named cursor value (raw).
    fn set_cursor_raw(&self, name: &str, value: String);

    /// Insert a withdrawal event.
    ///
    /// Semantics:
    /// - If the event key is new, we insert it.
    /// - If the same event was already inserted, this is a no-op.
    /// - If a different event with the same key was already inserted, we return an error.
    fn insert(&self, event: WithdrawalEvent) -> anyhow::Result<()>;

    // ========================================================================
    // Correlator Functions
    // ========================================================================

    /// List unprocessed (E4) events.
    fn list_unprocessed_e4(&self, limit: usize) -> Vec<E4BtcSpendFromHashi>;

    /// Mark an (E4) event as processed.
    fn mark_e4_processed(&self, event: &E4BtcSpendFromHashi);

    /// List unprocessed (E3) events.
    fn list_unprocessed_e3(&self, limit: usize) -> Vec<E3SuiApproved>;

    /// Mark an (E3) event as processed.
    fn mark_e3_processed(&self, event: &E3SuiApproved);

    /// List unprocessed (E2) events.
    fn list_unprocessed_e2(&self, limit: usize) -> Vec<E2GuardianApproved>;

    /// Mark an (E2) event as processed.
    fn mark_e2_processed(&self, event: &E2GuardianApproved);

    /// Return the (E1) event for `wid`, if any.
    fn get_e1_by_wid(&self, wid: WithdrawalID) -> Option<E1SuiInit>;

    /// Return the (E2) event for `wid`, if any.
    fn get_e2_by_wid(&self, wid: WithdrawalID) -> Option<E2GuardianApproved>;

    /// Return the (E2) event for `txid`, if any.
    fn get_e2_by_txid(&self, txid: &Txid) -> Option<E2GuardianApproved>;

    /// Return the (E3) event for `wid`, if any.
    fn get_e3_by_wid(&self, wid: WithdrawalID) -> Option<E3SuiApproved>;

    /// Return the (E3) event for `txid`, if any.
    fn get_e3_by_txid(&self, txid: &Txid) -> Option<E3SuiApproved>;
}

#[derive(Default)]
struct Inner {
    cursors: HashMap<String, String>,

    // (E1)
    e1_by_wid: HashMap<WithdrawalID, E1SuiInit>,

    // (E2)
    e2_by_wid: HashMap<WithdrawalID, E2GuardianApproved>,
    e2_by_txid: HashMap<Txid, E2GuardianApproved>,
    e2_unprocessed: HashSet<WithdrawalID>,

    // (E3)
    e3_by_wid: HashMap<WithdrawalID, E3SuiApproved>,
    e3_by_txid: HashMap<Txid, E3SuiApproved>,
    e3_unprocessed: HashSet<WithdrawalID>,

    // (E4)
    e4_by_txid: HashMap<Txid, E4BtcSpendFromHashi>,
    e4_unprocessed: HashSet<Txid>,
}

/// In-memory store implementation.
///
/// Useful for unit tests and as a placeholder while we decide on the persistent backend.
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

impl InMemoryStore {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("in-memory store mutex poisoned")
    }
}

fn conflicting_reinsert(
    kind: &str,
    key: impl std::fmt::Display,
    existing: &impl std::fmt::Debug,
    attempted: &impl std::fmt::Debug,
) -> anyhow::Error {
    anyhow!(
        "conflicting re-insert for {kind} ({key}): existing={existing:?} attempted={attempted:?}"
    )
}

impl Store for InMemoryStore {
    fn get_cursor_raw(&self, name: &str) -> Option<String> {
        self.lock().cursors.get(name).cloned()
    }

    fn set_cursor_raw(&self, name: &str, value: String) {
        self.lock().cursors.insert(name.to_owned(), value);
    }

    fn insert(&self, event: WithdrawalEvent) -> anyhow::Result<()> {
        let mut inner = self.lock();

        match event {
            WithdrawalEvent::SuiInit(init) => match inner.e1_by_wid.entry(init.wid) {
                Entry::Vacant(v) => {
                    v.insert(init);
                    Ok(())
                }
                Entry::Occupied(o) if o.get() == &init => Ok(()),
                Entry::Occupied(o) => Err(conflicting_reinsert(
                    "E1",
                    format!("wid={:?}", init.wid),
                    o.get(),
                    &init,
                )),
            },

            WithdrawalEvent::GuardianApproved(approved) => {
                if let Some(existing) = inner.e2_by_wid.get(&approved.wid) {
                    return if existing == &approved {
                        Ok(())
                    } else {
                        Err(conflicting_reinsert(
                            "E2",
                            format!("wid={:?}", approved.wid),
                            existing,
                            &approved,
                        ))
                    };
                }

                if let Some(existing) = inner.e2_by_txid.get(&approved.btc_txid) {
                    return if existing == &approved {
                        Ok(())
                    } else {
                        Err(conflicting_reinsert(
                            "E2",
                            format!("txid={:?}", approved.btc_txid),
                            existing,
                            &approved,
                        ))
                    };
                }

                inner.e2_by_wid.insert(approved.wid, approved.clone());
                inner.e2_by_txid.insert(approved.btc_txid, approved.clone());
                inner.e2_unprocessed.insert(approved.wid);
                Ok(())
            }

            WithdrawalEvent::SuiApproved(approved) => {
                if let Some(existing) = inner.e3_by_wid.get(&approved.wid) {
                    return if existing == &approved {
                        Ok(())
                    } else {
                        Err(conflicting_reinsert(
                            "E3",
                            format!("wid={:?}", approved.wid),
                            existing,
                            &approved,
                        ))
                    };
                }

                if let Some(existing) = inner.e3_by_txid.get(&approved.btc_txid) {
                    return if existing == &approved {
                        Ok(())
                    } else {
                        Err(conflicting_reinsert(
                            "E3",
                            format!("txid={:?}", approved.btc_txid),
                            existing,
                            &approved,
                        ))
                    };
                }

                inner.e3_by_wid.insert(approved.wid, approved.clone());
                inner.e3_by_txid.insert(approved.btc_txid, approved.clone());
                inner.e3_unprocessed.insert(approved.wid);
                Ok(())
            }

            WithdrawalEvent::BtcSpend(spend) => match inner.e4_by_txid.entry(spend.txid) {
                Entry::Vacant(v) => {
                    v.insert(spend.clone());
                    inner.e4_unprocessed.insert(spend.txid);
                    Ok(())
                }
                Entry::Occupied(o) if o.get() == &spend => Ok(()),
                Entry::Occupied(o) => Err(conflicting_reinsert(
                    "E4",
                    format!("txid={:?}", spend.txid),
                    o.get(),
                    &spend,
                )),
            },
        }
    }

    fn list_unprocessed_e4(&self, limit: usize) -> Vec<E4BtcSpendFromHashi> {
        let inner = self.lock();
        info!("found {} unprocessed e4 events", inner.e4_unprocessed.len());
        let mut out = Vec::new();
        for txid in inner.e4_unprocessed.iter().copied().take(limit) {
            if let Some(spend) = inner.e4_by_txid.get(&txid) {
                out.push(spend.clone());
            }
        }
        out
    }

    fn mark_e4_processed(&self, e4: &E4BtcSpendFromHashi) {
        self.lock().e4_unprocessed.remove(&e4.txid);
    }

    fn list_unprocessed_e3(&self, limit: usize) -> Vec<E3SuiApproved> {
        let inner = self.lock();
        info!("found {} unprocessed e3 events", inner.e3_unprocessed.len());
        let mut out = Vec::new();
        for wid in inner.e3_unprocessed.iter().copied().take(limit) {
            if let Some(e3) = inner.e3_by_wid.get(&wid) {
                out.push(e3.clone());
            }
        }
        out
    }

    fn mark_e3_processed(&self, e3: &E3SuiApproved) {
        self.lock().e3_unprocessed.remove(&e3.wid);
    }

    fn list_unprocessed_e2(&self, limit: usize) -> Vec<E2GuardianApproved> {
        let inner = self.lock();
        info!("found {} unprocessed e2 events", inner.e2_unprocessed.len());
        let mut out = Vec::new();
        for wid in inner.e2_unprocessed.iter().copied().take(limit) {
            if let Some(e2) = inner.e2_by_wid.get(&wid) {
                out.push(e2.clone());
            }
        }
        out
    }

    fn mark_e2_processed(&self, e2: &E2GuardianApproved) {
        self.lock().e2_unprocessed.remove(&e2.wid);
    }

    fn get_e1_by_wid(&self, wid: WithdrawalID) -> Option<E1SuiInit> {
        self.lock().e1_by_wid.get(&wid).cloned()
    }

    fn get_e2_by_wid(&self, wid: WithdrawalID) -> Option<E2GuardianApproved> {
        self.lock().e2_by_wid.get(&wid).cloned()
    }

    fn get_e2_by_txid(&self, txid: &Txid) -> Option<E2GuardianApproved> {
        self.lock().e2_by_txid.get(txid).cloned()
    }

    fn get_e3_by_wid(&self, wid: WithdrawalID) -> Option<E3SuiApproved> {
        self.lock().e3_by_wid.get(&wid).cloned()
    }

    fn get_e3_by_txid(&self, txid: &Txid) -> Option<E3SuiApproved> {
        self.lock().e3_by_txid.get(txid).cloned()
    }
}
