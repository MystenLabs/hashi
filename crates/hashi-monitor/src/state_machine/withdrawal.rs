// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The state machine that follows one withdrawal through its three events.
//!
//! Why it exists: the withdrawal's events come from three sources at
//! different times and in any order. The machine joins them by withdrawal id
//! and judges each pair of neighbors by the timing bounds, so the auditors
//! need not know the order the sources were read in.
//!
//! How it works:
//! 1. The first event creates the machine. The machine expects the event's
//!    missing neighbors, each by a deadline: a predecessor by the event's
//!    time plus the predecessor's skew, a successor by the event's time plus
//!    the successor's delay.
//! 2. A later event is checked against the machine's wid, txid and
//!    transaction. A contradiction is reported and the event is dropped.
//! 3. A consistent event is kept. It is judged against each neighbor the
//!    machine has seen, and it removes itself from the expected events.
//! 4. The auditor looks the transaction up on Bitcoin while E3 is expected,
//!    and asks for violations each tick: an expected event whose deadline the
//!    source's cursor has passed is reported missing.
//!
//! Invariants:
//! - `expected_events` never holds an event type in `seen_events`.
//! - Findings are returned to the caller and not kept. A complete machine
//!   may have reported findings earlier.

use crate::domain::ConfirmedWithdrawal;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::WithdrawalTx;
use crate::findings::EventRelation;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::state_machine::BtcFetchOutcome;
use crate::timing::Timing;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// The events seen and still expected for one withdrawal. See the module
/// doc for how an event is added and judged.
pub struct WithdrawalStateMachine {
    /// The events seen so far, at most one per type.
    seen_events: Vec<MonitorWithdrawalEvent>,
    /// Each `(event, deadline, relation)` entry means `event` is expected by
    /// `deadline`; `relation` records whether it precedes or follows an event
    /// already observed for this withdrawal.
    expected_events: Vec<(WithdrawalEventType, UnixSeconds, EventRelation)>,
    /// The time of the last Bitcoin lookup of the transaction.
    btc_checked_at: Option<UnixSeconds>,
    /// The withdrawal for the UTXO pool, once Bitcoin confirmed it.
    confirmed: Option<ConfirmedWithdrawal>,
    /// The withdrawal id. Every event must carry it.
    wid: WithdrawalID,
    /// The transaction id. Every event must carry it.
    btc_txid: Txid,
    /// The inputs and outputs stated by the first event seen. Every later
    /// event must state the same.
    tx: WithdrawalTx,
}

impl WithdrawalStateMachine {
    /// A machine holding `event`. The first event cannot produce a finding.
    pub fn new(event: MonitorWithdrawalEvent, timing: &Timing) -> Self {
        let mut sm = Self {
            seen_events: Vec::new(),
            expected_events: Vec::new(),
            btc_checked_at: None,
            confirmed: None,
            wid: event.wid,
            btc_txid: event.btc_txid,
            tx: event.tx.clone(),
        };
        assert!(
            sm.add_event(event, timing).is_empty(),
            "first event cannot produce a finding"
        );
        sm
    }

    pub fn get(&self, event_type: WithdrawalEventType) -> Option<&MonitorWithdrawalEvent> {
        self.seen_events
            .iter()
            .find(|event| event.event_type == event_type)
    }

    pub fn btc_txid(&self) -> Txid {
        self.btc_txid
    }

    /// The withdrawal's inputs and outputs, as every event states them.
    pub fn tx(&self) -> &WithdrawalTx {
        &self.tx
    }

    /// The withdrawal for the UTXO pool, or `None` until Bitcoin confirmed it.
    pub fn confirmed(&self) -> Option<&ConfirmedWithdrawal> {
        self.confirmed.as_ref()
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    pub fn expects(&self, event_type: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _, _)| *event == event_type)
    }

    /// Is the Hashi approval still missing after the Sui cursor passed its deadline?
    pub fn is_missing_hashi_approval(&self, cursors: &Cursors) -> bool {
        self.expected_events
            .iter()
            .any(|(event_type, deadline, _)| {
                *event_type == WithdrawalEventType::E1HashiApproved && *deadline <= cursors.sui
            })
    }

    /// Are any expected neighboring events still outstanding?
    ///
    /// This does not mean that no timing finding was emitted during ingestion.
    /// Callers must ensure `is_since()` is true before using this for
    /// garbage collection. Out-of-window withdrawals with pending expectations
    /// may remain in memory, but they arise only from the bounded lookback or
    /// lookahead ranges.
    pub fn is_expecting_events(&self) -> bool {
        !self.expected_events.is_empty()
    }

    pub fn expected_event_types(&self) -> Vec<WithdrawalEventType> {
        self.expected_events
            .iter()
            .map(|(event_type, _, _)| *event_type)
            .collect()
    }

    /// Whether any seen event is at or after `window_start`.
    pub fn is_since(&self, window_start: UnixSeconds) -> bool {
        self.seen_events
            .iter()
            .any(|e| e.timestamp_secs >= window_start)
    }

    /// The time of the earliest event seen.
    pub fn earliest_event_at(&self) -> UnixSeconds {
        self.seen_events
            .iter()
            .map(|e| e.timestamp_secs)
            .min()
            .expect("a machine holds its first event")
    }

    /// Add an event and update expectations for its immediate neighbors.
    /// The auditor adds E1 and E2 as it reads Sui and the guardian log.
    /// `try_fetch_btc_tx` adds E3 from Bitcoin's confirmation.
    ///
    /// A missing predecessor is expected by the event timestamp plus the
    /// predecessor's clock skew; a missing successor is expected by the
    /// event timestamp plus the successor's delay. A neighbor already seen is
    /// checked against the pair's deadlines, so findings do not depend on
    /// ingestion order.
    ///
    /// Event retention is based on structural validity, not finding category.
    /// `MonitorFinding::InvalidEventAdded` denotes a contradictory, definite
    /// safety issue, so it is returned immediately without storing the event.
    /// A structurally valid event is stored and updates subsequent expectations
    /// even when its timing produces a safety or liveness finding.
    ///
    /// The return value contains every resulting finding. An empty vector means
    /// the event was accepted without one.
    pub fn add_event(
        &mut self,
        new_event: MonitorWithdrawalEvent,
        timing: &Timing,
    ) -> Vec<MonitorFinding> {
        if let Some(existing_event) = self.get(new_event.event_type) {
            return if *existing_event == new_event {
                Vec::new()
            } else {
                vec![MonitorFinding::InvalidEventAdded(
                    "duplicate event for same wid with different contents".to_string(),
                )]
            };
        }

        if self.wid != new_event.wid {
            return vec![MonitorFinding::InvalidEventAdded("invalid wid".to_string())];
        }

        if self.btc_txid != new_event.btc_txid {
            return vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string(),
            )];
        }

        let mut timing_findings = Vec::new();
        // The txid pins the inputs and outputs, but not which outputs Sui
        // calls change. Sui's and the guardian's statements must be equal,
        // else a committee can label a payout to itself as change.
        if new_event.tx != self.tx {
            let (sui, guardian) = match new_event.event_type {
                WithdrawalEventType::E1HashiApproved => (new_event.tx.clone(), self.tx.clone()),
                _ => (self.tx.clone(), new_event.tx.clone()),
            };
            timing_findings.push(MonitorFinding::WithdrawalMismatch {
                wid: self.wid,
                sui,
                guardian,
            });
        }
        if let Some(predecessor_event_type) = new_event.event_type.predecessor() {
            match self.get(predecessor_event_type) {
                Some(predecessor) => timing_findings.extend(neighbor_timing_findings(
                    predecessor,
                    &new_event,
                    timing,
                )),
                None => self.expected_events.push((
                    predecessor_event_type,
                    timing.predecessor_deadline(&new_event),
                    EventRelation::Predecessor,
                )),
            }
        }
        if let Some(successor_event_type) = new_event.event_type.successor() {
            match self.get(successor_event_type) {
                Some(successor) => {
                    timing_findings.extend(neighbor_timing_findings(&new_event, successor, timing))
                }
                None => self.expected_events.push((
                    successor_event_type,
                    timing.successor_deadline(&new_event),
                    EventRelation::Successor,
                )),
            }
        }

        // remove any previously stored expected events
        self.expected_events
            .retain(|(src, _, _)| *src != new_event.event_type);
        // add to seen events
        self.seen_events.push(new_event);
        timing_findings
    }

    /// If expecting BTC confirmation, query BTC RPC and add the event if confirmed.
    ///     - Returns `Ok(BtcFetchOutcome::NotExpected)` if a BTC event is not expected.
    ///     - Returns `Ok(BtcFetchOutcome::Unconfirmed)` if checked but block not yet mined.
    ///     - Returns `Ok(BtcFetchOutcome::Confirmed(findings))` if confirmed; `findings` may be empty.
    ///     - Returns `Err` for BTC RPC/infrastructure failures.
    pub fn try_fetch_btc_tx(
        &mut self,
        timing: &Timing,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.expects(WithdrawalEventType::E3BtcConfirmed) {
            return Ok(BtcFetchOutcome::NotExpected);
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid)?;
        self.btc_checked_at = Some(now_timestamp_secs());
        Ok(match confirmation {
            Some(confirmation) => {
                let e_btc = MonitorWithdrawalEvent::from_btc(
                    &confirmation,
                    self.wid,
                    self.btc_txid,
                    self.tx.clone(),
                );
                // E3 is expected only after E2, so E2 is present here. The
                // pool takes the change layout from E2, the guardian's word.
                let e2 = self
                    .get(WithdrawalEventType::E2GuardianApproved)
                    .expect("E3 is expected only after E2");
                self.confirmed = Some(ConfirmedWithdrawal::from_confirmation(e2, confirmation));
                BtcFetchOutcome::Confirmed(self.add_event(e_btc, timing))
            }
            None => BtcFetchOutcome::Unconfirmed,
        })
    }

    /// Check for violations given per-source cursors.
    /// Only reports a missing event if its deadline has passed relative to the relevant cursor.
    /// Callers must ensure is_since() is true before calling this function.
    pub fn violations(&self, cursors: &Cursors) -> Vec<MonitorFinding> {
        let mut out = Vec::new();
        for (event_type, deadline, relation) in &self.expected_events {
            let cursor = match event_type {
                WithdrawalEventType::E3BtcConfirmed => match self.btc_checked_at {
                    Some(checked_at) => checked_at,
                    None => {
                        // Bitcoin and state checks have independent schedules.
                        // Wait for the first lookup before evaluating absence.
                        continue;
                    }
                },
                _ => cursors.for_event_type(*event_type),
            };
            if *deadline <= cursor {
                out.push(MonitorFinding::ExpectedEventMissing {
                    event_id: MonitorEventId::Withdrawal(self.wid),
                    event_type: MonitorEventType::Withdrawal(*event_type),
                    relation: *relation,
                    deadline: *deadline,
                    cursor,
                });
            }
        }
        out
    }
}

/// Both timing bounds between consecutive events.
fn neighbor_timing_findings(
    predecessor: &MonitorWithdrawalEvent,
    successor: &MonitorWithdrawalEvent,
    timing: &Timing,
) -> Vec<MonitorFinding> {
    let mut findings = Vec::new();
    let deadline = timing.successor_deadline(predecessor);
    if deadline < successor.timestamp_secs {
        findings.push(MonitorFinding::EventOccurredAfterDeadline {
            event: MonitorEvent::Withdrawal(successor.clone()),
            relation: EventRelation::Successor,
            deadline,
            occurred_at: successor.timestamp_secs,
        });
    }
    let deadline = timing.predecessor_deadline(successor);
    if deadline < predecessor.timestamp_secs {
        findings.push(MonitorFinding::EventOccurredAfterDeadline {
            event: MonitorEvent::Withdrawal(predecessor.clone()),
            relation: EventRelation::Predecessor,
            deadline,
            occurred_at: predecessor.timestamp_secs,
        });
    }
    findings
}

#[cfg(test)]
impl WithdrawalStateMachine {
    /// A complete machine: `approval` as E1, the same a minute later as
    /// E2, and `confirmation` as E3, with no timing finding.
    pub fn complete_for_tests(
        approval: MonitorWithdrawalEvent,
        confirmation: crate::domain::BtcConfirmation,
        timing: &Timing,
    ) -> Self {
        let e2 = MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            timestamp_secs: approval.timestamp_secs + 60,
            ..approval.clone()
        };
        let e3 = MonitorWithdrawalEvent::from_btc(
            &confirmation,
            approval.wid,
            approval.btc_txid,
            approval.tx.clone(),
        );
        let mut sm = Self::new(approval, timing);
        assert!(sm.add_event(e2.clone(), timing).is_empty());
        assert!(sm.add_event(e3, timing).is_empty());
        sm.confirmed = Some(ConfirmedWithdrawal::from_confirmation(&e2, confirmation));
        assert!(!sm.is_expecting_events());
        sm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingCategory;
    use crate::test_utils::test_hashi_btc_keys;
    use crate::test_utils::txid;
    use crate::test_utils::withdrawal_tx;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::witness_program_from_address;

    fn event(
        source: WithdrawalEventType,
        wid_seed: u8,
        timestamp: UnixSeconds,
        fill: u8,
    ) -> MonitorWithdrawalEvent {
        MonitorWithdrawalEvent {
            event_type: source,
            wid: WithdrawalID::new([wid_seed; 32]),
            timestamp_secs: timestamp,
            btc_txid: txid(fill),
            tx: withdrawal_tx(bridge_program(&change_path())),
        }
    }

    fn change_path() -> DerivationPath {
        DerivationPath::new([0x42; 32])
    }

    /// The bridge address of `path` as a witness program.
    fn bridge_program(path: &DerivationPath) -> Vec<u8> {
        witness_program_from_address(&test_hashi_btc_keys().address(Some(path))).unwrap()
    }

    #[test]
    fn add_event_rejects_duplicate_source() {
        let timing = Timing::for_tests();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
            &timing,
        );

        let findings = sm.add_event(
            event(WithdrawalEventType::E1HashiApproved, 1, 110, 1),
            &timing,
        );
        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "duplicate event for same wid with different contents".to_string()
            )]
        );

        let wid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 2, 120, 1),
            &timing,
        );
        assert_eq!(
            wid_findings,
            vec![MonitorFinding::InvalidEventAdded("invalid wid".to_string())]
        );

        let txid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2),
            &timing,
        );
        assert_eq!(
            txid_findings,
            vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string()
            )]
        );
    }

    #[test]
    fn in_order_flow_completes() {
        let timing = Timing::for_tests();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 9, 100, 7),
            &timing,
        );
        assert!(sm.expects(WithdrawalEventType::E2GuardianApproved));

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
                &timing,
            )
            .is_empty()
        );
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7),
                &timing
            )
            .is_empty()
        );

        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn add_event_records_event_past_deadline() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &timing,
        );
        let event = event(WithdrawalEventType::E2GuardianApproved, 4, 201, 4);

        let findings = sm.add_event(event.clone(), &timing);
        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(event),
                relation: EventRelation::Successor,
                deadline: 200,
                occurred_at: 201,
            }]
        );
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());
        assert!(!sm.expects(WithdrawalEventType::E2GuardianApproved));
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));
    }

    #[test]
    fn add_event_records_all_timing_findings() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &timing,
        );
        let btc_confirmed = event(WithdrawalEventType::E3BtcConfirmed, 4, 600, 4);
        assert!(sm.add_event(btc_confirmed.clone(), &timing).is_empty());

        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 4, 311, 4);
        let findings = sm.add_event(guardian_approval.clone(), &timing);

        assert_eq!(
            findings,
            vec![
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(guardian_approval),
                    relation: EventRelation::Successor,
                    deadline: 200,
                    occurred_at: 311,
                },
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(btc_confirmed),
                    relation: EventRelation::Successor,
                    deadline: 511,
                    occurred_at: 600,
                },
            ]
        );
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn timing_findings_do_not_depend_on_ingestion_order() {
        let timing = Timing::for_tests();
        let late = |event: &MonitorWithdrawalEvent, relation, deadline| {
            MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(event.clone()),
                relation,
                deadline,
                occurred_at: event.timestamp_secs,
            }
        };

        // The last two cases have a block time before the guardian signature,
        // within and past E2's clock skew.
        for (approved_at, signed_at, confirmed_at) in [
            (100, 150, 300),
            (100, 200, 400),
            (100, 201, 300),
            (100, 400_000, 400_100),
            (110, 100, 300),
            (111, 100, 301),
            (100, 150, 120),
            (100, 150, 119),
        ] {
            let events = [
                event(WithdrawalEventType::E1HashiApproved, 5, approved_at, 5),
                event(WithdrawalEventType::E2GuardianApproved, 5, signed_at, 5),
                event(WithdrawalEventType::E3BtcConfirmed, 5, confirmed_at, 5),
            ];
            let [approval, signature, confirmation] = &events;
            let mut expected = Vec::new();
            if signed_at > approved_at + 100 {
                expected.push(late(signature, EventRelation::Successor, approved_at + 100));
            }
            if approved_at > signed_at + 10 {
                expected.push(late(approval, EventRelation::Predecessor, signed_at + 10));
            }
            if confirmed_at > signed_at + 200 {
                expected.push(late(
                    confirmation,
                    EventRelation::Successor,
                    signed_at + 200,
                ));
            }
            if signed_at > confirmed_at + 30 {
                expected.push(late(
                    signature,
                    EventRelation::Predecessor,
                    confirmed_at + 30,
                ));
            }

            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let mut sm = WithdrawalStateMachine::new(events[order[0]].clone(), &timing);
                let findings: Vec<_> = order[1..]
                    .iter()
                    .flat_map(|&i| sm.add_event(events[i].clone(), &timing))
                    .collect();
                assert_eq!(findings.len(), expected.len(), "{order:?}: {findings:?}");
                assert!(
                    expected.iter().all(|finding| findings.contains(finding)),
                    "{order:?}: {findings:?}"
                );
                assert!(!sm.is_expecting_events(), "{order:?}");
            }
        }
    }

    #[test]
    fn violations_only_after_cursor_passes_deadline() {
        let timing = Timing::for_tests();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 5),
            &timing,
        );

        let no_violation = sm.violations(&Cursors {
            sui: 0,
            guardian: 199,
        });
        assert!(no_violation.is_empty());

        let violations = sm.violations(&Cursors {
            sui: 0,
            guardian: 200,
        });
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorFinding::ExpectedEventMissing {
                event_id: MonitorEventId::Withdrawal(WithdrawalID::new([1; 32])),
                event_type: MonitorEventType::Withdrawal(WithdrawalEventType::E2GuardianApproved),
                relation: EventRelation::Successor,
                deadline: 200,
                cursor: 200,
            }
        );
    }

    #[test]
    fn hashi_approval_is_missing_once_the_sui_cursor_passes_its_deadline() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E2GuardianApproved, 7, 100, 7),
            &timing,
        );
        let cursors = |sui| Cursors {
            sui,
            guardian: 1_000,
        };

        assert!(!sm.is_missing_hashi_approval(&cursors(109)));
        assert!(sm.is_missing_hashi_approval(&cursors(110)));

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E1HashiApproved, 7, 10, 7),
                &timing
            )
            .is_empty()
        );
        assert!(!sm.is_missing_hashi_approval(&cursors(1_000)));
        assert!(sm.violations(&cursors(1_000)).is_empty());
    }

    #[test]
    fn a_late_or_mismatched_hashi_approval_is_a_safety_finding() {
        let timing = Timing::for_tests();
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 8, 100, 8);

        let mut late = WithdrawalStateMachine::new(guardian_approval.clone(), &timing);
        let approval = event(WithdrawalEventType::E1HashiApproved, 8, 111, 8);
        let findings = late.add_event(approval.clone(), &timing);
        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(approval),
                relation: EventRelation::Predecessor,
                deadline: 110,
                occurred_at: 111,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);

        let mut mismatched = WithdrawalStateMachine::new(guardian_approval, &timing);
        let findings = mismatched.add_event(
            event(WithdrawalEventType::E1HashiApproved, 8, 50, 9),
            &timing,
        );
        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string()
            )]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        assert!(mismatched.is_missing_hashi_approval(&Cursors {
            sui: 110,
            guardian: 1_000,
        }));
    }

    #[test]
    fn a_guardian_approval_past_its_skew_after_the_block_time_is_a_safety_finding() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 6, 100, 6),
            &timing,
        );
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 6, 150, 6);
        assert!(sm.add_event(guardian_approval.clone(), &timing).is_empty());

        let findings = sm.add_event(
            event(WithdrawalEventType::E3BtcConfirmed, 6, 119, 6),
            &timing,
        );

        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(guardian_approval),
                relation: EventRelation::Predecessor,
                deadline: 149,
                occurred_at: 150,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn backfill_e1_outside_window_e2_inside_is_still_valid() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 31, 90, 1),
            &timing,
        );

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 31, 100, 1),
                &timing,
            )
            .is_empty()
        );
        assert!(sm.is_since(100));

        let findings = sm.violations(&Cursors {
            sui: 1_000,
            guardian: 1_000,
        });

        assert!(findings.is_empty());
    }

    #[test]
    fn e1_inside_window_without_e2_is_in_scope() {
        let timing = Timing::for_tests();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 88, 120, 2),
            &timing,
        );

        assert!(sm.is_since(100));
    }

    #[test]
    fn equal_transactions_from_sui_and_the_guardian_have_no_finding() {
        let timing = Timing::for_tests();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        let e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &timing);
        assert!(sm.add_event(e2.clone(), &timing).is_empty());

        // The check runs in either ingestion order.
        let mut sm = WithdrawalStateMachine::new(e2, &timing);
        assert!(sm.add_event(e1, &timing).is_empty());
    }

    #[test]
    fn a_change_output_not_paying_the_guardians_path_is_a_safety_finding() {
        let timing = Timing::for_tests();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        let mut e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);
        e2.tx = withdrawal_tx(bridge_program(&DerivationPath::new([0x43; 32])));
        let expected = vec![MonitorFinding::WithdrawalMismatch {
            wid: e1.wid,
            sui: e1.tx.clone(),
            guardian: e2.tx.clone(),
        }];
        assert_eq!(expected[0].category(), FindingCategory::Safety);

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &timing);
        assert_eq!(sm.add_event(e2.clone(), &timing), expected);
        // The event is kept, so the flow goes on to E3.
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());

        let mut sm = WithdrawalStateMachine::new(e2, &timing);
        assert_eq!(sm.add_event(e1, &timing), expected);
    }

    #[test]
    fn an_output_sui_calls_change_and_the_guardian_calls_a_payout_is_a_safety_finding() {
        let timing = Timing::for_tests();
        // The committee pays itself at vout 1, tells Sui it is change, and
        // tells the guardian it is a user payout.
        let mut e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        e1.tx = withdrawal_tx(vec![0x54; 20]);
        let mut e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);
        e2.tx = WithdrawalTx {
            withdrawal_outputs: [
                e1.tx.withdrawal_outputs.clone(),
                e1.tx.change_outputs.clone(),
            ]
            .concat(),
            change_outputs: Vec::new(),
            ..e1.tx.clone()
        };

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &timing);
        assert_eq!(
            sm.add_event(e2.clone(), &timing),
            vec![MonitorFinding::WithdrawalMismatch {
                wid: e1.wid,
                sui: e1.tx,
                guardian: e2.tx,
            }]
        );
    }
}
