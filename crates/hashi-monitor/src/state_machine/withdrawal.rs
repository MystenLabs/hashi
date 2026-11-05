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
//! 2. A later event is checked against the txid, an event of the same
//!    type, and the transaction. A txid or event contradiction is reported,
//!    and the event is dropped. A transaction contradiction is reported, and
//!    the event is kept.
//! 3. A kept event is judged against each neighbor the machine has seen,
//!    and it removes itself from the expected events.
//! 4. The auditor looks the transaction up on Bitcoin while E3 is expected,
//!    and asks for timing violations each tick: an expected event whose
//!    deadline the source's cursor has passed is reported missing.
//!
//! Invariants:
//! - `expected_events` never holds an event type in `seen_events`.
//! - Findings are returned to the caller and not kept. A complete machine
//!   may have reported findings earlier.

use crate::domain::Cursors;
use crate::domain::FinishedWithdrawal;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::WithdrawalTx;
use crate::findings::EventDiff;
use crate::findings::EventRelation;
use crate::findings::EventTiming;
use crate::findings::MonitorFinding;
use crate::findings::WithdrawalInvalidReason;
use crate::rpc::btc::BtcRpcClient;
use crate::timing::Timing;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;

/// The events seen and still expected for one withdrawal. See the module
/// doc for how an event is added and judged.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
    confirmed: Option<FinishedWithdrawal>,
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
    pub fn finished(&self) -> Option<&FinishedWithdrawal> {
        self.confirmed.as_ref()
    }

    /// The withdrawal Bitcoin confirmed, if any.
    pub fn into_finished(self) -> Option<FinishedWithdrawal> {
        self.confirmed
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    /// A `WithdrawalInvalid` for two events that disagree on `kind`.
    fn events_differ(
        &self,
        kind: EventDiff,
        held: &MonitorWithdrawalEvent,
        new: MonitorWithdrawalEvent,
    ) -> MonitorFinding {
        MonitorFinding::WithdrawalInvalid {
            wid: self.wid,
            reason: WithdrawalInvalidReason::EventsDiffer {
                kind,
                held: held.clone(),
                new,
            },
        }
    }

    pub fn expects(&self, event_type: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _, _)| *event == event_type)
    }

    /// Permit Bitcoin lookups only after both the Sui and guardian approvals arrive.
    /// Sui approves a withdrawal after the flows that made its inputs, so the monitor has read them.
    /// Thus every flow this one spends from is open or closed when this one closes.
    pub fn expects_btc(&self) -> bool {
        self.get(WithdrawalEventType::E1HashiApproved).is_some()
            && self.get(WithdrawalEventType::E2GuardianApproved).is_some()
            && self.expects(WithdrawalEventType::E3BtcConfirmed)
    }

    /// Whether every expected event was seen, so the pool can take the flow
    /// and the auditor can drop it.
    ///
    /// This does not mean that no timing finding was emitted during ingestion.
    pub fn is_ready_for_gc(&self) -> bool {
        self.expected_events.is_empty()
    }

    pub fn expected_event_types(&self) -> Vec<WithdrawalEventType> {
        self.expected_events
            .iter()
            .map(|(event_type, _, _)| *event_type)
            .collect()
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
    /// An event that names another txid, or repeats with other contents, gives
    /// `EventsDiffer` at once and is not stored. Every other event is stored and
    /// updates the expected events. This includes an event with other inputs or
    /// outputs (`Tx`), and an event whose timing gives a finding.
    ///
    /// The return value contains every resulting finding. An empty vector means
    /// the event was accepted without one.
    pub fn add_event(
        &mut self,
        new_event: MonitorWithdrawalEvent,
        timing: &Timing,
    ) -> Vec<MonitorFinding> {
        debug_assert_eq!(
            self.wid, new_event.wid,
            "the auditor gives each machine only its own wid"
        );
        // The first event sets `btc_txid` and `tx`, so it is the one to show.
        // The txid and tx checks always pass for the first event.
        if self.btc_txid != new_event.btc_txid {
            return vec![self.events_differ(EventDiff::Txid, &self.seen_events[0], new_event)];
        }

        if let Some(existing_event) = self.get(new_event.event_type) {
            return if *existing_event == new_event {
                Vec::new()
            } else {
                vec![self.events_differ(EventDiff::Full, existing_event, new_event)]
            };
        }

        let mut timing_findings = Vec::new();
        // The txid pins the inputs and outputs, but not which outputs Sui
        // calls change. Sui's and the guardian's statements must be equal,
        // else a committee can label a payout to itself as change.
        if new_event.tx != self.tx {
            timing_findings.push(self.events_differ(
                EventDiff::Tx,
                &self.seen_events[0],
                new_event.clone(),
            ));
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
    /// Returns the findings from the new event. An error is the RPC's.
    ///
    /// `checked_at` must be no later than the lookup.
    pub fn try_fetch_btc_tx(
        &mut self,
        timing: &Timing,
        btc_rpc_client: &BtcRpcClient,
        checked_at: UnixSeconds,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        if !self.expects_btc() {
            return Ok(Vec::new());
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid)?;
        self.btc_checked_at = Some(checked_at);
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
                self.confirmed = Some(FinishedWithdrawal::from_confirmation(e2, confirmation));
                self.add_event(e_btc, timing)
            }
            None => Vec::new(),
        })
    }

    /// Check for timing violations given per-source cursors.
    /// Only reports a missing event if its deadline has passed relative to the relevant cursor.
    pub fn timing_violations(&self, cursors: &Cursors) -> Vec<MonitorFinding> {
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
                out.push(MonitorFinding::withdrawal_timing(
                    self.wid,
                    *event_type,
                    *relation,
                    *deadline,
                    EventTiming::Missing { cursor },
                ));
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
        findings.push(late(successor, EventRelation::Successor, deadline));
    }
    let deadline = timing.predecessor_deadline(successor);
    if deadline < predecessor.timestamp_secs {
        findings.push(late(predecessor, EventRelation::Predecessor, deadline));
    }
    findings
}

/// The finding for `event`, which came after its `deadline` as the
/// `relation` of its neighbor.
fn late(
    event: &MonitorWithdrawalEvent,
    relation: EventRelation,
    deadline: UnixSeconds,
) -> MonitorFinding {
    MonitorFinding::withdrawal_timing(
        event.wid,
        event.event_type,
        relation,
        deadline,
        EventTiming::Late {
            event: event.clone(),
        },
    )
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
        sm.confirmed = Some(FinishedWithdrawal::from_confirmation(&e2, confirmation));
        assert!(sm.is_ready_for_gc());
        sm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let repeat = event(WithdrawalEventType::E1HashiApproved, 1, 110, 1);
        assert_eq!(
            sm.add_event(repeat.clone(), &timing),
            vec![MonitorFinding::WithdrawalInvalid {
                wid: WithdrawalID::new([1; 32]),
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Full,
                    held: event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
                    new: repeat,
                },
            }]
        );
        // The machine keeps the first event.
        assert_eq!(
            sm.get(WithdrawalEventType::E1HashiApproved),
            Some(&event(WithdrawalEventType::E1HashiApproved, 1, 100, 1))
        );

        // The txid check runs first, so an event that repeats with another txid is `Txid`.
        let repeat_other_txid = event(WithdrawalEventType::E1HashiApproved, 1, 100, 2);
        assert_eq!(
            sm.add_event(repeat_other_txid.clone(), &timing),
            vec![MonitorFinding::WithdrawalInvalid {
                wid: WithdrawalID::new([1; 32]),
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Txid,
                    held: event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
                    new: repeat_other_txid,
                },
            }]
        );

        let other_txid = event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2);
        assert_eq!(
            sm.add_event(other_txid.clone(), &timing),
            vec![MonitorFinding::WithdrawalInvalid {
                wid: WithdrawalID::new([1; 32]),
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Txid,
                    held: event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
                    new: other_txid,
                },
            }]
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
        assert!(!sm.expects_btc());

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
                &timing,
            )
            .is_empty()
        );
        assert!(sm.expects_btc());

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7),
                &timing
            )
            .is_empty()
        );

        assert!(sm.is_ready_for_gc());
        assert!(!sm.expects_btc());
    }

    #[test]
    fn bitcoin_lookups_wait_for_sui_after_guardian_approval() {
        let timing = Timing::for_tests();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
            &timing,
        );
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));
        assert!(!sm.expects_btc());

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E1HashiApproved, 9, 100, 7),
                &timing,
            )
            .is_empty()
        );
        assert!(sm.expects_btc());
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
        assert_eq!(findings, vec![late(&event, EventRelation::Successor, 200)]);
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());
        assert!(!sm.expects(WithdrawalEventType::E2GuardianApproved));
        assert!(sm.expects_btc());
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
                late(&guardian_approval, EventRelation::Successor, 200),
                late(&btc_confirmed, EventRelation::Successor, 511),
            ]
        );
        assert!(sm.is_ready_for_gc());
    }

    #[test]
    fn timing_findings_do_not_depend_on_ingestion_order() {
        let timing = Timing::for_tests();

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
                assert!(sm.is_ready_for_gc(), "{order:?}");
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

        let no_violation = sm.timing_violations(&Cursors {
            sui: 0,
            guardian: 199,
        });
        assert!(no_violation.is_empty());

        let violations = sm.timing_violations(&Cursors {
            sui: 0,
            guardian: 200,
        });
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorFinding::withdrawal_timing(
                WithdrawalID::new([1; 32]),
                WithdrawalEventType::E2GuardianApproved,
                EventRelation::Successor,
                200,
                EventTiming::Missing { cursor: 200 }
            )
        );

        // A missing E1 is judged by the Sui cursor.
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E2GuardianApproved, 7, 100, 7),
            &timing,
        );
        let sui = |sui| Cursors {
            sui,
            guardian: 1_000,
        };
        assert!(sm.timing_violations(&sui(109)).is_empty());
        let violations = sm.timing_violations(&sui(110));
        assert_eq!(
            violations,
            vec![MonitorFinding::withdrawal_timing(
                WithdrawalID::new([7; 32]),
                WithdrawalEventType::E1HashiApproved,
                EventRelation::Predecessor,
                110,
                EventTiming::Missing { cursor: 110 }
            )]
        );
    }

    #[test]
    fn a_late_or_missing_predecessor_is_unapproved_and_a_successor_is_stuck() {
        use WithdrawalEventType::*;
        let timing = Timing::for_tests();
        let cursors = |sui, guardian| Cursors { sui, guardian };

        // E2 at 100 expects E1 by 110.
        let signed = WithdrawalStateMachine::new(event(E2GuardianApproved, 7, 100, 7), &timing);
        let unapproved = signed.timing_violations(&cursors(110, 0))[0].clone();
        assert!(matches!(
            unapproved,
            MonitorFinding::WithdrawalUnapproved {
                event_type: E1HashiApproved,
                timing: EventTiming::Missing { cursor: 110 },
                ..
            }
        ));
        assert!(unapproved.is_essential());
        let mut signed = signed;
        assert!(matches!(
            signed.add_event(event(E1HashiApproved, 7, 111, 7), &timing)[..],
            [MonitorFinding::WithdrawalUnapproved {
                event_type: E1HashiApproved,
                timing: EventTiming::Late { .. },
                ..
            }]
        ));

        // E1 at 100 expects E2 by 200.
        let approved = WithdrawalStateMachine::new(event(E1HashiApproved, 7, 100, 7), &timing);
        let stuck = approved.timing_violations(&cursors(0, 200))[0].clone();
        assert!(matches!(
            stuck,
            MonitorFinding::WithdrawalStuck {
                event_type: E2GuardianApproved,
                timing: EventTiming::Missing { cursor: 200 },
                ..
            }
        ));
        assert!(stuck.is_essential());
        let mut approved = approved;
        let late_e2 = approved.add_event(event(E2GuardianApproved, 7, 201, 7), &timing);
        assert!(matches!(
            late_e2[..],
            [MonitorFinding::WithdrawalStuck {
                event_type: E2GuardianApproved,
                timing: EventTiming::Late { .. },
                ..
            }]
        ));
        // The late event came, so the withdrawal finished.
        assert!(!late_e2[0].is_essential());
    }

    #[test]
    fn a_late_or_mismatched_hashi_approval_is_a_finding() {
        let timing = Timing::for_tests();
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 8, 100, 8);

        let mut sm = WithdrawalStateMachine::new(guardian_approval.clone(), &timing);
        let approval = event(WithdrawalEventType::E1HashiApproved, 8, 111, 8);
        let findings = sm.add_event(approval.clone(), &timing);
        assert_eq!(
            findings,
            vec![late(&approval, EventRelation::Predecessor, 110)]
        );

        let mut mismatched = WithdrawalStateMachine::new(guardian_approval.clone(), &timing);
        let other_txid = event(WithdrawalEventType::E1HashiApproved, 8, 50, 9);
        assert_eq!(
            mismatched.add_event(other_txid.clone(), &timing),
            vec![MonitorFinding::WithdrawalInvalid {
                wid: WithdrawalID::new([8; 32]),
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Txid,
                    held: guardian_approval,
                    new: other_txid,
                },
            }]
        );
        assert!(mismatched.expects(WithdrawalEventType::E1HashiApproved));
    }

    #[test]
    fn a_guardian_approval_past_its_skew_after_the_block_time_is_a_finding() {
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
            vec![late(&guardian_approval, EventRelation::Predecessor, 149)]
        );
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
    fn a_change_output_not_paying_the_guardians_path_is_a_finding() {
        let timing = Timing::for_tests();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        let mut e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);
        e2.tx = withdrawal_tx(bridge_program(&DerivationPath::new([0x43; 32])));
        let differ = |held: &MonitorWithdrawalEvent, new: &MonitorWithdrawalEvent| {
            vec![MonitorFinding::WithdrawalInvalid {
                wid: e1.wid,
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Tx,
                    held: held.clone(),
                    new: new.clone(),
                },
            }]
        };

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &timing);
        assert_eq!(sm.add_event(e2.clone(), &timing), differ(&e1, &e2));
        // The event is kept, so the flow goes on to E3.
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());

        let mut sm = WithdrawalStateMachine::new(e2.clone(), &timing);
        assert_eq!(sm.add_event(e1.clone(), &timing), differ(&e2, &e1));
    }

    #[test]
    fn an_output_sui_calls_change_and_the_guardian_calls_a_payout_is_a_finding() {
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
            vec![MonitorFinding::WithdrawalInvalid {
                wid: e1.wid,
                reason: WithdrawalInvalidReason::EventsDiffer {
                    kind: EventDiff::Tx,
                    held: e1,
                    new: e2,
                },
            }]
        );
    }
}
