// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal state machine for tracking event flow.

use crate::audit::AuditWindow;
use crate::config::Config;
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
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// A record of all the events tracking a single withdrawal.
///
/// `add_event` validates and stores an event. A structurally valid late event
/// is retained even though the method returns its timing finding.
///
/// `violations(cursors)` checks if there are any violations given current cursors
///
/// Invariant: `expected_events` should not contain an event type that exists in `seen_events`.
///
/// Four current scope/progress combinations are possible:
/// - Window: Out, In
/// - Progress: Expecting events, Complete
///
/// `is_expecting_events()` distinguishes the two progress states. Findings are
/// emitted to the caller and are not retained in the WSM, so `Complete` does not
/// mean that no earlier finding was reported.
pub struct WithdrawalStateMachine {
    /// the set of non-zero events we have seen until now related to this withdrawal.
    seen_events: Vec<MonitorWithdrawalEvent>,
    /// Each `(event, deadline, relation)` entry means `event` is expected by
    /// `deadline`; `relation` records whether it precedes or follows an event
    /// already observed for this withdrawal.
    expected_events: Vec<(WithdrawalEventType, UnixSeconds, EventRelation)>,
    /// last time at which we checked for a btc withdrawal tx
    btc_checked_at: Option<UnixSeconds>,
    /// immutable wid
    wid: WithdrawalID,
    /// immutable txid
    btc_txid: Txid,
    /// The inputs and outputs stated by the first event seen. Every later
    /// event must state the same.
    tx: WithdrawalTx,
}

impl WithdrawalStateMachine {
    /// Note: Initialization ensures that the state machine has at least one event.
    pub fn new(event: MonitorWithdrawalEvent, cfg: &Config) -> Self {
        let mut sm = Self {
            seen_events: Vec::new(),
            expected_events: Vec::new(),
            btc_checked_at: None,
            wid: event.wid,
            btc_txid: event.btc_txid,
            tx: event.tx.clone(),
        };
        assert!(
            sm.add_event(event, cfg).is_empty(),
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

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    /// The withdrawal's inputs and outputs.
    pub fn tx(&self) -> &WithdrawalTx {
        &self.tx
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
    /// Callers must ensure `is_in_audit_window()` is true before using this for
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

    // TODO: If we fully move to strict guardian-led audits, this can be relaxed to only include
    // withdrawals with guardian E2 in the user window.
    pub fn is_in_audit_window(&self, window: &impl AuditWindow) -> bool {
        self.seen_events
            .iter()
            .any(|e| window.in_window(e.timestamp_secs))
    }

    /// Add an event and update expectations for its immediate neighbors.
    ///
    /// A missing predecessor is expected by the event timestamp plus the
    /// predecessor's clock skew; a missing successor is expected by the
    /// configured next-event deadline. A neighbor already seen is checked
    /// against the pair's deadlines, so findings do not depend on ingestion order.
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
        cfg: &Config,
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
                Some(predecessor) => {
                    timing_findings.extend(neighbor_timing_findings(predecessor, &new_event, cfg))
                }
                None => self.expected_events.push((
                    predecessor_event_type,
                    cfg.predecessor_deadline(&new_event),
                    EventRelation::Predecessor,
                )),
            }
        }
        if let Some(successor_event_type) = new_event.event_type.successor() {
            match self.get(successor_event_type) {
                Some(successor) => {
                    timing_findings.extend(neighbor_timing_findings(&new_event, successor, cfg))
                }
                None => self.expected_events.push((
                    successor_event_type,
                    cfg.successor_deadline(&new_event),
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
        cfg: &Config,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.expects(WithdrawalEventType::E3BtcConfirmed) {
            return Ok(BtcFetchOutcome::NotExpected);
        }
        let btc_txid = self.btc_txid;
        let wid = self.wid;
        let cur_time = now_timestamp_secs();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(confirmation)) => {
                self.btc_checked_at = Some(cur_time);
                let e_btc =
                    MonitorWithdrawalEvent::from_btc(&confirmation, wid, btc_txid, self.tx.clone());
                Ok(BtcFetchOutcome::Confirmed(self.add_event(e_btc, cfg)))
            }
            Ok(None) => {
                self.btc_checked_at = Some(cur_time);
                Ok(BtcFetchOutcome::Unconfirmed)
            }
            Err(e) => Err(e),
        }
    }

    /// Check for violations given per-source cursors.
    /// Only reports a missing event if its deadline has passed relative to the relevant cursor.
    /// Callers must ensure is_in_audit_window() is true before calling this function.
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
    cfg: &Config,
) -> Vec<MonitorFinding> {
    let mut findings = Vec::new();
    let deadline = cfg.successor_deadline(predecessor);
    if deadline < successor.timestamp_secs {
        findings.push(MonitorFinding::EventOccurredAfterDeadline {
            event: MonitorEvent::Withdrawal(successor.clone()),
            relation: EventRelation::Successor,
            deadline,
            occurred_at: successor.timestamp_secs,
        });
    }
    let deadline = cfg.predecessor_deadline(successor);
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
mod tests {
    use super::*;
    use crate::findings::FindingCategory;
    use crate::rpc::sui::approval::tests::test_hashi_btc_keys;
    use bitcoin::hashes::Hash as _;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::witness_program_from_address;
    use hashi_types::move_types::OutputUtxo;
    use hashi_types::move_types::Utxo;
    use hashi_types::move_types::UtxoId;

    struct TestWindow {
        start: UnixSeconds,
        end: UnixSeconds,
    }

    impl AuditWindow for TestWindow {
        fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
            timestamp_secs >= self.start && timestamp_secs <= self.end
        }
    }

    fn cfg() -> Config {
        Config::for_tests()
    }

    fn txid(fill: u8) -> Txid {
        Txid::from_slice(&[fill; 32]).expect("valid txid")
    }

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

    /// One input, one user payout, and change to `change_address`.
    fn withdrawal_tx(change_address: Vec<u8>) -> WithdrawalTx {
        WithdrawalTx::new(
            vec![Utxo {
                id: UtxoId {
                    txid: txid(0x51).into(),
                    vout: 1,
                },
                amount: 120_000,
                derivation_path: Some(DerivationPath::new([0x52; 32])),
            }],
            vec![OutputUtxo {
                amount: 100_000,
                bitcoin_address: vec![0x53; 20],
            }],
            vec![OutputUtxo {
                amount: 19_000,
                bitcoin_address: change_address,
            }],
        )
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
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
            &cfg,
        );

        let findings = sm.add_event(event(WithdrawalEventType::E1HashiApproved, 1, 110, 1), &cfg);
        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "duplicate event for same wid with different contents".to_string()
            )]
        );

        let wid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 2, 120, 1),
            &cfg,
        );
        assert_eq!(
            wid_findings,
            vec![MonitorFinding::InvalidEventAdded("invalid wid".to_string())]
        );

        let txid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2),
            &cfg,
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
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 9, 100, 7),
            &cfg,
        );
        assert!(sm.expects(WithdrawalEventType::E2GuardianApproved));

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
                &cfg,
            )
            .is_empty()
        );
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));

        assert!(
            sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7), &cfg)
                .is_empty()
        );

        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn add_event_records_event_past_deadline() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &cfg,
        );
        let event = event(WithdrawalEventType::E2GuardianApproved, 4, 201, 4);

        let findings = sm.add_event(event.clone(), &cfg);
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
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &cfg,
        );
        let btc_confirmed = event(WithdrawalEventType::E3BtcConfirmed, 4, 600, 4);
        assert!(sm.add_event(btc_confirmed.clone(), &cfg).is_empty());

        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 4, 311, 4);
        let findings = sm.add_event(guardian_approval.clone(), &cfg);

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
        let cfg = cfg();
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
                let mut sm = WithdrawalStateMachine::new(events[order[0]].clone(), &cfg);
                let findings: Vec<_> = order[1..]
                    .iter()
                    .flat_map(|&i| sm.add_event(events[i].clone(), &cfg))
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
        let cfg = cfg();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 5),
            &cfg,
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
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E2GuardianApproved, 7, 100, 7),
            &cfg,
        );
        let cursors = |sui| Cursors {
            sui,
            guardian: 1_000,
        };

        assert!(!sm.is_missing_hashi_approval(&cursors(109)));
        assert!(sm.is_missing_hashi_approval(&cursors(110)));

        assert!(
            sm.add_event(event(WithdrawalEventType::E1HashiApproved, 7, 10, 7), &cfg)
                .is_empty()
        );
        assert!(!sm.is_missing_hashi_approval(&cursors(1_000)));
        assert!(sm.violations(&cursors(1_000)).is_empty());
    }

    #[test]
    fn a_late_or_mismatched_hashi_approval_is_a_safety_finding() {
        let cfg = cfg();
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 8, 100, 8);

        let mut late = WithdrawalStateMachine::new(guardian_approval.clone(), &cfg);
        let approval = event(WithdrawalEventType::E1HashiApproved, 8, 111, 8);
        let findings = late.add_event(approval.clone(), &cfg);
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

        let mut mismatched = WithdrawalStateMachine::new(guardian_approval, &cfg);
        let findings =
            mismatched.add_event(event(WithdrawalEventType::E1HashiApproved, 8, 50, 9), &cfg);
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
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 6, 100, 6),
            &cfg,
        );
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 6, 150, 6);
        assert!(sm.add_event(guardian_approval.clone(), &cfg).is_empty());

        let findings = sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 6, 119, 6), &cfg);

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
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 31, 90, 1),
            &cfg,
        );
        let window = TestWindow {
            start: 100,
            end: 200,
        };

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 31, 100, 1),
                &cfg,
            )
            .is_empty()
        );
        assert!(sm.is_in_audit_window(&window));

        let findings = sm.violations(&Cursors {
            sui: 1_000,
            guardian: 1_000,
        });

        assert!(findings.is_empty());
    }

    #[test]
    fn e1_inside_window_without_e2_is_in_scope() {
        let cfg = cfg();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 88, 120, 2),
            &cfg,
        );
        let window = TestWindow {
            start: 100,
            end: 200,
        };

        assert!(sm.is_in_audit_window(&window));
    }

    #[test]
    fn equal_transactions_from_sui_and_the_guardian_have_no_finding() {
        let cfg = cfg();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        let e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &cfg);
        assert!(sm.add_event(e2.clone(), &cfg).is_empty());

        // The check runs in either ingestion order.
        let mut sm = WithdrawalStateMachine::new(e2, &cfg);
        assert!(sm.add_event(e1, &cfg).is_empty());
    }

    #[test]
    fn a_change_output_not_paying_the_guardians_path_is_a_safety_finding() {
        let cfg = cfg();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 5, 100, 5);
        let mut e2 = event(WithdrawalEventType::E2GuardianApproved, 5, 150, 5);
        e2.tx = withdrawal_tx(bridge_program(&DerivationPath::new([0x43; 32])));
        let expected = vec![MonitorFinding::WithdrawalMismatch {
            wid: e1.wid,
            sui: e1.tx.clone(),
            guardian: e2.tx.clone(),
        }];
        assert_eq!(expected[0].category(), FindingCategory::Safety);

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &cfg);
        assert_eq!(sm.add_event(e2.clone(), &cfg), expected);
        // The event is kept, so the flow goes on to E3.
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());

        let mut sm = WithdrawalStateMachine::new(e2, &cfg);
        assert_eq!(sm.add_event(e1, &cfg), expected);
    }

    #[test]
    fn an_output_sui_calls_change_and_the_guardian_calls_a_payout_is_a_safety_finding() {
        let cfg = cfg();
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

        let mut sm = WithdrawalStateMachine::new(e1.clone(), &cfg);
        assert_eq!(
            sm.add_event(e2.clone(), &cfg),
            vec![MonitorFinding::WithdrawalMismatch {
                wid: e1.wid,
                sui: e1.tx,
                guardian: e2.tx,
            }]
        );
    }
}
