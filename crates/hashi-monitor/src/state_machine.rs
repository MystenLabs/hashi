// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal state machine for tracking event flow.

use crate::audit::AuditWindow;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use crate::findings::EventRelation;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time_utils::UnixSeconds;

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
}

pub enum BtcFetchOutcome {
    NotExpected,
    Unconfirmed,
    Confirmed(Vec<MonitorFinding>),
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

    pub fn expects(&self, event_type: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _, _)| *event == event_type)
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

    // TODO: If we fully move to strict guardian-led audits, this can be relaxed to only include
    // withdrawals with guardian E2 in the user window.
    pub fn is_in_audit_window(&self, window: &impl AuditWindow) -> bool {
        self.seen_events
            .iter()
            .any(|e| window.in_window(e.timestamp_secs))
    }

    /// Add an event and update expectations for its immediate neighbors.
    ///
    /// A missing predecessor is expected by the event timestamp plus
    /// `clock_skew`; a missing successor is expected by the configured
    /// next-event deadline. Events may be ingested in any order.
    ///
    /// Event retention is based on structural validity, not finding category.
    /// `MonitorFinding::InvalidEventAdded` denotes a contradictory, definite
    /// safety issue, so it is returned immediately without storing the event.
    /// A structurally valid event is stored and updates subsequent expectations
    /// even when its timing produces a safety or liveness finding.
    ///
    /// The return value contains every resulting finding. An empty vector means
    /// the event was accepted without one.
    ///
    /// TODO: Represent a missing neighbor with its full allowed timestamp
    /// interval, and apply both bounds regardless of event ingestion order. For
    /// consecutive events `E_i` and `E_{i+1}`, observing `E_i` should constrain
    /// `E_{i+1}` to `[E_i - clock_skew, E_i + next_event_delay]`; observing
    /// `E_{i+1}` first should impose the equivalent inverse interval on `E_i`.
    /// The current single-deadline representation checks only one side of that
    /// interval, so timing findings can depend on which event is ingested first.
    /// Before applying this uniformly to E2/E3, account for a Bitcoin block
    /// header's timestamp being an approximate miner-provided time rather than
    /// the wall-clock time at which the transaction was confirmed.
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

        // If a neighbor is already expected, record a timing finding but still
        // ingest the event. The monitor must retain a late event so it can
        // distinguish liveness from safety and continue validating the flow.
        let mut timing_findings = Vec::new();
        for (src, deadline, relation) in self.expected_events.iter() {
            if *src == new_event.event_type && *deadline < new_event.timestamp_secs {
                timing_findings.push(MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(new_event.clone()),
                    relation: *relation,
                    deadline: *deadline,
                    occurred_at: new_event.timestamp_secs,
                });
            }
        }

        // if neighbor is not there, then we add an expectation indicating when we expect to see it.
        if let Some(predecessor_event_type) = new_event.event_type.predecessor()
            && self.get(predecessor_event_type).is_none()
        {
            let predecessor_deadline = new_event.timestamp_secs + cfg.clock_skew;
            self.expected_events.push((
                predecessor_event_type,
                predecessor_deadline,
                EventRelation::Predecessor,
            ));
        }
        if let Some(successor_event_type) = new_event.event_type.successor()
            && self.get(successor_event_type).is_none()
        {
            let successor_deadline = new_event.timestamp_secs
                + cfg
                    .next_event_delay(new_event.event_type)
                    .expect("has a successor");
            self.expected_events.push((
                successor_event_type,
                successor_deadline,
                EventRelation::Successor,
            ));
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
        let cur_time = now_unix_seconds();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(block_time)) => {
                self.btc_checked_at = Some(cur_time);
                let e_btc = MonitorWithdrawalEvent {
                    event_type: WithdrawalEventType::E3BtcConfirmed,
                    wid,
                    btc_txid,
                    timestamp_secs: block_time,
                };
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

/// Deposit State Machine. Unlike withdrawal state machine, here we only listen for a sui event,
/// which in turn triggers a lookup for a specific btc event. So we simplify the struct & its impl's.
pub struct DepositStateMachine {
    /// The hashi deposit event
    hashi_deposit_event: MonitorDepositEvent,
    /// None initially and Some post BTC event find
    btc_event: Option<MonitorDepositEvent>,
    btc_event_expected_at: UnixSeconds,
    btc_checked_at: Option<UnixSeconds>,
}

impl DepositStateMachine {
    pub fn new(event: MonitorDepositEvent, cfg: &Config) -> Self {
        if event.event_type != DepositEventType::E2HashiApproved {
            panic!("unexpected event type");
        }
        // btc confirmation is a predecessor event => we set the deadline to now (+skew).
        let t_btc_expected = event.timestamp_secs + cfg.clock_skew;
        Self {
            hashi_deposit_event: event,
            btc_event: None,
            btc_event_expected_at: t_btc_expected,
            btc_checked_at: None,
        }
    }

    pub fn btc_txid(&self) -> Txid {
        self.hashi_deposit_event.deposit_id.txid()
    }

    pub fn deposit_id(&self) -> DepositId {
        self.hashi_deposit_event.deposit_id
    }

    pub fn hashi_deposit_event(&self) -> &MonitorDepositEvent {
        &self.hashi_deposit_event
    }

    pub fn is_expecting_events(&self) -> bool {
        self.btc_event.is_none()
    }

    pub fn try_fetch_btc_tx(
        &mut self,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.is_expecting_events() {
            return Ok(BtcFetchOutcome::NotExpected);
        }

        let deadline = self.btc_event_expected_at;
        let deposit_id = self.hashi_deposit_event.deposit_id;
        let btc_txid = deposit_id.txid();
        let cur_time = now_unix_seconds();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(block_time)) => {
                self.btc_checked_at = Some(cur_time);
                let e_btc = MonitorDepositEvent {
                    event_type: DepositEventType::E1BtcConfirmed,
                    deposit_id,
                    timestamp_secs: block_time,
                };

                let mut findings = Vec::new();
                if deadline < block_time {
                    findings.push(MonitorFinding::EventOccurredAfterDeadline {
                        event: MonitorEvent::Deposit(e_btc.clone()),
                        relation: EventRelation::Predecessor,
                        deadline,
                        occurred_at: block_time,
                    });
                }
                self.btc_event = Some(e_btc);
                Ok(BtcFetchOutcome::Confirmed(findings))
            }
            Ok(None) => {
                self.btc_checked_at = Some(cur_time);
                Ok(BtcFetchOutcome::Unconfirmed)
            }
            Err(e) => Err(e),
        }
    }

    pub fn violations(&self) -> Vec<MonitorFinding> {
        if self.btc_event.is_some() {
            // btc event found => no violations!
            return Vec::new();
        };

        // btc event not yet found
        let Some(cursor) = self.btc_checked_at else {
            // Bitcoin and state checks have independent schedules. Wait for
            // the first lookup before evaluating absence.
            return Vec::new();
        };

        let deadline = self.btc_event_expected_at;
        if deadline > cursor {
            return Vec::new();
        }

        vec![MonitorFinding::ExpectedEventMissing {
            event_id: MonitorEventId::Deposit(self.hashi_deposit_event.deposit_id),
            event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
            relation: EventRelation::Predecessor,
            deadline,
            cursor,
        }]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::BtcConfig;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;
    use bitcoin::hashes::Hash as _;
    use hashi_types::guardian::UnresolvedS3Config;

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
        Config {
            next_event_delays: NextEventDelays::new(vec![
                (WithdrawalEventType::E1HashiApproved, 100),
                (WithdrawalEventType::E2GuardianApproved, 200),
            ])
            .expect("valid intra-event delays"),
            clock_skew: 10,
            withdrawal_predecessor_lookback: 60 * 60,
            guardian_s3: UnresolvedS3Config {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: Some("access-key".to_string()),
                secret_key: Some("secret-key".to_string()),
                retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
            },
            pcr_allowlist: hashi_types::guardian::PcrAllowlist::new(
                hashi_types::guardian::BuildPcrs::new("", vec![]),
                vec![],
            )
            .expect("valid PCR allowlist"),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
                package_id: format!("0x{}", "11".repeat(32)),
            },
            btc: BtcConfig {
                rpc_url: "http://btc".to_string(),
                http_headers: BTreeMap::new(),
            },
        }
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
        }
    }

    fn deposit_event(timestamp: UnixSeconds, fill: u8) -> MonitorDepositEvent {
        MonitorDepositEvent {
            event_type: DepositEventType::E2HashiApproved,
            timestamp_secs: timestamp,
            deposit_id: DepositId::new(txid(fill), 0),
        }
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
        assert!(
            sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 4, 300, 4), &cfg)
                .is_empty()
        );

        let event = event(WithdrawalEventType::E2GuardianApproved, 4, 311, 4);
        let findings = sm.add_event(event.clone(), &cfg);

        assert_eq!(
            findings,
            vec![
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(event.clone()),
                    relation: EventRelation::Successor,
                    deadline: 200,
                    occurred_at: 311,
                },
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(event),
                    relation: EventRelation::Predecessor,
                    deadline: 310,
                    occurred_at: 311,
                },
            ]
        );
        assert!(!sm.is_expecting_events());
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
    fn deposit_violations_wait_for_btc_check() {
        let cfg = cfg();
        let mut sm = DepositStateMachine::new(deposit_event(100, 8), &cfg);

        assert!(sm.violations().is_empty());

        sm.btc_checked_at = Some(109);
        assert!(sm.violations().is_empty());

        sm.btc_checked_at = Some(110);
        let violations = sm.violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorFinding::ExpectedEventMissing {
                event_id: MonitorEventId::Deposit(DepositId::new(txid(8), 0)),
                event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
                relation: EventRelation::Predecessor,
                deadline: 110,
                cursor: 110,
            }
        );
    }
}
