// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal state machine for tracking event flow.

use crate::audit::AuditWindow;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::DepositEventType;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventType;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use crate::errors::MonitorError;
use crate::errors::MonitorError::*;
use crate::rpc::btc::BtcRpcClient;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time_utils::UnixSeconds;

/// A record of all the events tracking a single withdrawal.
///
/// `add_event` adds an event e and checks if it is appropriate w.r.t already seen events, e.g., arrived at expected time.
///
/// `violations(cursors)` checks if there are any violations given current cursors
///
/// Invariant: `expected_events` should not contain an event type that exists in `seen_events`.
///
/// Six different states that a withdrawal can be in
/// - Window: Out, In
/// - Status:
///     - Valid: is_valid() == true,
///     - Invalid: |violations()| > 0,
///     - Pending: neither valid nor invalid.
pub struct WithdrawalStateMachine {
    /// the set of non-zero events we have seen until now related to this withdrawal.
    seen_events: Vec<MonitorWithdrawalEvent>,
    /// an entry (e, t) in expected_events signals that we are expecting to hear e by time t
    expected_events: Vec<(WithdrawalEventType, UnixSeconds)>,
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
    Confirmed(Option<MonitorError>),
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
        sm.add_event(event, cfg).expect("First event never fails");
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
            .any(|(event, _)| *event == event_type)
    }

    /// Is the withdrawal valid? Put differently, has it passed all the checks?
    ///
    /// Note: Callers must ensure is_in_audit_window() is true before calling this function.
    /// More precisely, we can always tell if a withdrawal is valid but not if it is invalid, e.g., an (Out, Pending) can transition to (In, Valid) / (Out, Valid).
    /// This means that (Out, Pending/Invalid) withdrawals may never get garbage collected.
    /// But such cases are likely few as they only get created for a short lookback or lookahead period.
    pub fn is_valid(&self) -> bool {
        self.expected_events.is_empty()
    }

    // TODO: If we fully move to strict guardian-led audits, this can be relaxed to only include
    // withdrawals with guardian E2 in the user window.
    pub fn is_in_audit_window(&self, window: &impl AuditWindow) -> bool {
        self.seen_events
            .iter()
            .any(|e| window.in_window(e.timestamp_secs))
    }

    /// `add_event` adds an event e and checks the following. Let e's neighbors be [e.predecessor(), e.successor()].
    ///    - if neighbor was seen before, checks time gap between two.
    ///    - if neighbor was not seen, adds an entry to expected_events signalling our expectation.
    ///         - we expect to see a predecessor at t - clock_skew, and a successor at t + next_event_delay(e)
    ///
    /// This is the minimal set of complete checks. A more extensive approach is to add an expectation for all other events except e.
    /// Note that add_event doesn't assume anything about the order of events, e.g., we could ingest e2 -> e1 -> e3.
    ///
    /// Throws: InvalidEventAdded, EventOccurredAfterDeadline
    pub fn add_event(
        &mut self,
        new_event: MonitorWithdrawalEvent,
        cfg: &Config,
    ) -> Result<(), MonitorError> {
        if let Some(existing_event) = self.get(new_event.event_type) {
            return if *existing_event == new_event {
                Ok(())
            } else {
                Err(InvalidEventAdded(
                    "duplicate event for same wid with different contents".to_string(),
                ))
            };
        }

        if self.wid != new_event.wid {
            return Err(InvalidEventAdded("invalid wid".to_string()));
        }

        if self.btc_txid != new_event.btc_txid {
            return Err(InvalidEventAdded("invalid btc_txid".to_string()));
        }

        // if neighbor is there, then we check that the gap between the two is as expected.
        for (src, deadline) in self.expected_events.iter() {
            if *src == new_event.event_type && *deadline < new_event.timestamp_secs {
                return Err(EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(new_event.clone()),
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
            self.expected_events
                .push((predecessor_event_type, predecessor_deadline));
        }
        if let Some(successor_event_type) = new_event.event_type.successor()
            && self.get(successor_event_type).is_none()
        {
            let successor_deadline = new_event.timestamp_secs
                + cfg
                    .next_event_delay(new_event.event_type)
                    .expect("has a successor");
            self.expected_events
                .push((successor_event_type, successor_deadline));
        }

        // remove any previously stored expected events
        self.expected_events
            .retain(|(src, _)| *src != new_event.event_type);
        // add to seen events
        self.seen_events.push(new_event);
        Ok(())
    }

    /// If expecting BTC confirmation, query BTC RPC and add the event if confirmed.
    ///     - Returns `Ok(BtcFetchOutcome::NotExpected)` if a BTC event is not expected.
    ///     - Returns `Ok(BtcFetchOutcome::Unconfirmed)` if checked but block not yet mined.
    ///     - Returns `Ok(BtcFetchOutcome::Confirmed(None))` if confirmed and E3 ingest succeeded.
    ///     - Returns `Ok(BtcFetchOutcome::Confirmed(Some(err)))` if confirmed but E3 ingest produced a domain finding.
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
                Ok(BtcFetchOutcome::Confirmed(self.add_event(e_btc, cfg).err()))
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
    pub fn violations(&self, cursors: &Cursors) -> Vec<MonitorError> {
        let mut out = Vec::new();
        for (event_type, deadline) in &self.expected_events {
            let cursor = match event_type {
                WithdrawalEventType::E3BtcConfirmed => match self.btc_checked_at {
                    Some(checked_at) => checked_at,
                    None => {
                        tracing::warn!(
                            "callers should avoid reaching this branch by calling try_fetch_btc_tx before"
                        );
                        continue;
                    }
                },
                _ => cursors.for_event_type(*event_type),
            };
            if *deadline <= cursor {
                out.push(ExpectedEventMissing {
                    event_type: MonitorEventType::Withdrawal(*event_type),
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
        if event.event_type != DepositEventType::E2HashiDeposited {
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

    pub fn is_valid(&self) -> bool {
        self.btc_event.is_some()
    }

    pub fn btc_txid(&self) -> Txid {
        self.hashi_deposit_event.btc_txid
    }

    pub fn hashi_deposit_event(&self) -> &MonitorDepositEvent {
        &self.hashi_deposit_event
    }

    pub fn expects_btc_event(&self) -> bool {
        self.btc_event.is_none()
    }

    pub fn try_fetch_btc_tx(
        &mut self,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.expects_btc_event() {
            return Ok(BtcFetchOutcome::NotExpected);
        }

        let deadline = self.btc_event_expected_at;
        let btc_txid = self.hashi_deposit_event.btc_txid;
        let cur_time = now_unix_seconds();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(block_time)) => {
                self.btc_checked_at = Some(cur_time);
                let e_btc = MonitorDepositEvent {
                    event_type: DepositEventType::E1BtcConfirmed,
                    btc_txid,
                    timestamp_secs: block_time,
                };

                let mut response = None;
                if deadline < block_time {
                    response = Some(EventOccurredAfterDeadline {
                        event: MonitorEvent::Deposit(e_btc.clone()),
                        deadline,
                        occurred_at: block_time,
                    });
                }
                self.btc_event = Some(e_btc);
                Ok(BtcFetchOutcome::Confirmed(response))
            }
            Ok(None) => {
                self.btc_checked_at = Some(cur_time);
                Ok(BtcFetchOutcome::Unconfirmed)
            }
            Err(e) => Err(e),
        }
    }

    pub fn violations(&self) -> Vec<MonitorError> {
        if self.btc_event.is_some() {
            // btc event found => no violations!
            return Vec::new();
        };

        // btc event not yet found
        let Some(cursor) = self.btc_checked_at else {
            tracing::warn!(
                txid = %self.hashi_deposit_event.btc_txid,
                "callers should avoid this branch by calling try_fetch_btc_tx before violations"
            );
            return Vec::new();
        };

        let deadline = self.btc_event_expected_at;
        if deadline > cursor {
            return Vec::new();
        }

        vec![ExpectedEventMissing {
            event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
            deadline,
            cursor,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BtcConfig;
    use crate::config::BtcRpcAuth;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;
    use bitcoin::hashes::Hash as _;
    use hashi_types::guardian::S3Config;

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
            guardian: S3Config::mock_for_testing(),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
            },
            btc: BtcConfig {
                rpc_url: "http://btc".to_string(),
                rpc_auth: BtcRpcAuth::None,
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
            wid: [wid_seed; 32],
            timestamp_secs: timestamp,
            btc_txid: txid(fill),
        }
    }

    fn deposit_event(timestamp: UnixSeconds, fill: u8) -> MonitorDepositEvent {
        MonitorDepositEvent {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: timestamp,
            btc_txid: txid(fill),
        }
    }

    #[test]
    fn add_event_rejects_duplicate_source() {
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
            &cfg,
        );

        let err = sm
            .add_event(event(WithdrawalEventType::E1HashiApproved, 1, 110, 1), &cfg)
            .expect_err("duplicate source should fail");
        assert_eq!(
            err,
            InvalidEventAdded("duplicate event for same wid with different contents".to_string())
        );

        let wid_err = sm
            .add_event(
                event(WithdrawalEventType::E2GuardianApproved, 2, 120, 1),
                &cfg,
            )
            .expect_err("wid mismatch should fail");
        assert_eq!(wid_err, InvalidEventAdded("invalid wid".to_string()));

        let txid_err = sm
            .add_event(
                event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2),
                &cfg,
            )
            .expect_err("txid mismatch should fail");
        assert_eq!(txid_err, InvalidEventAdded("invalid btc_txid".to_string()));
    }

    #[test]
    fn in_order_flow_completes() {
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 9, 100, 7),
            &cfg,
        );
        assert!(sm.expects(WithdrawalEventType::E2GuardianApproved));

        sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
            &cfg,
        )
        .expect("e2 is valid");
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));

        sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7), &cfg)
            .expect("e3 is valid");

        assert!(sm.is_valid());
    }

    #[test]
    fn add_event_rejects_event_past_deadline() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &cfg,
        );
        let event = event(WithdrawalEventType::E2GuardianApproved, 4, 201, 4);

        let err = sm
            .add_event(event.clone(), &cfg)
            .expect_err("e2 should fail after deadline");
        assert_eq!(
            err,
            EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(event),
                deadline: 200,
                occurred_at: 201,
            }
        );
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
            ExpectedEventMissing {
                event_type: MonitorEventType::Withdrawal(WithdrawalEventType::E2GuardianApproved),
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

        sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 31, 100, 1),
            &cfg,
        )
        .expect("e2 is valid even with e1 out-of-window");
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
            ExpectedEventMissing {
                event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
                deadline: 110,
                cursor: 110,
            }
        );
    }
}
