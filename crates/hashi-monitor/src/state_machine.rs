//! Withdrawal state machine for tracking event flow.

use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use std::collections::BTreeSet;

use crate::OutputUTXO;
use crate::audit::AuditWindow;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use crate::errors::MonitorError;
use crate::errors::MonitorError::*;

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
    /// the set of events we have seen until now related to this withdrawal
    seen_events: Vec<WithdrawalEvent>,
    /// an entry (e, t) in expected_events signals that we are expecting to hear e by time t
    expected_events: Vec<(WithdrawalEventType, UnixSeconds)>,
    /// last time at which we checked for a btc withdrawal tx
    btc_checked_at: Option<UnixSeconds>,
    /// immutable wid
    wid: WithdrawalID,
    /// immutable txid
    btc_txid: Txid,
    /// internal output utxos
    internal_output_utxos: BTreeSet<OutputUTXO>,
    /// external output utxos
    external_output_utxos: BTreeSet<OutputUTXO>,
}

pub enum BtcFetchOutcome {
    NotExpected,
    Unconfirmed,
    Confirmed(Option<MonitorError>),
}

impl WithdrawalStateMachine {
    pub fn new(event: WithdrawalEvent, cfg: &Config) -> Self {
        let mut sm = Self {
            seen_events: Vec::new(),
            expected_events: Vec::new(),
            btc_checked_at: None,
            wid: event.wid,
            btc_txid: event.btc_txid,
            internal_output_utxos: event.internal_output_utxos.clone(),
            external_output_utxos: event.external_output_utxos.clone(),
        };
        sm.add_event(event, cfg).expect("First event never fails");
        sm
    }

    pub fn get(&self, event_type: WithdrawalEventType) -> Option<&WithdrawalEvent> {
        self.seen_events
            .iter()
            .find(|event| event.event_type == event_type)
    }

    pub fn btc_txid(&self) -> Txid {
        self.btc_txid
    }

    pub fn all_outputs(&self) -> impl Iterator<Item = &OutputUTXO> {
        self.external_output_utxos
            .iter()
            .chain(self.internal_output_utxos.iter())
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    pub fn expects(&self, event_type: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _)| *event == event_type)
    }

    pub fn is_empty(&self) -> bool {
        self.seen_events.is_empty()
    }

    /// Is the withdrawal valid? Put differently, has it passed all the checks?
    ///
    /// Note: Callers must ensure is_in_audit_window() is true before calling this function.
    /// More precisely, we can always tell if a withdrawal is valid but not if it is invalid, e.g., an (Out, Pending) can transition to (In, Valid) / (Out, Valid).
    /// This means that (Out, Pending/Invalid) withdrawals may never get garbage collected.
    /// But such cases are likely few as they only get created for a short lookback or lookahead period.
    pub fn is_valid(&self) -> bool {
        !self.is_empty() && self.expected_events.is_empty()
    }

    // TODO: If we fully move to strict guardian-led audits, this can be relaxed to only include
    // withdrawals with guardian E2 in the user window.
    pub fn is_in_audit_window(&self, window: &impl AuditWindow) -> bool {
        self.seen_events.iter().any(|e| window.in_window(e))
    }

    pub fn earliest_event_time(&self) -> Option<UnixSeconds> {
        self.seen_events.iter().map(|e| e.timestamp).min()
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
        new_event: WithdrawalEvent,
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

        if self.external_output_utxos != new_event.external_output_utxos {
            return Err(InvalidEventAdded(
                "invalid external_output_utxos".to_string(),
            ));
        }

        if self.internal_output_utxos != new_event.internal_output_utxos {
            return Err(InvalidEventAdded(
                "invalid internal_output_utxos".to_string(),
            ));
        }

        // if neighbor is there, then we check that the gap between the two is as expected.
        for (src, deadline) in self.expected_events.iter() {
            if *src == new_event.event_type && *deadline < new_event.timestamp {
                return Err(EventOccurredAfterDeadline {
                    event: new_event.clone(),
                    deadline: *deadline,
                    occurred_at: new_event.timestamp,
                });
            }
        }

        // if neighbor is not there, then we add an expectation indicating when we expect to see it.
        if let Some(predecessor_event_type) = new_event.event_type.predecessor()
            && self.get(predecessor_event_type).is_none()
        {
            let predecessor_deadline = new_event.timestamp + cfg.clock_skew;
            self.expected_events
                .push((predecessor_event_type, predecessor_deadline));
        }
        if let Some(successor_event_type) = new_event.event_type.successor()
            && self.get(successor_event_type).is_none()
        {
            let successor_deadline = new_event.timestamp
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
    pub fn try_fetch_btc_tx(&mut self, cfg: &Config) -> anyhow::Result<BtcFetchOutcome> {
        if !self.expects(WithdrawalEventType::E3BtcConfirmed) {
            return Ok(BtcFetchOutcome::NotExpected);
        }
        let btc_txid = self.btc_txid;
        let wid = self.wid;
        let cur_time = now_unix_seconds();

        match crate::rpc::lookup_btc_confirmation(cfg, btc_txid) {
            Ok(Some((block_time, utxos))) => {
                self.btc_checked_at = Some(cur_time);

                if !utxos.iter().eq(self.all_outputs()) {
                    return Ok(BtcFetchOutcome::Confirmed(Some(InvalidEventAdded(
                        "btc outputs do not match expected outputs".to_string(),
                    ))));
                }

                let e_btc = WithdrawalEvent {
                    event_type: WithdrawalEventType::E3BtcConfirmed,
                    wid,
                    btc_txid,
                    timestamp: block_time,
                    external_output_utxos: self.external_output_utxos.clone(),
                    internal_output_utxos: self.internal_output_utxos.clone(),
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
                    event_type: *event_type,
                    deadline: *deadline,
                    cursor,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::hashes::Hash as _;
    use hashi_types::guardian::BitcoinAddress;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use super::*;
    use crate::config::BtcConfig;
    use crate::config::GuardianConfig;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;

    struct TestWindow {
        start: UnixSeconds,
        end: UnixSeconds,
    }

    impl AuditWindow for TestWindow {
        fn in_window(&self, e: &WithdrawalEvent) -> bool {
            e.timestamp >= self.start && e.timestamp <= self.end
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
            guardian: GuardianConfig {
                s3_bucket: "bucket".to_string(),
            },
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
            },
            btc: BtcConfig {
                rpc_url: "http://btc".to_string(),
            },
        }
    }

    fn txid(fill: u8) -> Txid {
        Txid::from_slice(&[fill; 32]).expect("valid txid")
    }

    fn event(
        source: WithdrawalEventType,
        wid: WithdrawalID,
        timestamp: UnixSeconds,
        fill: u8,
    ) -> WithdrawalEvent {
        let external_output_utxos = vec![OutputUTXO {
            address: BitcoinAddress::<NetworkUnchecked>::from_str(
                "mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP",
            )
            .expect("valid btc address"),
            amount: Amount::from_sat(1_000),
        }]
        .into_iter()
        .collect::<BTreeSet<_>>();

        let internal_output_utxos = vec![OutputUTXO {
            address: BitcoinAddress::<NetworkUnchecked>::from_str(
                "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            )
            .expect("valid btc address"),
            amount: Amount::from_sat(250),
        }]
        .into_iter()
        .collect::<BTreeSet<_>>();

        WithdrawalEvent {
            event_type: source,
            wid,
            timestamp,
            btc_txid: txid(fill),
            external_output_utxos,
            internal_output_utxos,
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
                event,
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
                event_type: WithdrawalEventType::E2GuardianApproved,
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
}
