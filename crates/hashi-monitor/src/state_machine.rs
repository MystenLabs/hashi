//! Withdrawal state machine for tracking event flow.

use bitcoin::Txid;
use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorError;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;

/// A record of all the events tracking a single withdrawal.
///
/// `add_event` adds an event.
///    - if neighbor exists, checks time gap between two.
///    - if neighbor doesn't exist, adds an entry to expected_events signalling our expectation on the neighbor.
///
/// `violations(cursors)`
///    - check if there are any violations given current cursors
///
/// Invariant: `expected_events` should not contain an event type that exists in `seen_events`.
#[derive(Default)]
pub struct WithdrawalStateMachine {
    seen_events: Vec<WithdrawalEvent>,
    expected_events: Vec<(WithdrawalEventType, UnixSeconds)>,
}

impl WithdrawalStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_events(
        events: Vec<WithdrawalEvent>,
        cfg: &Config,
    ) -> Result<Self, MonitorError> {
        let mut s = Self::default();
        for e in events {
            s.add_event(e, cfg)?;
        }
        Ok(s)
    }

    pub fn get(&self, source: WithdrawalEventType) -> Option<&WithdrawalEvent> {
        self.seen_events
            .iter()
            .find(|event| *event.source() == source)
    }

    pub fn btc_txid(&self) -> Option<Txid> {
        self.seen_events.last().map(|event| event.btc_txid())
    }

    pub fn wid(&self) -> Option<WithdrawalID> {
        self.seen_events.last().map(|event| event.wid())
    }

    pub fn expects(&self, source: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _)| *event == source)
    }

    pub fn is_complete(&self) -> bool {
        self.expected_events.is_empty() && !self.seen_events.is_empty()
    }

    pub fn add_event(&mut self, event: WithdrawalEvent, cfg: &Config) -> Result<(), MonitorError> {
        let cur_event_source = *event.source();
        let cur_event_timestamp = event.timestamp();
        let cur_event_btc_txid = event.btc_txid();
        let cur_event_wid = event.wid();

        if self
            .seen_events
            .iter()
            .any(|e| *e.source() == cur_event_source)
        {
            return Err(MonitorError::DuplicateEventForSameWid);
        }

        if !self.seen_events.is_empty() && self.seen_events.iter().any(|e| e.wid() != cur_event_wid)
        {
            return Err(MonitorError::InvalidWid);
        }

        if !self.seen_events.is_empty()
            && self
                .seen_events
                .iter()
                .any(|e| e.btc_txid() != cur_event_btc_txid)
        {
            return Err(MonitorError::InvalidBtcTxid);
        }

        // if neighbor is there, then we check that the gap between the two is as expected.
        for (src, deadline) in self.expected_events.iter() {
            if *src == cur_event_source && *deadline < cur_event_timestamp {
                return Err(MonitorError::EventOccurredAfterDeadline {
                    event,
                    deadline: *deadline,
                    occurred_at: cur_event_timestamp,
                });
            }
        }

        // if neighbor is not there, then we add an expectation indicating when we expect to see it.
        if let Some(predecessor_event_type) = cur_event_source.predecessor()
            && self.get(predecessor_event_type).is_none()
        {
            let predecessor_deadline = cur_event_timestamp + cfg.clock_skew;
            self.expected_events
                .push((predecessor_event_type, predecessor_deadline));
        }
        if let Some(successor_event_type) = cur_event_source.successor()
            && self.get(successor_event_type).is_none()
        {
            let successor_deadline = cur_event_timestamp
                + cfg
                    .next_event_delay(cur_event_source)
                    .expect("has a successor");
            self.expected_events
                .push((successor_event_type, successor_deadline));
        }

        self.expected_events
            .retain(|(src, _)| *src != cur_event_source);
        self.seen_events.push(event);
        Ok(())
    }

    /// If expecting BTC confirmation, query BTC RPC and add the event if confirmed.
    ///     - Returns `Some(result)` if a fetch was attempted.
    ///     - Returns `None` if not expecting or block not yet mined.
    ///     - Panics upon btc rpc error.
    pub fn try_fetch_btc_tx(&mut self, cfg: &Config) -> Option<Result<(), MonitorError>> {
        if !self.expects(WithdrawalEventType::E3BtcConfirmed) {
            return None;
        }
        let txid = self
            .btc_txid()
            .expect("if there is an expectation for BTC tx, then btc_txid must exist");
        let wid = self
            .wid()
            .expect("if there is an expectation for BTC tx, then wid must exist");

        match crate::rpc::lookup_btc_confirmation(cfg, txid) {
            Ok(Some(block_time)) => {
                let e3 = WithdrawalEvent::new(
                    WithdrawalEventType::E3BtcConfirmed,
                    wid,
                    block_time,
                    txid,
                );
                Some(self.add_event(e3, cfg))
            }
            Ok(None) => None, // Not yet confirmed
            Err(e) => {
                panic!("btc rpc failed: {:?}", e);
            }
        }
    }

    /// Check for violations given per-source cursors.
    /// Only reports a missing event if its deadline has passed relative to the relevant cursor.
    pub fn violations(&self, cursors: &Cursors) -> Vec<MonitorError> {
        let mut out = Vec::new();
        for (event_type, deadline) in &self.expected_events {
            let cursor = cursors.for_event_type(*event_type);
            if *deadline <= cursor {
                out.push(MonitorError::ExpectedEventMissing {
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
    use bitcoin::hashes::Hash as _;

    use super::*;
    use crate::config::BtcConfig;
    use crate::config::GuardianConfig;
    use crate::config::SuiConfig;

    fn cfg() -> Config {
        Config {
            e1_e2_delay_secs: 100,
            e2_e3_delay_secs: 200,
            clock_skew: 10,
            poll_interval_secs: 1,
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
        WithdrawalEvent::new(source, wid, timestamp, txid(fill))
    }

    #[test]
    fn new_is_empty_not_complete() {
        let sm = WithdrawalStateMachine::new();

        assert!(!sm.is_complete());
        assert!(
            sm.violations(&Cursors {
                sui: u64::MAX,
                guardian: u64::MAX,
                btc: u64::MAX,
            })
            .is_empty()
        );
    }

    #[test]
    fn add_event_rejects_duplicate_source() {
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new();
        sm.add_event(event(WithdrawalEventType::E1HashiApproved, 1, 100, 1), &cfg)
            .expect("first event is valid");

        let err = sm
            .add_event(event(WithdrawalEventType::E1HashiApproved, 1, 110, 1), &cfg)
            .expect_err("duplicate source should fail");
        assert_eq!(err, MonitorError::DuplicateEventForSameWid);

        let wid_err = sm
            .add_event(
                event(WithdrawalEventType::E2GuardianApproved, 2, 120, 1),
                &cfg,
            )
            .expect_err("wid mismatch should fail");
        assert_eq!(wid_err, MonitorError::InvalidWid);

        let txid_err = sm
            .add_event(
                event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2),
                &cfg,
            )
            .expect_err("txid mismatch should fail");
        assert_eq!(txid_err, MonitorError::InvalidBtcTxid);
    }

    #[test]
    fn in_order_flow_completes() {
        let mut sm = WithdrawalStateMachine::new();
        let cfg = cfg();

        sm.add_event(event(WithdrawalEventType::E1HashiApproved, 9, 100, 7), &cfg)
            .expect("e1 is valid");
        assert!(sm.expects(WithdrawalEventType::E2GuardianApproved));

        sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
            &cfg,
        )
        .expect("e2 is valid");
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));

        sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7), &cfg)
            .expect("e3 is valid");

        assert!(sm.is_complete());
    }

    #[test]
    fn add_event_rejects_event_past_deadline() {
        let mut sm = WithdrawalStateMachine::new();
        let cfg = cfg();
        let e1 = event(WithdrawalEventType::E1HashiApproved, 4, 100, 4);
        let e2 = event(WithdrawalEventType::E2GuardianApproved, 4, 201, 4);

        sm.add_event(e1, &cfg).expect("e1 is valid");

        let err = sm
            .add_event(e2.clone(), &cfg)
            .expect_err("e2 should fail after deadline");
        assert_eq!(
            err,
            MonitorError::EventOccurredAfterDeadline {
                event: e2,
                deadline: 200,
                occurred_at: 201,
            }
        );
    }

    #[test]
    fn violations_only_after_cursor_passes_deadline() {
        let mut sm = WithdrawalStateMachine::new();
        let cfg = cfg();
        sm.add_event(event(WithdrawalEventType::E1HashiApproved, 1, 100, 5), &cfg)
            .expect("e1 is valid");

        let no_violation = sm.violations(&Cursors {
            sui: 0,
            guardian: 199,
            btc: 0,
        });
        assert!(no_violation.is_empty());

        let violations = sm.violations(&Cursors {
            sui: 0,
            guardian: 200,
            btc: 0,
        });
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorError::ExpectedEventMissing {
                event_type: WithdrawalEventType::E2GuardianApproved,
                deadline: 200,
                cursor: 200,
            }
        );
    }
}
