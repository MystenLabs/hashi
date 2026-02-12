//! Withdrawal state machine for tracking event flow.

use bitcoin::Txid;
use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::EventType;
use crate::domain::MonitorError;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

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
    expected_events: Vec<(EventType, UnixSeconds)>,
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

    pub fn get(&self, source: EventType) -> Option<&WithdrawalEvent> {
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

    pub fn expects(&self, source: EventType) -> bool {
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
            return Err(MonitorError::InternalError(
                "duplicate event for same wid".to_string(),
            ));
        }

        if !self.seen_events.is_empty() && self.seen_events.iter().any(|e| e.wid() != cur_event_wid)
        {
            return Err(MonitorError::InternalError("invalid wid".to_string()));
        }

        if !self.seen_events.is_empty()
            && self
                .seen_events
                .iter()
                .any(|e| e.btc_txid() != cur_event_btc_txid)
        {
            return Err(MonitorError::InternalError("invalid btc txid".to_string()));
        }

        // if neighbor is there, then we check that the gap between the two is as expected.
        for (src, deadline) in self.expected_events.iter() {
            if *src == cur_event_source && *deadline > cur_event_timestamp {
                return Err(MonitorError::InternalError(format!(
                    "expected {:?} to occur by {} whereas it occurred at {}",
                    cur_event_source, deadline, cur_event_timestamp
                )));
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
        if !self.expects(EventType::E3BtcConfirmed) {
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
                let e3 = WithdrawalEvent::new(EventType::E3BtcConfirmed, wid, block_time, txid);
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
                out.push(MonitorError::InternalError(format!(
                    "expected event {:?} to occur by {} (cursor={})",
                    event_type, deadline, cursor
                )));
            }
        }
        out
    }
}
