//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of event sets:
//! - E1: Hashi approval event on sui (PendingWithdrawal creation)
//! - E2: Guardian approval event on S3
//! - E3: BTC tx broadcast
//!
//! Predecessor checks: for every E_{i+1}, there exists a corresponding E_i within a small clock skew.
//! Successor checks: for every E_i, there exists a corresponding E_{i+1} within time `t`.
//!
//! E2 also triggers a BTC RPC check to verify the transaction exists on Bitcoin.

use std::error::Error as StdError;
use std::fmt;

use bitcoin::Txid;
use hashi_guardian_shared::WithdrawalID;

pub type UnixSeconds = u64;

pub fn now_unix_seconds() -> UnixSeconds {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// TODO: Add external_address, amount, etc?
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalEvent {
    /// Who produced the event?
    source: EventType,

    /// Stable withdrawal identifier.
    wid: WithdrawalID,

    /// Unix timestamp of sui checkpoint / s3 log / btc block
    timestamp: UnixSeconds,

    /// btc txid
    btc_txid: Txid,
}

impl WithdrawalEvent {
    pub fn new(
        source: EventType,
        wid: WithdrawalID,
        timestamp: UnixSeconds,
        btc_txid: Txid,
    ) -> Self {
        Self {
            source,
            wid,
            timestamp,
            btc_txid,
        }
    }

    pub fn source(&self) -> &EventType {
        &self.source
    }
    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }
    pub fn timestamp(&self) -> UnixSeconds {
        self.timestamp
    }
    pub fn btc_txid(&self) -> Txid {
        self.btc_txid
    }
}

/// Event source or type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EventType {
    E1HashiApproved,
    E2GuardianApproved,
    E3BtcConfirmed,
}

impl EventType {
    pub(crate) fn successor(&self) -> Option<Self> {
        match self {
            EventType::E1HashiApproved => Some(EventType::E2GuardianApproved),
            EventType::E2GuardianApproved => Some(EventType::E3BtcConfirmed),
            EventType::E3BtcConfirmed => None,
        }
    }

    pub(crate) fn predecessor(&self) -> Option<Self> {
        match self {
            EventType::E1HashiApproved => None,
            EventType::E2GuardianApproved => Some(EventType::E1HashiApproved),
            EventType::E3BtcConfirmed => Some(EventType::E2GuardianApproved),
        }
    }
}

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorError {
    InternalError(String),
}

impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl StdError for MonitorError {}

/// Per-source cursors tracking how far we've read from each data source.
#[derive(Clone, Copy, Debug)]
pub struct Cursors {
    pub sui: UnixSeconds,
    pub guardian: UnixSeconds,
    pub btc: UnixSeconds,
}

impl Cursors {
    pub fn for_event_type(&self, et: EventType) -> UnixSeconds {
        match et {
            EventType::E1HashiApproved => self.sui,
            EventType::E2GuardianApproved => self.guardian,
            EventType::E3BtcConfirmed => self.btc,
        }
    }
}
