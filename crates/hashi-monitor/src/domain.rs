//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of event sets:
//! - E1: Hashi approval event on sui (PendingWithdrawal creation)
//! - E2: Guardian approval event on S3
//! - E3: BTC tx broadcast
//!
//! Predecessor checks: for every E_{i+1}, there exists a corresponding E_i within a small clock skew.
//! Successor checks: for every E_i, there exists a corresponding E_{i+1} within time `t`.

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
    source: WithdrawalEventType,

    /// Stable withdrawal identifier.
    wid: WithdrawalID,

    /// Unix timestamp of sui checkpoint / s3 log / btc block
    timestamp: UnixSeconds,

    /// btc txid
    btc_txid: Txid,
}

impl WithdrawalEvent {
    pub fn new(
        source: WithdrawalEventType,
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

    pub fn source(&self) -> &WithdrawalEventType {
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
pub enum WithdrawalEventType {
    E1HashiApproved,
    E2GuardianApproved,
    E3BtcConfirmed,
}

impl WithdrawalEventType {
    pub fn successor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => Some(WithdrawalEventType::E2GuardianApproved),
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E3BtcConfirmed),
            WithdrawalEventType::E3BtcConfirmed => None,
        }
    }

    pub fn predecessor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => None,
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E1HashiApproved),
            WithdrawalEventType::E3BtcConfirmed => Some(WithdrawalEventType::E2GuardianApproved),
        }
    }
}

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorError {
    DuplicateEventForSameWid,
    InvalidWid,
    InvalidBtcTxid,
    EventOccurredAfterDeadline {
        event: WithdrawalEvent,
        deadline: UnixSeconds,
        occurred_at: UnixSeconds, // same as event.timestamp
    },
    ExpectedEventMissing {
        event_type: WithdrawalEventType,
        deadline: UnixSeconds,
        cursor: UnixSeconds,
    },
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
    // note: btc cursor is usually just the current time as we just do point queries;
    // we define it for uniformity.
    pub btc: UnixSeconds,
}

impl Cursors {
    pub fn for_event_type(&self, et: WithdrawalEventType) -> UnixSeconds {
        match et {
            WithdrawalEventType::E1HashiApproved => self.sui,
            WithdrawalEventType::E2GuardianApproved => self.guardian,
            WithdrawalEventType::E3BtcConfirmed => self.btc,
        }
    }
}
