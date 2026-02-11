//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of event sets:
//! - E1: Sui withdrawal initiation (user intent)
//! - E2: Guardian approval
//! - E3: Hashi approval (on Sui)
//!
//! Safety checks: for every event in E_{i+1}, there exists a corresponding event in E_i.
//! Liveness checks: for every event in E_i, there exists a corresponding event in E_{i+1} within time `t`.
//!
//! E3 triggers a BTC RPC check to verify the transaction exists on Bitcoin (liveness).
//!
//! For now, only information critical for security or liveness checks is added to the events.
//! TODO: More info can be added later to the event fields, e.g., external_address, amount, etc.

use std::error::Error as StdError;
use std::fmt;

use bitcoin::Txid;
use hashi_guardian_shared::WithdrawalID;

/// Unix timestamp (seconds).
///
/// Used for liveness checks ("event in E_{i+1} within time t").
pub type UnixSeconds = u64;

/// (E1) A Sui-side withdrawal initiation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E1SuiInit {
    /// Stable ID for the withdrawal request.
    pub wid: WithdrawalID,
    /// Unix timestamp of the cursor checkpoint in which this init appears.
    pub timestamp: UnixSeconds,
}

/// (E2) Guardian signing and approval event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E2GuardianApproved {
    /// Stable withdrawal identifier.
    pub wid: WithdrawalID,

    /// Bitcoin transaction id authorized by the Guardian.
    pub btc_txid: Txid,

    /// Unix timestamp in the corresponding Guardian log record.
    pub timestamp: UnixSeconds,
}

/// (E3) Hashi signing and approval event on Sui.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E3SuiApproved {
    /// Stable withdrawal identifier.
    pub wid: WithdrawalID,

    /// Bitcoin transaction id approved by Hashi and recorded on Sui.
    pub btc_txid: Txid,

    /// Unix timestamp of the cursor checkpoint in which approval appears.
    pub timestamp: UnixSeconds,
}

/// A unified view of events relevant to the withdrawal flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WithdrawalEvent {
    SuiInit(E1SuiInit),
    GuardianApproved(E2GuardianApproved),
    SuiApproved(E3SuiApproved),
}

impl WithdrawalEvent {
    /// Unix timestamp (seconds) associated with this event.
    pub fn timestamp(&self) -> UnixSeconds {
        match self {
            Self::SuiInit(e) => e.timestamp,
            Self::GuardianApproved(e) => e.timestamp,
            Self::SuiApproved(e) => e.timestamp,
        }
    }
}

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Finding {
    /// Safety violation: observed an `E_{i+1}` event without a corresponding `E_i`.
    /// The recorded event type implicitly tells us the missing predecessor's event type.
    SafetyMissingPredecessor(WithdrawalEvent),

    /// Liveness violation: observed an `E_{i}` event without a corresponding `E_{i+1}` after some delay.
    /// The recorded event type implicitly tells us the missing successor's event type.
    LivenessMissingSuccessor(WithdrawalEvent),

    /// Use for all other internal errors.
    InternalError {
        /// The observed event that triggered the check.
        observed: WithdrawalEvent,

        /// The other event that conflicted with `observed`.
        other: WithdrawalEvent,

        /// Details of the finding
        details: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl StdError for Finding {}
