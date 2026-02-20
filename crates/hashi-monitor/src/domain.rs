//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of events:
//! - E1 or E_hashi: Hashi approval event on sui (corresponds to WithdrawalPickedForProcessingEvent)
//! - E2 or E_guardian: Guardian approval event on S3 (corresponds to NormalWithdrawalSuccess)
//! - E3 or E_btc: BTC tx broadcast
//!
//! Predecessor checks: for every E_{i+1}, there exists a corresponding E_i within a small clock skew.
//! Successor checks: for every E_i, there exists a corresponding E_{i+1} within time `t`.
//!
//! TODO: Track IOP-203 which plans to add a check in Sui: match the withdrawal destination & amount that a user inputs with that in E_hashi.
//! The monitor is insecure without this check as a malicious hashi committee can include an arbitrary destination address.

use std::collections::BTreeSet;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use serde::Deserialize;

use crate::OutputUTXO;

pub type UnixSeconds = u64;

pub fn now_unix_seconds() -> UnixSeconds {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Note that utxo's are, strictly speaking, unnecessary to monitor, and txid tracking alone suffices.
/// We keep track of it for the sake of providing richer context when something fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalEvent {
    /// Who produced the event?
    pub event_type: WithdrawalEventType,

    /// Stable withdrawal identifier.
    pub wid: WithdrawalID,

    /// Unix timestamp of sui checkpoint / s3 log / btc block
    pub timestamp: UnixSeconds,

    /// btc txid
    pub btc_txid: Txid,

    /// output utxo's belonging to external parties
    /// TODO: Check address belongs to right network for all UTXO's
    pub external_output_utxos: BTreeSet<OutputUTXO>,

    /// output utxo's belonging to hashi
    pub internal_output_utxos: BTreeSet<OutputUTXO>,
}

/// Event source or type.
/// Note: Make sure WithdrawalEventType::NON_TERMINAL_EVENTS and TERMINAL_EVENT are up-to-date.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Hash)]
pub enum WithdrawalEventType {
    /// E_hashi
    E1HashiApproved,
    /// E_guardian
    E2GuardianApproved,
    /// E_btc
    E3BtcConfirmed,
}

impl WithdrawalEventType {
    pub const NON_TERMINAL_EVENTS: [WithdrawalEventType; 2] =
        [Self::E1HashiApproved, Self::E2GuardianApproved];
    pub const TERMINAL_EVENT: Self = Self::E3BtcConfirmed;

    pub fn successor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => Some(WithdrawalEventType::E2GuardianApproved),
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E3BtcConfirmed),
            WithdrawalEventType::E3BtcConfirmed => None,
        }
    }

    pub fn has_successor(&self) -> bool {
        self.successor().is_some()
    }

    pub fn predecessor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => None,
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E1HashiApproved),
            WithdrawalEventType::E3BtcConfirmed => Some(WithdrawalEventType::E2GuardianApproved),
        }
    }
}

/// Per-source cursors tracking how far we've read from each data source.
#[derive(Clone, Copy, Debug)]
pub struct Cursors {
    pub sui: UnixSeconds,
    pub guardian: UnixSeconds,
}

impl Cursors {
    pub fn for_event_type(&self, et: WithdrawalEventType) -> UnixSeconds {
        match et {
            WithdrawalEventType::E1HashiApproved => self.sui,
            WithdrawalEventType::E2GuardianApproved => self.guardian,
            WithdrawalEventType::E3BtcConfirmed => {
                unreachable!("E3 cursor is tracked per-withdrawal via btc_checked_at")
            }
        }
    }

    pub fn min(&self) -> UnixSeconds {
        self.sui.min(self.guardian)
    }
}
