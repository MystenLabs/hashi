// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The monitor's core types: the events it follows, their ids, and the
//! cursors of its sources.
//!
//! Why it exists: every source, Sui, the guardian's S3 logs and Bitcoin, is
//! parsed into one of these events, and the state machines reason about the
//! events alone. Each event type has a constructor named for its source, so
//! the mapping from a source's shape to the monitor's lives next to the type.
//!
//! The flows:
//! - A withdrawal is three events: E1, the Hashi approval on Sui; E2, the
//!   guardian's signature in its log; E3, the transaction confirmed on
//!   Bitcoin. Every event states the transaction in Move's shape,
//!   `WithdrawalTx`, so the sources can be compared as a whole.
//! - A deposit is two events: E1, the output confirmed on Bitcoin; E2,
//!   Hashi's `DepositConfirmed` on Sui.
//!
//! Formatting of times lives in `time`, and the bridge keys in `keys`.

pub mod deposit;
pub mod withdrawal;

use bitcoin::TxOut;
pub use deposit::DepositEventType;
pub use deposit::DepositId;
pub use deposit::MonitorDepositEvent;
pub use withdrawal::MonitorWithdrawalEvent;
pub use withdrawal::WithdrawalEventType;
pub use withdrawal::WithdrawalTx;

use std::fmt;

use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;

use crate::findings::MonitorFinding;
use crate::time::utc_timestamp;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorEvent {
    Withdrawal(MonitorWithdrawalEvent),
    Deposit(MonitorDepositEvent),
}

impl fmt::Display for MonitorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Withdrawal(event) => write!(
                formatter,
                "Withdrawal(type={:?}, wid={}, timestamp={}, btc_txid={})",
                event.event_type,
                event.wid,
                utc_timestamp(event.timestamp_secs),
                event.btc_txid,
            ),
            Self::Deposit(event) => write!(
                formatter,
                "Deposit(type={:?}, deposit_id={}, timestamp={}, amount={}, script_pubkey={:x})",
                event.event_type,
                event.deposit_id,
                utc_timestamp(event.timestamp_secs),
                event.amount,
                event.script_pubkey,
            ),
        }
    }
}

/// Correlation identifier for an event in the monitor's withdrawal or deposit model.
/// This is not a chain-native event ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorEventId {
    Withdrawal(WithdrawalID),
    Deposit(DepositId),
}

impl fmt::Display for MonitorEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Withdrawal(wid) => write!(formatter, "wid={wid}"),
            Self::Deposit(deposit_id) => write!(formatter, "deposit_id={deposit_id}"),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum MonitorEventType {
    Withdrawal(WithdrawalEventType),
    Deposit(DepositEventType),
}

/// A transaction mined at least `MIN_CONFIRMATIONS` blocks deep.
#[derive(Clone, Debug)]
pub struct BtcConfirmation {
    /// The time of the block that holds the transaction. The recovery leaf's
    /// clock starts at this block, so a coin's age counts from here.
    pub block_time: UnixSeconds,
    /// The time of the block that gave the transaction `MIN_CONFIRMATIONS`.
    /// The bridge acts on that block, so the Bitcoin events carry this time.
    pub confirmed_time: UnixSeconds,
    /// The transaction's outputs, in order.
    pub outputs: Vec<TxOut>,
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

/// Outcome of a Guardian or Sui poll
pub enum PollOutcome {
    /// The events of the newly scanned range, and the findings of events that failed a check.
    CursorAdvanced {
        events: Vec<MonitorEvent>,
        findings: Vec<MonitorFinding>,
    },
    CursorUnmoved,
}
