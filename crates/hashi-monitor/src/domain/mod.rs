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
//! - A deposit is three events: E1, the user's `DepositRequested` on Sui;
//!   E2, the output confirmed on Bitcoin; E3, the `DepositApproved` on
//!   Sui, after which Move mints. Each request is followed on its own.
//!
//! Formatting of times lives in `time`, and the bridge keys in `keys`.

pub mod deposit;
pub mod withdrawal;

use bitcoin::OutPoint;
use bitcoin::TxOut;
pub use deposit::ConfirmedDeposit;
pub use deposit::DepositId;
pub use deposit::SuiDepositApprovedEvent;
pub use deposit::SuiDepositRequestedEvent;
use serde::Deserialize;
use serde::Serialize;
pub use withdrawal::ConfirmedWithdrawal;
pub use withdrawal::MonitorWithdrawalEvent;
pub use withdrawal::WithdrawalEventType;
pub use withdrawal::WithdrawalTx;

use std::fmt;

use hashi_types::guardian::time::UnixSeconds;

use crate::findings::MonitorFinding;
use crate::time::utc_timestamp;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorEvent {
    Withdrawal(MonitorWithdrawalEvent),
    DepositApproved(SuiDepositApprovedEvent),
    DepositRequested(SuiDepositRequestedEvent),
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
            Self::DepositApproved(event) => write!(
                formatter,
                "DepositApproved(request_id={}, deposit_id={}, timestamp={}, amount={}, script_pubkey={:x})",
                event.request_id,
                event.deposit_id,
                utc_timestamp(event.timestamp_secs),
                event.amount,
                event.script_pubkey,
            ),
            Self::DepositRequested(event) => write!(
                formatter,
                "DepositRequested(request_id={}, deposit_id={}, timestamp={}, amount={}, script_pubkey={:x})",
                event.request_id,
                event.deposit_id,
                utc_timestamp(event.timestamp_secs),
                event.amount,
                event.script_pubkey,
            ),
        }
    }
}

/// A transaction mined at least Hashi's confirmation threshold deep.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BtcConfirmation {
    /// The time of the block that holds the transaction. The recovery leaf's
    /// clock starts at this block, so a UTXO's age counts from here.
    pub block_time: UnixSeconds,
    /// The time of the block that gave the transaction the threshold depth.
    /// The bridge acts on that block, so the Bitcoin events carry this time.
    pub confirmed_time: UnixSeconds,
    /// The outpoints the transaction spends, in order.
    pub inputs: Vec<OutPoint>,
    /// The transaction's outputs, in order.
    pub outputs: Vec<TxOut>,
}

/// How a UTXO entered the monitor's UTXO pool.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UtxoOrigin {
    /// A deposit Bitcoin confirmed at a bridge address.
    Deposit,
    /// A change output of a withdrawal Bitcoin confirmed.
    Change,
}

/// The time through which each source has been read.
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
}

/// Outcome of a guardian or Sui poll.
pub enum PollOutcome {
    /// The events of the newly scanned range, and the findings of events that failed a check.
    CursorAdvanced {
        events: Vec<MonitorEvent>,
        findings: Vec<MonitorFinding>,
    },
    CursorUnmoved,
}
