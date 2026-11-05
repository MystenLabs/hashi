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
pub mod utxo_pool;
pub mod withdrawal;

use bitcoin::OutPoint;
use bitcoin::TxOut;
pub use deposit::BtcConfirmedDeposit;
pub use deposit::DepositId;
pub use deposit::FinishedDeposit;
pub use deposit::SuiDepositApprovedEvent;
pub use deposit::SuiDepositRequestedEvent;
use serde::Deserialize;
use serde::Serialize;
pub use withdrawal::FinishedWithdrawal;
pub use withdrawal::MonitorWithdrawalEvent;
pub use withdrawal::WithdrawalEventType;
pub use withdrawal::WithdrawalTx;

use std::fmt;

use hashi_types::guardian::time::UnixSeconds;

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
    /// A deposit Bitcoin confirmed at a bridge address, with a Sui
    /// `DepositApproved`.
    Deposit,
    /// A deposit Bitcoin confirmed at a bridge address, with no Sui
    /// `DepositApproved` yet. For example, a sanction or a user mistake keeps
    /// a deposit here.
    UnapprovedDeposit {
        /// The time of the latest request for the deposit. The approval
        /// deadline counts from it.
        requested_at: UnixSeconds,
        /// The amount that the latest request claims.
        requested_amount: u64,
    },
    /// A change output of a withdrawal Bitcoin confirmed.
    Change,
}

impl UtxoOrigin {
    /// Whether Move's pool holds the UTXO: an approved deposit, or change.
    /// Only these count in the pool value. Move adds an approved deposit
    /// after the deposit delay.
    pub fn in_move_pool(self) -> bool {
        !matches!(self, Self::UnapprovedDeposit { .. })
    }

    fn is_change(self) -> bool {
        self == Self::Change
    }

    /// The origin of a held UTXO after a second add with the origin `new`.
    /// `None` means that a deposit and change claim one outpoint.
    fn updated_by(self, new: Self) -> Option<Self> {
        // 1. A deposit and change cannot share an outpoint.
        if self.is_change() != new.is_change() {
            return None;
        }
        // 2. Both are change: a repeat keeps the held origin.
        if self.is_change() {
            return Some(self);
        }
        // 3. Both are deposits.
        match (self, new) {
            // A second request for an approved deposit. Move mints only once.
            (Self::Deposit, Self::Deposit | Self::UnapprovedDeposit { .. }) => Some(self),
            // An approval approves the held deposit.
            (Self::UnapprovedDeposit { .. }, Self::Deposit) => Some(Self::Deposit),
            // The later of two requests stays.
            (
                Self::UnapprovedDeposit {
                    requested_at: held_at,
                    ..
                },
                Self::UnapprovedDeposit { requested_at, .. },
            ) => Some(if requested_at > held_at { new } else { self }),
            (Self::Change, _) | (_, Self::Change) => {
                unreachable!("steps 1 and 2 return for change")
            }
        }
    }
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
