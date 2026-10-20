// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The state machines that follow one flow each, by its events.
//!
//! A withdrawal has three events from three sources. A deposit is a user's
//! request resolved on Bitcoin for the UTXO pool; Hashi's confirmation of
//! it is checked against the pool. Each machine keeps what it has seen,
//! says what it still expects, and reports what is late or wrong.

mod deposit;
mod withdrawal;

pub use deposit::DepositStateMachine;
pub use withdrawal::WithdrawalStateMachine;

use crate::findings::MonitorFinding;

pub enum BtcFetchOutcome {
    NotExpected,
    Unconfirmed,
    Confirmed(Vec<MonitorFinding>),
}
