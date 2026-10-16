// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The state machines that follow one flow each, by its events.
//!
//! A withdrawal has three events from three sources, and a deposit a Sui
//! claim checked against Bitcoin. Each machine keeps what it has seen,
//! says what it still expects, and reports what is late or wrong.

mod deposit;
mod withdrawal;

pub use deposit::DepositStateMachine;
pub use deposit::deposit_mismatch;
pub use withdrawal::WithdrawalStateMachine;

use crate::findings::MonitorFinding;

pub enum BtcFetchOutcome {
    NotExpected,
    Unconfirmed,
    Confirmed(Vec<MonitorFinding>),
}
