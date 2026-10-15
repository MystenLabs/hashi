// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Timing bounds of the withdrawal and deposit flows.
//!
//! Why it exists: the bounds describe the protocol, not a deployment. The
//! guardian signs within minutes of a Hashi approval, a Bitcoin block time
//! may run hours off real time, and six confirmations take about an hour.
//! Every environment runs the same values, so they live here and not in the
//! config file.
//!
//! How to change a bound: edit the constant and its reason below. If an
//! environment ever needs a different set, select it on
//! `deployment.retention_environment` and keep both sets in this file.
//!
//! The bounds, with E1, E2 and E3 as in `domain`:
//! - Withdrawals: each successor must follow its predecessor within its
//!   delay. Each predecessor may be recorded after its successor by at most
//!   its skew.
//! - Deposits: the Bitcoin confirmation time may be after the Hashi
//!   confirmation by at most the skew. The Bitcoin event is the user's
//!   payment, so no delay bounds it.
//!
//! A Bitcoin event is timed by the block that gave the transaction
//! `MIN_CONFIRMATIONS`, not by the block that holds it.

use std::collections::BTreeMap;

use anyhow::anyhow;

use crate::domain::WithdrawalEventType;

/// E1 -> E2. The guardian signs about 15 minutes after a Hashi approval on
/// testnet. An hour covers a guardian restart or a reconfiguration.
pub const WITHDRAWAL_E1_TO_E2_DELAY: u64 = 60 * 60;

/// E2 -> E3. The signed transaction must confirm on Bitcoin within a day.
/// E3 is timed by the block that gave it `MIN_CONFIRMATIONS`, so the bound
/// includes the wait for those blocks, about 50 minutes.
pub const WITHDRAWAL_E2_TO_E3_DELAY: u64 = 24 * 60 * 60;

/// E1 after E2. The guardian's request clock tolerance is five minutes.
pub const WITHDRAWAL_E1_AFTER_E2_SKEW: u64 = 5 * 60;

/// E2 after E3. A block time is set by its miner and need only exceed the
/// median of the last 11 blocks, which lags real time by about an hour.
pub const WITHDRAWAL_E2_AFTER_E3_SKEW: u64 = 2 * 60 * 60;

/// Deposit E1 after E2. E1 is timed by the block that gave the deposit its
/// confirmations, and a miner may date a block up to two hours ahead of
/// real time.
pub const DEPOSIT_CONFIRMATION_SKEW: u64 = 2 * 60 * 60;

/// The bounds in force. `Default` is the protocol set above. Tests build
/// their own with small numbers.
#[derive(Clone, Debug)]
pub struct Timing {
    /// Each withdrawal successor must follow its predecessor within this,
    /// keyed by the predecessor.
    pub successor_delays: EventBounds,
    /// Each withdrawal predecessor may be recorded after its successor by at
    /// most this, keyed by the predecessor.
    pub predecessor_skews: EventBounds,
    /// How far a deposit's confirmation time may be after its Hashi
    /// confirmation.
    pub deposit_confirmation_skew: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            successor_delays: EventBounds::new([
                (
                    WithdrawalEventType::E1HashiApproved,
                    WITHDRAWAL_E1_TO_E2_DELAY,
                ),
                (
                    WithdrawalEventType::E2GuardianApproved,
                    WITHDRAWAL_E2_TO_E3_DELAY,
                ),
            ])
            .expect("one bound per non-terminal event"),
            predecessor_skews: EventBounds::new([
                (
                    WithdrawalEventType::E1HashiApproved,
                    WITHDRAWAL_E1_AFTER_E2_SKEW,
                ),
                (
                    WithdrawalEventType::E2GuardianApproved,
                    WITHDRAWAL_E2_AFTER_E3_SKEW,
                ),
            ])
            .expect("one bound per non-terminal event"),
            deposit_confirmation_skew: DEPOSIT_CONFIRMATION_SKEW,
        }
    }
}

impl Timing {
    /// How far before the guardian audit start to scan Sui for E1. An E1
    /// precedes its E2 by at most the E1 delay; an older one is a late E2.
    /// An E1 outside the scan is still read from Sui by its withdrawal id.
    pub fn sui_lookback(&self) -> u64 {
        self.successor_delays
            .get(WithdrawalEventType::E1HashiApproved)
            .expect("E1 has a successor")
    }
}

/// One bound per non-terminal withdrawal event.
#[derive(Clone, Debug)]
pub struct EventBounds(BTreeMap<WithdrawalEventType, u64>);

impl EventBounds {
    /// The constructor ensures that there is one entry for every non-terminal
    /// event and none for the terminal one.
    pub fn new(
        bounds: impl IntoIterator<Item = (WithdrawalEventType, u64)>,
    ) -> anyhow::Result<Self> {
        let bounds: BTreeMap<_, _> = bounds.into_iter().collect();
        if bounds.contains_key(&WithdrawalEventType::TERMINAL_EVENT) {
            return Err(anyhow!(
                "a bound for the terminal event {:?} is not allowed",
                WithdrawalEventType::TERMINAL_EVENT
            ));
        }
        for event in WithdrawalEventType::NON_TERMINAL_EVENTS {
            if !bounds.contains_key(&event) {
                return Err(anyhow!("missing bound for {event:?}"));
            }
        }
        Ok(Self(bounds))
    }

    pub fn get(&self, event: WithdrawalEventType) -> Option<u64> {
        self.0.get(&event).copied()
    }

    pub fn max(&self) -> u64 {
        self.0.values().copied().max().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sui_lookback_is_the_e1_delay() {
        assert_eq!(Timing::default().sui_lookback(), WITHDRAWAL_E1_TO_E2_DELAY);
    }

    #[test]
    fn every_event_with_a_successor_needs_a_bound() {
        let error = EventBounds::new([(WithdrawalEventType::E1HashiApproved, 1)])
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("missing bound for E2GuardianApproved"),
            "{error}"
        );
    }

    #[test]
    fn the_terminal_event_takes_no_bound() {
        let error = EventBounds::new([
            (WithdrawalEventType::E1HashiApproved, 1),
            (WithdrawalEventType::E2GuardianApproved, 1),
            (WithdrawalEventType::E3BtcConfirmed, 1),
        ])
        .unwrap_err()
        .to_string();

        assert!(error.contains("terminal event"), "{error}");
    }
}
