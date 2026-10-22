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
//! - Deposits: the deposit's block time may be after the Hashi
//!   approval by at most the skew. The Bitcoin event is the user's
//!   payment, so no delay bounds it.
//! - Deposit requests: Bitcoin is asked about a request's transaction for
//!   the watch period. The monitor assumes an honest deposit confirms on
//!   Bitcoin within it.
//! - The UTXO pool: a UTXO the bridge holds is reported by its age on
//!   Bitcoin, and by its absence from Bitcoin after a grace period.
//!
//! A Bitcoin event is timed by the block that gave the transaction Hashi's
//! confirmation threshold (see `rpc::btc`), not by the block that holds it.

use std::collections::BTreeMap;

use anyhow::anyhow;
use hashi_types::guardian::time::UnixSeconds;

use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;

/// E1 -> E2. The guardian signs about 15 minutes after a Hashi approval on
/// testnet. An hour covers a guardian restart or a reconfiguration.
pub const WITHDRAWAL_E1_TO_E2_DELAY: u64 = 60 * 60;

/// E2 -> E3. The signed transaction must confirm on Bitcoin within a day.
/// E3 is timed by the block that gave it the confirmation threshold, so the
/// bound includes the wait for those blocks, about 50 minutes at six.
pub const WITHDRAWAL_E2_TO_E3_DELAY: u64 = 24 * 60 * 60;

/// E1 after E2. The guardian's request clock tolerance is five minutes.
pub const WITHDRAWAL_E1_AFTER_E2_SKEW: u64 = 5 * 60;

/// E2 after E3. A block time is set by its miner and need only exceed the
/// median of the last 11 blocks, which lags real time by about an hour.
pub const WITHDRAWAL_E2_AFTER_E3_SKEW: u64 = 2 * 60 * 60;

/// A deposit's Bitcoin block after its Sui `DepositApproved`. A miner may
/// date a block up to two hours ahead of real time.
pub const DEPOSIT_APPROVAL_SKEW: u64 = 2 * 60 * 60;

/// How long Bitcoin is asked about a deposit request's transaction.
/// Assumption: an honest deposit confirms on Bitcoin within two days of
/// its request. Move marks a request expired after a day
/// (`MAX_DEPOSIT_REQUEST_AGE_MS` in `deposit_queue.move`) and an honest
/// leader deletes it then, so the user requests again, which is a new
/// watch. But Move does not refuse to approve an old request. A UTXO that
/// confirms after the watch never enters the UTXO pool, so an approval of
/// it is reported as `DepositUnbacked`.
pub const DEPOSIT_REQUEST_WATCH: u64 = 2 * 24 * 60 * 60;

/// Age of an unspent bridge UTXO that is a finding. The committee can spend
/// it alone at 60 days, so the finding leaves 20 days to act. Coin selection
/// in the `hashi` crate spends UTXOs older than 30 days first
/// (`RECOVERY_PRIORITY_AGE_BLOCKS`), but only as extra inputs of a withdrawal.
pub const UTXO_MAX_AGE: u64 = 40 * 24 * 60 * 60;

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
    pub deposit_approval_skew: u64,
    /// How long Bitcoin is asked about a deposit request's transaction.
    pub deposit_request_watch: u64,
    /// Age of an unspent bridge UTXO that is a finding.
    pub utxo_max_age: u64,
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
            deposit_approval_skew: DEPOSIT_APPROVAL_SKEW,
            deposit_request_watch: DEPOSIT_REQUEST_WATCH,
            utxo_max_age: UTXO_MAX_AGE,
        }
    }
}

impl Timing {
    /// The time by which `event`'s predecessor must be recorded.
    pub fn predecessor_deadline(&self, event: &MonitorWithdrawalEvent) -> UnixSeconds {
        let predecessor = event.event_type.predecessor().expect("has a predecessor");
        event.timestamp_secs
            + self
                .predecessor_skews
                .get(predecessor)
                .expect("a predecessor has a successor")
    }

    /// The time by which `event`'s successor must follow.
    pub fn successor_deadline(&self, event: &MonitorWithdrawalEvent) -> UnixSeconds {
        event.timestamp_secs
            + self
                .successor_delays
                .get(event.event_type)
                .expect("has a successor")
    }
}

#[cfg(test)]
impl Timing {
    /// Short bounds for tests: E1 -> E2 in 100 s and E2 -> E3 in 200 s, with
    /// skews of 10 s, 30 s and 10 s.
    pub fn for_tests() -> Self {
        Self {
            successor_delays: EventBounds::new([
                (WithdrawalEventType::E1HashiApproved, 100),
                (WithdrawalEventType::E2GuardianApproved, 200),
            ])
            .expect("valid successor delays"),
            predecessor_skews: EventBounds::new([
                (WithdrawalEventType::E1HashiApproved, 10),
                (WithdrawalEventType::E2GuardianApproved, 30),
            ])
            .expect("valid predecessor skews"),
            deposit_approval_skew: 10,
            deposit_request_watch: 1_000,
            utxo_max_age: 100,
        }
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
