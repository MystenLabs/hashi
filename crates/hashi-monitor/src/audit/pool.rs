// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The monitor's own view of the bridge's UTXOs, anchored on Bitcoin.
//!
//! Why it exists: Move's `utxo_records` is written by the committee. A
//! compromised committee can mark a coin spent on Move without spending it on
//! Bitcoin, or keep a deposit out of Move, then spend the coin alone once the
//! 60-day recovery leaf opens. This pool only changes on a Bitcoin fact, so
//! the committee cannot make a coin leave it or keep one out of it.
//!
//! How it works:
//! 1. The pool starts empty, at the bridge's genesis. Move's records are
//!    never read for it. Keeping it between runs follows in a later change.
//! 2. A coin is added when Bitcoin confirms a deposit request's output at
//!    the bridge script of the claimed path. The committee is not needed.
//! 3. When a withdrawal flow is complete, E1, E2 and E3 seen, its change
//!    outputs are added and its inputs move to the spent record, with the
//!    spending txid. The inputs and amounts come from the confirmed Bitcoin
//!    transaction. Which outputs are change comes from E2: the guardian
//!    labels each output from paths it derives itself, and the committee's
//!    E1 is not trusted for it. A withdrawal that never completes never
//!    touches the pool, so its inputs stay held and the daily check reports
//!    them, on top of the finding for its missing event.
//! 4. Every operation is strict. An operation the pool already applied is a
//!    repeat and is skipped, so a restart can replay any range of events.
//!    An operation that contradicts the pool is a finding: an outpoint
//!    confirmed with a second amount, a coin spent by a second transaction,
//!    or a spend of a coin the pool never held. That last spend is recorded
//!    too, so a late add of the coin is a repeat.
//! 5. In one pass, every add comes before every spend. A pass can answer a
//!    deposit and the withdrawal that spends it, or a withdrawal and the one
//!    that spends its change, in any order.
//! 6. Once a day the monitor asks Bitcoin about every coin held. `check`
//!    turns the answers into findings. An unspent coin is reported by age.
//!    A spent coin is a spend outside Hashi. A missing coin is a phantom,
//!    after a grace period.
//!
//! Invariants:
//! - An outpoint is held or spent, never both.
//! - The spent record is never pruned. A spent coin is a few dozen bytes.
//! - The pool is a function of Bitcoin facts alone: a coin's time is its
//!   block time, so two monitors build the same pool.
//!
//! Assumptions:
//! - The first run starts at the bridge's genesis on a fullnode that still
//!   serves the history, so every coin is seen enter. A coin paid to a bridge
//!   address with no `DepositRequested`, or with a wrong derivation path, is
//!   invisible to the monitor and out of scope. A withdrawal that spends such
//!   a coin is reported as a spend of an unknown coin.
//! - A change output exists on Bitcoin only once its withdrawal confirms, so
//!   a coin may be missing for `UTXO_MISSING_GRACE` after it is first seen.

use std::collections::BTreeMap;
use std::collections::HashMap;

use bitcoin::OutPoint;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;

use crate::domain::BtcConfirmation;
use crate::domain::CoinOrigin;
use crate::domain::WithdrawalTx;
use crate::findings::MonitorFinding;
use crate::rpc::btc::OutpointState;
use crate::timing::Timing;

/// A coin the bridge holds, by Bitcoin's account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolCoin {
    pub amount: u64,
    pub origin: CoinOrigin,
    /// The time of the block that holds the coin.
    pub first_seen: UnixSeconds,
}

/// A coin a confirmed Hashi withdrawal spent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpentCoin {
    #[serde(flatten)]
    pub coin: PoolCoin,
    pub spent_by: Txid,
}

/// A withdrawal Bitcoin confirmed, with the approval that says which of its
/// outputs are change.
pub struct ConfirmedWithdrawal {
    pub txid: Txid,
    pub confirmation: BtcConfirmation,
    pub tx: WithdrawalTx,
}

/// The coins the bridge holds and the coins it spent, by Bitcoin's account.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(from = "StoredPool", into = "StoredPool")]
pub struct UtxoPool {
    coins: BTreeMap<OutPoint, PoolCoin>,
    spent: BTreeMap<OutPoint, SpentCoin>,
}

/// The pool as stored: two lists, since a JSON map needs string keys.
#[derive(Deserialize, Serialize)]
struct StoredPool {
    coins: Vec<StoredCoin>,
    spent: Vec<StoredSpentCoin>,
}

#[derive(Deserialize, Serialize)]
struct StoredCoin {
    outpoint: OutPoint,
    #[serde(flatten)]
    coin: PoolCoin,
}

#[derive(Deserialize, Serialize)]
struct StoredSpentCoin {
    outpoint: OutPoint,
    #[serde(flatten)]
    spent: SpentCoin,
}

impl From<StoredPool> for UtxoPool {
    fn from(stored: StoredPool) -> Self {
        Self {
            coins: stored
                .coins
                .into_iter()
                .map(|stored| (stored.outpoint, stored.coin))
                .collect(),
            spent: stored
                .spent
                .into_iter()
                .map(|stored| (stored.outpoint, stored.spent))
                .collect(),
        }
    }
}

impl From<UtxoPool> for StoredPool {
    fn from(pool: UtxoPool) -> Self {
        Self {
            coins: pool
                .coins
                .into_iter()
                .map(|(outpoint, coin)| StoredCoin { outpoint, coin })
                .collect(),
            spent: pool
                .spent
                .into_iter()
                .map(|(outpoint, spent)| StoredSpentCoin { outpoint, spent })
                .collect(),
        }
    }
}

impl UtxoPool {
    /// The outpoints held, in order.
    pub fn outpoints(&self) -> Vec<OutPoint> {
        self.coins.keys().copied().collect()
    }

    /// Add a deposit Bitcoin confirmed in the block at `block_time`.
    pub fn add_deposit(
        &mut self,
        outpoint: OutPoint,
        amount: u64,
        block_time: UnixSeconds,
    ) -> Option<MonitorFinding> {
        self.add(
            outpoint,
            PoolCoin {
                amount,
                origin: CoinOrigin::Deposit,
                first_seen: block_time,
            },
        )
    }

    /// Apply withdrawals Bitcoin confirmed: every change output enters,
    /// then every input is spent. See the module doc for why in that order.
    pub fn apply_confirmed_withdrawals(
        &mut self,
        withdrawals: &[ConfirmedWithdrawal],
    ) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for withdrawal in withdrawals {
            findings.extend(self.add_change_outputs(withdrawal));
        }
        for withdrawal in withdrawals {
            for input in &withdrawal.confirmation.inputs {
                findings.extend(self.spend(*input, withdrawal));
            }
        }
        findings
    }

    /// Add a withdrawal's change outputs. They trail the user payouts, as
    /// Move lays them out. A vout the transaction does not have is ignored.
    fn add_change_outputs(&mut self, withdrawal: &ConfirmedWithdrawal) -> Vec<MonitorFinding> {
        let first_change_vout = withdrawal.tx.withdrawal_outputs.len();
        let change_vouts =
            first_change_vout..first_change_vout + withdrawal.tx.change_outputs.len();
        change_vouts
            .filter_map(|vout| {
                let output = withdrawal.confirmation.outputs.get(vout)?;
                let outpoint = OutPoint {
                    txid: withdrawal.txid,
                    vout: vout as u32,
                };
                self.add(
                    outpoint,
                    PoolCoin {
                        amount: output.value.to_sat(),
                        origin: CoinOrigin::Change,
                        first_seen: withdrawal.confirmation.block_time,
                    },
                )
            })
            .collect()
    }

    /// Add a coin. A coin already held or spent with the same amount is a
    /// repeat and keeps its entry. One with another amount is a finding.
    fn add(&mut self, outpoint: OutPoint, coin: PoolCoin) -> Option<MonitorFinding> {
        let held_amount = match (self.coins.get(&outpoint), self.spent.get(&outpoint)) {
            (Some(held), _) => held.amount,
            (None, Some(spent)) => spent.coin.amount,
            (None, None) => {
                self.coins.insert(outpoint, coin);
                return None;
            }
        };
        (held_amount != coin.amount).then_some(MonitorFinding::UtxoAmountMismatch {
            outpoint,
            held_amount,
            seen_amount: coin.amount,
        })
    }

    /// Spend a coin. A coin already spent by this withdrawal is a repeat.
    /// One spent by another transaction, or never held, is a finding. The
    /// unknown coin is recorded as spent too, with the amount E2 states.
    fn spend(
        &mut self,
        outpoint: OutPoint,
        withdrawal: &ConfirmedWithdrawal,
    ) -> Option<MonitorFinding> {
        let txid = withdrawal.txid;
        if let Some(coin) = self.coins.remove(&outpoint) {
            self.spent.insert(
                outpoint,
                SpentCoin {
                    coin,
                    spent_by: txid,
                },
            );
            return None;
        }
        match self.spent.get(&outpoint) {
            Some(spent) if spent.spent_by == txid => None,
            Some(spent) => Some(MonitorFinding::UtxoSpentTwice {
                outpoint,
                first_txid: spent.spent_by,
                second_txid: txid,
            }),
            None => {
                let amount = withdrawal
                    .tx
                    .inputs
                    .iter()
                    .find(|input| {
                        Txid::from(input.id.txid) == outpoint.txid && input.id.vout == outpoint.vout
                    })
                    .map_or(0, |input| input.amount);
                self.spent.insert(
                    outpoint,
                    SpentCoin {
                        coin: PoolCoin {
                            amount,
                            origin: CoinOrigin::Unknown,
                            first_seen: withdrawal.confirmation.block_time,
                        },
                        spent_by: txid,
                    },
                );
                Some(MonitorFinding::UtxoUnknownInputSpent { outpoint, txid })
            }
        }
    }

    /// The findings of one pass over Bitcoin's answer for every coin held.
    /// A coin with no answer counts as missing.
    pub fn check(
        &self,
        states: &HashMap<OutPoint, OutpointState>,
        now: UnixSeconds,
        timing: &Timing,
    ) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for (outpoint, coin) in &self.coins {
            match states.get(outpoint) {
                Some(OutpointState::Unspent { block_time }) => {
                    let age_secs = now.saturating_sub(*block_time);
                    if age_secs >= timing.utxo_age_critical {
                        findings.push(MonitorFinding::UtxoTooOld {
                            outpoint: *outpoint,
                            age_secs,
                            threshold_secs: timing.utxo_age_critical,
                            critical: true,
                        });
                    } else if age_secs >= timing.utxo_age_warn {
                        findings.push(MonitorFinding::UtxoTooOld {
                            outpoint: *outpoint,
                            age_secs,
                            threshold_secs: timing.utxo_age_warn,
                            critical: false,
                        });
                    }
                }
                Some(OutpointState::Spent) => {
                    findings.push(MonitorFinding::UtxoUnexpectedSpend {
                        outpoint: *outpoint,
                        amount: coin.amount,
                    });
                }
                Some(OutpointState::Missing) | None => {
                    if now.saturating_sub(coin.first_seen) >= timing.utxo_missing_grace {
                        findings.push(MonitorFinding::UtxoVanished {
                            outpoint: *outpoint,
                            first_seen: coin.first_seen,
                        });
                    }
                }
            }
        }
        findings
    }
}
