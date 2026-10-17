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

#[cfg(test)]
impl UtxoPool {
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<&PoolCoin> {
        self.coins.get(outpoint)
    }

    pub fn get_spent(&self, outpoint: &OutPoint) -> Option<&SpentCoin> {
        self.spent.get(outpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::TxOut;
    use hashi_types::move_types::OutputUtxo;
    use hashi_types::move_types::Utxo;
    use hashi_types::move_types::UtxoId;

    use crate::findings::FindingCategory;
    use crate::test_utils::txid;

    // `Timing::for_tests` values.
    const WARN: u64 = 100;
    const CRITICAL: u64 = 200;
    const GRACE: u64 = 50;

    fn outpoint(fill: u8) -> OutPoint {
        OutPoint {
            txid: txid(fill),
            vout: 0,
        }
    }

    fn output(amount: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }
    }

    /// A withdrawal `txid(fill)` with one user payout and one change output
    /// of 550 at vout 1, spending `inputs`. E2 states each input at 1_000.
    fn withdrawal(fill: u8, inputs: Vec<OutPoint>) -> ConfirmedWithdrawal {
        let stated_inputs = inputs
            .iter()
            .map(|input| Utxo {
                id: UtxoId {
                    txid: input.txid.into(),
                    vout: input.vout,
                },
                amount: 1_000,
                derivation_path: None,
            })
            .collect();
        ConfirmedWithdrawal {
            txid: txid(fill),
            confirmation: BtcConfirmation {
                block_time: 700,
                confirmed_time: 760,
                inputs,
                outputs: vec![output(400), output(550)],
            },
            tx: WithdrawalTx::new(
                stated_inputs,
                vec![OutputUtxo {
                    amount: 400,
                    bitcoin_address: vec![0x53; 20],
                }],
                vec![OutputUtxo {
                    amount: 550,
                    bitcoin_address: vec![0x54; 20],
                }],
            ),
        }
    }

    fn change_of(fill: u8) -> OutPoint {
        OutPoint {
            txid: txid(fill),
            vout: 1,
        }
    }

    /// A pool holding `outpoint(1)` of 1_000, first seen at 500.
    fn pool_with_one() -> UtxoPool {
        pool_seen_at(500)
    }

    /// A pool holding `outpoint(1)` of 1_000, first seen at `first_seen`.
    fn pool_seen_at(first_seen: UnixSeconds) -> UtxoPool {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(outpoint(1), 1_000, first_seen).is_none());
        pool
    }

    /// The findings of a check with `state` as Bitcoin's answer for
    /// `outpoint(1)`.
    fn check_one(
        pool: &UtxoPool,
        state: Option<OutpointState>,
        now: UnixSeconds,
    ) -> Vec<MonitorFinding> {
        let states = state
            .map(|state| HashMap::from([(outpoint(1), state)]))
            .unwrap_or_default();
        pool.check(&states, now, &Timing::for_tests())
    }

    #[test]
    fn a_confirmed_withdrawal_spends_its_inputs_and_adds_its_change() {
        let mut pool = pool_with_one();
        assert!(pool.add_deposit(outpoint(2), 2_000, 500).is_none());

        let findings = pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(findings.is_empty());
        assert_eq!(pool.outpoints(), vec![outpoint(2), change_of(7)]);
        assert_eq!(
            pool.get(&change_of(7)),
            Some(&PoolCoin {
                amount: 550,
                origin: CoinOrigin::Change,
                first_seen: 700
            })
        );
        assert_eq!(
            pool.get_spent(&outpoint(1)),
            Some(&SpentCoin {
                coin: PoolCoin {
                    amount: 1_000,
                    origin: CoinOrigin::Deposit,
                    first_seen: 500
                },
                spent_by: txid(7),
            })
        );
    }

    #[test]
    fn a_change_vout_the_transaction_lacks_is_ignored() {
        let mut pool = UtxoPool::default();
        let mut withdrawal = withdrawal(7, vec![]);
        withdrawal.confirmation.outputs.pop();

        assert!(pool.apply_confirmed_withdrawals(&[withdrawal]).is_empty());

        assert!(pool.is_empty());
    }

    #[test]
    fn a_repeated_add_keeps_the_coin_and_another_amount_is_a_finding() {
        let mut pool = pool_with_one();

        assert!(pool.add_deposit(outpoint(1), 1_000, 900).is_none());
        assert_eq!(pool.get(&outpoint(1)).unwrap().first_seen, 500);

        let finding = pool.add_deposit(outpoint(1), 1_001, 900).unwrap();
        assert_eq!(
            finding,
            MonitorFinding::UtxoAmountMismatch {
                outpoint: outpoint(1),
                held_amount: 1_000,
                seen_amount: 1_001,
            }
        );
        assert_eq!(finding.category(), FindingCategory::Safety);
    }

    #[test]
    fn a_replayed_add_of_a_spent_coin_is_a_repeat() {
        let mut pool = pool_with_one();
        pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(pool.add_deposit(outpoint(1), 1_000, 900).is_none());
        assert!(pool.get(&outpoint(1)).is_none());
        assert_eq!(pool.get_spent(&outpoint(1)).unwrap().spent_by, txid(7));

        assert!(matches!(
            pool.add_deposit(outpoint(1), 1_001, 900),
            Some(MonitorFinding::UtxoAmountMismatch { .. })
        ));
    }

    #[test]
    fn a_replayed_spend_is_a_repeat_and_a_second_spender_is_a_finding() {
        let mut pool = pool_with_one();
        pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(
            pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])])
                .is_empty()
        );

        let findings = pool.apply_confirmed_withdrawals(&[withdrawal(8, vec![outpoint(1)])]);
        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoSpentTwice {
                outpoint: outpoint(1),
                first_txid: txid(7),
                second_txid: txid(8),
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn spending_a_coin_the_pool_never_held_is_a_finding_and_is_recorded() {
        let mut pool = UtxoPool::default();

        let findings = pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(9)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: outpoint(9),
                txid: txid(7),
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Liveness);
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
        assert_eq!(
            pool.get_spent(&outpoint(9)),
            Some(&SpentCoin {
                coin: PoolCoin {
                    amount: 1_000,
                    origin: CoinOrigin::Unknown,
                    first_seen: 700,
                },
                spent_by: txid(7),
            })
        );

        // The coin's deposit arrives late: a repeat, not a held coin.
        assert!(pool.add_deposit(outpoint(9), 1_000, 600).is_none());
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
    }

    #[test]
    fn in_one_pass_every_add_comes_before_every_spend() {
        // Withdrawal 8 spends the change of withdrawal 7, and the pass lists
        // the spender first.
        let mut pool = UtxoPool::default();

        let findings = pool.apply_confirmed_withdrawals(&[
            withdrawal(8, vec![change_of(7)]),
            withdrawal(7, vec![]),
        ]);

        assert!(findings.is_empty());
        assert_eq!(pool.outpoints(), vec![change_of(8)]);
        assert_eq!(pool.get_spent(&change_of(7)).unwrap().spent_by, txid(8));
    }

    #[test]
    fn a_young_unspent_coin_is_fine() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };
        assert!(check_one(&pool, Some(state), 1_000 + WARN - 1).is_empty());
    }

    #[test]
    fn an_unspent_coin_is_reported_at_the_warn_age_then_the_critical_age() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };

        let warn = check_one(&pool, Some(state.clone()), 1_000 + WARN);
        assert_eq!(
            warn,
            vec![MonitorFinding::UtxoTooOld {
                outpoint: outpoint(1),
                age_secs: WARN,
                threshold_secs: WARN,
                critical: false,
            }]
        );
        assert_eq!(warn[0].category(), FindingCategory::Liveness);

        let critical = check_one(&pool, Some(state), 1_000 + CRITICAL);
        assert_eq!(
            critical,
            vec![MonitorFinding::UtxoTooOld {
                outpoint: outpoint(1),
                age_secs: CRITICAL,
                threshold_secs: CRITICAL,
                critical: true,
            }]
        );
        assert_eq!(critical[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_spent_coin_is_an_unexpected_spend() {
        let pool = pool_seen_at(0);
        let findings = check_one(&pool, Some(OutpointState::Spent), 1);
        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnexpectedSpend {
                outpoint: outpoint(1),
                amount: 1_000,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_missing_coin_is_reported_only_after_the_grace_period() {
        let pool = pool_seen_at(1_000);

        assert!(check_one(&pool, Some(OutpointState::Missing), 1_000 + GRACE - 1).is_empty());
        // No answer at all counts as missing.
        assert!(check_one(&pool, None, 1_000 + GRACE - 1).is_empty());

        let findings = check_one(&pool, Some(OutpointState::Missing), 1_000 + GRACE);
        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoVanished {
                outpoint: outpoint(1),
                first_seen: 1_000,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_spent_coin_is_not_checked() {
        let mut pool = pool_seen_at(0);
        pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(check_one(&pool, Some(OutpointState::Spent), 1).is_empty());
    }

    #[test]
    fn a_pool_round_trips_through_json() {
        let mut pool = pool_with_one();
        pool.add_deposit(outpoint(2), 2_000, 1_500);
        pool.apply_confirmed_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let json = serde_json::to_vec(&pool).unwrap();
        let loaded: UtxoPool = serde_json::from_slice(&json).unwrap();

        assert_eq!(loaded.outpoints(), pool.outpoints());
        assert_eq!(loaded.get(&outpoint(2)), pool.get(&outpoint(2)));
        assert_eq!(loaded.get(&change_of(7)), pool.get(&change_of(7)));
        assert_eq!(loaded.get_spent(&outpoint(1)), pool.get_spent(&outpoint(1)));
    }
}
