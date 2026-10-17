// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The monitor's own view of the bridge's UTXOs, anchored on Bitcoin.
//!
//! Why it exists: Move's `utxo_records` is written by the committee. A
//! compromised committee can mark a UTXO spent on Move without spending it on
//! Bitcoin, or keep a deposit out of Move, then spend the UTXO alone once the
//! 60-day recovery leaf opens. This pool only changes on a Bitcoin fact, so
//! the committee cannot make a UTXO leave it or keep one out of it.
//!
//! Scope: this module does two things. It keeps an accurate record of the
//! UTXOs Hashi holds, built from Bitcoin facts alone. It makes every
//! operation safe to replay, so a restart can feed it the same facts again.
//! The pool is Bitcoin's answers for the outputs the bridge's events name:
//! a deposit request names an outpoint, a withdrawal names a txid, and the
//! pool keeps what Bitcoin confirms for them. The one label Bitcoin cannot
//! give, which outputs of a withdrawal are change, comes from the guardian,
//! and it is verified: the monitor derives each change script from the
//! guardian's path and the layout must hash to the txid.
//! It does not detect a committee that pollutes the pool on Move, such as
//! a mint for a UTXO already spent. Only a comparison of Move's records
//! against this pool can do that, and that is a separate check.
//!
//! How it works:
//! 1. The pool starts empty, at the bridge's genesis. Move's records are
//!    never read for it. The continuous auditor keeps it in its snapshot,
//!    so a restart resumes with the pool the last run built.
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
//!    An operation that contradicts the pool is a finding. An outpoint
//!    confirmed with a second amount or script, or a UTXO spent by a second
//!    transaction, is an `RpcInconsistency`: Bitcoin cannot produce it. A
//!    spend of a UTXO the pool never held is `UtxoUnknownInputSpent`. The
//!    pool records nothing for that last spend: the finding is the signal.
//! 5. In one pass, every add comes before every spend. A pass can answer a
//!    deposit and the withdrawal that spends it, or a withdrawal and the one
//!    that spends its change, in any order.
//! 6. Once a day the monitor asks Bitcoin about every UTXO held. `check`
//!    turns the answers into findings. An unspent UTXO is reported by age.
//!    A spent UTXO is a spend outside Hashi. A missing UTXO is a phantom:
//!    every UTXO held was confirmed when it entered, so a missing answer is
//!    an RPC inconsistency. A UTXO that a withdrawal the monitor follows
//!    spends is not checked: Bitcoin spends it about an hour before the
//!    flow completes, and an incomplete flow has its own finding.
//!
//! Invariants:
//! - An outpoint is held or spent, never both.
//! - The spent record is never pruned. A spent UTXO is a few dozen bytes.
//! - The pool is a function of Bitcoin facts alone: a UTXO's time is its
//!   block time, so two monitors build the same pool.
//!
//! Assumptions:
//! - The first run starts at the bridge's genesis on a fullnode that still
//!   serves the history, so every UTXO is seen enter. A UTXO paid to a bridge
//!   address with no `DepositRequested`, or with a wrong derivation path, is
//!   invisible to the monitor and out of scope. A withdrawal that spends such
//!   a UTXO is reported as a spend of an unknown UTXO.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;

use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::UtxoOrigin;
use crate::findings::MonitorFinding;
use crate::findings::RpcInconsistency;
use crate::rpc::btc::OutpointState;
use crate::timing::Timing;

/// A UTXO the bridge holds, by Bitcoin's account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Utxo {
    pub amount: u64,
    /// The bridge script the output pays.
    pub script_pubkey: ScriptBuf,
    pub origin: UtxoOrigin,
    /// The time of the block that holds the UTXO.
    pub first_seen: UnixSeconds,
}

/// A UTXO a confirmed Hashi withdrawal spent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpentUtxo {
    #[serde(flatten)]
    pub utxo: Utxo,
    pub spent_by: Txid,
}

/// The UTXOs the bridge holds and the UTXOs it spent, by Bitcoin's account.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "UtxoPoolWire", into = "UtxoPoolWire")]
pub struct UtxoPool {
    utxos: BTreeMap<OutPoint, Utxo>,
    spent: BTreeMap<OutPoint, SpentUtxo>,
}

/// The pool as serialized: two lists, since a JSON map needs string keys.
#[derive(Deserialize, Serialize)]
struct UtxoPoolWire {
    utxos: Vec<UtxoWire>,
    spent: Vec<SpentUtxoWire>,
}

#[derive(Deserialize, Serialize)]
struct UtxoWire {
    outpoint: OutPoint,
    #[serde(flatten)]
    utxo: Utxo,
}

#[derive(Deserialize, Serialize)]
struct SpentUtxoWire {
    outpoint: OutPoint,
    #[serde(flatten)]
    spent: SpentUtxo,
}

impl From<UtxoPoolWire> for UtxoPool {
    fn from(wire: UtxoPoolWire) -> Self {
        Self {
            utxos: wire
                .utxos
                .into_iter()
                .map(|wire| (wire.outpoint, wire.utxo))
                .collect(),
            spent: wire
                .spent
                .into_iter()
                .map(|wire| (wire.outpoint, wire.spent))
                .collect(),
        }
    }
}

impl From<UtxoPool> for UtxoPoolWire {
    fn from(pool: UtxoPool) -> Self {
        Self {
            utxos: pool
                .utxos
                .into_iter()
                .map(|(outpoint, utxo)| UtxoWire { outpoint, utxo })
                .collect(),
            spent: pool
                .spent
                .into_iter()
                .map(|(outpoint, spent)| SpentUtxoWire { outpoint, spent })
                .collect(),
        }
    }
}

impl UtxoPool {
    /// The number of UTXOs held.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether no UTXO is held.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// The number of UTXOs in the spent record.
    pub fn spent_len(&self) -> usize {
        self.spent.len()
    }

    /// The outpoints held, in order.
    pub fn outpoints(&self) -> Vec<OutPoint> {
        self.utxos.keys().copied().collect()
    }

    /// Add a deposit Bitcoin confirmed.
    pub fn add_deposit(&mut self, deposit: &ConfirmedDeposit) -> Option<MonitorFinding> {
        self.add(
            deposit.deposit_id.into(),
            Utxo {
                amount: deposit.amount,
                script_pubkey: deposit.script_pubkey.clone(),
                origin: UtxoOrigin::Deposit,
                first_seen: deposit.block_time,
            },
        )
    }

    /// Apply withdrawals Bitcoin confirmed: every change output enters,
    /// then every input is spent. See the module doc for why in that order.
    pub fn add_withdrawals(&mut self, withdrawals: &[ConfirmedWithdrawal]) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for withdrawal in withdrawals {
            findings.extend(self.add_change_outputs(withdrawal));
        }
        for withdrawal in withdrawals {
            for input in &withdrawal.confirmation.inputs {
                findings.extend(self.spend(*input, withdrawal.txid));
            }
        }
        findings
    }

    /// Add a withdrawal's change outputs: every output from the first
    /// change vout on.
    fn add_change_outputs(&mut self, withdrawal: &ConfirmedWithdrawal) -> Vec<MonitorFinding> {
        let outputs = &withdrawal.confirmation.outputs;
        (withdrawal.first_change_vout..outputs.len())
            .filter_map(|vout| {
                let outpoint = OutPoint {
                    txid: withdrawal.txid,
                    vout: vout as u32,
                };
                self.add(
                    outpoint,
                    Utxo {
                        amount: outputs[vout].value.to_sat(),
                        script_pubkey: outputs[vout].script_pubkey.clone(),
                        origin: UtxoOrigin::Change,
                        first_seen: withdrawal.confirmation.block_time,
                    },
                )
            })
            .collect()
    }

    /// Add a UTXO. One already held or spent with the same amount and
    /// script is a repeat and keeps its entry. One that differs is a finding.
    fn add(&mut self, outpoint: OutPoint, utxo: Utxo) -> Option<MonitorFinding> {
        let held = match (self.utxos.get(&outpoint), self.spent.get(&outpoint)) {
            (Some(held), _) => held,
            // Not a finding: the utxo pool is sourced from Bitcoin RPC node, so a
            // second add of a spent UTXO is a replay.
            (None, Some(spent)) => &spent.utxo,
            (None, None) => {
                self.utxos.insert(outpoint, utxo);
                return None;
            }
        };
        let same = held.amount == utxo.amount && held.script_pubkey == utxo.script_pubkey;
        (!same).then_some(MonitorFinding::RpcInconsistency(
            RpcInconsistency::UtxoMismatch {
                outpoint,
                held_amount: held.amount,
                seen_amount: utxo.amount,
                held_script: held.script_pubkey.clone(),
                seen_script: utxo.script_pubkey,
            },
        ))
    }

    /// Spend a UTXO by the transaction `txid`. One already spent by it is a
    /// repeat. One spent by another transaction, or never held, is a finding.
    fn spend(&mut self, outpoint: OutPoint, txid: Txid) -> Option<MonitorFinding> {
        if let Some(utxo) = self.utxos.remove(&outpoint) {
            self.spent.insert(
                outpoint,
                SpentUtxo {
                    utxo,
                    spent_by: txid,
                },
            );
            return None;
        }
        match self.spent.get(&outpoint) {
            Some(spent) if spent.spent_by == txid => None,
            Some(spent) => Some(MonitorFinding::RpcInconsistency(
                RpcInconsistency::UtxoSpentTwice {
                    outpoint,
                    first_txid: spent.spent_by,
                    second_txid: txid,
                },
            )),
            None => Some(MonitorFinding::UtxoUnknownInputSpent { outpoint, txid }),
        }
    }

    /// The findings of one pass over Bitcoin's answer for every UTXO held.
    /// A UTXO with no answer counts as missing. A UTXO in `pending_inputs`,
    /// one a withdrawal the monitor follows spends, is skipped.
    pub fn check(
        &self,
        states: &HashMap<OutPoint, OutpointState>,
        pending_inputs: &HashSet<OutPoint>,
        now: UnixSeconds,
        timing: &Timing,
    ) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        for (outpoint, utxo) in &self.utxos {
            if pending_inputs.contains(outpoint) {
                continue;
            }
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
                        amount: utxo.amount,
                    });
                }
                Some(OutpointState::Missing) | None => {
                    findings.push(MonitorFinding::RpcInconsistency(
                        RpcInconsistency::UtxoVanished {
                            outpoint: *outpoint,
                            first_seen: utxo.first_seen,
                        },
                    ));
                }
            }
        }
        findings
    }
}

#[cfg(test)]
impl UtxoPool {
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
    }

    pub fn get_spent(&self, outpoint: &OutPoint) -> Option<&SpentUtxo> {
        self.spent.get(outpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::TxOut;

    use crate::domain::BtcConfirmation;
    use crate::domain::DepositId;
    use crate::findings::FindingCategory;
    use crate::test_utils::txid;

    // `Timing::for_tests` values.
    const WARN: u64 = 100;
    const CRITICAL: u64 = 200;

    fn outpoint(fill: u8) -> OutPoint {
        OutPoint {
            txid: txid(fill),
            vout: 0,
        }
    }

    /// The bridge script every test output pays.
    fn script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    /// A deposit at `outpoint(fill)`, confirmed in the block at `block_time`.
    fn deposit(fill: u8, amount: u64, block_time: UnixSeconds) -> ConfirmedDeposit {
        ConfirmedDeposit {
            deposit_id: DepositId::new(txid(fill), 0),
            amount,
            script_pubkey: script(),
            block_time,
        }
    }

    fn output(amount: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script(),
        }
    }

    /// A withdrawal `txid(fill)` with one user payout and one change output
    /// of 550 at vout 1, spending `inputs`.
    fn withdrawal(fill: u8, inputs: Vec<OutPoint>) -> ConfirmedWithdrawal {
        ConfirmedWithdrawal {
            txid: txid(fill),
            confirmation: BtcConfirmation {
                block_time: 700,
                confirmed_time: 760,
                inputs,
                outputs: vec![output(400), output(550)],
            },
            first_change_vout: 1,
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
        assert!(pool.add_deposit(&deposit(1, 1_000, first_seen)).is_none());
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
        pool.check(&states, &HashSet::new(), now, &Timing::for_tests())
    }

    #[test]
    fn a_confirmed_withdrawal_spends_its_inputs_and_adds_its_change() {
        let mut pool = pool_with_one();
        assert!(pool.add_deposit(&deposit(2, 2_000, 500)).is_none());

        let findings = pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(findings.is_empty());
        assert_eq!(pool.outpoints(), vec![outpoint(2), change_of(7)]);
        assert_eq!(
            pool.get(&change_of(7)),
            Some(&Utxo {
                amount: 550,
                script_pubkey: script(),
                origin: UtxoOrigin::Change,
                first_seen: 700
            })
        );
        assert_eq!(
            pool.get_spent(&outpoint(1)),
            Some(&SpentUtxo {
                utxo: Utxo {
                    amount: 1_000,
                    script_pubkey: script(),
                    origin: UtxoOrigin::Deposit,
                    first_seen: 500
                },
                spent_by: txid(7),
            })
        );
    }

    #[test]
    fn a_withdrawal_with_no_change_adds_nothing() {
        let mut pool = UtxoPool::default();
        let mut withdrawal = withdrawal(7, vec![]);
        withdrawal.first_change_vout = withdrawal.confirmation.outputs.len();

        assert!(pool.add_withdrawals(&[withdrawal]).is_empty());

        assert!(pool.is_empty());
    }

    #[test]
    fn a_repeated_add_keeps_the_utxo_and_another_amount_is_a_finding() {
        let mut pool = pool_with_one();

        assert!(pool.add_deposit(&deposit(1, 1_000, 900)).is_none());
        assert_eq!(pool.get(&outpoint(1)).unwrap().first_seen, 500);

        let finding = pool.add_deposit(&deposit(1, 1_001, 900)).unwrap();
        assert_eq!(
            finding,
            MonitorFinding::RpcInconsistency(RpcInconsistency::UtxoMismatch {
                outpoint: outpoint(1),
                held_amount: 1_000,
                seen_amount: 1_001,
                held_script: script(),
                seen_script: script(),
            })
        );
        assert_eq!(finding.category(), FindingCategory::Safety);
    }

    #[test]
    fn a_repeated_add_with_another_script_is_a_finding() {
        let mut pool = pool_with_one();
        let mut deposit = deposit(1, 1_000, 900);
        deposit.script_pubkey = ScriptBuf::from_bytes(vec![0x52]);

        let finding = pool.add_deposit(&deposit).unwrap();

        assert_eq!(
            finding,
            MonitorFinding::RpcInconsistency(RpcInconsistency::UtxoMismatch {
                outpoint: outpoint(1),
                held_amount: 1_000,
                seen_amount: 1_000,
                held_script: script(),
                seen_script: ScriptBuf::from_bytes(vec![0x52]),
            })
        );
        assert_eq!(pool.get(&outpoint(1)).unwrap().script_pubkey, script());
    }

    #[test]
    fn a_replayed_add_of_a_spent_utxo_is_a_repeat() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(pool.add_deposit(&deposit(1, 1_000, 900)).is_none());
        assert!(pool.get(&outpoint(1)).is_none());
        assert_eq!(pool.get_spent(&outpoint(1)).unwrap().spent_by, txid(7));

        assert!(matches!(
            pool.add_deposit(&deposit(1, 1_001, 900)),
            Some(MonitorFinding::RpcInconsistency(
                RpcInconsistency::UtxoMismatch { .. }
            ))
        ));
    }

    #[test]
    fn a_replayed_spend_is_a_repeat_and_a_second_spender_is_a_finding() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert!(
            pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])])
                .is_empty()
        );

        let findings = pool.add_withdrawals(&[withdrawal(8, vec![outpoint(1)])]);
        assert_eq!(
            findings,
            vec![MonitorFinding::RpcInconsistency(
                RpcInconsistency::UtxoSpentTwice {
                    outpoint: outpoint(1),
                    first_txid: txid(7),
                    second_txid: txid(8),
                }
            )]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn spending_a_utxo_the_pool_never_held_is_a_finding_and_records_nothing() {
        let mut pool = UtxoPool::default();

        let findings = pool.add_withdrawals(&[withdrawal(7, vec![outpoint(9)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: outpoint(9),
                txid: txid(7),
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Liveness);
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
        assert_eq!(pool.get_spent(&outpoint(9)), None);
    }

    #[test]
    fn in_one_pass_every_add_comes_before_every_spend() {
        // Withdrawal 8 spends the change of withdrawal 7, and the pass lists
        // the spender first.
        let mut pool = UtxoPool::default();

        let findings =
            pool.add_withdrawals(&[withdrawal(8, vec![change_of(7)]), withdrawal(7, vec![])]);

        assert!(findings.is_empty());
        assert_eq!(pool.outpoints(), vec![change_of(8)]);
        assert_eq!(pool.get_spent(&change_of(7)).unwrap().spent_by, txid(8));
    }

    #[test]
    fn a_young_unspent_utxo_is_fine() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };
        assert!(check_one(&pool, Some(state), 1_000 + WARN - 1).is_empty());
    }

    #[test]
    fn an_unspent_utxo_is_reported_at_the_warn_age_then_the_critical_age() {
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
    fn a_spent_utxo_is_an_unexpected_spend() {
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
    fn a_missing_utxo_is_an_rpc_inconsistency() {
        let pool = pool_seen_at(1_000);
        let vanished = MonitorFinding::RpcInconsistency(RpcInconsistency::UtxoVanished {
            outpoint: outpoint(1),
            first_seen: 1_000,
        });

        let findings = check_one(&pool, Some(OutpointState::Missing), 1_000);

        assert_eq!(findings, vec![vanished.clone()]);
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        // No answer at all counts as missing.
        assert_eq!(check_one(&pool, None, 1_000), vec![vanished]);
    }

    #[test]
    fn a_utxo_a_pending_withdrawal_spends_is_not_checked() {
        let pool = pool_seen_at(0);
        let states = HashMap::from([(outpoint(1), OutpointState::Spent)]);
        let pending_inputs = HashSet::from([outpoint(1)]);

        let findings = pool.check(&states, &pending_inputs, 1_000, &Timing::for_tests());

        assert!(findings.is_empty());
    }

    #[test]
    fn a_spent_utxo_is_not_checked() {
        let mut pool = pool_seen_at(0);
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);
        let states = HashMap::from([
            (outpoint(1), OutpointState::Spent),
            (change_of(7), OutpointState::Unspent { block_time: 700 }),
        ]);

        let findings = pool.check(&states, &HashSet::new(), 701, &Timing::for_tests());

        assert!(findings.is_empty());
    }

    #[test]
    fn a_pool_round_trips_through_json() {
        let mut pool = pool_with_one();
        pool.add_deposit(&deposit(2, 2_000, 1_500));
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let json = serde_json::to_vec(&pool).unwrap();
        let loaded: UtxoPool = serde_json::from_slice(&json).unwrap();

        assert_eq!(loaded.outpoints(), pool.outpoints());
        assert_eq!(loaded.get(&outpoint(2)), pool.get(&outpoint(2)));
        assert_eq!(loaded.get(&change_of(7)), pool.get(&change_of(7)));
        assert_eq!(loaded.get_spent(&outpoint(1)), pool.get_spent(&outpoint(1)));
    }
}
