// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The monitor's own record of the UTXOs the bridge holds, built from Bitcoin facts.
//!
//! Why it exists: the committee writes Move's `utxo_records`. A compromised
//! committee can mark a UTXO spent on Move without spending it, or keep a
//! deposit out of Move, then spend the UTXO alone when the 60-day recovery
//! leaf opens. Only a Bitcoin fact changes this pool, so the committee
//! cannot remove a UTXO from it or keep one out.
//!
//! How it works:
//! 1. The pool starts empty at the bridge's genesis. The snapshot keeps it
//!    across restarts.
//! 2. A deposit enters when Bitcoin confirms the request's output at the
//!    bridge script of the claimed path.
//! 3. A complete withdrawal (E1, E2, E3) removes its inputs and adds its
//!    change. The guardian's E2 labels the change; the monitor verifies it.
//! 4. In one pass, every add comes before every spend.
//! 5. A second add of a held UTXO is a repeat. A second amount or script is
//!    an `BtcRpcInconsistency`. A spend of a UTXO the pool does not hold is
//!    `UtxoUnknownInputSpent`.
//! 6. A `DepositApproved` must match a held deposit's amount and script.
//! 7. Once a day, `check` asks Bitcoin about every held UTXO. It reports old,
//!    spent and missing UTXOs.
//! 8. The pool keeps no record of spent UTXOs. Move refuses a request after
//!    the first DC, so every add for a UTXO comes before its spend.
//!
//! The pool can hold a UTXO that Move never holds, for example a deposit
//! that AML screening rejects or a request with a wrong amount.
//!
//! Assumptions:
//! - The first run starts at genesis, so the monitor sees every UTXO enter.
//! - Sui and the guardian deliver each event once: no repeat and no miss.

use std::collections::BTreeMap;
use std::collections::HashMap;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;

use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::UtxoOrigin;
use crate::findings::BtcRpcInconsistency;
use crate::findings::MonitorFinding;
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

/// A held UTXO that Bitcoin reports spent, which no followed withdrawal
/// explains. The auditor judges it once the Sui cursor is past `checked_at`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SuspectSpend {
    /// When the Bitcoin lookups finished.
    pub checked_at: UnixSeconds,
    pub amount: u64,
}

/// The UTXOs the bridge holds, by Bitcoin's account.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtxoPool {
    utxos: BTreeMap<OutPoint, Utxo>,
}

/// A held UTXO as stored: a JSON map needs string keys, so a list.
#[derive(Deserialize, Serialize)]
pub struct UtxoWire {
    outpoint: OutPoint,
    #[serde(flatten)]
    utxo: Utxo,
}

impl UtxoPool {
    /// The held UTXOs, ready to store.
    pub fn held_to_wire(&self) -> Vec<UtxoWire> {
        self.utxos
            .iter()
            .map(|(outpoint, utxo)| UtxoWire {
                outpoint: *outpoint,
                utxo: utxo.clone(),
            })
            .collect()
    }

    /// A pool from its stored UTXOs.
    pub fn from_wire(held: Vec<UtxoWire>) -> Self {
        Self {
            utxos: held
                .into_iter()
                .map(|wire| (wire.outpoint, wire.utxo))
                .collect(),
        }
    }

    /// Whether the pool holds the UTXO.
    pub fn holds(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// The number of UTXOs held.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether no UTXO is held.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// The earliest block timestamp among held UTXOs.
    /// The sum of the held amounts, in satoshis.
    pub fn value(&self) -> u64 {
        self.utxos
            .values()
            .fold(0, |sum, utxo| sum.saturating_add(utxo.amount))
    }

    pub fn oldest_timestamp(&self) -> Option<UnixSeconds> {
        self.utxos.values().map(|utxo| utxo.first_seen).min()
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

    /// Check the Sui `DepositApproved` against the pool: the UTXO must be a
    /// deposit the pool holds. See `SuiDepositApprovedEvent::judge`.
    pub fn check_sui_approval(
        &self,
        sui: &SuiDepositApprovedEvent,
        skew: u64,
    ) -> Vec<MonitorFinding> {
        let outpoint = OutPoint::from(sui.deposit_id);
        let paid = self
            .utxos
            .get(&outpoint)
            .filter(|utxo| utxo.origin == UtxoOrigin::Deposit)
            .map(|utxo| ConfirmedDeposit {
                deposit_id: sui.deposit_id,
                amount: utxo.amount,
                script_pubkey: utxo.script_pubkey.clone(),
                block_time: utxo.first_seen,
            });
        sui.judge(paid.as_ref(), skew)
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

    /// Add a UTXO. One already held with the same amount and script is a
    /// repeat and keeps its entry. One that differs is a finding.
    fn add(&mut self, outpoint: OutPoint, utxo: Utxo) -> Option<MonitorFinding> {
        let Some(held) = self.utxos.get(&outpoint) else {
            self.utxos.insert(outpoint, utxo);
            return None;
        };
        let same = held.amount == utxo.amount && held.script_pubkey == utxo.script_pubkey;
        (!same).then_some(MonitorFinding::BtcRpcInconsistency(
            BtcRpcInconsistency::UtxoMismatch {
                outpoint,
                held_amount: held.amount,
                seen_amount: utxo.amount,
                held_script: held.script_pubkey.clone(),
                seen_script: utxo.script_pubkey,
            },
        ))
    }

    /// Spend a UTXO by the transaction `txid`. One the pool does not hold is
    /// a finding.
    fn spend(&mut self, outpoint: OutPoint, txid: Txid) -> Option<MonitorFinding> {
        self.utxos
            .remove(&outpoint)
            .is_none()
            .then_some(MonitorFinding::UtxoUnknownInputSpent { outpoint, txid })
    }

    /// Check held outputs against Bitcoin results and return findings and suspect spends.
    /// Use the lookup completion time `now` for ages and suspect timestamps.
    /// The auditor judges suspects after Sui polling catches up.
    pub fn check(
        &self,
        states: &HashMap<OutPoint, OutpointState>,
        now: UnixSeconds,
        timing: &Timing,
    ) -> (Vec<MonitorFinding>, HashMap<OutPoint, SuspectSpend>) {
        let mut findings = Vec::new();
        let mut suspects = HashMap::new();
        for (outpoint, utxo) in &self.utxos {
            match states.get(outpoint) {
                Some(OutpointState::Unspent { block_time }) => {
                    let age_secs = now.saturating_sub(*block_time);
                    if age_secs >= timing.utxo_max_age {
                        findings.push(MonitorFinding::UtxoTooOld {
                            outpoint: *outpoint,
                            age_secs,
                            threshold_secs: timing.utxo_max_age,
                        });
                    }
                }
                Some(OutpointState::Spent) => {
                    suspects.insert(
                        *outpoint,
                        SuspectSpend {
                            checked_at: now,
                            amount: utxo.amount,
                        },
                    );
                }
                Some(OutpointState::Missing) | None => {
                    findings.push(MonitorFinding::BtcRpcInconsistency(
                        BtcRpcInconsistency::UtxoVanished {
                            outpoint: *outpoint,
                            first_seen: utxo.first_seen,
                        },
                    ));
                }
            }
        }
        (findings, suspects)
    }
}

#[cfg(test)]
impl UtxoPool {
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
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
    use crate::domain::SuiDepositRequestedEvent;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use crate::test_utils::txid;

    // `Timing::for_tests` values.
    const MAX_AGE: u64 = 100;

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
    ) -> (Vec<MonitorFinding>, HashMap<OutPoint, SuspectSpend>) {
        let states = state
            .map(|state| HashMap::from([(outpoint(1), state)]))
            .unwrap_or_default();
        pool.check(&states, now, &Timing::for_tests())
    }

    /// The findings of `check_one`, with no suspects.
    fn findings_one(
        pool: &UtxoPool,
        state: Option<OutpointState>,
        now: UnixSeconds,
    ) -> Vec<MonitorFinding> {
        let (findings, suspects) = check_one(pool, state, now);
        assert!(suspects.is_empty());
        findings
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
            MonitorFinding::BtcRpcInconsistency(BtcRpcInconsistency::UtxoMismatch {
                outpoint: outpoint(1),
                held_amount: 1_000,
                seen_amount: 1_001,
                held_script: script(),
                seen_script: script(),
            })
        );
    }

    #[test]
    fn a_repeated_add_with_another_script_is_a_finding() {
        let mut pool = pool_with_one();
        let mut deposit = deposit(1, 1_000, 900);
        deposit.script_pubkey = ScriptBuf::from_bytes(vec![0x52]);

        let finding = pool.add_deposit(&deposit).unwrap();

        assert_eq!(
            finding,
            MonitorFinding::BtcRpcInconsistency(BtcRpcInconsistency::UtxoMismatch {
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
    fn a_second_spend_of_a_utxo_is_a_spend_of_an_unknown_utxo() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let findings = pool.add_withdrawals(&[withdrawal(8, vec![outpoint(1)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: outpoint(1),
                txid: txid(8),
            }]
        );
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
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
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
    }

    const SKEW: u64 = 10;

    /// The Sui `DepositApproved` for `outpoint(fill)`, at time 600.
    fn sui_approval(fill: u8, amount: u64, script_pubkey: ScriptBuf) -> SuiDepositApprovedEvent {
        let request = SuiDepositRequestedEvent {
            deposit_id: DepositId::new(txid(fill), 0),
            amount,
            script_pubkey,
            ..deposit_request()
        };
        approval_of(&request, 600)
    }

    #[test]
    fn an_approval_of_a_held_deposit_is_backed() {
        let pool = pool_with_one();

        let sui = sui_approval(1, 1_000, script());
        assert!(pool.check_sui_approval(&sui, SKEW).is_empty());
    }

    #[test]
    fn an_approval_of_a_spent_deposit_is_unbacked() {
        // Move refuses this approval, so the pool need not remember spends.
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(5, vec![outpoint(1)])]);

        let sui = sui_approval(1, 1_000, script());
        assert_eq!(
            pool.check_sui_approval(&sui, SKEW),
            vec![MonitorFinding::DepositUnbacked { sui }]
        );
    }

    #[test]
    fn an_approval_the_pool_never_held_is_unbacked() {
        let pool = pool_with_one();

        let sui = sui_approval(2, 1_000, script());
        let findings = pool.check_sui_approval(&sui, SKEW);
        assert_eq!(findings, vec![MonitorFinding::DepositUnbacked { sui }]);
    }

    #[test]
    fn an_approval_of_a_change_output_is_unbacked() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(5, vec![outpoint(1)])]);
        let change = change_of(5);

        let sui = SuiDepositApprovedEvent {
            deposit_id: DepositId::new(change.txid, change.vout),
            ..sui_approval(5, 550, script())
        };
        assert_eq!(
            pool.check_sui_approval(&sui, SKEW),
            vec![MonitorFinding::DepositUnbacked { sui }]
        );
    }

    #[test]
    fn an_approval_with_another_amount_or_script_is_a_mismatch() {
        let pool = pool_with_one();

        for sui in [
            sui_approval(1, 2_000, script()),
            sui_approval(1, 1_000, ScriptBuf::from_bytes(vec![0x52])),
        ] {
            let findings = pool.check_sui_approval(&sui, SKEW);
            assert!(
                matches!(&findings[..], [MonitorFinding::DepositMismatch { sui: claimed, .. }] if *claimed == sui)
            );
        }
    }

    #[test]
    fn a_deposit_mined_after_its_approval_and_the_skew_is_late() {
        let sui = sui_approval(1, 1_000, script());

        assert!(
            pool_seen_at(600 + SKEW)
                .check_sui_approval(&sui, SKEW)
                .is_empty()
        );
        assert!(matches!(
            &pool_seen_at(600 + SKEW + 1).check_sui_approval(&sui, SKEW)[..],
            [MonitorFinding::DepositLate {
                deadline: 610,
                block_time: 611,
                ..
            }]
        ));
    }

    #[test]
    fn an_unspent_utxo_is_reported_at_the_max_age() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };
        assert!(findings_one(&pool, Some(state.clone()), 1_000 + MAX_AGE - 1).is_empty());

        assert_eq!(
            findings_one(&pool, Some(state), 1_000 + MAX_AGE),
            vec![MonitorFinding::UtxoTooOld {
                outpoint: outpoint(1),
                age_secs: MAX_AGE,
                threshold_secs: MAX_AGE,
            }]
        );
    }

    #[test]
    fn a_spent_utxo_is_a_suspect() {
        let pool = pool_seen_at(0);
        let (findings, suspects) = check_one(&pool, Some(OutpointState::Spent), 1);
        assert!(findings.is_empty());
        assert_eq!(
            suspects,
            HashMap::from([(
                outpoint(1),
                SuspectSpend {
                    checked_at: 1,
                    amount: 1_000,
                }
            )])
        );
    }

    #[test]
    fn a_missing_utxo_is_an_rpc_inconsistency() {
        let pool = pool_seen_at(1_000);
        let vanished = MonitorFinding::BtcRpcInconsistency(BtcRpcInconsistency::UtxoVanished {
            outpoint: outpoint(1),
            first_seen: 1_000,
        });

        let findings = findings_one(&pool, Some(OutpointState::Missing), 1_000);

        assert_eq!(findings, vec![vanished.clone()]);
        // No answer at all counts as missing.
        assert_eq!(findings_one(&pool, None, 1_000), vec![vanished]);
    }

    #[test]
    fn a_spent_utxo_is_not_checked() {
        let mut pool = pool_seen_at(0);
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);
        let states = HashMap::from([
            (outpoint(1), OutpointState::Spent),
            (change_of(7), OutpointState::Unspent { block_time: 700 }),
        ]);

        let (findings, suspects) = pool.check(&states, 701, &Timing::for_tests());

        assert!(findings.is_empty());
        assert!(suspects.is_empty());
        assert!(!pool.holds(&outpoint(1)));
    }

    #[test]
    fn a_pool_round_trips_through_its_stored_parts() {
        let mut pool = pool_with_one();
        pool.add_deposit(&deposit(2, 2_000, 1_500));
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let loaded = UtxoPool::from_wire(pool.held_to_wire());

        assert_eq!(loaded, pool);
    }
}
