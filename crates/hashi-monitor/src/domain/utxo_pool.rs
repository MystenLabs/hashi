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
//! operation safe to repeat, so the same fact given twice changes nothing.
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
//! 2. A UTXO is added when Bitcoin confirms a deposit request's output at
//!    the bridge script of the claimed path. The committee is not needed.
//! 3. When a withdrawal flow is complete, E1, E2 and E3 seen, its change
//!    outputs are added and its inputs move to the spent record, with the
//!    spending txid. The inputs and amounts come from the confirmed Bitcoin
//!    transaction. Which outputs are change comes from E2: the guardian
//!    labels each output from paths it derives itself, and the committee's
//!    E1 is not trusted for it. A withdrawal that never completes never
//!    touches the pool, so its inputs stay held and the daily check reports
//!    them once they are too old, on top of the finding for its missing
//!    event. The auditor feeds
//!    the pool right after its Bitcoin lookups, so a withdrawal's inputs
//!    have entered before the withdrawal spends them.
//! 4. Every operation is strict. An operation the pool already applied is a
//!    repeat and is skipped. For example, two requests for one UTXO give
//!    the pool the same deposit twice.
//!    An operation that contradicts the pool is a finding. An outpoint
//!    confirmed with a second amount or script, or a UTXO spent by a second
//!    transaction, is an `RpcInconsistency`: Bitcoin cannot produce it. A
//!    spend of a UTXO the pool never held is `UtxoUnknownInputSpent`. The
//!    pool records nothing for that last spend: the finding is the signal.
//! 5. In one pass, every add comes before every spend. A pass can answer a
//!    deposit and the withdrawal that spends it, or a withdrawal and the one
//!    that spends its change, in any order.
//! 6. A `DepositApproved`, which Hashi needs before it mints, whose
//!    request's machine has closed is checked against the pool: the pool
//!    must hold the UTXO, or have spent it, as a deposit with the same
//!    amount and script. One that arrives earlier is judged by its machine,
//!    by the same rule. So every hBTC minted matches BTC that Bitcoin shows
//!    paid to the bridge. A late approval can come after the pool spent
//!    the UTXO. The spent record keeps the amount and script, so a spent
//!    UTXO is still found.
//! 7. Once a day the monitor asks Bitcoin about every UTXO held. `check`
//!    turns the answers into findings. An unspent UTXO is reported by age.
//!    A spent UTXO is a spend outside Hashi. A missing UTXO is a phantom:
//!    every UTXO held was confirmed when it entered, so a missing answer is
//!    an RPC inconsistency. A UTXO that a withdrawal the monitor follows
//!    spends is not checked: Bitcoin spends it about an hour before the
//!    flow completes, and an incomplete flow has its own finding.
//!
//! Differences from Move's pool: this pool can hold a UTXO that Move never
//! holds, with no fault of the committee. Two causes:
//! - Sanctions (IOP-820): a member's AML screening rejects the deposit. The
//!   UTXO is real bridge money, but no `DepositApproved` follows, so it
//!   stays outside Move until the recovery leaf opens.
//! - User mistakes: the pool takes a UTXO that pays the bridge script of the
//!   claimed path, but an honest committee approves only a correct, live
//!   request. A request with a wrong amount is rejected; the pool keeps the
//!   UTXO at the amount Bitcoin paid. A request whose transaction confirms
//!   after Move marks it expired (one day) but within the watch
//!   (`DEPOSIT_REQUEST_WATCH`) is deleted. In both cases Move holds the UTXO
//!   only once the user sends a correct request again.
//!
//! Invariants:
//! - An outpoint is held or spent, never both.
//! - The spent record is never pruned, and it only grows: an entry is added
//!   once and never changes. The snapshot keeps it in files by that order.
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

/// A held UTXO that Bitcoin reports spent, which no followed withdrawal
/// explains. The auditor judges it once the Sui cursor is past `asked_at`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SuspectSpend {
    /// When Bitcoin was asked.
    pub asked_at: UnixSeconds,
    pub amount: u64,
}

/// The UTXOs the bridge holds and the UTXOs it spent, by Bitcoin's account.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtxoPool {
    utxos: BTreeMap<OutPoint, Utxo>,
    spent: BTreeMap<OutPoint, SpentUtxo>,
    /// The spent outpoints in the order the pool spent them. The record
    /// only grows, so a prefix of this list never changes.
    spent_order: Vec<OutPoint>,
}

/// A held UTXO as stored: a JSON map needs string keys, so a list.
#[derive(Deserialize, Serialize)]
pub struct UtxoWire {
    outpoint: OutPoint,
    #[serde(flatten)]
    utxo: Utxo,
}

/// A spent UTXO as stored.
#[derive(Deserialize, Serialize)]
pub struct SpentUtxoWire {
    pub outpoint: OutPoint,
    #[serde(flatten)]
    pub spent: SpentUtxo,
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

    /// The spent UTXOs at positions `range` of the order the pool spent
    /// them in, ready to store.
    pub fn spent_to_wire(&self, range: std::ops::Range<usize>) -> Vec<SpentUtxoWire> {
        self.spent_order[range]
            .iter()
            .map(|outpoint| SpentUtxoWire {
                outpoint: *outpoint,
                spent: self.spent[outpoint].clone(),
            })
            .collect()
    }

    /// A pool from stored parts. `spent` is in the order the pool spent them.
    pub fn from_wire(held: Vec<UtxoWire>, spent: Vec<SpentUtxoWire>) -> Self {
        let mut pool = Self {
            utxos: held
                .into_iter()
                .map(|wire| (wire.outpoint, wire.utxo))
                .collect(),
            ..Self::default()
        };
        for wire in spent {
            pool.record_spent(wire.outpoint, wire.spent);
        }
        pool
    }

    /// Add to the spent record. A UTXO already in it keeps its entry.
    fn record_spent(&mut self, outpoint: OutPoint, spent: SpentUtxo) {
        if self.spent.insert(outpoint, spent).is_none() {
            self.spent_order.push(outpoint);
        }
    }

    /// Whether a withdrawal the pool took spent the UTXO.
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent.contains_key(outpoint)
    }

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

    /// The earliest block timestamp among held UTXOs.
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
    /// deposit the pool holds or spent. See `SuiDepositApprovedEvent::judge`.
    pub fn check_sui_approval(
        &self,
        sui: &SuiDepositApprovedEvent,
        skew: u64,
    ) -> Vec<MonitorFinding> {
        let outpoint = OutPoint::from(sui.deposit_id);
        let paid = self
            .utxos
            .get(&outpoint)
            .or_else(|| self.spent.get(&outpoint).map(|spent| &spent.utxo))
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

    /// Add a UTXO. One already held or spent with the same amount and
    /// script is a repeat and keeps its entry. One that differs is a finding.
    fn add(&mut self, outpoint: OutPoint, utxo: Utxo) -> Option<MonitorFinding> {
        let held = match (self.utxos.get(&outpoint), self.spent.get(&outpoint)) {
            (Some(held), _) => held,
            // Not a finding: the utxo pool is sourced from Bitcoin RPC node, so a
            // second add of a spent UTXO is a repeat.
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
            self.record_spent(
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

    /// One pass over Bitcoin's answer for every UTXO held: the findings,
    /// and the spent UTXOs as suspects. A spend is not a finding yet: a
    /// withdrawal the monitor follows, or one committed since the last Sui
    /// poll, can have spent the UTXO, and only the auditor can tell. A
    /// UTXO with no answer counts as missing.
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
                    suspects.insert(
                        *outpoint,
                        SuspectSpend {
                            asked_at: now,
                            amount: utxo.amount,
                        },
                    );
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
        (findings, suspects)
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
    use crate::domain::SuiDepositRequestedEvent;
    use crate::findings::FindingCategory;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
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
    fn a_second_add_of_a_spent_utxo_is_a_repeat() {
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
    fn a_repeated_spend_is_a_repeat_and_a_second_spender_is_a_finding() {
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
        assert_eq!(findings[0].category(), FindingCategory::Safety);
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
    fn an_approval_of_a_spent_deposit_is_backed() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(5, vec![outpoint(1)])]);
        assert!(pool.is_spent(&outpoint(1)));

        let sui = sui_approval(1, 1_000, script());
        assert!(pool.check_sui_approval(&sui, SKEW).is_empty());
    }

    #[test]
    fn an_approval_the_pool_never_held_is_unbacked() {
        let pool = pool_with_one();

        let sui = sui_approval(2, 1_000, script());
        let findings = pool.check_sui_approval(&sui, SKEW);
        assert_eq!(findings, vec![MonitorFinding::DepositUnbacked { sui }]);
        assert_eq!(findings[0].category(), FindingCategory::Safety);
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
            assert_eq!(findings[0].category(), FindingCategory::Safety);
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
    fn a_young_unspent_utxo_is_fine() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };
        assert!(findings_one(&pool, Some(state), 1_000 + WARN - 1).is_empty());
    }

    #[test]
    fn an_unspent_utxo_is_reported_at_the_warn_age_then_the_critical_age() {
        let pool = pool_seen_at(0);
        let state = OutpointState::Unspent { block_time: 1_000 };

        let warn = findings_one(&pool, Some(state.clone()), 1_000 + WARN);
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

        let critical = findings_one(&pool, Some(state), 1_000 + CRITICAL);
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
    fn a_spent_utxo_is_a_suspect() {
        let pool = pool_seen_at(0);
        let (findings, suspects) = check_one(&pool, Some(OutpointState::Spent), 1);
        assert!(findings.is_empty());
        assert_eq!(
            suspects,
            HashMap::from([(
                outpoint(1),
                SuspectSpend {
                    asked_at: 1,
                    amount: 1_000,
                }
            )])
        );
    }

    #[test]
    fn a_missing_utxo_is_an_rpc_inconsistency() {
        let pool = pool_seen_at(1_000);
        let vanished = MonitorFinding::RpcInconsistency(RpcInconsistency::UtxoVanished {
            outpoint: outpoint(1),
            first_seen: 1_000,
        });

        let findings = findings_one(&pool, Some(OutpointState::Missing), 1_000);

        assert_eq!(findings, vec![vanished.clone()]);
        assert_eq!(findings[0].category(), FindingCategory::Safety);
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
        assert!(pool.is_spent(&outpoint(1)));
    }

    #[test]
    fn a_pool_round_trips_through_its_stored_parts() {
        let mut pool = pool_with_one();
        pool.add_deposit(&deposit(2, 2_000, 1_500));
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let loaded =
            UtxoPool::from_wire(pool.held_to_wire(), pool.spent_to_wire(0..pool.spent_len()));

        assert_eq!(loaded, pool);
    }

    #[test]
    fn the_spent_record_keeps_the_order_the_pool_spent_in() {
        let mut pool = pool_with_one();
        pool.add_deposit(&deposit(2, 2_000, 1_500));
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(2)])]);
        pool.add_withdrawals(&[withdrawal(8, vec![outpoint(1)])]);

        let spent = pool.spent_to_wire(0..2);

        assert_eq!(spent[0].outpoint, outpoint(2));
        assert_eq!(spent[1].outpoint, outpoint(1));
        assert_eq!(pool.spent_to_wire(1..2)[0].outpoint, outpoint(1));
    }
}
