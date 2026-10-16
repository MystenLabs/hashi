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
//!    never read for it. Keeping it between runs follows in a later change.
//! 2. A UTXO is added when Bitcoin confirms a deposit request's output at
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
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
}
