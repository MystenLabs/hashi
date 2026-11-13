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
//!    bridge script of the claimed path. It enters as an unapproved deposit,
//!    unless its deposit machine holds a Sui `DepositApproved`.
//! 3. A complete withdrawal (E1, E2, E3) removes its inputs and adds its
//!    change. The guardian's E2 labels the change; the monitor verifies it.
//! 4. In one pass, every add comes before every spend.
//! 5. A second add of a held UTXO is a repeat. It can approve a held
//!    unapproved deposit, or give it a later request. A second amount or
//!    script is a `BtcRpcInconsistency`. A deposit against change is a
//!    `UtxoOriginConflict`. A spend of a UTXO that is not in Move's pool is
//!    `UtxoOutsideMovePoolSpent`.
//! 6. A `DepositApproved` must match a held deposit's amount and script. It
//!    marks the deposit approved, also when it does not match: Move mints on
//!    it.
//! 7. Once a day, `check` asks Bitcoin about every held UTXO. It reports
//!    spent and missing UTXOs, and old ones in Move's pool.
//!    `log_unapproved_past_deadline` logs the unapproved deposits that are
//!    past their deadline. `approval_stall` reports overdue ones that look valid.
//! 8. The pool keeps no record of spent UTXOs. Move refuses a request after
//!    the first DC, so every add for a UTXO comes before its spend.
//!
//! The pool can hold a UTXO that Move never holds, for example a deposit
//! that AML screening rejects or a request with a wrong amount. Such a UTXO
//! stays an unapproved deposit.
//!
//! UTXOs in Move's pool: the pool value and the pool gauges use only these.
//! The daily check looks up every held UTXO, but `UtxoTooOld` covers only
//! these.
//! - A deposit enters Move's pool when the monitor has seen both its Bitcoin
//!   confirmation and its Sui `DepositApproved`.
//! - A change output enters Move's pool at the Bitcoin confirmation of its
//!   withdrawal.
//! - A UTXO leaves the pool at the Bitcoin confirmation of the withdrawal
//!   that spends it.
//!
//! Assumptions:
//! - The first run starts at genesis, so the monitor sees every UTXO enter.
//! - Sui and the guardian deliver each event once: no repeat and no miss.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;

use crate::domain::BtcConfirmedDeposit;
use crate::domain::DepositId;
use crate::domain::FinishedDeposit;
use crate::domain::FinishedWithdrawal;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::UtxoOrigin;
use crate::findings::BtcRpcInconsistency;
use crate::findings::MonitorFinding;
use crate::rpc::btc::OutpointState;
use crate::time::utc_timestamp;
use crate::timing::Timing;

/// Overdue deposits that look valid for a `DepositApprovalStalled`. Two, so
/// one sanctioned deposit is not a finding.
const MIN_STALLED_DEPOSITS: usize = 2;

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

/// Why a paid deposit has no approval, as far as the monitor can infer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnapprovedCause {
    /// Bitcoin paid another amount than the request claims.
    AmountMismatch,
    /// The block is more than `DEPOSIT_REQUEST_EXPIRY` after the request.
    PaidAfterExpiry,
    /// Neither of the above: a sanction, or a committee that withholds the
    /// approval. The monitor cannot tell them apart.
    SanctionOrWithheld,
}

/// A held unapproved deposit, with the causes the monitor can infer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositNotApproved {
    pub outpoint: OutPoint,
    pub requested_amount: u64,
    pub paid_amount: u64,
    pub requested_at: UnixSeconds,
    pub block_time: UnixSeconds,
    pub causes: Vec<UnapprovedCause>,
}

impl fmt::Display for DepositNotApproved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DepositNotApproved(outpoint={}, requested_amount={}, paid_amount={}, requested_at={}, block_time={}, causes={:?})",
            self.outpoint,
            self.requested_amount,
            self.paid_amount,
            utc_timestamp(self.requested_at),
            utc_timestamp(self.block_time),
            self.causes,
        )
    }
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

    /// The number of UTXOs held, approved or not.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// The number of UTXOs in Move's pool.
    pub fn in_move_pool_len(&self) -> usize {
        self.in_move_pool().count()
    }

    /// Whether no UTXO is held.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// The sum of the amounts in Move's pool, in satoshis.
    pub fn value(&self) -> u64 {
        self.in_move_pool()
            .fold(0, |sum, utxo| sum.saturating_add(utxo.amount))
    }

    /// The earliest block timestamp among the UTXOs in Move's pool.
    pub fn oldest_timestamp(&self) -> Option<UnixSeconds> {
        self.in_move_pool().map(|utxo| utxo.first_seen).min()
    }

    fn in_move_pool(&self) -> impl Iterator<Item = &Utxo> {
        self.utxos
            .values()
            .filter(|utxo| utxo.origin.in_move_pool())
    }

    /// The outpoints held, in order.
    pub fn outpoints(&self) -> Vec<OutPoint> {
        self.utxos.keys().copied().collect()
    }

    /// Add the UTXO of a closed deposit machine.
    pub fn add_deposit(&mut self, deposit: &FinishedDeposit) -> Vec<MonitorFinding> {
        self.add(OutPoint::from(deposit.deposit_id), deposit.utxo.clone())
    }

    /// Mark a held unapproved deposit approved. Any other UTXO is unchanged.
    fn mark_approved(&mut self, deposit_id: DepositId) {
        if let Some(utxo) = self.utxos.get_mut(&OutPoint::from(deposit_id))
            && matches!(utxo.origin, UtxoOrigin::UnapprovedDeposit { .. })
        {
            utxo.origin = UtxoOrigin::Deposit;
        }
    }

    /// Log each unapproved deposit whose latest request is more than
    /// `deposit_request_watch` before `sui_cursor`. The Sui cursor makes sure
    /// that an approval not yet read is not logged as missing.
    pub fn log_unapproved_past_deadline(&self, sui_cursor: UnixSeconds, timing: &Timing) {
        for deposit in self
            .unapproved_deposits(timing)
            .filter(|deposit| deposit.requested_at + timing.deposit_request_watch < sui_cursor)
        {
            tracing::info!(%deposit, "deposit not approved");
        }
    }

    /// A `DepositApprovalStalled` if at least `MIN_STALLED_DEPOSITS` deposits
    /// that look valid became overdue after `last_approval` and before
    /// `sui_cursor`.
    pub fn approval_stall(
        &self,
        last_approval: Option<UnixSeconds>,
        sui_cursor: UnixSeconds,
        timing: &Timing,
    ) -> Option<MonitorFinding> {
        let outpoints: Vec<_> = self
            .unapproved_deposits(timing)
            .filter(|deposit| {
                let overdue_at =
                    deposit.requested_at.max(deposit.block_time) + timing.deposit_approval_overdue;
                deposit.causes == [UnapprovedCause::SanctionOrWithheld]
                    && last_approval.is_none_or(|approved_at| approved_at < overdue_at)
                    && overdue_at < sui_cursor
            })
            .map(|deposit| deposit.outpoint)
            .collect();
        (outpoints.len() >= MIN_STALLED_DEPOSITS).then_some(
            MonitorFinding::DepositApprovalStalled {
                outpoints,
                last_approval,
            },
        )
    }

    fn unapproved_deposits<'a>(
        &'a self,
        timing: &'a Timing,
    ) -> impl Iterator<Item = DepositNotApproved> + 'a {
        self.utxos
            .iter()
            .filter_map(move |(outpoint, utxo)| match utxo.origin {
                UtxoOrigin::UnapprovedDeposit {
                    requested_at,
                    requested_amount,
                } => {
                    let mut causes = Vec::new();
                    if utxo.amount != requested_amount {
                        causes.push(UnapprovedCause::AmountMismatch);
                    }
                    if utxo.first_seen > requested_at + timing.deposit_request_expiry {
                        causes.push(UnapprovedCause::PaidAfterExpiry);
                    }
                    if causes.is_empty() {
                        causes.push(UnapprovedCause::SanctionOrWithheld);
                    }
                    Some(DepositNotApproved {
                        outpoint: *outpoint,
                        requested_amount,
                        paid_amount: utxo.amount,
                        requested_at,
                        block_time: utxo.first_seen,
                        causes,
                    })
                }
                UtxoOrigin::Deposit | UtxoOrigin::Change => None,
            })
    }

    /// Check the Sui `DepositApproved` against the pool: the UTXO must be a
    /// deposit the pool holds. See `SuiDepositApprovedEvent::judge`. Then
    /// mark the deposit approved, also on a finding: Move mints on it.
    pub fn check_sui_approval(
        &mut self,
        sui: &SuiDepositApprovedEvent,
        skew: u64,
    ) -> Vec<MonitorFinding> {
        let outpoint = OutPoint::from(sui.deposit_id);
        let paid = self
            .utxos
            .get(&outpoint)
            // Change is not a deposit. A held approved deposit is judged again,
            // because a new committee can approve it again.
            .filter(|utxo| utxo.origin != UtxoOrigin::Change)
            .map(|utxo| BtcConfirmedDeposit {
                deposit_id: sui.deposit_id,
                amount: utxo.amount,
                script_pubkey: utxo.script_pubkey.clone(),
                block_time: utxo.first_seen,
            });
        let findings = sui.judge(paid.as_ref(), skew);
        self.mark_approved(sui.deposit_id);
        findings
    }

    /// Apply withdrawals Bitcoin confirmed: every change output enters,
    /// then every input is spent. See the module doc for why in that order.
    pub fn add_withdrawals(&mut self, withdrawals: &[FinishedWithdrawal]) -> Vec<MonitorFinding> {
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
    fn add_change_outputs(&mut self, withdrawal: &FinishedWithdrawal) -> Vec<MonitorFinding> {
        let outputs = &withdrawal.confirmation.outputs;
        (withdrawal.first_change_vout..outputs.len())
            .flat_map(|vout| {
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

    /// Add a UTXO. A held one is a repeat: it keeps its entry, and its origin
    /// follows `UtxoOrigin::updated_by`. Another amount or script is a
    /// finding.
    fn add(&mut self, outpoint: OutPoint, utxo: Utxo) -> Vec<MonitorFinding> {
        let Some(held) = self.utxos.get_mut(&outpoint) else {
            self.utxos.insert(outpoint, utxo);
            return Vec::new();
        };
        let mut findings = Vec::new();
        match held.origin.updated_by(utxo.origin) {
            Some(origin) => held.origin = origin,
            None => findings.push(MonitorFinding::UtxoOriginConflict {
                outpoint,
                held: held.origin,
                new: utxo.origin,
            }),
        }
        if held.amount != utxo.amount || held.script_pubkey != utxo.script_pubkey {
            findings.push(MonitorFinding::BtcRpcInconsistency(
                BtcRpcInconsistency::UtxoMismatch {
                    outpoint,
                    held_amount: held.amount,
                    seen_amount: utxo.amount,
                    held_script: held.script_pubkey.clone(),
                    seen_script: utxo.script_pubkey,
                },
            ));
        }
        findings
    }

    /// Spend a UTXO by the transaction `txid`. One that is not in Move's pool
    /// is a finding.
    fn spend(&mut self, outpoint: OutPoint, txid: Txid) -> Option<MonitorFinding> {
        match self.utxos.remove(&outpoint) {
            Some(utxo) if utxo.origin.in_move_pool() => None,
            held => Some(MonitorFinding::UtxoOutsideMovePoolSpent {
                outpoint,
                txid,
                held: held.map(|utxo| utxo.origin),
            }),
        }
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
                    if utxo.origin.in_move_pool() && age_secs >= timing.utxo_max_age {
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
    use crate::findings::DepositMismatchReason;
    use crate::findings::DepositUnbackedReason;

    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::TxOut;

    use crate::domain::BtcConfirmation;
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
    fn deposit(fill: u8, amount: u64, block_time: UnixSeconds) -> BtcConfirmedDeposit {
        BtcConfirmedDeposit {
            deposit_id: DepositId::new(txid(fill), 0),
            amount,
            script_pubkey: script(),
            block_time,
        }
    }

    /// The deposit `deposit(fill, amount, block_time)`, unapproved and
    /// requested at `requested_at` for the paid amount.
    fn unapproved(
        fill: u8,
        amount: u64,
        block_time: UnixSeconds,
        requested_at: UnixSeconds,
    ) -> FinishedDeposit {
        FinishedDeposit::new(
            deposit(fill, amount, block_time),
            unapproved_origin(requested_at, amount),
        )
    }

    fn unapproved_origin(requested_at: UnixSeconds, requested_amount: u64) -> UtxoOrigin {
        UtxoOrigin::UnapprovedDeposit {
            requested_at,
            requested_amount,
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
    fn withdrawal(fill: u8, inputs: Vec<OutPoint>) -> FinishedWithdrawal {
        FinishedWithdrawal {
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

    /// A pool holding the approved deposit `outpoint(1)` of 1_000, first
    /// seen at 500.
    fn pool_with_one() -> UtxoPool {
        pool_seen_at(500)
    }

    /// A pool holding the approved deposit `outpoint(1)` of 1_000, first
    /// seen at `first_seen`.
    fn pool_seen_at(first_seen: UnixSeconds) -> UtxoPool {
        let mut pool = UtxoPool::default();
        let approved = FinishedDeposit::new(deposit(1, 1_000, first_seen), UtxoOrigin::Deposit);
        assert!(pool.add_deposit(&approved).is_empty());
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
        assert!(pool.add_deposit(&unapproved(2, 2_000, 500, 0)).is_empty());

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

        assert!(pool.add_deposit(&unapproved(1, 1_000, 900, 0)).is_empty());
        assert_eq!(pool.get(&outpoint(1)).unwrap().first_seen, 500);

        let findings = pool.add_deposit(&unapproved(1, 1_001, 900, 0));
        assert_eq!(
            findings,
            vec![MonitorFinding::BtcRpcInconsistency(
                BtcRpcInconsistency::UtxoMismatch {
                    outpoint: outpoint(1),
                    held_amount: 1_000,
                    seen_amount: 1_001,
                    held_script: script(),
                    seen_script: script(),
                }
            )]
        );
    }

    #[test]
    fn a_repeated_add_with_another_script_is_a_finding() {
        let mut pool = pool_with_one();
        let mut deposit = deposit(1, 1_000, 900);
        deposit.script_pubkey = ScriptBuf::from_bytes(vec![0x52]);

        let findings = pool.add_deposit(&FinishedDeposit::new(deposit, UtxoOrigin::Deposit));

        assert_eq!(
            findings,
            vec![MonitorFinding::BtcRpcInconsistency(
                BtcRpcInconsistency::UtxoMismatch {
                    outpoint: outpoint(1),
                    held_amount: 1_000,
                    seen_amount: 1_000,
                    held_script: script(),
                    seen_script: ScriptBuf::from_bytes(vec![0x52]),
                }
            )]
        );
        assert_eq!(pool.get(&outpoint(1)).unwrap().script_pubkey, script());
    }

    #[test]
    fn a_repeated_add_keeps_an_approved_deposit_approved() {
        let mut pool = pool_with_one();

        assert!(pool.add_deposit(&unapproved(1, 1_000, 500, 0)).is_empty());

        assert_eq!(pool.get(&outpoint(1)).unwrap().origin, UtxoOrigin::Deposit);
    }

    #[test]
    fn an_unapproved_deposit_is_held_but_does_not_count() {
        let mut pool = pool_with_one();
        assert!(pool.add_deposit(&unapproved(2, 2_000, 400, 0)).is_empty());

        assert!(pool.holds(&outpoint(2)));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.in_move_pool_len(), 1);
        assert_eq!(pool.value(), 1_000);
        assert_eq!(pool.oldest_timestamp(), Some(500));

        pool.mark_approved(DepositId::new(txid(2), 0));

        assert_eq!(pool.in_move_pool_len(), 2);
        assert_eq!(pool.value(), 3_000);
        assert_eq!(pool.oldest_timestamp(), Some(400));
    }

    #[test]
    fn a_second_spend_of_a_utxo_is_a_spend_outside_the_move_pool() {
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let findings = pool.add_withdrawals(&[withdrawal(8, vec![outpoint(1)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoOutsideMovePoolSpent {
                outpoint: outpoint(1),
                txid: txid(8),
                held: None,
            }]
        );
    }

    #[test]
    fn spending_a_utxo_the_pool_never_held_is_a_finding_and_records_nothing() {
        let mut pool = UtxoPool::default();

        let findings = pool.add_withdrawals(&[withdrawal(7, vec![outpoint(9)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoOutsideMovePoolSpent {
                outpoint: outpoint(9),
                txid: txid(7),
                held: None,
            }]
        );
        assert_eq!(pool.outpoints(), vec![change_of(7)]);
    }

    #[test]
    fn spending_an_unapproved_deposit_is_a_finding() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 500, 0)).is_empty());

        let findings = pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoOutsideMovePoolSpent {
                outpoint: outpoint(1),
                txid: txid(7),
                held: Some(unapproved_origin(0, 1_000)),
            }]
        );
        assert!(!pool.holds(&outpoint(1)));
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
        let mut pool = pool_with_one();

        let sui = sui_approval(1, 1_000, script());
        assert!(pool.check_sui_approval(&sui, SKEW).is_empty());
    }

    #[test]
    fn an_approval_marks_a_held_unapproved_deposit_approved() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 500, 0)).is_empty());
        assert_eq!(
            pool.get(&outpoint(1)).unwrap().origin,
            unapproved_origin(0, 1_000)
        );

        let sui = sui_approval(1, 1_000, script());
        assert!(pool.check_sui_approval(&sui, SKEW).is_empty());

        assert_eq!(pool.get(&outpoint(1)).unwrap().origin, UtxoOrigin::Deposit);
    }

    #[test]
    fn an_approval_of_a_spent_deposit_is_unbacked() {
        // Move refuses this approval, so the pool need not remember spends.
        let mut pool = pool_with_one();
        pool.add_withdrawals(&[withdrawal(5, vec![outpoint(1)])]);

        let sui = sui_approval(1, 1_000, script());
        assert_eq!(
            pool.check_sui_approval(&sui, SKEW),
            vec![MonitorFinding::DepositUnbacked {
                sui,
                reason: DepositUnbackedReason::NotFound
            }]
        );
    }

    #[test]
    fn an_approval_the_pool_never_held_is_unbacked() {
        let mut pool = pool_with_one();

        let sui = sui_approval(2, 1_000, script());
        let findings = pool.check_sui_approval(&sui, SKEW);
        assert_eq!(
            findings,
            vec![MonitorFinding::DepositUnbacked {
                sui,
                reason: DepositUnbackedReason::NotFound
            }]
        );
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
            vec![MonitorFinding::DepositUnbacked {
                sui,
                reason: DepositUnbackedReason::NotFound
            }]
        );
    }

    #[test]
    fn an_approval_with_another_amount_or_script_is_a_mismatch() {
        let mut pool = pool_with_one();

        for sui in [
            sui_approval(1, 2_000, script()),
            sui_approval(1, 1_000, ScriptBuf::from_bytes(vec![0x52])),
        ] {
            let findings = pool.check_sui_approval(&sui, SKEW);
            assert!(matches!(&findings[..], [MonitorFinding::DepositMismatch {
                    reason: DepositMismatchReason::PaymentDiffers { sui: claimed, .. },
                    ..
                }] if *claimed == sui));
        }
    }

    #[test]
    fn a_mismatched_approval_still_marks_the_deposit_approved() {
        // Move mints on the approval, so the deposit counts.
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 500, 0)).is_empty());

        let sui = sui_approval(1, 2_000, script());
        assert_eq!(pool.check_sui_approval(&sui, SKEW).len(), 1);

        assert_eq!(pool.get(&outpoint(1)).unwrap().origin, UtxoOrigin::Deposit);
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
    fn an_unapproved_deposit_is_not_reported_at_the_max_age() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 0, 0)).is_empty());
        let state = OutpointState::Unspent { block_time: 0 };

        assert!(findings_one(&pool, Some(state), MAX_AGE).is_empty());
    }

    #[test]
    fn an_unapproved_deposit_spent_is_a_suspect() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 0, 0)).is_empty());

        let (findings, suspects) = check_one(&pool, Some(OutpointState::Spent), 1);

        assert!(findings.is_empty());
        assert!(suspects.contains_key(&outpoint(1)));
    }

    #[test]
    fn a_missing_unapproved_deposit_is_an_rpc_inconsistency() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 0, 0)).is_empty());

        assert_eq!(
            findings_one(&pool, Some(OutpointState::Missing), 1),
            vec![MonitorFinding::BtcRpcInconsistency(
                BtcRpcInconsistency::UtxoVanished {
                    outpoint: outpoint(1),
                    first_seen: 0,
                }
            )]
        );
    }

    #[test]
    fn a_repeated_request_keeps_the_later_request() {
        let mut pool = UtxoPool::default();
        let add = |pool: &mut UtxoPool, requested_at, requested_amount| {
            pool.add_deposit(&FinishedDeposit::new(
                deposit(1, 1_000, 0),
                unapproved_origin(requested_at, requested_amount),
            ))
        };
        assert!(add(&mut pool, 300, 900).is_empty());

        assert!(add(&mut pool, 200, 800).is_empty());
        assert_eq!(
            pool.get(&outpoint(1)).unwrap().origin,
            unapproved_origin(300, 900)
        );

        assert!(add(&mut pool, 400, 1_000).is_empty());
        assert_eq!(
            pool.get(&outpoint(1)).unwrap().origin,
            unapproved_origin(400, 1_000)
        );
    }

    #[test]
    fn a_second_add_keeps_an_approval_and_the_later_request() {
        let unapproved = unapproved_origin(300, 1_000);
        let deposit = UtxoOrigin::Deposit;

        assert_eq!(unapproved.updated_by(deposit), Some(deposit));
        let later = unapproved_origin(400, 900);
        assert_eq!(unapproved.updated_by(later), Some(later));
        // An equal or earlier request keeps the held one.
        assert_eq!(
            unapproved.updated_by(unapproved_origin(300, 900)),
            Some(unapproved)
        );
        assert_eq!(
            unapproved.updated_by(unapproved_origin(200, 900)),
            Some(unapproved)
        );
        assert_eq!(deposit.updated_by(unapproved), Some(deposit));
        assert_eq!(
            UtxoOrigin::Change.updated_by(UtxoOrigin::Change),
            Some(UtxoOrigin::Change)
        );
    }

    #[test]
    fn a_deposit_against_change_is_a_conflict() {
        let unapproved = unapproved_origin(300, 1_000);
        let (deposit, change) = (UtxoOrigin::Deposit, UtxoOrigin::Change);

        assert_eq!(unapproved.updated_by(change), None);
        assert_eq!(change.updated_by(unapproved), None);
        assert_eq!(deposit.updated_by(change), None);
        assert_eq!(change.updated_by(deposit), None);
    }

    #[test]
    fn change_for_a_held_unapproved_deposit_is_a_conflict() {
        let mut pool = UtxoPool::default();
        let change = OutPoint {
            txid: txid(7),
            vout: 1,
        };
        let request = FinishedDeposit {
            deposit_id: DepositId::new(txid(7), 1),
            utxo: Utxo {
                amount: 550,
                script_pubkey: script(),
                origin: unapproved_origin(300, 550),
                first_seen: 700,
            },
        };
        assert!(pool.add_deposit(&request).is_empty());

        assert_eq!(
            pool.add_withdrawals(&[withdrawal(7, vec![])]),
            vec![MonitorFinding::UtxoOriginConflict {
                outpoint: change,
                held: unapproved_origin(300, 550),
                new: UtxoOrigin::Change,
            }]
        );
        assert_eq!(
            pool.get(&change).unwrap().origin,
            unapproved_origin(300, 550)
        );
    }

    #[test]
    fn an_approved_add_of_a_held_unapproved_deposit_approves_it() {
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 0, 300)).is_empty());

        let approved = FinishedDeposit::new(deposit(1, 1_000, 0), UtxoOrigin::Deposit);
        assert!(pool.add_deposit(&approved).is_empty());
        assert_eq!(pool.get(&outpoint(1)).unwrap().origin, UtxoOrigin::Deposit);

        // A later unapproved add does not undo the approval.
        assert!(pool.add_deposit(&unapproved(1, 1_000, 0, 400)).is_empty());
        assert_eq!(pool.get(&outpoint(1)).unwrap().origin, UtxoOrigin::Deposit);
    }

    #[test]
    fn valid_deposits_overdue_since_the_last_approval_are_a_stall() {
        // `Timing::for_tests` gives an approval 50 s. Overdue at 150 and 250:
        // the later of the request and the block counts.
        let mut pool = UtxoPool::default();
        assert!(pool.add_deposit(&unapproved(1, 1_000, 100, 0)).is_empty());
        assert!(pool.add_deposit(&unapproved(2, 1_000, 0, 200)).is_empty());
        let mismatch = FinishedDeposit::new(deposit(3, 999, 0), unapproved_origin(0, 1_000));
        assert!(pool.add_deposit(&mismatch).is_empty());
        let timing = Timing::for_tests();
        let stall = |last_approval| {
            Some(MonitorFinding::DepositApprovalStalled {
                outpoints: vec![outpoint(1), outpoint(2)],
                last_approval,
            })
        };

        assert_eq!(pool.approval_stall(None, 250, &timing), None);
        assert_eq!(pool.approval_stall(None, 251, &timing), stall(None));
        assert_eq!(
            pool.approval_stall(Some(149), 251, &timing),
            stall(Some(149))
        );
        // An approval since one became overdue leaves too few.
        assert_eq!(pool.approval_stall(Some(150), 251, &timing), None);

        pool.mark_approved(DepositId::new(txid(2), 0));
        assert_eq!(pool.approval_stall(None, 251, &timing), None);
    }

    /// The causes of `DepositNotApproved` for a request of 1_000 at 100.
    /// `Timing::for_tests` expires a request after 500 s.
    fn causes(paid_amount: u64, block_time: UnixSeconds) -> Vec<UnapprovedCause> {
        let mut pool = UtxoPool::default();
        let paid = FinishedDeposit::new(
            deposit(1, paid_amount, block_time),
            unapproved_origin(100, 1_000),
        );
        assert!(pool.add_deposit(&paid).is_empty());
        let timing = Timing::for_tests();
        let mut deposits = pool.unapproved_deposits(&timing);
        deposits.next().expect("one unapproved deposit").causes
    }

    #[test]
    fn a_missing_approval_names_the_causes_the_monitor_can_infer() {
        use UnapprovedCause::*;

        assert_eq!(causes(1_000, 600), vec![SanctionOrWithheld]);
        assert_eq!(causes(999, 600), vec![AmountMismatch]);
        assert_eq!(causes(1_000, 601), vec![PaidAfterExpiry]);
        assert_eq!(causes(999, 601), vec![AmountMismatch, PaidAfterExpiry]);
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
        pool.add_deposit(&unapproved(2, 2_000, 1_500, 1_400));
        pool.add_withdrawals(&[withdrawal(7, vec![outpoint(1)])]);

        let loaded = UtxoPool::from_wire(pool.held_to_wire());

        assert_eq!(loaded, pool);
    }
}
