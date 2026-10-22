// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit state machine: the user's request resolved on Bitcoin, and
//! its Sui approval.

use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde::Serialize;
use sui_sdk_types::Address;

use crate::domain::BtcConfirmation;
use crate::domain::ConfirmedDeposit;
use crate::domain::DepositId;
use crate::domain::MonitorEvent;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::timing::Timing;

/// Lookups after the approval that find the transaction not yet confirmed
/// before the approval is reported unbacked. The honest committee approves
/// at the confirmation depth, so the first lookup may race it by seconds.
const EMPTY_LOOKUPS_BEFORE_ALERT: u8 = 2;

/// What Bitcoin said about a deposit request's transaction. Only a lookup
/// that a synced node answered changes it: a failed RPC changes nothing.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
enum BtcAnswer {
    /// Not asked yet, or not confirmed yet: unknown to Bitcoin, in the
    /// mempool, or below Hashi's confirmation threshold. Bitcoin is still asked.
    Pending,
    /// Confirmed, and the claimed vout pays the claimed script.
    /// The amount may differ from E1's: the judge later checks it against E3.
    Paid(ConfirmedDeposit),
    /// Confirmed, but the claimed vout is missing or pays another script.
    NotPaid,
    /// Not confirmed by the end of the watch.
    Lapsed,
}

/// Deposit state machine. It follows three events: E1 is the user's
/// `DepositRequested`, E2 is Bitcoin's confirmation, and E3 is the Sui
/// `DepositApproved`, after which Move mints. It feeds the UTXO pool. `DepositRequested` is the
/// user's claim that a Bitcoin output pays the bridge; the committee cannot
/// suppress it. One machine per request: Move accepts several requests for
/// one UTXO, and each gets its own. The machine asks Bitcoin until the
/// transaction confirms or the request's life ends, then closes:
/// - Confirmed, and the output pays the bridge script of the claimed path:
///   the UTXO is bridge money. The pool takes it, whatever Move does with
///   the request later. Two requests for one UTXO give the pool the same
///   UTXO twice, which it stores once.
/// - Confirmed, but no such output: the claim is wrong. It is the user's
///   problem, and nothing is kept.
/// - Not confirmed within `DEPOSIT_REQUEST_WATCH`: the request lapses.
///   An honest deposit is assumed to confirm within the watch; a slow one
///   is requested again by the user once Move expires the request.
///
/// It does not wait for the Sui `DepositApproved`. The first one that
/// arrives while the machine is open is kept and judged against Bitcoin's
/// answer when the machine closes. One that arrives after the machine
/// closed is judged against the pool by the auditor.
///
/// The rules between the deposit's events:
/// - E1 does not expect E2. A user may never pay, so a request that
///   lapses is not a finding.
/// - E2 does not expect E3. Sanctions and user mistakes leave valid
///   deposits unapproved, so a missing E3 is not a finding yet.
/// - E3 expects E2 already. `EMPTY_LOOKUPS_BEFORE_ALERT` lookups after E3
///   that find no E2 report E3 unbacked, before the machine closes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DepositStateMachine {
    sui_request: SuiDepositRequestedEvent,
    /// The first Sui `DepositApproved` for this request, if it arrived while
    /// the machine was open.
    sui_approval: Option<SuiDepositApprovedEvent>,
    /// Lookups since the approval that found the transaction not yet
    /// confirmed.
    empty_lookups_since_approval: u8,
    /// What Bitcoin said. The machine is closed once it is not `Pending`.
    btc_answer: BtcAnswer,
}

impl DepositStateMachine {
    pub fn new(sui_request: SuiDepositRequestedEvent) -> Self {
        Self {
            sui_request,
            sui_approval: None,
            empty_lookups_since_approval: 0,
            btc_answer: BtcAnswer::Pending,
        }
    }

    /// The Sui `DepositRequest` this machine follows.
    pub fn request_id(&self) -> Address {
        self.sui_request.request_id
    }

    pub fn requested_at(&self) -> UnixSeconds {
        self.sui_request.timestamp_secs
    }

    pub fn deposit_id(&self) -> DepositId {
        self.sui_request.deposit_id
    }

    pub fn btc_txid(&self) -> Txid {
        self.sui_request.deposit_id.txid()
    }

    /// The deposit, once Bitcoin confirmed it at the claimed script.
    pub fn confirmed(&self) -> Option<&ConfirmedDeposit> {
        match &self.btc_answer {
            BtcAnswer::Paid(deposit) => Some(deposit),
            BtcAnswer::Pending | BtcAnswer::NotPaid | BtcAnswer::Lapsed => None,
        }
    }

    /// The deposit Bitcoin confirmed, if any.
    pub fn into_confirmed(self) -> Option<ConfirmedDeposit> {
        match self.btc_answer {
            BtcAnswer::Paid(deposit) => Some(deposit),
            BtcAnswer::Pending | BtcAnswer::NotPaid | BtcAnswer::Lapsed => None,
        }
    }

    /// The request seen again. One with other contents is a finding and is
    /// dropped.
    pub fn add_sui_request(&self, event: &SuiDepositRequestedEvent) -> Option<MonitorFinding> {
        (*event != self.sui_request).then(|| {
            MonitorFinding::InvalidEventAdded(
                "duplicate deposit request for same request id with different contents".to_string(),
            )
        })
    }

    /// Keep the first Sui `DepositApproved` for this request, and judge it
    /// at once if Bitcoin already answered. One that differs from the
    /// request is a finding and is dropped. A later one, from a new
    /// committee, is dropped: it names the same UTXO with a later deadline.
    pub fn add_sui_approval(
        &mut self,
        event: SuiDepositApprovedEvent,
        timing: &Timing,
    ) -> Vec<MonitorFinding> {
        if !event.matches_request(&self.sui_request) {
            return vec![MonitorFinding::InvalidEventAdded(format!(
                "deposit approval differs from its request: {}",
                MonitorEvent::DepositApproved(event),
            ))];
        }
        if self.sui_approval.is_some() {
            return Vec::new();
        }
        self.sui_approval = Some(event);
        // Usually still open. If Bitcoin already closed the machine and GC
        // has not run yet, judge now: the pool lacks this UTXO yet.
        self.judge_held_sui_approval(timing)
    }

    /// Judge the held Sui approval against Bitcoin's answer, once the
    /// machine is closed.
    fn judge_held_sui_approval(&self, timing: &Timing) -> Vec<MonitorFinding> {
        // Still open: Bitcoin may still answer.
        if self.btc_answer == BtcAnswer::Pending {
            return Vec::new();
        }
        // Closed, but no Sui approval arrived to judge.
        let Some(sui) = &self.sui_approval else {
            return Vec::new();
        };
        sui.judge(self.confirmed(), timing.deposit_approval_skew)
    }

    /// Whether the machine is done and the auditor can drop it: Bitcoin
    /// answered, or the request lapsed.
    pub fn is_ready_for_gc(&self) -> bool {
        self.btc_answer != BtcAnswer::Pending
    }

    /// Whether Bitcoin still has to be asked about this request.
    pub fn expects_btc(&self) -> bool {
        self.btc_answer == BtcAnswer::Pending
    }

    /// Look up the transaction on Bitcoin and keep the UTXO if it pays the
    /// claimed script. If that closes the machine, by an answer or by the
    /// lapse, the held Sui approval is judged. An error is the RPC's.
    /// `checked_at` must be no later than the lookup.
    pub fn try_fetch_btc_tx(
        &mut self,
        timing: &Timing,
        btc_rpc_client: &BtcRpcClient,
        checked_at: UnixSeconds,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        if self.btc_answer != BtcAnswer::Pending {
            return Ok(Vec::new());
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid())?;
        Ok(self.record_lookup(timing, checked_at, confirmation.as_ref()))
    }

    /// Record a lookup made at `checked_at`, and Bitcoin's confirmation if
    /// any. A lookup past the watch that found nothing lapses the request.
    /// If the machine is now closed, the held Sui approval is judged.
    /// Otherwise an empty lookup after the approval is counted.
    pub fn record_lookup(
        &mut self,
        timing: &Timing,
        checked_at: UnixSeconds,
        confirmation: Option<&BtcConfirmation>,
    ) -> Vec<MonitorFinding> {
        match confirmation {
            Some(confirmation) => self.btc_answer = self.answer_from(confirmation),
            None if self.sui_request.timestamp_secs + timing.deposit_request_watch
                <= checked_at =>
            {
                self.btc_answer = BtcAnswer::Lapsed;
            }
            // Not confirmed yet, and the watch is still open: stay Pending.
            None => {}
        }
        if self.btc_answer == BtcAnswer::Pending {
            return self.count_empty_lookup();
        }
        self.judge_held_sui_approval(timing)
    }

    /// Count a lookup that found the transaction not yet confirmed. The
    /// count starts at the approval. Every lookup from the alert on reports.
    fn count_empty_lookup(&mut self) -> Vec<MonitorFinding> {
        let Some(sui) = &self.sui_approval else {
            return Vec::new();
        };
        self.empty_lookups_since_approval = self.empty_lookups_since_approval.saturating_add(1);
        if self.empty_lookups_since_approval < EMPTY_LOOKUPS_BEFORE_ALERT {
            return Vec::new();
        }
        vec![MonitorFinding::DepositUnbacked { sui: sui.clone() }]
    }

    /// Bitcoin's confirmation of the transaction, read against the claim.
    fn answer_from(&self, confirmation: &BtcConfirmation) -> BtcAnswer {
        let request = &self.sui_request;
        let Some(deposit) = ConfirmedDeposit::from_confirmation(request, confirmation) else {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                output_count = confirmation.outputs.len(),
                "deposit request names a vout the transaction does not have, or a path its output does not pay"
            );
            return BtcAnswer::NotPaid;
        };
        if deposit.amount != request.amount {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                claimed_amount = request.amount,
                paid_amount = deposit.amount,
                "deposit request claims an amount the output does not pay; the UTXO is kept with the paid amount"
            );
        }
        BtcAnswer::Paid(deposit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::approval_of;
    use crate::test_utils::confirmation;
    use crate::test_utils::deposit_request;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;

    fn machine(request: SuiDepositRequestedEvent) -> DepositStateMachine {
        DepositStateMachine::new(request)
    }

    /// The approval of `deposit_request()`, at time 200.
    fn approval() -> SuiDepositApprovedEvent {
        approval_of(&deposit_request(), 200)
    }

    #[test]
    fn a_held_sui_approval_is_judged_when_bitcoin_answers() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request());
        assert!(
            sm.add_sui_approval(approval(), &Timing::for_tests())
                .is_empty()
        );

        // Bitcoin pays less than the request claims and Sui approves.
        let findings = sm.record_lookup(
            &Timing::for_tests(),
            500,
            Some(&confirmation(40_000, script)),
        );
        assert!(matches!(
            &findings[..],
            [MonitorFinding::DepositMismatch { btc, .. }] if btc.amount == 40_000
        ));
    }

    #[test]
    fn a_held_sui_approval_is_unbacked_when_the_request_lapses() {
        let mut sm = machine(deposit_request());
        sm.add_sui_approval(approval(), &Timing::for_tests());

        assert_eq!(
            sm.record_lookup(&Timing::for_tests(), 100 + 1_000, None),
            vec![MonitorFinding::DepositUnbacked { sui: approval() }]
        );
    }

    #[test]
    fn a_sui_approval_after_bitcoin_answered_is_judged_at_once() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request());
        assert!(
            sm.record_lookup(
                &Timing::for_tests(),
                500,
                Some(&confirmation(40_000, script))
            )
            .is_empty()
        );

        assert!(matches!(
            &sm.add_sui_approval(approval(), &Timing::for_tests())[..],
            [MonitorFinding::DepositMismatch { btc, .. }] if btc.amount == 40_000
        ));
    }

    #[test]
    fn a_repeated_request_with_other_contents_is_a_finding() {
        let request = deposit_request();
        let sm = machine(request.clone());

        assert_eq!(sm.add_sui_request(&request), None);
        let other_amount = SuiDepositRequestedEvent {
            amount: 60_000,
            ..request
        };
        assert!(matches!(
            sm.add_sui_request(&other_amount),
            Some(MonitorFinding::InvalidEventAdded(_))
        ));
    }

    #[test]
    fn a_sui_approval_that_differs_from_its_request_is_a_finding() {
        let mut sm = machine(deposit_request());
        let other_path = SuiDepositApprovedEvent {
            script_pubkey: p2wpkh(0x55),
            ..approval()
        };

        assert!(matches!(
            &sm.add_sui_approval(other_path, &Timing::for_tests())[..],
            [MonitorFinding::InvalidEventAdded(_)]
        ));
        assert_eq!(sm.sui_approval, None);
    }

    #[test]
    fn a_later_sui_approval_keeps_the_first() {
        let mut sm = machine(deposit_request());
        let reapproval = SuiDepositApprovedEvent {
            timestamp_secs: 900,
            ..approval()
        };

        assert!(
            sm.add_sui_approval(approval(), &Timing::for_tests())
                .is_empty()
        );
        assert!(
            sm.add_sui_approval(reapproval, &Timing::for_tests())
                .is_empty()
        );
        assert_eq!(sm.sui_approval, Some(approval()));
    }

    #[test]
    fn every_empty_lookup_from_the_second_after_the_approval_reports_it() {
        let mut sm = machine(deposit_request());
        // An empty lookup before the approval does not count.
        assert!(sm.record_lookup(&Timing::for_tests(), 150, None).is_empty());
        assert!(
            sm.add_sui_approval(approval(), &Timing::for_tests())
                .is_empty()
        );

        // The first may race the committee's view of Bitcoin.
        assert!(sm.record_lookup(&Timing::for_tests(), 300, None).is_empty());
        let unbacked = vec![MonitorFinding::DepositUnbacked { sui: approval() }];
        assert_eq!(sm.record_lookup(&Timing::for_tests(), 400, None), unbacked);
        assert_eq!(sm.record_lookup(&Timing::for_tests(), 500, None), unbacked);

        // A deposit Bitcoin confirms in time after all closes the machine
        // without a new finding.
        assert!(
            sm.record_lookup(
                &Timing::for_tests(),
                600,
                Some(&confirmation(50_000, p2wpkh(0x54)))
            )
            .is_empty()
        );
        assert!(sm.is_ready_for_gc());
    }

    #[test]
    fn a_request_bitcoin_pays_at_a_claimed_script_is_a_deposit() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request());
        assert!(sm.expects_btc());

        sm.record_lookup(
            &Timing::for_tests(),
            500,
            Some(&confirmation(50_000, script.clone())),
        );

        assert_eq!(
            sm.confirmed(),
            Some(&ConfirmedDeposit {
                deposit_id: DepositId::new(txid(9), 1),
                amount: 50_000,
                script_pubkey: script,
                block_time: 30,
            })
        );
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_bitcoin_pays_elsewhere_keeps_no_deposit() {
        let mut sm = machine(deposit_request());

        sm.record_lookup(
            &Timing::for_tests(),
            500,
            Some(&confirmation(50_000, p2wpkh(0x55))),
        );

        assert_eq!(sm.confirmed(), None);
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_without_an_output_at_its_vout_keeps_no_deposit() {
        let request = SuiDepositRequestedEvent {
            deposit_id: DepositId::new(txid(9), 5),
            ..deposit_request()
        };
        let mut sm = machine(request);

        sm.record_lookup(
            &Timing::for_tests(),
            500,
            Some(&confirmation(50_000, p2wpkh(0x54))),
        );

        assert_eq!(sm.confirmed(), None);
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_paid_with_another_amount_keeps_the_deposit_with_the_paid_amount() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request());

        sm.record_lookup(
            &Timing::for_tests(),
            500,
            Some(&confirmation(40_000, script)),
        );

        assert_eq!(sm.confirmed().map(|deposit| deposit.amount), Some(40_000));
    }

    #[test]
    fn a_request_lapses_once_a_lookup_after_its_watch_found_nothing() {
        let mut sm = machine(deposit_request());

        sm.record_lookup(&Timing::for_tests(), 100 + 1_000 - 1, None);
        assert!(sm.expects_btc());

        sm.record_lookup(&Timing::for_tests(), 1_100, None);
        assert!(!sm.expects_btc());
        assert_eq!(sm.confirmed(), None);
    }
}
