// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit state machine: the user's request resolved on Bitcoin, and
//! its Sui confirmation.

use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

use crate::domain::BtcConfirmation;
use crate::domain::ConfirmedDeposit;
use crate::domain::DepositId;
use crate::domain::MonitorEvent;
use crate::domain::SuiDepositConfirmedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::timing::Timing;

/// What Bitcoin said about a deposit request's transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BtcAnswer {
    /// Not confirmed yet; Bitcoin is still asked.
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
/// `DepositConfirmed`, on which Move mints. It feeds the UTXO pool. `DepositRequested` is the
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
/// It does not wait for the Sui `DepositConfirmed`. One that arrives while
/// the machine is open is kept and judged against Bitcoin's answer when the
/// machine closes. Until then, a confirmation Bitcoin has not matched by its
/// deadline is a timing violation. One that arrives after the machine
/// closed is judged against the pool by the auditor.
pub struct DepositStateMachine {
    sui_request: SuiDepositRequestedEvent,
    /// The Sui `DepositConfirmed` for this request, if it arrived while the
    /// machine was open.
    sui_confirmation: Option<SuiDepositConfirmedEvent>,
    /// When Bitcoin was last asked.
    btc_checked_at: Option<UnixSeconds>,
    /// What Bitcoin said. The machine is closed once it is not `Pending`.
    btc_answer: BtcAnswer,
    /// How long Bitcoin is asked about the request.
    time_limit: u64,
    /// How far the deposit's Bitcoin time may follow its Sui confirmation. A
    /// miner may date a block up to two hours ahead, and our lookups lag.
    confirmation_skew: u64,
}

impl DepositStateMachine {
    pub fn new(sui_request: SuiDepositRequestedEvent, timing: &Timing) -> Self {
        Self {
            sui_request,
            sui_confirmation: None,
            btc_checked_at: None,
            btc_answer: BtcAnswer::Pending,
            time_limit: timing.deposit_request_watch,
            confirmation_skew: timing.deposit_confirmation_skew,
        }
    }

    pub fn deposit_id(&self) -> DepositId {
        self.sui_request.deposit_id
    }

    pub fn btc_txid(&self) -> Txid {
        self.sui_request.deposit_id.txid()
    }

    /// When the request was made on Sui.
    pub fn requested_at(&self) -> UnixSeconds {
        self.sui_request.timestamp_secs
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
        self.confirmed().cloned()
    }

    /// The request seen again, as a replay does. One with other contents
    /// is a finding and is dropped.
    pub fn add_sui_request(&self, event: &SuiDepositRequestedEvent) -> Option<MonitorFinding> {
        (*event != self.sui_request).then(|| {
            MonitorFinding::InvalidEventAdded(
                "duplicate deposit request for same request id with different contents".to_string(),
            )
        })
    }

    /// Keep the Sui `DepositConfirmed` for this request, and judge it at
    /// once if Bitcoin already answered. One that differs from the request,
    /// or a second one with other contents, is a finding and is dropped.
    pub fn add_sui_confirmation(&mut self, event: SuiDepositConfirmedEvent) -> Vec<MonitorFinding> {
        if !event.matches_request(&self.sui_request) {
            return vec![MonitorFinding::InvalidEventAdded(format!(
                "deposit confirmation differs from its request: {}",
                MonitorEvent::DepositConfirmed(event),
            ))];
        }
        match &self.sui_confirmation {
            Some(held) if *held != event => vec![MonitorFinding::InvalidEventAdded(
                "duplicate deposit confirmation for same request with different contents"
                    .to_string(),
            )],
            Some(_) => Vec::new(),
            None => {
                self.sui_confirmation = Some(event);
                // Usually still open. If Bitcoin already closed the machine and
                // GC has not run yet, judge now: the pool lacks this UTXO yet.
                self.judge_held_sui_confirmation()
            }
        }
    }

    /// Judge the held Sui confirmation against Bitcoin's answer, once the
    /// machine is closed.
    fn judge_held_sui_confirmation(&self) -> Vec<MonitorFinding> {
        // Still open: Bitcoin may still answer.
        if self.btc_answer == BtcAnswer::Pending {
            return Vec::new();
        }
        // Closed, but no Sui confirmation arrived to judge.
        let Some(sui) = &self.sui_confirmation else {
            return Vec::new();
        };
        sui.judge(self.confirmed(), self.confirmation_skew)
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
    /// lapse, the held Sui confirmation is judged. An error is the RPC's.
    pub fn try_fetch_btc_tx(
        &mut self,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        if self.btc_answer != BtcAnswer::Pending {
            return Ok(Vec::new());
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid())?;
        Ok(self.record_lookup(now_timestamp_secs(), confirmation.as_ref()))
    }

    /// Record a lookup made at `checked_at`, and Bitcoin's confirmation if
    /// any. A lookup past the watch that found nothing lapses the request.
    /// If the machine is now closed, the held Sui confirmation is judged.
    pub fn record_lookup(
        &mut self,
        checked_at: UnixSeconds,
        confirmation: Option<&BtcConfirmation>,
    ) -> Vec<MonitorFinding> {
        self.btc_checked_at = Some(checked_at);
        match confirmation {
            Some(confirmation) => self.btc_answer = self.answer_from(confirmation),
            None if self.sui_request.timestamp_secs + self.time_limit <= checked_at => {
                self.btc_answer = BtcAnswer::Lapsed;
            }
            // Not confirmed yet, and the watch is still open: stay Pending.
            None => {}
        }
        self.judge_held_sui_confirmation()
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

    /// The timing rules between the deposit's events:
    /// - E1 does not expect E2. A user may never pay, so a request that
    ///   lapses is not a finding.
    /// - E2 does not expect E3. Sanctions and user mistakes leave valid
    ///   deposits unminted, so a missing E3 is not a finding yet.
    /// - E3 expects E2 by E3 plus `DEPOSIT_CONFIRMATION_SKEW`. This reports
    ///   E2 missing while the machine is open; the machine judges it when
    ///   it closes.
    pub fn timing_violations(&self) -> Vec<MonitorFinding> {
        // No E3: nothing is due.
        let Some(sui) = &self.sui_confirmation else {
            return Vec::new();
        };
        // E3 expects E2 by this time.
        let deadline = sui.timestamp_secs + self.confirmation_skew;
        // E2 is missing once a lookup at or past the deadline found nothing.
        let e2_missing = self.btc_answer == BtcAnswer::Pending
            && self.btc_checked_at.is_some_and(|cursor| deadline <= cursor);
        if !e2_missing {
            return Vec::new();
        }
        vec![MonitorFinding::DepositUnbacked {
            sui: sui.clone(),
            deadline,
            block_time: None,
        }]
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;

    use super::*;
    use crate::test_utils::confirmation;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;

    fn deposit_request(script_pubkey: ScriptBuf) -> SuiDepositRequestedEvent {
        SuiDepositRequestedEvent {
            request_id: sui_sdk_types::Address::new([0x61; 32]),
            timestamp_secs: 100,
            deposit_id: DepositId::new(txid(9), 1),
            amount: 50_000,
            script_pubkey,
        }
    }

    fn machine(request: SuiDepositRequestedEvent) -> DepositStateMachine {
        DepositStateMachine::new(request, &Timing::for_tests())
    }

    /// The Sui `DepositConfirmed` for `deposit_request`, at time 200.
    fn sui_confirmation(amount: u64) -> SuiDepositConfirmedEvent {
        SuiDepositConfirmedEvent {
            timestamp_secs: 200,
            request_id: sui_sdk_types::Address::new([0x61; 32]),
            deposit_id: DepositId::new(txid(9), 1),
            amount,
            script_pubkey: p2wpkh(0x54),
        }
    }

    #[test]
    fn a_held_sui_confirmation_is_judged_when_bitcoin_answers() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        assert!(sm.add_sui_confirmation(sui_confirmation(50_000)).is_empty());

        // Bitcoin pays less than the request claims and Sui mints.
        let findings = sm.record_lookup(500, Some(&confirmation(40_000, script)));
        assert!(matches!(
            &findings[..],
            [MonitorFinding::DepositMismatch { btc, .. }] if btc.amount == 40_000
        ));
    }

    #[test]
    fn a_held_sui_confirmation_is_unbacked_when_the_request_lapses() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));
        sm.add_sui_confirmation(sui_confirmation(50_000));

        assert_eq!(
            sm.record_lookup(100 + 1_000, None),
            vec![MonitorFinding::DepositUnbacked {
                sui: sui_confirmation(50_000),
                deadline: 210,
                block_time: None,
            }]
        );
    }

    #[test]
    fn a_sui_confirmation_after_bitcoin_answered_is_judged_at_once() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        assert!(
            sm.record_lookup(500, Some(&confirmation(40_000, script)))
                .is_empty()
        );

        assert!(matches!(
            &sm.add_sui_confirmation(sui_confirmation(50_000))[..],
            [MonitorFinding::DepositMismatch { btc, .. }] if btc.amount == 40_000
        ));
    }

    #[test]
    fn a_repeated_request_with_other_contents_is_a_finding() {
        let request = deposit_request(p2wpkh(0x54));
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
    fn a_sui_confirmation_that_differs_from_its_request_is_a_finding() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));
        let other_path = SuiDepositConfirmedEvent {
            script_pubkey: p2wpkh(0x55),
            ..sui_confirmation(50_000)
        };

        assert!(matches!(
            &sm.add_sui_confirmation(other_path)[..],
            [MonitorFinding::InvalidEventAdded(_)]
        ));
        assert_eq!(sm.sui_confirmation, None);
    }

    #[test]
    fn a_second_sui_confirmation_with_other_contents_is_a_finding() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        assert!(sm.add_sui_confirmation(sui_confirmation(50_000)).is_empty());
        assert!(sm.add_sui_confirmation(sui_confirmation(50_000)).is_empty());
        assert!(matches!(
            &sm.add_sui_confirmation(sui_confirmation(60_000))[..],
            [MonitorFinding::InvalidEventAdded(_)]
        ));
        assert_eq!(sm.sui_confirmation, Some(sui_confirmation(50_000)));
    }

    #[test]
    fn a_sui_confirmation_bitcoin_has_not_matched_by_its_deadline_is_a_violation() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        sm.btc_checked_at = Some(500);
        // Without the Sui confirmation, nothing is due.
        assert!(sm.timing_violations().is_empty());

        sm.add_sui_confirmation(sui_confirmation(50_000));
        sm.btc_checked_at = Some(209);
        assert!(sm.timing_violations().is_empty());

        sm.btc_checked_at = Some(210);
        assert_eq!(
            sm.timing_violations(),
            vec![MonitorFinding::DepositUnbacked {
                sui: sui_confirmation(50_000),
                deadline: 210,
                block_time: None,
            }]
        );

        sm.record_lookup(500, Some(&confirmation(50_000, script)));
        assert!(sm.timing_violations().is_empty());
    }

    #[test]
    fn a_request_bitcoin_pays_at_a_claimed_script_is_a_deposit() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        assert!(sm.expects_btc());

        sm.record_lookup(500, Some(&confirmation(50_000, script.clone())));

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
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        sm.record_lookup(500, Some(&confirmation(50_000, p2wpkh(0x55))));

        assert_eq!(sm.confirmed(), None);
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_without_an_output_at_its_vout_keeps_no_deposit() {
        let request = SuiDepositRequestedEvent {
            deposit_id: DepositId::new(txid(9), 5),
            ..deposit_request(p2wpkh(0x54))
        };
        let mut sm = machine(request);

        sm.record_lookup(500, Some(&confirmation(50_000, p2wpkh(0x54))));

        assert_eq!(sm.confirmed(), None);
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_paid_with_another_amount_keeps_the_deposit_with_the_paid_amount() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));

        sm.record_lookup(500, Some(&confirmation(40_000, script)));

        assert_eq!(sm.confirmed().map(|deposit| deposit.amount), Some(40_000));
    }

    #[test]
    fn a_request_lapses_once_a_lookup_after_its_watch_found_nothing() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        sm.record_lookup(100 + 1_000 - 1, None);
        assert!(sm.expects_btc());

        sm.record_lookup(1_100, None);
        assert!(!sm.expects_btc());
        assert_eq!(sm.confirmed(), None);
    }
}
