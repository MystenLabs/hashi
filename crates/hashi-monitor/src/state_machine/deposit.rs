// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit state machine: the user's request resolved on Bitcoin, and
//! Hashi's confirmation of it.

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

/// Deposit state machine. It feeds the UTXO pool. `DepositRequested` is the
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
/// It does not wait for Hashi's `DepositConfirmed`. One that arrives while
/// the machine is open is kept, and the auditor checks it against the pool
/// when the machine closes. Until then, a confirmation Bitcoin has not
/// matched by its deadline is a violation.
pub struct DepositStateMachine {
    sui_request: SuiDepositRequestedEvent,
    /// Hashi's `DepositConfirmed` for this request, if it arrived while the
    /// machine was open.
    sui_confirmation: Option<SuiDepositConfirmedEvent>,
    /// When Bitcoin was last asked.
    btc_checked_at: Option<UnixSeconds>,
    /// True once Bitcoin confirmed the transaction, with or without the UTXO.
    btc_answered: bool,
    /// The deposit, once Bitcoin confirmed it at the claimed script.
    confirmed: Option<ConfirmedDeposit>,
    /// How long Bitcoin is asked about the request.
    time_limit: u64,
    /// How long after Hashi's confirmation Bitcoin may confirm.
    confirmation_skew: u64,
}

impl DepositStateMachine {
    pub fn new(sui_request: SuiDepositRequestedEvent, timing: &Timing) -> Self {
        Self {
            sui_request,
            sui_confirmation: None,
            btc_checked_at: None,
            btc_answered: false,
            confirmed: None,
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
        self.confirmed.as_ref()
    }

    /// The deposit Bitcoin confirmed, and Hashi's confirmation if it arrived.
    pub fn into_parts(self) -> (Option<ConfirmedDeposit>, Option<SuiDepositConfirmedEvent>) {
        (self.confirmed, self.sui_confirmation)
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

    /// Keep Hashi's `DepositConfirmed` for this request. One that differs
    /// from the request, or a second one with other contents, is a finding
    /// and is dropped.
    pub fn add_sui_confirmation(
        &mut self,
        event: SuiDepositConfirmedEvent,
    ) -> Option<MonitorFinding> {
        if !event.matches_request(&self.sui_request) {
            return Some(MonitorFinding::InvalidEventAdded(format!(
                "deposit confirmation differs from its request: {}",
                MonitorEvent::DepositConfirmed(event),
            )));
        }
        match &self.sui_confirmation {
            Some(held) if *held != event => Some(MonitorFinding::InvalidEventAdded(
                "duplicate deposit confirmation for same request with different contents"
                    .to_string(),
            )),
            Some(_) => None,
            None => {
                self.sui_confirmation = Some(event);
                None
            }
        }
    }

    /// Whether the machine is done and the auditor can drop it: Bitcoin
    /// answered, or the request lapsed.
    pub fn is_ready_for_gc(&self) -> bool {
        !self.expects_btc()
    }

    /// Whether Bitcoin still has to be asked about this request.
    pub fn expects_btc(&self) -> bool {
        // Bitcoin confirmed the txid exists, whether or not it has the claimed UTXO.
        if self.btc_answered {
            return false;
        }

        // Not confirmed, and the request's time limit has passed.
        if self.btc_checked_at.is_some_and(|checked_at| {
            self.sui_request.timestamp_secs + self.time_limit <= checked_at
        }) {
            return false;
        }

        true
    }

    /// Look up the transaction on Bitcoin and keep the UTXO if it pays the
    /// claimed script. Nothing here is a finding; an error is the RPC's.
    pub fn try_fetch_btc_tx(&mut self, btc_rpc_client: &BtcRpcClient) -> anyhow::Result<()> {
        if !self.expects_btc() {
            return Ok(());
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid())?;
        self.btc_checked_at = Some(now_timestamp_secs());
        if let Some(confirmation) = confirmation {
            self.record_confirmation(&confirmation);
        }
        Ok(())
    }

    /// Close the machine with Bitcoin's confirmation of the transaction.
    pub fn record_confirmation(&mut self, confirmation: &BtcConfirmation) {
        self.btc_answered = true;
        let request = &self.sui_request;
        let Some(deposit) = ConfirmedDeposit::from_confirmation(request, confirmation) else {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                output_count = confirmation.outputs.len(),
                "deposit request names a vout the transaction does not have, or a path its output does not pay"
            );
            return;
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
        self.confirmed = Some(deposit);
    }

    /// Hashi confirmed the deposit, and Bitcoin still had not confirmed the
    /// transaction at a lookup past the deadline. Reported until the machine
    /// closes; the auditor then checks the confirmation against the pool.
    ///
    /// E1 (DepositRequested) and E2 (Bitcoin confirmation) currently do not trigger a timing violation.
    /// A valid E2 could create an expectation over E3 (DepositConfirmed).
    /// We do not currently enforce it since sanctions and user mistakes can legitimately
    /// cause this case.
    ///
    /// For now, we only enforce E3 induced expectations.
    /// An E3 event causes a timing expectation on E2
    pub fn timing_violations(&self) -> Vec<MonitorFinding> {
        let (Some(sui), Some(cursor)) = (&self.sui_confirmation, self.btc_checked_at) else {
            return Vec::new();
        };
        let deadline = sui.timestamp_secs + self.confirmation_skew;
        if self.btc_answered || cursor < deadline {
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

    /// Hashi's `DepositConfirmed` for `deposit_request`, at time 200.
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
            sm.add_sui_confirmation(other_path),
            Some(MonitorFinding::InvalidEventAdded(_))
        ));
        assert_eq!(sm.into_parts().1, None);
    }

    #[test]
    fn a_second_sui_confirmation_with_other_contents_is_a_finding() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        assert_eq!(sm.add_sui_confirmation(sui_confirmation(50_000)), None);
        assert_eq!(sm.add_sui_confirmation(sui_confirmation(50_000)), None);
        assert!(matches!(
            sm.add_sui_confirmation(sui_confirmation(60_000)),
            Some(MonitorFinding::InvalidEventAdded(_))
        ));
        assert_eq!(sm.into_parts().1, Some(sui_confirmation(50_000)));
    }

    #[test]
    fn a_sui_confirmation_bitcoin_has_not_matched_by_its_deadline_is_a_violation() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        sm.btc_checked_at = Some(500);
        // Without Hashi's confirmation, nothing is due.
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

        sm.record_confirmation(&confirmation(50_000, script));
        assert!(sm.timing_violations().is_empty());
    }

    #[test]
    fn a_request_bitcoin_pays_at_a_claimed_script_is_a_deposit() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        assert!(sm.expects_btc());

        sm.record_confirmation(&confirmation(50_000, script.clone()));

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

        sm.record_confirmation(&confirmation(50_000, p2wpkh(0x55)));

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

        sm.record_confirmation(&confirmation(50_000, p2wpkh(0x54)));

        assert_eq!(sm.confirmed(), None);
        assert!(!sm.expects_btc());
    }

    #[test]
    fn a_request_paid_with_another_amount_keeps_the_deposit_with_the_paid_amount() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));

        sm.record_confirmation(&confirmation(40_000, script));

        assert_eq!(sm.confirmed().map(|deposit| deposit.amount), Some(40_000));
    }

    #[test]
    fn a_request_lapses_once_a_lookup_after_its_watch_found_nothing() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        sm.btc_checked_at = Some(100 + 1_000 - 1);
        assert!(sm.expects_btc());

        sm.btc_checked_at = Some(1_100);
        assert!(!sm.expects_btc());
        assert_eq!(sm.confirmed(), None);
    }
}
