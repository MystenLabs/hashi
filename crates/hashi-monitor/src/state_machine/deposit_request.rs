// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit request state machine: the user's claim resolved on Bitcoin.

use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

use crate::domain::BtcConfirmation;
use crate::domain::ConfirmedDeposit;
use crate::domain::DepositId;
use crate::domain::SuiDepositRequestedEvent;
use crate::rpc::btc::BtcRpcClient;
use crate::timing::Timing;

/// Deposit request state machine. It feeds the UTXO pool. `DepositRequested`
/// is the user's claim that a Bitcoin output pays the bridge; the committee
/// cannot suppress it. One machine per request: Move accepts several
/// requests for one UTXO, and each gets its own. The machine asks Bitcoin
/// until the transaction confirms or the request's life ends, then closes:
/// - Confirmed, and the output pays the bridge script of the claimed path:
///   the coin is bridge money. The pool takes it, whatever Move does with
///   the request later. Two requests for one UTXO give the pool the same
///   coin twice, which it stores once.
/// - Confirmed, but no such output: the claim is wrong. It is the user's
///   problem, and nothing is kept.
/// - Not confirmed within `DEPOSIT_REQUEST_WATCH`: the request lapses.
///   An honest deposit is assumed to confirm within the watch; a slow one
///   is requested again by the user once Move expires the request.
///
/// Nothing here is a finding. A coin Move never confirms shows up in the
/// pool's checks.
pub struct DepositRequestStateMachine {
    request: SuiDepositRequestedEvent,
    /// When Bitcoin was last asked.
    btc_checked_at: Option<UnixSeconds>,
    /// True once Bitcoin confirmed the transaction, with or without the coin.
    btc_answered: bool,
    /// The coin, once Bitcoin confirmed it at the claimed script.
    coin: Option<ConfirmedDeposit>,
    /// How long Bitcoin is asked about the request.
    time_limit: u64,
}

impl DepositRequestStateMachine {
    pub fn new(request: SuiDepositRequestedEvent, timing: &Timing) -> Self {
        Self {
            request,
            btc_checked_at: None,
            btc_answered: false,
            coin: None,
            time_limit: timing.deposit_request_watch,
        }
    }

    pub fn deposit_id(&self) -> DepositId {
        self.request.deposit_id
    }

    pub fn btc_txid(&self) -> Txid {
        self.request.deposit_id.txid()
    }

    /// When the request was made on Sui.
    pub fn requested_at(&self) -> UnixSeconds {
        self.request.timestamp_secs
    }

    /// The coin, once Bitcoin confirmed it at the claimed script.
    pub fn coin(&self) -> Option<&ConfirmedDeposit> {
        self.coin.as_ref()
    }

    pub fn into_coin(self) -> Option<ConfirmedDeposit> {
        self.coin
    }

    /// The transaction was not on Bitcoin by the end of the request's watch.
    fn lapsed(&self) -> bool {
        self.btc_checked_at
            .is_some_and(|checked_at| self.request.timestamp_secs + self.time_limit <= checked_at)
    }

    /// Whether Bitcoin still has to be asked about this request.
    pub fn is_expecting_events(&self) -> bool {
        // Bitcoin confirmed the transaction, with or without the coin.
        if self.btc_answered {
            return false;
        }
        // Not confirmed, and the request's time limit has passed.
        if self.lapsed() {
            return false;
        }
        true
    }

    /// Look up the transaction on Bitcoin and keep the coin if it pays the
    /// claimed script. Nothing here is a finding; an error is the RPC's.
    pub fn try_fetch_btc_tx(&mut self, btc_rpc_client: &BtcRpcClient) -> anyhow::Result<()> {
        if !self.is_expecting_events() {
            return Ok(());
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid())?;
        self.btc_checked_at = Some(now_timestamp_secs());
        if let Some(confirmation) = confirmation {
            self.record_confirmation(&confirmation);
        }
        Ok(())
    }

    fn record_confirmation(&mut self, confirmation: &BtcConfirmation) {
        self.btc_answered = true;
        let request = &self.request;
        let Some(output) = confirmation.outputs.get(request.deposit_id.vout() as usize) else {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                output_count = confirmation.outputs.len(),
                "deposit request names a vout the transaction does not have"
            );
            return;
        };
        if output.script_pubkey != request.script_pubkey {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                paid_script = %output.script_pubkey,
                "deposit request claims a path the output does not pay"
            );
            return;
        }
        let amount = output.value.to_sat();
        if amount != request.amount {
            tracing::debug!(
                request_id = %request.request_id,
                deposit_id = %request.deposit_id,
                claimed_amount = request.amount,
                paid_amount = amount,
                "deposit request claims an amount the output does not pay; the coin is kept with the paid amount"
            );
        }
        self.coin = Some(ConfirmedDeposit {
            deposit_id: request.deposit_id,
            amount,
            block_time: confirmation.block_time,
        });
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

    fn machine(request: SuiDepositRequestedEvent) -> DepositRequestStateMachine {
        DepositRequestStateMachine::new(request, &Timing::for_tests())
    }

    #[test]
    fn a_request_bitcoin_pays_at_a_claimed_script_is_a_coin() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));
        assert!(sm.is_expecting_events());

        sm.record_confirmation(&confirmation(50_000, script));

        assert_eq!(
            sm.coin(),
            Some(&ConfirmedDeposit {
                deposit_id: DepositId::new(txid(9), 1),
                amount: 50_000,
                block_time: 30,
            })
        );
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn a_request_bitcoin_pays_elsewhere_keeps_no_coin() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        sm.record_confirmation(&confirmation(50_000, p2wpkh(0x55)));

        assert_eq!(sm.coin(), None);
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn a_request_without_an_output_at_its_vout_keeps_no_coin() {
        let request = SuiDepositRequestedEvent {
            deposit_id: DepositId::new(txid(9), 5),
            ..deposit_request(p2wpkh(0x54))
        };
        let mut sm = machine(request);

        sm.record_confirmation(&confirmation(50_000, p2wpkh(0x54)));

        assert_eq!(sm.coin(), None);
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn a_request_paid_with_another_amount_keeps_the_coin_with_the_paid_amount() {
        let script = p2wpkh(0x54);
        let mut sm = machine(deposit_request(script.clone()));

        sm.record_confirmation(&confirmation(40_000, script));

        assert_eq!(sm.coin().map(|coin| coin.amount), Some(40_000));
    }

    #[test]
    fn a_request_lapses_once_a_lookup_after_its_watch_found_nothing() {
        let mut sm = machine(deposit_request(p2wpkh(0x54)));

        sm.btc_checked_at = Some(100 + 1_000 - 1);
        assert!(sm.is_expecting_events());

        sm.btc_checked_at = Some(1_100);
        assert!(!sm.is_expecting_events());
        assert_eq!(sm.coin(), None);
    }
}
