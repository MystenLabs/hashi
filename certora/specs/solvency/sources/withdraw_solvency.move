/// @module Solvency
module solvency::withdraw_solvency;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::{
    btc::BTC,
    committee::CommitteeSignature,
    hashi::Hashi,
    utxo::UtxoId,
    withdraw,
    withdrawal_queue::OutputUtxo,
};
use solvency::summaries_utxo_pool::total_active_amount;
use sui::{clock::Clock, random::Random};

public fun cvlm_manifest() {
    target(@hashi, b"withdraw", b"request_withdrawal");
    target(@hashi, b"withdraw", b"cancel_withdrawal");
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"confirm_withdrawal");
    target(@hashi, b"withdraw", b"reallocate_presigs");
    target(@hashi, b"withdraw", b"cleanup_spent_utxos");
    target(@hashi, b"withdraw", b"commit_withdrawal_tx");
    target(@hashi, b"withdraw", b"archive_confirmed_withdrawals");
    target(@hashi, b"withdraw", b"archive_withdrawal_requests");
    target(@hashi, b"withdraw", b"finish_archive_withdrawal_txns");

    invoker(b"invoke");
    rule(b"withdraw_functions_never_shrink_solvency_gap");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Withdraw entry points never shrink the solvency gap
/// @description For each of the twelve withdraw entry points, a successful call does
///   not decrease pool BTC minus hBTC supply. In particular, commit_withdrawal_tx burns
///   at least as much hBTC as the input UTXO amount it locks minus the change it returns
///   to the pool.
/// @link_property SOLVENCY
/// @status VERIFIED
/// @report solvency.conf https://prover.certora.com/output/497546/46cf5d8e98dd495c9f9382c508edc339?anonymousKey=d972de29a927f4c954207d9c23c3846a0752f3bb
public fun withdraw_functions_never_shrink_solvency_gap(hashi: &mut Hashi, target: Function) {
    let pool_btc_before = *total_active_amount();
    let hbtc_before = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    invoke(target, hashi);

    let pool_btc_after = *total_active_amount();
    let hbtc_after = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    // assert pool_btc_after - hbtc_after >= pool_btc_before - hbtc_before,
    // but in additive form to avoid underflow
    cvlm_assert(pool_btc_after + hbtc_before >= pool_btc_before + hbtc_after);
}
