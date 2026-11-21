/// @module Solvency
/// @contract hashi::withdraw
/// @contract hashi::utxo_pool
/// @contract hashi::treasury
///
/// @property CONSTANT-BTC-HBTC Only confirm_deposit and commit_withdrawal_tx can change
///   pool BTC or total hBTC supply; every other deposit and withdraw entry point leaves
///   both unchanged
module solvency::withdraw_pool_supply_frame;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::{btc::BTC, hashi::Hashi};
use solvency::summaries_utxo_pool::total_active_amount;

public fun cvlm_manifest() {
    // Every `withdraw` entry point except `commit_withdrawal_tx`, the only
    // one that burns hBTC and locks pool UTXOs (see
    // `withdraw_solvency::withdraw_functions_never_shrink_solvency_gap` for
    // the property that does cover it).
    target(@hashi, b"withdraw", b"request_withdrawal");
    target(@hashi, b"withdraw", b"cancel_withdrawal");
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"confirm_withdrawal");
    target(@hashi, b"withdraw", b"reallocate_presigs");
    target(@hashi, b"withdraw", b"cleanup_spent_utxos");
    target(@hashi, b"withdraw", b"archive_confirmed_withdrawals");
    target(@hashi, b"withdraw", b"archive_withdrawal_requests");
    target(@hashi, b"withdraw", b"finish_archive_withdrawal_txns");

    invoker(b"invoke");
    rule(b"withdraw_functions_leave_pool_and_supply_unchanged");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Withdraw entry points other than commit_withdrawal_tx leave pool and supply unchanged
/// @description For each withdraw entry point except commit_withdrawal_tx, a successful
///   call changes neither pool BTC nor hBTC supply.
/// @link_property CONSTANT-BTC-HBTC
/// @status VERIFIED
/// @report constant_btc_hbtc.conf https://prover.certora.com/output/497546/9535a693ba5442478fdd7d228e1ca430?anonymousKey=659daa04fadc4acacec6995498c4589495ca1625
public fun withdraw_functions_leave_pool_and_supply_unchanged(hashi: &mut Hashi, target: Function) {
    let pool_btc_before = *total_active_amount();
    let hbtc_before = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    invoke(target, hashi);

    let pool_btc_after = *total_active_amount();
    let hbtc_after = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    cvlm_assert(pool_btc_after == pool_btc_before);
    cvlm_assert(hbtc_after == hbtc_before);
}
