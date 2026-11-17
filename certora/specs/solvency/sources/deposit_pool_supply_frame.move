/// @module Solvency
/// @contract hashi::deposit
/// @contract hashi::utxo_pool
/// @contract hashi::treasury
module solvency::deposit_pool_supply_frame;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::{btc::BTC, hashi::Hashi};
use solvency::summaries_utxo_pool::total_active_amount;

public fun cvlm_manifest() {
    // Every `deposit` entry point except `confirm_deposit`, the only one
    // that mints hBTC and inserts into the pool (see
    // `deposit_solvency::deposit_functions_never_shrink_solvency_gap` for the
    // property that does cover it).
    target(@hashi, b"deposit", b"deposit");
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");

    invoker(b"invoke");
    rule(b"deposit_functions_leave_pool_and_supply_unchanged");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Deposit entry points other than confirm_deposit leave pool and supply unchanged
/// @description For each of deposit, approve_deposit and delete_expired_deposit, a
///   successful call changes neither pool BTC nor hBTC supply.
/// @link_property CONSTANT-BTC-HBTC
/// @status VERIFIED
/// @report constant_btc_hbtc.conf https://prover.certora.com/output/497546/9535a693ba5442478fdd7d228e1ca430?anonymousKey=659daa04fadc4acacec6995498c4589495ca1625
public fun deposit_functions_leave_pool_and_supply_unchanged(hashi: &mut Hashi, target: Function) {
    let pool_btc_before = *total_active_amount();
    let hbtc_before = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    invoke(target, hashi);

    let pool_btc_after = *total_active_amount();
    let hbtc_after = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    cvlm_assert(pool_btc_after == pool_btc_before);
    cvlm_assert(hbtc_after == hbtc_before);
}
