/// @module Solvency
/// @contract hashi::deposit
/// @contract hashi::withdraw
/// @contract hashi::utxo_pool
/// @contract hashi::treasury
/// @impact hBTC could be minted without matching BTC entering the pool, or pool BTC
///   released without matching hBTC being burned, breaking the 1:1 peg.
///
/// @global_assumption Pool BTC, the total amount of UTXOs with spent_by == none, is
///   tracked by the ghost total_active_amount, updated by summaries of insert_active,
///   insert_pending, lock and their batched withdraw-side callers
/// @global_assumption The loops in the withdrawal flow are summarized by opaque
///   per-call amounts: the input UTXO total (locked from the pool and used for fee
///   accounting), the change UTXO total (returned to the pool), the per-request output
///   total, the committed requests' balance total, and the request and output counts.
///   None of these is tied to the actual UTXOs or requests
/// @global_assumption The only relationship assumed between those amounts is that the
///   per-request output total plus request count times the per-user miner fee equals
///   the committed requests' balance total. Dust and destination-address checks on
///   withdrawal outputs are not modeled
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
///
/// @property SOLVENCY No entry point decreases pool BTC minus total hBTC supply
module solvency::deposit_solvency;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::{btc::BTC, hashi::Hashi};
use solvency::summaries_utxo_pool::total_active_amount;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"deposit");
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");

    invoker(b"invoke");
    rule(b"deposit_functions_never_shrink_solvency_gap");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Deposit entry points never shrink the solvency gap
/// @description For each of deposit, approve_deposit, confirm_deposit and
///   delete_expired_deposit, a successful call does not decrease pool BTC minus hBTC
///   supply. In particular, confirm_deposit mints no more hBTC than the UTXO amount it
///   adds to the pool.
/// @link_property SOLVENCY
/// @status VERIFIED
/// @report solvency.conf https://prover.certora.com/output/497546/46cf5d8e98dd495c9f9382c508edc339?anonymousKey=d972de29a927f4c954207d9c23c3846a0752f3bb
public fun deposit_functions_never_shrink_solvency_gap(hashi: &mut Hashi, target: Function) {
    let pool_btc_before = *total_active_amount();
    let hbtc_before = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    invoke(target, hashi);

    let pool_btc_after = *total_active_amount();
    let hbtc_after = hashi.treasury().treasury_cap_ref<BTC>().total_supply();

    cvlm_assert(pool_btc_after + hbtc_before >= pool_btc_before + hbtc_after);
}
