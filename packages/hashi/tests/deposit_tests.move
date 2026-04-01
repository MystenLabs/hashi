// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::deposit_tests;

use hashi::{deposit, deposit_queue, test_utils};
use sui::clock;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const REQUESTER: address = @0x100;

#[test]
fun test_deposit_at_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 546, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let fee = sui::coin::zero(ctx);

    deposit::deposit(&mut hashi, request, fee);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_deposit_below_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 545, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let fee = sui::coin::zero(ctx);

    deposit::deposit(&mut hashi, request, fee);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// A spent UTXO cannot be used for a new deposit request.
/// Simulates: deposit confirmed → UTXO used in withdrawal (spent) → new deposit attempt aborts.
#[test]
#[expected_failure]
fun test_spent_utxo_cannot_be_redeposited() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 1000, option::none());

    // Simulate: deposit confirmed (UTXO inserted into active pool)
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    // Simulate: UTXO spent in a withdrawal (moved to spent_utxos)
    hashi.bitcoin_mut().utxo_pool_mut().confirm_spent(utxo_id, 0);

    // Attempt to deposit the same UTXO again — should abort because
    // is_spent_or_active() returns true (UTXO is in spent_utxos permanently).
    let utxo2 = hashi::utxo::utxo(utxo_id, 1000, option::none());
    let request = deposit_queue::deposit_request(utxo2, &clock, ctx);
    let fee = sui::coin::zero(ctx);
    deposit::deposit(&mut hashi, request, fee);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// Multiple deposit requests for the same UTXO are allowed (anti-griefing).
/// Only the first to be confirmed will succeed; the rest will be rejected
/// by the is_spent_or_active check in confirm_deposit.
#[test]
fun test_multiple_deposit_requests_same_utxo_allowed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);

    // First deposit request succeeds
    let utxo1 = hashi::utxo::utxo(utxo_id, 1000, option::none());
    let request1 = deposit_queue::deposit_request(utxo1, &clock, ctx);
    let fee1 = sui::coin::zero(ctx);
    deposit::deposit(&mut hashi, request1, fee1);

    // Second deposit request with the same UTXO also succeeds (anti-griefing)
    let utxo2 = hashi::utxo::utxo(utxo_id, 1000, option::none());
    let request2 = deposit_queue::deposit_request(utxo2, &clock, ctx);
    let fee2 = sui::coin::zero(ctx);
    deposit::deposit(&mut hashi, request2, fee2);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
