// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, deprecated_usage, unused_variable)]
module hashi::deposit_queue_tests;

use hashi::{deposit_queue, test_utils};
use sui::clock;

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const NON_VOTER: address = @0x999;

#[test]
fun test_delete_deposit_request() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // Create a UTXO and deposit request, insert into queue
    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 1000, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let request_id = request.id();
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().insert(request);
    assert!(hashi.borrow_bitcoin_state().deposit_queue().contains(request_id));

    // Advance clock past the expiration time (3 days + 1 ms)
    let three_days_ms = 1000 * 60 * 60 * 24 * 3;
    clock.set_for_testing(three_days_ms + 1);

    // Delete the expired deposit request and verify it is no longer in the queue
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().delete_expired(request_id, &clock);
    assert!(!hashi.borrow_bitcoin_state().deposit_queue().contains(request_id));

    // Clean up
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = deposit_queue::EDepositRequestNotExpired)]
fun test_delete_unexpired_deposit_request() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // Create a UTXO and deposit request, insert into queue
    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 1000, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let request_id = request.id();
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().insert(request);
    assert!(hashi.borrow_bitcoin_state().deposit_queue().contains(request_id));

    // Advance clock by only 1 day (not enough to expire)
    let one_day_ms = 1000 * 60 * 60 * 24;
    clock.set_for_testing(one_day_ms);

    // Attempt to delete the unexpired deposit request - should fail
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().delete_expired(request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
