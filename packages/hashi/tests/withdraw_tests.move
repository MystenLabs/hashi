// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::withdraw_tests;

use hashi::{btc::BTC, test_utils, withdrawal_queue};
use sui::clock;

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const REQUESTER: address = @0x100;
const OTHER_USER: address = @0x999;

/// Helper: creates a withdrawal request in the queue and returns its request_id.
fun setup_withdrawal_request(
    hashi: &mut hashi::hashi::Hashi,
    clock: &clock::Clock,
    btc_amount: u64,
    ctx: &mut TxContext,
): address {
    let btc = sui::balance::create_for_testing<BTC>(btc_amount);
    let bitcoin_address = x"0000000000000000000000000000000000000000"; // 20 bytes
    let request = withdrawal_queue::withdrawal_request(btc, bitcoin_address, clock, ctx);
    let request_id = request.request_id();
    hashi.withdrawal_queue_mut().insert_request(request);
    request_id
}

#[test]
fun test_cancel_withdrawal() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    let request_id = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Advance clock past the 1-hour cooldown
    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);

    // Cancel the withdrawal
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, request_id, &clock, ctx);

    // Verify the returned balance has the correct amount
    assert!(btc.value() == 10_000);

    // Clean up
    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdraw::EUnauthorizedCancellation)]
fun test_cancel_withdrawal_unauthorized() {
    let requester_ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, requester_ctx);
    let mut clock = clock::create_for_testing(requester_ctx);

    let request_id = setup_withdrawal_request(&mut hashi, &clock, 10_000, requester_ctx);

    // Advance clock past cooldown
    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);

    // Attempt cancellation from a different sender — should fail
    let other_ctx = &mut test_utils::new_tx_context(OTHER_USER, 0);
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, request_id, &clock, other_ctx);
    btc.destroy_for_testing();

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdraw::ECooldownNotElapsed)]
fun test_cancel_withdrawal_cooldown_not_elapsed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Do NOT advance clock — cooldown has not elapsed
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, request_id, &clock, ctx);
    btc.destroy_for_testing();

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
