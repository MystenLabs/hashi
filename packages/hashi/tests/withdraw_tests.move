// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::withdraw_tests;

use hashi::{btc::BTC, test_utils, withdrawal_queue};
use sui::{bcs, clock};

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
    btc.burn_for_testing();
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
    btc.burn_for_testing();

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
    btc.burn_for_testing();

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

// ======== Certificate-based tests ========

/// Helper: build the signing message bytes for a certificate.
/// Format: BCS(epoch) || BCS(message)
fun build_cert_message<T: copy + drop + store>(epoch: u64, message: &T): vector<u8> {
    let mut bytes = bcs::to_bytes(&epoch);
    bytes.append(bcs::to_bytes(message));
    bytes
}

#[test]
fun test_approve_request_with_certificate() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Create two withdrawal requests
    let id1 = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);
    let id2 = setup_withdrawal_request(&mut hashi, &clock, 20_000, ctx);

    // Approve each request individually with its own certificate
    let approval1 = hashi::withdraw::new_request_approval_message(id1);
    let message_bytes1 = build_cert_message(epoch, &approval1);
    let (sig1, bitmap1) = test_utils::sign_with_committee(&message_bytes1, 3);
    hashi::withdraw::approve_request(&mut hashi, id1, epoch, sig1, bitmap1);

    let approval2 = hashi::withdraw::new_request_approval_message(id2);
    let message_bytes2 = build_cert_message(epoch, &approval2);
    let (sig2, bitmap2) = test_utils::sign_with_committee(&message_bytes2, 3);
    hashi::withdraw::approve_request(&mut hashi, id2, epoch, sig2, bitmap2);

    // Verify both requests are now approved by removing them as approved
    let r1 = hashi.withdrawal_queue_mut().remove_approved_request(id1);
    let r2 = hashi.withdrawal_queue_mut().remove_approved_request(id2);

    let (_, btc1) = withdrawal_queue::request_into_parts(r1);
    let (_, btc2) = withdrawal_queue::request_into_parts(r2);
    assert!(btc1.value() == 10_000);
    assert!(btc2.value() == 20_000);

    btc1.destroy_for_testing();
    btc2.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee::ESigVerification)]
fun test_approve_request_bad_signature() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let id1 = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Sign over WRONG data (empty message instead of actual approval message)
    let wrong_bytes = bcs::to_bytes(&epoch);
    let (bad_signature, signers_bitmap) = test_utils::sign_with_committee(&wrong_bytes, 3);

    // Should fail signature verification
    hashi::withdraw::approve_request(&mut hashi, id1, epoch, bad_signature, signers_bitmap);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdraw::ERequestAlreadyApproved)]
fun test_approve_then_cancel() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    let id1 = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Approve via certificate
    let approval = hashi::withdraw::new_request_approval_message(id1);
    let message_bytes = build_cert_message(epoch, &approval);
    let (signature, signers_bitmap) = test_utils::sign_with_committee(&message_bytes, 3);
    hashi::withdraw::approve_request(&mut hashi, id1, epoch, signature, signers_bitmap);

    // Cancelling an approved request should fail
    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, id1, &clock, ctx);
    btc.burn_for_testing();

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
