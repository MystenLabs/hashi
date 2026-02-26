// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, unused_const)]
module hashi::withdrawal_queue_tests;

use hashi::{btc::BTC, test_utils, utxo, withdrawal_queue};
use sui::clock;

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const REQUESTER: address = @0x100;

// ======== Helpers ========

fun setup_queue(ctx: &mut TxContext): withdrawal_queue::WithdrawalRequestQueue {
    withdrawal_queue::create(ctx)
}

fun setup_request(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    ctx: &mut TxContext,
): address {
    let btc = sui::balance::create_for_testing<BTC>(btc_amount);
    let bitcoin_address = x"0000000000000000000000000000000000000000"; // 20 bytes
    let request = withdrawal_queue::withdrawal_request(btc, bitcoin_address, clock, ctx);
    let request_id = request.request_id();
    queue.insert_request(request);
    request_id
}

fun make_test_output(amount: u64): withdrawal_queue::OutputUtxo {
    withdrawal_queue::output_utxo_from_bcs({
        let mut bytes = vector[];
        bytes.append(sui::bcs::to_bytes(&amount));
        let addr = x"0000000000000000000000000000000000000000";
        bytes.append(sui::bcs::to_bytes(&addr));
        bytes
    })
}

/// Creates a request, approves it, removes it, and returns info + destroys BTC.
fun approve_and_extract_info(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    ctx: &mut TxContext,
): withdrawal_queue::WithdrawalRequestInfo {
    let id = setup_request(queue, clock, btc_amount, ctx);
    queue.approve_request(id);
    let req = queue.remove_approved_request(id);
    let (info, btc) = withdrawal_queue::request_into_parts(req);
    btc.destroy_for_testing();
    info
}

/// Creates a pending withdrawal in the queue and returns its ID.
fun setup_pending_withdrawal(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    txid: address,
    ctx: &mut TxContext,
): address {
    let info = approve_and_extract_info(queue, clock, btc_amount, ctx);
    let utxo_id = utxo::utxo_id(txid, 0);
    let test_utxo = utxo::utxo(utxo_id, btc_amount * 2, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[info],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        txid,
        clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);
    pending_id
}

// ======== approve_request tests ========

#[test]
fun test_approve_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Approve the request via mutable borrow
    queue.approve_request(request_id);

    // Verify by removing as approved — should not abort
    let request = queue.remove_approved_request(request_id);
    let (_, btc) = withdrawal_queue::request_into_parts(request);
    assert!(btc.value() == 10_000);

    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_approve_multiple_requests() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let id1 = setup_request(&mut queue, &clock, 5_000, ctx);
    let id2 = setup_request(&mut queue, &clock, 15_000, ctx);
    let id3 = setup_request(&mut queue, &clock, 25_000, ctx);

    // Approve all three
    queue.approve_request(id1);
    queue.approve_request(id2);
    queue.approve_request(id3);

    // Remove all as approved
    let r1 = queue.remove_approved_request(id1);
    let r2 = queue.remove_approved_request(id2);
    let r3 = queue.remove_approved_request(id3);

    let (_, btc1) = withdrawal_queue::request_into_parts(r1);
    let (_, btc2) = withdrawal_queue::request_into_parts(r2);
    let (_, btc3) = withdrawal_queue::request_into_parts(r3);

    assert!(btc1.value() == 5_000);
    assert!(btc2.value() == 15_000);
    assert!(btc3.value() == 25_000);

    btc1.destroy_for_testing();
    btc2.destroy_for_testing();
    btc3.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== remove_approved_request tests ========

#[test]
#[expected_failure(abort_code = withdrawal_queue::ERequestNotApproved)]
fun test_remove_approved_request_fails_when_not_approved() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Try to remove as approved without approving first — should abort
    let request = queue.remove_approved_request(request_id);

    // Cleanup (won't be reached)
    let (_, btc) = withdrawal_queue::request_into_parts(request);
    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Pending withdrawal lifecycle tests ========

#[test]
fun test_pending_withdrawal_insert_and_remove() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let pending_id = setup_pending_withdrawal(&mut queue, &clock, 50_000, @0xDEAD, ctx);

    // Remove and destroy
    let pending = queue.remove_pending_withdrawal(pending_id);
    pending.destroy_pending_withdrawal();

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_sign_pending_withdrawal() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let pending_id = setup_pending_withdrawal(&mut queue, &clock, 50_000, @0xBEEF, ctx);

    // Sign the pending withdrawal via mutable borrow
    let test_signatures = vector[x"DEADBEEF", x"CAFEBABE"];
    queue.sign_pending_withdrawal(pending_id, test_signatures);

    // Remove and destroy
    let pending = queue.remove_pending_withdrawal(pending_id);
    pending.destroy_pending_withdrawal();

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_full_withdrawal_queue_lifecycle() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    // Step 1: Request — insert into queue
    let request_id = setup_request(&mut queue, &clock, 30_000, ctx);

    // Step 2: Approve — mutate in place
    queue.approve_request(request_id);

    // Step 3: Construct — remove approved, create pending withdrawal
    let request = queue.remove_approved_request(request_id);
    let (info, btc) = withdrawal_queue::request_into_parts(request);
    assert!(btc.value() == 30_000);
    btc.destroy_for_testing();

    let utxo_id = utxo::utxo_id(@0xAAAA, 1);
    let test_utxo = utxo::utxo(utxo_id, 50_000, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[info],
        vector[test_utxo],
        vector[make_test_output(30_000)],
        @0xBBBB,
        &clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);

    // Step 4: Sign — mutate pending withdrawal in place
    queue.sign_pending_withdrawal(pending_id, vector[x"AA", x"BB"]);

    // Step 5: Confirm — remove and destroy
    let pending = queue.remove_pending_withdrawal(pending_id);
    pending.destroy_pending_withdrawal();

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Cancel + approve interaction ========

#[test]
fun test_cancel_unapproved_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 20_000, ctx);

    // Cancel (remove without approval check)
    let request = queue.remove_request(request_id);
    let (_, btc) = withdrawal_queue::request_into_parts(request);
    assert!(btc.value() == 20_000);

    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_cancel_approved_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 20_000, ctx);

    // Approve first, then cancel via remove_request (not remove_approved_request)
    queue.approve_request(request_id);
    let request = queue.remove_request(request_id);
    let (_, btc) = withdrawal_queue::request_into_parts(request);
    assert!(btc.value() == 20_000);

    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}
