// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, unused_const)]
module hashi::withdrawal_queue_tests;

use hashi::{
    btc::BTC,
    config,
    test_utils,
    utxo,
    withdrawal_queue::{
        Self,
        EOutputBelowDust,
        EOutputAmountMismatch,
        EOutputAddressMismatch,
        EMinerFeeExceedsMax
    }
};
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
    let (balance, request, request_id) = withdrawal_queue::create_withdrawal(
        btc,
        bitcoin_address,
        clock,
        ctx,
    );
    queue.insert_withdrawal(request_id, balance, request);
    request_id
}

fun make_test_output(amount: u64): withdrawal_queue::OutputUtxo {
    make_test_output_with_address(amount, x"0000000000000000000000000000000000000000")
}

fun make_test_output_with_address(amount: u64, addr: vector<u8>): withdrawal_queue::OutputUtxo {
    withdrawal_queue::output_utxo(amount, addr)
}

/// Creates a pending withdrawal in the queue and returns its ID.
fun setup_pending_withdrawal(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    txid: address,
    ctx: &mut TxContext,
): address {
    let id = setup_request(queue, clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (_requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let utxo_id = utxo::utxo_id(txid, 0);
    let test_utxo = utxo::utxo(utxo_id, btc_amount * 2, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::none(),
        txid,
        clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);
    pending_id
}

// ======== approve_withdrawal tests ========

#[test]
fun test_approve_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Approve the request
    queue.approve_withdrawal(request_id);

    // Verify by consuming as approved -- should not abort
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[request_id],
        pending_id,
    );
    assert!(btc_balances.borrow(0).value() == 10_000);

    btc_balances.destroy!(|btc| btc.destroy_for_testing());
    std::unit_test::destroy(requests);
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
    queue.approve_withdrawal(id1);
    queue.approve_withdrawal(id2);
    queue.approve_withdrawal(id3);

    // Consume all as approved
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[id1, id2, id3],
        pending_id,
    );

    assert!(btc_balances.borrow(0).value() == 5_000);
    assert!(btc_balances.borrow(1).value() == 15_000);
    assert!(btc_balances.borrow(2).value() == 25_000);

    btc_balances.destroy!(|btc| btc.destroy_for_testing());
    std::unit_test::destroy(requests);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== consume_approved_balances tests ========

#[test]
#[expected_failure(abort_code = withdrawal_queue::ERequestNotApproved)]
fun test_remove_approved_request_fails_when_not_approved() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Try to consume as approved without approving first -- should abort
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[request_id],
        pending_id,
    );

    // Cleanup (won't be reached)
    btc_balances.destroy!(|btc| btc.destroy_for_testing());
    std::unit_test::destroy(requests);
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

    // Remove and destroy -- no change output expected
    let pending = queue.remove_pending_withdrawal(pending_id);
    let (_request_ids, _txid, change_utxo) = pending.destroy_pending_withdrawal();
    change_utxo.destroy_none();

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
    let (_request_ids, _txid, change_utxo) = pending.destroy_pending_withdrawal();
    change_utxo.destroy_none();

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_full_withdrawal_queue_lifecycle() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    // Step 1: Request -- insert into queue
    let request_id = setup_request(&mut queue, &clock, 30_000, ctx);

    // Step 2: Approve -- mutate in place
    queue.approve_withdrawal(request_id);

    // Step 3: Construct -- consume approved balances, create pending withdrawal
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[request_id],
        pending_id,
    );
    assert!(btc_balances.borrow(0).value() == 30_000);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let utxo_id = utxo::utxo_id(@0xAAAA, 1);
    let test_utxo = utxo::utxo(utxo_id, 50_000, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(30_000)],
        option::none(),
        @0xBBBB,
        &clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);

    // Step 4: Sign -- mutate pending withdrawal in place
    queue.sign_pending_withdrawal(pending_id, vector[x"AA", x"BB"]);

    // Step 5: Confirm -- remove and destroy
    let pending = queue.remove_pending_withdrawal(pending_id);
    let (_request_ids, _txid, change_utxo) = pending.destroy_pending_withdrawal();
    change_utxo.destroy_none();

    std::unit_test::destroy(requests);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Change output tests ========

#[test]
fun test_pending_withdrawal_with_change_output() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let btc_amount = 50_000u64;
    let change_amount = 49_000u64;
    let txid = @0xCAFE;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (_requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let utxo_id = utxo::utxo_id(txid, 0);
    // Input UTXO is larger than withdrawal amount (100k > 50k, leaving 49k change + 1k fee)
    let test_utxo = utxo::utxo(utxo_id, 100_000, option::none());

    let change_output = make_test_output(change_amount);

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::some(change_output),
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);

    // Remove and destroy -- should return a change UTXO
    let pending = queue.remove_pending_withdrawal(pending_id);
    let (_request_ids, _txid, change_utxo) = pending.destroy_pending_withdrawal();
    assert!(change_utxo.is_some());

    let utxo = change_utxo.destroy_some();
    // Change vout = number of user outputs = 1
    let expected_utxo_id = utxo::utxo_id(txid, 1);
    assert!(utxo.id() == expected_utxo_id);
    assert!(utxo.amount() == change_amount);
    assert!(utxo.derivation_path().is_none());
    utxo.delete();

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_pending_withdrawal_without_change_output() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let btc_amount = 50_000u64;
    let txid = @0xDEAD;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (_requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let utxo_id = utxo::utxo_id(txid, 0);
    // Input UTXO exactly matches withdrawal amount (no change)
    let test_utxo = utxo::utxo(utxo_id, btc_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::none(),
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.pending_withdrawal_id();
    queue.insert_pending_withdrawal(pending);

    // Remove and destroy -- should return None
    let pending = queue.remove_pending_withdrawal(pending_id);
    let (_request_ids, _txid, change_utxo) = pending.destroy_pending_withdrawal();
    assert!(change_utxo.is_none());
    change_utxo.destroy_none();

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

    // Cancel (remove balance without approval check)
    let btc = queue.cancel_withdrawal(request_id);
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

    // Approve first, then cancel via cancel_withdrawal
    queue.approve_withdrawal(request_id);
    let btc = queue.cancel_withdrawal(request_id);
    assert!(btc.value() == 20_000);

    btc.destroy_for_testing();
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Miner fee split validation tests ========

#[test]
fun test_miner_fee_single_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    // btc_amount is net of protocol fee (already deducted at request time)
    let btc_amount = 30_000u64;
    let input_amount = 50_000u64;
    let miner_fee = 1_000u64;
    let user_output = btc_amount - miner_fee;
    let change = input_amount - user_output - miner_fee;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xAA01, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xAA01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_single_request_large_fee() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount = 40_000u64;
    let miner_fee = 5_000u64;
    let user_output = btc_amount - miner_fee;
    let input_amount = 100_000u64;
    let change = input_amount - user_output - miner_fee;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xAA02, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xAA02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_batched_even_split() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount = 30_000u64;
    let input_amount = 100_000u64;
    let miner_fee = 2_000u64;
    let per_user = miner_fee / 2;
    let user_output = btc_amount - per_user;
    let change = input_amount - (user_output * 2) - miner_fee;

    let id1 = setup_request(&mut queue, &clock, btc_amount, ctx);
    let id2 = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id1);
    queue.approve_withdrawal(id2);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[id1, id2],
        pending_id,
    );
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xBB01, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id1, id2],
        &requests,
        vector[test_utxo],
        vector[
            make_test_output(user_output),
            make_test_output(user_output),
            make_test_output(change),
        ],
        @0xBB01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_batched_with_remainder() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    // 3 requests, miner_fee=1001 -> per_user=333, remainder=2 goes to miner
    let btc_amount = 40_000u64;
    let miner_fee = 1_001u64;
    let per_user = miner_fee / 3; // 333
    let user_output = btc_amount - per_user;
    let total_user_outputs = user_output * 3;
    let input_amount = total_user_outputs + miner_fee + 10_000; // 10k change
    let change = input_amount - total_user_outputs - miner_fee;

    let id1 = setup_request(&mut queue, &clock, btc_amount, ctx);
    let id2 = setup_request(&mut queue, &clock, btc_amount, ctx);
    let id3 = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id1);
    queue.approve_withdrawal(id2);
    queue.approve_withdrawal(id3);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[id1, id2, id3],
        pending_id,
    );
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xBB02, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id1, id2, id3],
        &requests,
        vector[test_utxo],
        vector[
            make_test_output(user_output),
            make_test_output(user_output),
            make_test_output(user_output),
            make_test_output(change),
        ],
        @0xBB02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_batched_unequal_amounts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount_1 = 50_000u64;
    let btc_amount_2 = 30_000u64;
    let miner_fee = 800u64;
    let per_user = miner_fee / 2; // 400
    let user_output_1 = btc_amount_1 - per_user;
    let user_output_2 = btc_amount_2 - per_user;
    let input_amount = user_output_1 + user_output_2 + miner_fee + 5_000;
    let change = input_amount - user_output_1 - user_output_2 - miner_fee;

    let id1 = setup_request(&mut queue, &clock, btc_amount_1, ctx);
    let id2 = setup_request(&mut queue, &clock, btc_amount_2, ctx);
    queue.approve_withdrawal(id1);
    queue.approve_withdrawal(id2);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(
        &vector[id1, id2],
        pending_id,
    );
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xBB03, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id1, id2],
        &requests,
        vector[test_utxo],
        vector[
            make_test_output(user_output_1),
            make_test_output(user_output_2),
            make_test_output(change),
        ],
        @0xBB03,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_zero() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount = 30_000u64;
    let user_output = btc_amount; // zero miner fee, btc_amount already net
    let input_amount = user_output + 5_000;
    let change = 5_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xCC01, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xCC01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
fun test_miner_fee_output_at_dust_floor() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    // btc_amount is net of protocol fee. Choose so user output is exactly dust.
    let miner_fee = 5_000u64;
    let btc_amount = miner_fee + hashi::btc_config::dust_relay_min_value();
    let user_output = hashi::btc_config::dust_relay_min_value();
    let input_amount = user_output + miner_fee + 1_000;
    let change = 1_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xCC02, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xCC02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    queue.insert_pending_withdrawal(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
#[expected_failure(abort_code = EOutputBelowDust)]
fun test_miner_fee_output_below_dust_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    // btc_amount is net of protocol fee. user_output = 1000 - 600 = 400 < 546 (dust)
    let btc_amount = 1_000u64;
    let miner_fee = 600u64;
    let user_output = btc_amount - miner_fee;
    let input_amount = user_output + miner_fee + 1_000;
    let change = 1_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xDD01, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xDD01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_pending_withdrawal(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
#[expected_failure(abort_code = EOutputAmountMismatch)]
fun test_miner_fee_wrong_output_amount_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount = 30_000u64;
    let input_amount = 50_000u64;
    // Construct outputs that don't match the expected split.
    let wrong_output = btc_amount - 500; // assumes 500 miner fee
    let change = input_amount - wrong_output - 1_000; // but actual miner fee = 1000
    // miner_fee = input - outputs = 50000 - wrong_output - change = 1000
    // per_user = 1000, expected = 30000 - 1000 = 29000
    // wrong_output = 30000 - 500 = 29500, which != 29000

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xDD02, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(wrong_output), make_test_output(change)],
        @0xDD02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_pending_withdrawal(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
#[expected_failure(abort_code = EOutputAddressMismatch)]
fun test_miner_fee_wrong_address_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    let btc_amount = 30_000u64;
    let miner_fee = 1_000u64;
    let user_output = btc_amount - miner_fee;
    let input_amount = user_output + miner_fee + 5_000;
    let change = 5_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xDD03, 0), input_amount, option::none());

    // Output uses a different address than the request (which uses all-zeros)
    let wrong_addr = x"1111111111111111111111111111111111111111";
    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output_with_address(user_output, wrong_addr), make_test_output(change)],
        @0xDD03,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_pending_withdrawal(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}

#[test]
#[expected_failure(abort_code = EMinerFeeExceedsMax)]
fun test_miner_fee_exceeds_max_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);
    // Set max_fee_rate=1, input_budget=1 to get a small max_network_fee:
    // tx_vbytes = 11 + 1*100 + 2*43 = 197, worst_case_fee = 1*197 = 197
    hashi::btc_config::set_max_fee_rate(&mut config, 1);
    hashi::btc_config::set_input_budget(&mut config, 1);

    let btc_amount = 30_000u64;
    let miner_fee = 200u64; // exceeds max_network_fee of 197
    let user_output = btc_amount - miner_fee;
    let input_amount = user_output + miner_fee + 5_000;
    let change = 5_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let pending_id = ctx.fresh_object_address();
    let (requests, btc_balances) = queue.consume_approved_balances(&vector[id], pending_id);
    btc_balances.destroy!(|btc| btc.destroy_for_testing());

    let test_utxo = utxo::utxo(utxo::utxo_id(@0xEE01, 0), input_amount, option::none());

    let pending = withdrawal_queue::new_pending_withdrawal(
        pending_id,
        vector[id],
        &requests,
        vector[test_utxo],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xEE01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_pending_withdrawal(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}
