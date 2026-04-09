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
    let request = withdrawal_queue::create_withdrawal(
        btc,
        bitcoin_address,
        clock,
        ctx,
    );
    let request_id = request.request_id().to_address();
    queue.insert_withdrawal(request, ctx);
    request_id
}

fun make_test_output(amount: u64): withdrawal_queue::OutputUtxo {
    make_test_output_with_address(amount, x"0000000000000000000000000000000000000000")
}

fun make_test_output_with_address(amount: u64, addr: vector<u8>): withdrawal_queue::OutputUtxo {
    withdrawal_queue::output_utxo(amount, addr)
}

/// Build a minimal test WithdrawalTransaction for the given request IDs.
/// Used by tests that just need a txn handle to pass to commit_requests.
fun make_test_txn(
    request_ids: vector<address>,
    txid: address,
    clock: &clock::Clock,
    ctx: &mut TxContext,
): withdrawal_queue::WithdrawalTransaction {
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), 1_000_000, option::none());
    withdrawal_queue::new_withdrawal_txn_for_testing(
        request_ids,
        vector[test_utxo],
        vector[make_test_output(1)],
        option::none(),
        txid,
        clock,
        ctx,
    )
}

/// Creates a request, approves it, builds a withdrawal txn, commits the request,
/// inserts the txn into the queue, and returns (request_id, info).
fun approve_and_commit(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    ctx: &mut TxContext,
): (address, withdrawal_queue::CommittedRequestInfo) {
    let id = setup_request(queue, clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let infos = queue.extract_request_infos(&vector[id]);
    let txid = @0xBEEF;
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), btc_amount * 2, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::none(),
        txid,
        clock,
        ctx,
    );
    let btc_balance = queue.commit_requests(&txn);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    let info = infos[0];
    (id, info)
}

/// Creates a request, approves it, builds a withdrawal txn, commits the request,
/// inserts the txn into the queue, and returns the txn ID.
fun setup_withdrawal_txn(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    btc_amount: u64,
    txid: address,
    ctx: &mut TxContext,
): address {
    let id = setup_request(queue, clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), btc_amount * 2, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::none(),
        txid,
        clock,
        ctx,
    );
    let txn_id = txn.withdrawal_txn_id();
    let btc_balance = queue.commit_requests(&txn);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    txn_id
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

    // Verify by committing — should not abort (only approved requests can be committed)
    let txn = make_test_txn(vector[request_id], @0xBEEF, &clock, ctx);
    let btc_balance = queue.commit_requests(&txn);
    let btc = &btc_balance;
    assert!(btc.value() == 10_000);

    btc_balance.destroy_for_testing();
    std::unit_test::destroy(txn);
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

    // Commit all as approved
    let txn = make_test_txn(vector[id1, id2, id3], @0xBEEF, &clock, ctx);
    let btc_balance = queue.commit_requests(&txn);

    // Total: 5_000 + 15_000 + 25_000 = 45_000
    assert!(btc_balance.value() == 45_000);

    btc_balance.destroy_for_testing();
    std::unit_test::destroy(txn);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== commit_requests tests ========

#[test]
#[expected_failure(abort_code = withdrawal_queue::ERequestNotApproved)]
fun test_remove_approved_request_fails_when_not_approved() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Try to commit without approving first — should abort
    let txn = make_test_txn(vector[request_id], @0xBEEF, &clock, ctx);
    let btc_balance = queue.commit_requests(&txn);

    // Cleanup (won't be reached)
    btc_balance.destroy_for_testing();
    std::unit_test::destroy(txn);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Pending withdrawal lifecycle tests ========

#[test]
fun test_withdrawal_txn_insert_and_remove() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let pending_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xDEAD, ctx);

    // Remove and destroy — no change output expected
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_id = pending.change_utxo_id();
    change_id.destroy_none();
    std::unit_test::destroy(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_sign_withdrawal_txn() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let pending_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);

    // Sign the pending withdrawal via mutable borrow
    let test_signatures = vector[x"DEADBEEF", x"CAFEBABE"];
    queue.sign_withdrawal_txn(pending_id, test_signatures);

    // Remove and destroy
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_id = pending.change_utxo_id();
    change_id.destroy_none();
    std::unit_test::destroy(pending);

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

    // Step 2: Approve
    queue.approve_withdrawal(request_id);

    // Step 3: Commit — drain BTC and move to processed
    let test_utxo = utxo::utxo(utxo::utxo_id(@0xAAAA, 1), 50_000, option::none());

    let pending = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(30_000)],
        option::none(),
        @0xBBBB,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    let btc_balance = queue.commit_requests(&pending);
    assert!(btc_balance.value() == 30_000);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

    // Step 4: Sign — mutate pending withdrawal in place
    queue.sign_withdrawal_txn(pending_id, vector[x"AA", x"BB"]);

    // Step 5: Confirm — remove and destroy
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_id = pending.change_utxo_id();
    change_id.destroy_none();
    std::unit_test::destroy(pending);

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== Change output tests ========

#[test]
fun test_withdrawal_txn_with_change_output() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let btc_amount = 50_000u64;
    let change_amount = 49_000u64;
    let txid = @0xCAFE;

    let (request_id, _info) = approve_and_commit(&mut queue, &clock, btc_amount, ctx);
    // Input UTXO is larger than withdrawal amount (100k > 50k, leaving 49k change + 1k fee)
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), 100_000, option::none());

    let change_output = make_test_output(change_amount);

    let pending = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::some(change_output),
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    queue.insert_withdrawal_txn(pending);

    // Remove and destroy — should return a change UTXO ID.
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_id = pending.change_utxo_id();
    assert!(change_id.is_some());

    // Change vout = number of user outputs = 1.
    let expected_utxo_id = utxo::utxo_id(txid, 1);
    assert!(change_id.destroy_some() == expected_utxo_id);

    std::unit_test::destroy(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_withdrawal_txn_without_change_output() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let btc_amount = 50_000u64;
    let txid = @0xDEAD;

    let (request_id, _info) = approve_and_commit(&mut queue, &clock, btc_amount, ctx);
    // Input UTXO exactly matches withdrawal amount (no change)
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), btc_amount, option::none());

    let pending = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        option::none(),
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    queue.insert_withdrawal_txn(pending);

    // Remove and destroy — should return None for the change UTXO ID.
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_id = pending.change_utxo_id();
    assert!(change_id.is_none());
    change_id.destroy_none();
    std::unit_test::destroy(pending);

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

    // Cancel (returns BTC balance)
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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xAA01, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xAA01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xAA02, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xAA02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id1, id2]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id1, id2],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xBB01, 0), input_amount, option::none())],
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
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id1, id2, id3]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id1, id2, id3],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xBB02, 0), input_amount, option::none())],
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
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id1, id2]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id1, id2],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xBB03, 0), input_amount, option::none())],
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
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xCC01, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xCC01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xCC02, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xCC02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );
    let btc_balance = queue.commit_requests(&pending);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xDD01, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xDD01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_withdrawal_txn(pending);
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
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xDD02, 0), input_amount, option::none())],
        vector[make_test_output(wrong_output), make_test_output(change)],
        @0xDD02,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_withdrawal_txn(pending);
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
    let infos = queue.extract_request_infos(&vector[id]);

    // Output uses a different address than the request (which uses all-zeros)
    let wrong_addr = x"1111111111111111111111111111111111111111";
    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xDD03, 0), input_amount, option::none())],
        vector[make_test_output_with_address(user_output, wrong_addr), make_test_output(change)],
        @0xDD03,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_withdrawal_txn(pending);
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
    // Set bitcoin_withdrawal_minimum = 743 to get a small max_network_fee:
    // worst_case_fee = 743 - 546 = 197.
    hashi::btc_config::set_bitcoin_withdrawal_minimum(&mut config, 743);

    let btc_amount = 30_000u64;
    let miner_fee = 200u64; // exceeds max_network_fee of 197
    let user_output = btc_amount - miner_fee;
    let input_amount = user_output + miner_fee + 5_000;
    let change = 5_000u64;

    let id = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id);
    let infos = queue.extract_request_infos(&vector[id]);

    let pending = withdrawal_queue::new_withdrawal_txn(
        ctx,
        vector[id],
        &infos,
        vector[utxo::utxo(utxo::utxo_id(@0xEE01, 0), input_amount, option::none())],
        vector[make_test_output(user_output), make_test_output(change)],
        @0xEE01,
        0,
        0,
        &config,
        &clock,
        vector[],
    );

    queue.insert_withdrawal_txn(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
    std::unit_test::destroy(config);
}
