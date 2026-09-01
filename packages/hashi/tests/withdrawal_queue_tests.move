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
        EMinerFeeExceedsMax,
        ECannotApproveCommittedRequest,
        EApprovalCertNotNewer,
        ERequestNotCancellable,
        EWithdrawalNotConfirmed,
        EWithdrawalAlreadyConfirmed,
        EMinerFeeNotEvenlySplit,
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
    queue.insert_withdrawal(request);
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
        vector[],
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
    queue.approve_withdrawal(id, dummy_cert(), clock);
    let infos = queue.extract_request_infos(&vector[id]);
    let txid = @0xBEEF;
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), btc_amount * 2, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        vector[],
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
    queue.approve_withdrawal(id, dummy_cert(), clock);
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), btc_amount * 2, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        vector[],
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

fun dummy_cert(): hashi::committee::CommitteeSignature {
    hashi::committee::new_committee_signature(0, vector[], vector[])
}

// ======== approve_withdrawal tests ========

#[test]
fun test_approve_request() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Approve the request
    queue.approve_withdrawal(request_id, dummy_cert(), &clock);

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
    queue.approve_withdrawal(id1, dummy_cert(), &clock);
    queue.approve_withdrawal(id2, dummy_cert(), &clock);
    queue.approve_withdrawal(id3, dummy_cert(), &clock);

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

#[test]
#[expected_failure(abort_code = EApprovalCertNotNewer)]
fun test_reapprove_in_same_epoch_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    queue.approve_withdrawal(request_id, dummy_cert(), &clock);

    // A second approval under the same epoch is a replay — should abort.
    queue.approve_withdrawal(request_id, dummy_cert(), &clock);

    // Cleanup (won't be reached)
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_reapprove_in_later_epoch_replaces_cert() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let request_id = setup_request(&mut queue, &clock, 10_000, ctx);

    // Approved in epoch 0; a reconfiguration then leaves the cert stale.
    queue.approve_withdrawal(request_id, dummy_cert(), &clock);

    // The epoch-1 committee refreshes the approval.
    let epoch1_cert = hashi::committee::new_committee_signature(1, vector[], vector[]);
    queue.approve_withdrawal(request_id, epoch1_cert, &clock);

    let cert = queue.borrow_request(request_id).request_approval_cert();
    assert!(cert.destroy_some().signature_epoch() == 1);

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
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.is_empty());
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

    // Record the (single) input's MPC signature, then finalize with the
    // one-shot guardian signature.
    queue.record_input_signatures(pending_id, vector[0], vector[x"DEADBEEF"]);
    assert!(!queue.withdrawal_txn_is_fully_signed(pending_id));
    queue.finalize_withdrawal_txn(pending_id, vector[x"AAAAAAAA"], &clock);
    assert!(queue.withdrawal_txn_is_fully_signed(pending_id));

    // Remove and destroy
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.is_empty());
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
    queue.approve_withdrawal(request_id, dummy_cert(), &clock);

    // Step 3: Commit — drain BTC and move to processed
    let test_utxo = utxo::utxo(utxo::utxo_id(@0xAAAA, 1), 50_000, option::none());

    let pending = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(30_000)],
        vector[],
        @0xBBBB,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    let btc_balance = queue.commit_requests(&pending);
    assert!(btc_balance.value() == 30_000);
    btc_balance.destroy_for_testing();
    queue.insert_withdrawal_txn(pending);

    // Step 4: Sign — record the input's MPC signature, then finalize.
    queue.record_input_signatures(pending_id, vector[0], vector[x"AA"]);
    queue.finalize_withdrawal_txn(pending_id, vector[x"CC"], &clock);

    // Step 5: Confirm — remove and destroy
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.is_empty());
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
        vector[change_output],
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    queue.insert_withdrawal_txn(pending);

    // Remove and destroy — should return a single change UTXO ID.
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.length() == 1);

    // Change vout = number of user outputs = 1.
    let expected_utxo_id = utxo::utxo_id(txid, 1);
    assert!(change_ids[0] == expected_utxo_id);

    std::unit_test::destroy(pending);
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_withdrawal_txn_with_multiple_change_outputs() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let btc_amount = 50_000u64;
    let txid = @0xFEED;

    let (request_id, _info) = approve_and_commit(&mut queue, &clock, btc_amount, ctx);
    let test_utxo = utxo::utxo(utxo::utxo_id(txid, 0), 100_000, option::none());

    // One user output followed by two trailing change outputs.
    let pending = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[request_id],
        vector[test_utxo],
        vector[make_test_output(btc_amount)],
        vector[make_test_output(30_000), make_test_output(19_000)],
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    queue.insert_withdrawal_txn(pending);

    let pending = queue.remove_withdrawal_txn(pending_id);

    // Two change UTXO IDs at vouts 1 and 2, after the single user output.
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.length() == 2);
    assert!(change_ids[0] == utxo::utxo_id(txid, 1));
    assert!(change_ids[1] == utxo::utxo_id(txid, 2));

    // build_change_utxos mirrors the IDs and carries the per-output amounts,
    // preserving on-chain order.
    let change_utxos = pending.build_change_utxos();
    assert!(change_utxos.length() == 2);
    assert!(change_utxos[0].id() == utxo::utxo_id(txid, 1));
    assert!(change_utxos[0].amount() == 30_000);
    assert!(change_utxos[1].id() == utxo::utxo_id(txid, 2));
    assert!(change_utxos[1].amount() == 19_000);

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
        vector[],
        txid,
        &clock,
        ctx,
    );
    let pending_id = pending.withdrawal_txn_id();
    queue.insert_withdrawal_txn(pending);

    // Remove and destroy — should return no change UTXO IDs.
    let pending = queue.remove_withdrawal_txn(pending_id);
    let change_ids = pending.change_utxo_ids();
    assert!(change_ids.is_empty());
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
    queue.approve_withdrawal(request_id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id1, dummy_cert(), &clock);
    queue.approve_withdrawal(id2, dummy_cert(), &clock);
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
#[expected_failure(abort_code = EMinerFeeNotEvenlySplit)]
fun test_miner_fee_batched_with_remainder_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);
    let mut config = config::create();
    hashi::btc_config::init_defaults(&mut config);

    // 1_001 sats across 3 requests leaves a remainder of 2, so no per-user
    // share sums to the miner fee exactly. Charge each user the rounded-up
    // share, which the bridge previously accepted and must now reject.
    let btc_amount = 40_000u64;
    let request_count = 3u64;
    let miner_fee = 1_001u64;
    assert!(miner_fee % request_count != 0);
    let per_user = miner_fee / request_count + 1;
    let user_output = btc_amount - per_user;
    let change = 10_000u64;
    let input_amount = user_output * request_count + miner_fee + change;

    let id1 = setup_request(&mut queue, &clock, btc_amount, ctx);
    let id2 = setup_request(&mut queue, &clock, btc_amount, ctx);
    let id3 = setup_request(&mut queue, &clock, btc_amount, ctx);
    queue.approve_withdrawal(id1, dummy_cert(), &clock);
    queue.approve_withdrawal(id2, dummy_cert(), &clock);
    queue.approve_withdrawal(id3, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id1, dummy_cert(), &clock);
    queue.approve_withdrawal(id2, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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
    queue.approve_withdrawal(id, dummy_cert(), &clock);
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

// ======== Deferred archival tests ========

#[test]
fun test_commit_leaves_request_in_requests_with_processing() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (id, _info) = approve_and_commit(&mut queue, &clock, 50_000, ctx);

    assert!(queue.request_in_requests(id));
    assert!(!queue.request_in_processed(id));
    assert!(queue.request_status_any(id).is_processing());
    // The bag-membership gate must still recognize the request as committed.
    assert!(queue.is_request_processing(id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
#[expected_failure(abort_code = ECannotApproveCommittedRequest)]
fun test_approve_committed_request_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (id, _info) = approve_and_commit(&mut queue, &clock, 50_000, ctx);
    // Replay of an approval cert against the committed request must not
    // reset Processing back to Approved (it would re-arm commit on a
    // drained request).
    queue.approve_withdrawal(id, dummy_cert(), &clock);
    abort 0
}

#[test]
fun test_update_requests_signed_both_locations() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    // v2-committed: request lives in `requests`.
    let (v2_id, _info) = approve_and_commit(&mut queue, &clock, 50_000, ctx);
    queue.update_requests_signed(&vector[v2_id]);
    assert!(queue.request_in_requests(v2_id));
    assert!(queue.request_status_any(v2_id).is_signed());

    // v1-committed (pre-upgrade): request lives in `processed`.
    let v1_id = setup_request(&mut queue, &clock, 60_000, ctx);
    queue.approve_withdrawal(v1_id, dummy_cert(), &clock);
    let txn = make_test_txn(vector[v1_id], @0xF00D, &clock, ctx);
    let btc = queue.commit_requests_v1_style_for_testing(&txn);
    btc.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    queue.update_requests_signed(&vector[v1_id]);
    assert!(queue.request_in_processed(v1_id));
    assert!(queue.request_status_any(v1_id).is_signed());

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_archive_moves_request_and_txn() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let txn_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.mark_txn_confirmed(txn_id, &clock);

    // Confirmed but not yet archived: txn still in the hot bag.
    assert!(queue.has_withdrawal_txn(txn_id));
    assert!(!queue.has_confirmed_txn(txn_id));

    queue.archive_withdrawal_txn(txn_id);

    assert!(!queue.has_withdrawal_txn(txn_id));
    assert!(queue.has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_archive_flips_request_to_confirmed_in_processed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let id = setup_request(&mut queue, &clock, 50_000, ctx);
    queue.approve_withdrawal(id, dummy_cert(), &clock);
    let txn = make_test_txn(vector[id], @0xBEEF, &clock, ctx);
    let txn_id = txn.withdrawal_txn_id();
    let btc = queue.commit_requests(&txn);
    btc.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.update_requests_signed(&vector[id]);
    queue.mark_txn_confirmed(txn_id, &clock);

    queue.archive_withdrawal_txn(txn_id);

    assert!(!queue.request_in_requests(id));
    assert!(queue.request_in_processed(id));
    assert!(queue.request_status_any(id).is_confirmed());
    assert!(queue.is_request_processing(id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_archive_idempotent() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let txn_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.mark_txn_confirmed(txn_id, &clock);

    queue.archive_withdrawal_txn(txn_id);
    // Re-run is a no-op, not an abort.
    queue.archive_withdrawal_txn(txn_id);

    assert!(!queue.has_withdrawal_txn(txn_id));
    assert!(queue.has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
#[expected_failure(abort_code = EWithdrawalNotConfirmed)]
fun test_archive_unconfirmed_txn_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let txn_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);
    queue.archive_withdrawal_txn(txn_id);
    abort 0
}

#[test]
fun test_archive_v1_leftover_stays_in_processed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    // Simulate a request committed before the upgrade: it already lives in
    // `processed`, status Processing.
    let id = setup_request(&mut queue, &clock, 50_000, ctx);
    queue.approve_withdrawal(id, dummy_cert(), &clock);
    let txn = make_test_txn(vector[id], @0xBEEF, &clock, ctx);
    let txn_id = txn.withdrawal_txn_id();
    let btc = queue.commit_requests_v1_style_for_testing(&txn);
    btc.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.update_requests_signed(&vector[id]);

    // Confirmed under v2, archived by GC: the request gets its terminal
    // status in place, no second move.
    queue.mark_txn_confirmed(txn_id, &clock);
    queue.archive_withdrawal_txn(txn_id);

    assert!(queue.request_in_processed(id));
    assert!(queue.request_status_any(id).is_confirmed());
    assert!(queue.has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
#[expected_failure(abort_code = EWithdrawalAlreadyConfirmed)]
fun test_mark_txn_confirmed_twice_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let txn_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.mark_txn_confirmed(txn_id, &clock);
    queue.mark_txn_confirmed(txn_id, &clock);
    abort 0
}

#[test]
#[expected_failure(abort_code = ERequestNotCancellable)]
fun test_queue_cancel_committed_request_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (id, _info) = approve_and_commit(&mut queue, &clock, 50_000, ctx);
    // The entry-level is_request_processing gate refuses first in production;
    // this defensive assert must also hold if the queue fn is reached.
    let btc = queue.cancel_withdrawal(id);
    btc.destroy_for_testing();
    abort 0
}

// ======== Chunked archival tests ========

/// Three-request txn: approved, committed (v2 in-place), fully signed,
/// finalized, and confirmed. Returns (ids, txn_id).
fun setup_confirmed_three_request_txn(
    queue: &mut withdrawal_queue::WithdrawalRequestQueue,
    clock: &clock::Clock,
    ctx: &mut TxContext,
): (vector<address>, address) {
    let id1 = setup_request(queue, clock, 10_000, ctx);
    let id2 = setup_request(queue, clock, 20_000, ctx);
    let id3 = setup_request(queue, clock, 30_000, ctx);
    queue.approve_withdrawal(id1, dummy_cert(), clock);
    queue.approve_withdrawal(id2, dummy_cert(), clock);
    queue.approve_withdrawal(id3, dummy_cert(), clock);
    let txn = make_test_txn(vector[id1, id2, id3], @0xC0FFEE, clock, ctx);
    let txn_id = txn.withdrawal_txn_id();
    let btc = queue.commit_requests(&txn);
    btc.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], clock);
    queue.update_requests_signed(&vector[id1, id2, id3]);
    queue.mark_txn_confirmed(txn_id, clock);
    (vector[id1, id2, id3], txn_id)
}

#[test]
fun test_chunked_archive_partial_then_finish() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (ids, txn_id) = setup_confirmed_three_request_txn(&mut queue, &clock, ctx);

    // Archive two of three: those move, the third stays, the txn stays hot.
    queue.archive_withdrawal_requests(txn_id, &vector[ids[0], ids[1]]);
    assert!(queue.request_in_processed(ids[0]));
    assert!(queue.request_status_any(ids[0]).is_confirmed());
    assert!(queue.request_in_processed(ids[1]));
    assert!(queue.request_in_requests(ids[2]));
    assert!(queue.request_status_any(ids[2]).is_signed());
    assert!(queue.has_withdrawal_txn(txn_id));

    // Finish must no-op while a request remains unarchived.
    queue.finish_archive_withdrawal_txn(txn_id);
    assert!(queue.has_withdrawal_txn(txn_id));
    assert!(!queue.has_confirmed_txn(txn_id));

    // Archive the last request; finish now moves the txn.
    queue.archive_withdrawal_requests(txn_id, &vector[ids[2]]);
    queue.finish_archive_withdrawal_txn(txn_id);
    assert!(!queue.has_withdrawal_txn(txn_id));
    assert!(queue.has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
fun test_chunked_archive_rerun_idempotent() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (ids, txn_id) = setup_confirmed_three_request_txn(&mut queue, &clock, ctx);

    queue.archive_withdrawal_requests(txn_id, &vector[ids[0]]);
    // Re-running the same chunk is a no-op status re-write, not an abort.
    queue.archive_withdrawal_requests(txn_id, &vector[ids[0]]);
    assert!(queue.request_in_processed(ids[0]));
    assert!(queue.request_status_any(ids[0]).is_confirmed());

    // After the txn is fully archived, chunk calls no-op entirely.
    queue.archive_withdrawal_requests(txn_id, &vector[ids[1], ids[2]]);
    queue.finish_archive_withdrawal_txn(txn_id);
    queue.archive_withdrawal_requests(txn_id, &vector[ids[0]]);
    assert!(queue.has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

#[test]
#[expected_failure(abort_code = withdrawal_queue::ERequestTxnMismatch)]
fun test_chunked_archive_foreign_request_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let (_ids, txn_id) = setup_confirmed_three_request_txn(&mut queue, &clock, ctx);
    // A request belonging to a different withdrawal must be rejected in the
    // requests branch (and the processed branch carries the same check).
    let (foreign_id, _info) = approve_and_commit(&mut queue, &clock, 40_000, ctx);
    queue.archive_withdrawal_requests(txn_id, &vector[foreign_id]);
    abort 0
}

#[test]
#[expected_failure(abort_code = EWithdrawalNotConfirmed)]
fun test_chunked_archive_unconfirmed_txn_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    let txn_id = setup_withdrawal_txn(&mut queue, &clock, 50_000, @0xBEEF, ctx);
    queue.archive_withdrawal_requests(txn_id, &vector[]);
    abort 0
}

#[test]
/// Regression: `processed` residency is not archival. A request committed
/// before the v2 upgrade lives in `processed` while still `Signed`, so an
/// adversarial early finish right after confirmation must no-op instead of
/// retiring the txn and stranding the request with a stale status; archiving
/// the request (Confirmed in place) then lets the finish complete.
fun test_finish_archive_waits_for_v1_committed_requests() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let mut queue = setup_queue(ctx);
    let clock = clock::create_for_testing(ctx);

    // v1-committed (pre-upgrade): request lives in `processed`.
    let id = setup_request(&mut queue, &clock, 60_000, ctx);
    queue.approve_withdrawal(id, dummy_cert(), &clock);
    let txn = make_test_txn(vector[id], @0xF00D, &clock, ctx);
    let txn_id = txn.withdrawal_txn_id();
    let btc = queue.commit_requests_v1_style_for_testing(&txn);
    btc.destroy_for_testing();
    queue.insert_withdrawal_txn(txn);
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], &clock);
    queue.update_requests_signed(&vector[id]);
    queue.mark_txn_confirmed(txn_id, &clock);
    assert!(queue.request_in_processed(id));
    assert!(queue.request_status_any(id).is_signed());

    // Adversarial early finish before any archive_request ran: must no-op.
    queue.finish_archive_withdrawal_txn(txn_id);
    assert!(queue.has_withdrawal_txn(txn_id));
    assert!(!queue.has_confirmed_txn(txn_id));
    assert!(queue.request_status_any(id).is_signed());

    // Archive the request (Confirmed in place), then the finish completes.
    queue.archive_withdrawal_requests(txn_id, &vector[id]);
    queue.finish_archive_withdrawal_txn(txn_id);
    assert!(!queue.has_withdrawal_txn(txn_id));
    assert!(queue.has_confirmed_txn(txn_id));
    assert!(queue.request_in_processed(id));
    assert!(queue.request_status_any(id).is_confirmed());

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}
