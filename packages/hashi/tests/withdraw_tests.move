// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::withdraw_tests;

use hashi::{btc::BTC, test_utils, utxo, withdrawal_queue};
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
    let request = withdrawal_queue::create_withdrawal(
        btc,
        bitcoin_address,
        clock,
        ctx,
    );
    let request_id = request.request_id().to_address();
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal(request);
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

// ======== Certificate-based tests ========

/// Helper: build the signing message bytes for a certificate.
/// Format: BCS(epoch) || BCS(message)
fun build_cert_message<T: copy + drop + store>(epoch: u64, intent: u16, message: &T): vector<u8> {
    let mut bytes = bcs::to_bytes(&intent);
    bytes.append(bcs::to_bytes(&epoch));
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
    let message_bytes1 = build_cert_message(
        epoch,
        hashi::intent::withdrawal_request_approval(),
        &approval1,
    );
    let cert1 = test_utils::sign_certificate(epoch, &message_bytes1, 3);
    hashi::withdraw::approve_request(&mut hashi, id1, cert1, &clock);

    let approval2 = hashi::withdraw::new_request_approval_message(id2);
    let message_bytes2 = build_cert_message(
        epoch,
        hashi::intent::withdrawal_request_approval(),
        &approval2,
    );
    let cert2 = test_utils::sign_certificate(epoch, &message_bytes2, 3);
    hashi::withdraw::approve_request(&mut hashi, id2, cert2, &clock);

    // Verify both requests are now approved by committing them
    let test_utxo = utxo::utxo(utxo::utxo_id(@0xBEEF, 0), 1_000_000, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id1, id2],
        vector[test_utxo],
        vector[withdrawal_queue::output_utxo(1, x"00")],
        vector[],
        @0xBEEF,
        &clock,
        ctx,
    );
    let btc_balance = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&txn);
    // Total: 10_000 + 20_000 = 30_000
    assert!(btc_balance.value() == 30_000);

    btc_balance.destroy_for_testing();
    std::unit_test::destroy(txn);
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
    let bad_cert = test_utils::sign_certificate(epoch, &wrong_bytes, 3);

    // Should fail signature verification
    hashi::withdraw::approve_request(&mut hashi, id1, bad_cert, &clock);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
/// Cancelling an approved (but not yet processing) request should succeed
/// and return the full BTC balance to the requester.
fun test_approve_then_cancel() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    let id1 = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Approve via certificate
    let approval = hashi::withdraw::new_request_approval_message(id1);
    let message_bytes = build_cert_message(
        epoch,
        hashi::intent::withdrawal_request_approval(),
        &approval,
    );
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 3);
    hashi::withdraw::approve_request(&mut hashi, id1, cert, &clock);

    // Cancelling an approved request should succeed — BTC hasn't been burned yet
    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, id1, &clock, ctx);
    assert!(btc.value() == 10_000);
    btc.destroy_for_testing();

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdraw::ECannotCancelProcessingWithdrawal)]
/// Once a request has been committed to a WithdrawalTransaction its BTC has
/// been burned — cancellation must be rejected.
fun test_cancel_processing_request() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    let id1 = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);

    // Approve the request.
    let approval = hashi::withdraw::new_request_approval_message(id1);
    let message_bytes = build_cert_message(
        epoch,
        hashi::intent::withdrawal_request_approval(),
        &approval,
    );
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 3);
    hashi::withdraw::approve_request(&mut hashi, id1, cert, &clock);

    // Commit the request into a WithdrawalTransaction.
    let test_utxo = utxo::utxo(utxo::utxo_id(@0xBEEF, 0), 1_000_000, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id1],
        vector[test_utxo],
        vector[withdrawal_queue::output_utxo(1, x"00")],
        vector[],
        @0xBEEF,
        &clock,
        ctx,
    );
    let btc_balance = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&txn);

    // Advance past cooldown and attempt cancellation — should abort.
    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);
    let btc = hashi::withdraw::cancel_withdrawal(&mut hashi, id1, &clock, ctx);

    // Cleanup — not reached.
    btc.destroy_for_testing();
    btc_balance.destroy_for_testing();
    std::unit_test::destroy(txn);
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

// ======== Deferred archival (entry-level) tests ========

fun dummy_queue_cert(): hashi::committee::CommitteeSignature {
    hashi::committee::new_committee_signature(0, vector[], vector[])
}

/// Create, approve, commit (v2 in-place), fully sign and finalize a
/// single-request withdrawal whose input UTXO is seeded in the pool.
/// Returns (request_id, txn_id).
fun setup_fully_signed_txn(
    hashi: &mut hashi::hashi::Hashi,
    clock: &clock::Clock,
    ctx: &mut TxContext,
): (address, address) {
    let id = setup_withdrawal_request(hashi, clock, 10_000, ctx);
    hashi.bitcoin_mut().withdrawal_queue_mut().approve_withdrawal(id, dummy_queue_cert(), clock);

    let input_id = utxo::utxo_id(@0xBEEF, 0);
    let input = utxo::utxo(input_id, 1_000_000, option::none());
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(input);

    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[input],
        vector[withdrawal_queue::output_utxo(1, x"00")],
        vector[],
        @0xBEEF,
        clock,
        ctx,
    );
    let txn_id = txn.withdrawal_txn_id();
    let btc = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&txn);
    btc.destroy_for_testing();
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal_txn(txn);

    let queue = hashi.bitcoin_mut().withdrawal_queue_mut();
    queue.record_input_signatures(txn_id, vector[0], vector[x"DEADBEEF"]);
    queue.finalize_withdrawal_txn(txn_id, vector[x"AAAAAAAA"], clock);
    (id, txn_id)
}

fun confirm_via_entry(hashi: &mut hashi::hashi::Hashi, txn_id: address, clock: &clock::Clock) {
    let epoch = 0u64;
    let message = hashi::withdraw::new_withdrawal_confirmation_message(txn_id);
    let message_bytes = build_cert_message(
        epoch,
        hashi::intent::withdrawal_confirmation(),
        &message,
    );
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 3);
    hashi::withdraw::confirm_withdrawal(hashi, txn_id, cert, clock);
}

#[test]
fun test_confirm_withdrawal_defers_archival() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let (id, txn_id) = setup_fully_signed_txn(&mut hashi, &clock, ctx);
    confirm_via_entry(&mut hashi, txn_id, &clock);

    // Confirm recorded in place: txn stays in the hot bag, request stays in
    // `requests`; both moves are deferred to archival.
    let queue = hashi.bitcoin().withdrawal_queue();
    assert!(queue.has_withdrawal_txn(txn_id));
    assert!(!queue.has_confirmed_txn(txn_id));
    assert!(queue.request_in_requests(id));

    // The archival GC completes both moves.
    hashi::withdraw::archive_confirmed_withdrawals(&mut hashi, vector[txn_id]);
    let queue = hashi.bitcoin().withdrawal_queue();
    assert!(!queue.has_withdrawal_txn(txn_id));
    assert!(queue.has_confirmed_txn(txn_id));
    assert!(queue.request_in_processed(id));

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdrawal_queue::EWithdrawalAlreadyConfirmed)]
fun test_confirm_withdrawal_replay_aborts() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let (_id, txn_id) = setup_fully_signed_txn(&mut hashi, &clock, ctx);
    confirm_via_entry(&mut hashi, txn_id, &clock);
    // A replayed confirmation cert must abort instead of double-emitting
    // events and re-running the UTXO spend marking.
    confirm_via_entry(&mut hashi, txn_id, &clock);
    abort 0
}

#[test]
fun test_archive_entry_batch_mixed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let (_id1, txn_id1) = setup_fully_signed_txn(&mut hashi, &clock, ctx);
    confirm_via_entry(&mut hashi, txn_id1, &clock);
    // Archive the first ahead of the batch call: the batch must skip it.
    hashi::withdraw::archive_confirmed_withdrawals(&mut hashi, vector[txn_id1]);

    let id2 = setup_withdrawal_request(&mut hashi, &clock, 20_000, ctx);
    hashi.bitcoin_mut().withdrawal_queue_mut().approve_withdrawal(id2, dummy_queue_cert(), &clock);
    let input2_id = utxo::utxo_id(@0xF00D, 0);
    let input2 = utxo::utxo(input2_id, 2_000_000, option::none());
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(input2);
    let txn2 = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id2],
        vector[input2],
        vector[withdrawal_queue::output_utxo(1, x"00")],
        vector[],
        @0xF00D,
        &clock,
        ctx,
    );
    let txn_id2 = txn2.withdrawal_txn_id();
    let btc2 = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&txn2);
    btc2.destroy_for_testing();
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal_txn(txn2);
    {
        let queue = hashi.bitcoin_mut().withdrawal_queue_mut();
        queue.record_input_signatures(txn_id2, vector[0], vector[x"DEADBEEF"]);
        queue.finalize_withdrawal_txn(txn_id2, vector[x"AAAAAAAA"], &clock);
    };
    confirm_via_entry(&mut hashi, txn_id2, &clock);

    // Batch containing one already-archived and one fresh id succeeds.
    hashi::withdraw::archive_confirmed_withdrawals(&mut hashi, vector[txn_id1, txn_id2]);
    let queue = hashi.bitcoin().withdrawal_queue();
    assert!(queue.has_confirmed_txn(txn_id1));
    assert!(queue.has_confirmed_txn(txn_id2));

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::withdraw::ECannotCancelProcessingWithdrawal)]
fun test_cancel_pre_upgrade_processed_request() {
    let epoch = 0u64;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // Simulate a request committed before the deferred-archival upgrade: it
    // sits in `processed`, so the cancellation gate must trip via the
    // fallback bag check rather than the in-place txn-link check.
    let id = setup_withdrawal_request(&mut hashi, &clock, 10_000, ctx);
    hashi.bitcoin_mut().withdrawal_queue_mut().approve_withdrawal(id, dummy_queue_cert(), &clock);
    let input = utxo::utxo(utxo::utxo_id(@0xBEEF, 0), 1_000_000, option::none());
    let txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[id],
        vector[input],
        vector[withdrawal_queue::output_utxo(1, x"00")],
        vector[],
        @0xBEEF,
        &clock,
        ctx,
    );
    let btc = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests_v1_style_for_testing(&txn);

    let one_hour_ms = 1000 * 60 * 60;
    clock.set_for_testing(one_hour_ms);
    let refund = hashi::withdraw::cancel_withdrawal(&mut hashi, id, &clock, ctx);

    // Cleanup — not reached.
    refund.destroy_for_testing();
    btc.destroy_for_testing();
    std::unit_test::destroy(txn);
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_archive_runs_while_paused() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let (_id, txn_id) = setup_fully_signed_txn(&mut hashi, &clock, ctx);
    confirm_via_entry(&mut hashi, txn_id, &clock);

    // Pause the system (proposer + one more vote reaches 2/3), then verify
    // archival (GC) still runs.
    let proposal_id = test_utils::create_emergency_pause_proposal(
        &mut hashi,
        VOTER1,
        true,
        &clock,
        ctx,
    );
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::proposal::vote<hashi::emergency_pause::EmergencyPause>(
        &mut hashi,
        VOTER2,
        proposal_id,
        &clock,
        ctx2,
    );
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    hashi::proposal::vote<hashi::emergency_pause::EmergencyPause>(
        &mut hashi,
        VOTER3,
        proposal_id,
        &clock,
        ctx3,
    );
    hashi::emergency_pause::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi.config().paused());

    hashi::withdraw::archive_confirmed_withdrawals(&mut hashi, vector[txn_id]);
    assert!(hashi.bitcoin().withdrawal_queue().has_confirmed_txn(txn_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
