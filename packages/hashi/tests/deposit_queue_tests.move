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
    let request = deposit_queue::create_deposit(utxo, &clock, ctx);
    let request_id = request.request_id().to_address();
    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);
    assert!(hashi.bitcoin().deposit_queue().contains(request_id));

    // Advance clock past the expiration time (1 day + 1 ms)
    let one_day_ms = 1000 * 60 * 60 * 24;
    clock.set_for_testing(one_day_ms + 1);

    // Delete the expired deposit request and verify it is no longer in the queue
    hashi.bitcoin_mut().deposit_queue_mut().delete_expired(request_id, &clock);
    assert!(!hashi.bitcoin().deposit_queue().contains(request_id));

    // Clean up
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

// ======== Expiry reference: creation time until approved, approval time after ========

/// Mirrors the private `MAX_DEPOSIT_REQUEST_AGE_MS` in `deposit_queue`.
const MAX_AGE_MS: u64 = 1000 * 60 * 60 * 24;
const HALF_MAX_AGE_MS: u64 = 1000 * 60 * 60 * 12;

/// Create a deposit request at the current clock time and insert it into `queue`.
fun insert_request(
    queue: &mut deposit_queue::DepositRequestQueue,
    clock: &clock::Clock,
    ctx: &mut TxContext,
): address {
    let utxo = hashi::utxo::utxo(hashi::utxo::utxo_id(@0xCAFE, 0), 1000, option::none());
    let request = deposit_queue::create_deposit(utxo, clock, ctx);
    let request_id = request.request_id().to_address();
    queue.insert_deposit(request);
    request_id
}

/// Approve a queued request at the current clock time, the way
/// `approve_deposit` does once it has verified the certificate. The queue
/// itself never verifies the certificate, so an empty one is enough here.
fun approve_request(
    queue: &mut deposit_queue::DepositRequestQueue,
    request_id: address,
    clock: &clock::Clock,
) {
    let cert = hashi::committee::new_committee_signature(0, vector[], vector[]);
    let mut request = queue.remove_request(request_id);
    request.approve(cert, clock);
    queue.insert_deposit(request);
}

/// An unapproved request still expires relative to its creation time.
#[test]
fun test_delete_unapproved_deposit_request_expires_from_creation() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    clock.set_for_testing(HALF_MAX_AGE_MS);
    let request_id = insert_request(&mut queue, &clock, ctx);

    clock.set_for_testing(HALF_MAX_AGE_MS + MAX_AGE_MS + 1);
    queue.delete_expired(request_id, &clock);
    assert!(!queue.contains(request_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

/// An approved request that is older than the maximum age since creation but
/// younger since approval must not be deletable.
#[test]
#[expected_failure(abort_code = deposit_queue::EDepositRequestNotExpired)]
fun test_delete_approved_deposit_request_expired_since_creation_only() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    // Created at 0, approved half a maximum age later.
    let request_id = insert_request(&mut queue, &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);

    // Past creation + max age, which would expire an unapproved request.
    clock.set_for_testing(MAX_AGE_MS + 1);
    queue.delete_expired(request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

/// The comparison is strict: at exactly approval + max age the request is
/// not expired yet.
#[test]
#[expected_failure(abort_code = deposit_queue::EDepositRequestNotExpired)]
fun test_delete_approved_deposit_request_at_max_age_since_approval() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    let request_id = insert_request(&mut queue, &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);

    clock.set_for_testing(HALF_MAX_AGE_MS + MAX_AGE_MS);
    queue.delete_expired(request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

/// An approved request older than the maximum age since approval is deletable.
#[test]
fun test_delete_approved_deposit_request_expired_since_approval() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    let request_id = insert_request(&mut queue, &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);

    clock.set_for_testing(HALF_MAX_AGE_MS + MAX_AGE_MS + 1);
    queue.delete_expired(request_id, &clock);
    assert!(!queue.contains(request_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

/// A re-approval moves the reference: past the first approval's expiry but
/// within the second's, the request must not be deletable.
#[test]
#[expected_failure(abort_code = deposit_queue::EDepositRequestNotExpired)]
fun test_delete_reapproved_deposit_request_expired_since_first_approval_only() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    let request_id = insert_request(&mut queue, &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);
    clock.set_for_testing(MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);

    // Past first approval + max age, not past second approval + max age.
    clock.set_for_testing(HALF_MAX_AGE_MS + MAX_AGE_MS + 1);
    queue.delete_expired(request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

/// After a re-approval the request expires relative to the latest approval.
#[test]
fun test_delete_reapproved_deposit_request_expired_since_reapproval() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let mut clock = clock::create_for_testing(ctx);
    let mut queue = deposit_queue::create(ctx);

    let request_id = insert_request(&mut queue, &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);
    clock.set_for_testing(MAX_AGE_MS);
    approve_request(&mut queue, request_id, &clock);

    clock.set_for_testing(MAX_AGE_MS + MAX_AGE_MS + 1);
    queue.delete_expired(request_id, &clock);
    assert!(!queue.contains(request_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(queue);
}

// ======== The same rule through the permissionless entry ========

/// `deposit::delete_expired_deposit` must not delete an approved request that
/// is older than the maximum age since creation but younger since approval.
#[test]
#[expected_failure(abort_code = deposit_queue::EDepositRequestNotExpired)]
fun test_delete_expired_deposit_entry_approved_request_expired_since_creation_only() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // Created at 0, approved half a maximum age later.
    let request_id = insert_request(hashi.bitcoin_mut().deposit_queue_mut(), &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(hashi.bitcoin_mut().deposit_queue_mut(), request_id, &clock);

    // Past creation + max age, which would expire an unapproved request.
    clock.set_for_testing(MAX_AGE_MS + 1);
    hashi::deposit::delete_expired_deposit(&mut hashi, request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// `deposit::delete_expired_deposit` deletes an approved request older than
/// the maximum age since approval and reports the deletion.
#[test]
fun test_delete_expired_deposit_entry_approved_request_expired_since_approval() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    let request_id = insert_request(hashi.bitcoin_mut().deposit_queue_mut(), &clock, ctx);
    clock.set_for_testing(HALF_MAX_AGE_MS);
    approve_request(hashi.bitcoin_mut().deposit_queue_mut(), request_id, &clock);

    clock.set_for_testing(HALF_MAX_AGE_MS + MAX_AGE_MS + 1);
    hashi::deposit::delete_expired_deposit(&mut hashi, request_id, &clock);
    assert!(!hashi.bitcoin().deposit_queue().contains(request_id));
    assert!(sui::event::events_by_type<hashi::deposit::ExpiredDepositDeleted>().length() == 1);

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
    let request = deposit_queue::create_deposit(utxo, &clock, ctx);
    let request_id = request.request_id().to_address();
    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);
    assert!(hashi.bitcoin().deposit_queue().contains(request_id));

    // Advance clock by only 1 day (not enough to expire)
    let one_day_ms = 1000 * 60 * 60 * 24;
    clock.set_for_testing(one_day_ms);

    // Attempt to delete the unexpired deposit request - should fail
    hashi.bitcoin_mut().deposit_queue_mut().delete_expired(request_id, &clock);

    // Clean up (shouldn't be reached due to expected failure)
    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
