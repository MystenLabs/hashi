// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::tob_pruning_tests;

use hashi::{cert_submission, committee, hashi::Hashi, test_utils};
use sui::bls12381;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

const CURRENT_EPOCH: u64 = 10;

// ~~~~~~~ Helpers ~~~~~~~

/// Hashi whose current committee epoch is `CURRENT_EPOCH`.
fun hashi_at_current_epoch(ctx: &mut TxContext): Hashi {
    test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx)
}

/// Register a (minimal) committee at `epoch` so `has_committee(epoch)` holds.
fun insert_committee_at(hashi: &mut Hashi, epoch: u64) {
    hashi.committee_set_mut().insert_committee_for_testing(committee_at(epoch));
}

fun committee_at(epoch: u64): committee::Committee {
    let sk = test_utils::bls_sk_for_testing();
    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let member = committee::new_committee_member(VOTER1, public_key, sk, 1);
    committee::new_committee(
        epoch,
        vector[member],
        hashi::mpc_config::new_for_testing(800, 3333, 0, 0),
    )
}

fun dkg_key(epoch: u64): hashi::tob::TobKey {
    hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg())
}

fun rotation_key(epoch: u64): hashi::tob::TobKey {
    hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_key_rotation())
}

fun nonce_key(epoch: u64, batch_index: u32): hashi::tob::TobKey {
    hashi::tob::tob_key(
        epoch,
        option::some(batch_index),
        hashi::tob::protocol_type_nonce_generation(),
    )
}

/// Create an (empty) bucket at `key`, bypassing the submit path's
/// current-or-pending epoch assert.
fun add_bucket(hashi: &mut Hashi, key: hashi::tob::TobKey, ctx: &mut TxContext) {
    hashi.epoch_certs(key, ctx);
}

// ~~~~~~~ Nonce Bucket Floors ~~~~~~~

#[test]
fun nonce_destroyed_at_exact_floor() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    add_bucket(&mut hashi, nonce_key(8, 0), ctx);

    cert_submission::destroy_nonce_certs(&mut hashi, 8, 0);

    assert!(!hashi.tob_contains(nonce_key(8, 0)));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = cert_submission::ETooEarlyToDestroyNonceCerts)]
fun nonce_below_floor_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    add_bucket(&mut hashi, nonce_key(9, 0), ctx);

    cert_submission::destroy_nonce_certs(&mut hashi, 9, 0);

    abort
}

#[test]
fun nonce_missing_bucket_is_noop() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);

    cert_submission::destroy_nonce_certs(&mut hashi, 5, 3);

    std::unit_test::destroy(hashi);
}

#[test]
fun nonce_destroy_targets_single_batch() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    add_bucket(&mut hashi, nonce_key(8, 0), ctx);
    add_bucket(&mut hashi, nonce_key(8, 1), ctx);
    add_bucket(&mut hashi, nonce_key(8, 2), ctx);

    cert_submission::destroy_nonce_certs(&mut hashi, 8, 2);

    assert!(hashi.tob_contains(nonce_key(8, 0)));
    assert!(hashi.tob_contains(nonce_key(8, 1)));
    assert!(!hashi.tob_contains(nonce_key(8, 2)));
    std::unit_test::destroy(hashi);
}

/// Nonce buckets are only ever read during their own epoch, so — unlike
/// key-generation buckets — the previous committee's epoch is fair game.
#[test]
fun nonce_previous_committee_epoch_prunable() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 2);
    add_bucket(&mut hashi, nonce_key(2, 0), ctx);

    cert_submission::destroy_nonce_certs(&mut hashi, 2, 0);

    assert!(!hashi.tob_contains(nonce_key(2, 0)));
    std::unit_test::destroy(hashi);
}

// ~~~~~~~ Key-Generation Bucket Floors ~~~~~~~

/// Committee epochs are Sui epochs and can gap: with committees {2, 10}, the
/// bucket at 2 clears the retention floor (10 >= 2 + 8) but belongs to the
/// PREVIOUS committee, whose certs seed the next rotation. This is exactly
/// the case a bare age floor gets wrong.
#[test]
#[expected_failure(abort_code = cert_submission::EKeyGenCertsStillNeeded)]
fun keygen_gap_previous_committee_protected() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 2);
    add_bucket(&mut hashi, rotation_key(2), ctx);

    cert_submission::destroy_key_gen_certs(&mut hashi, 2);

    abort
}

#[test]
fun keygen_destroyed_when_strictly_older_than_previous_committee() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 0);
    insert_committee_at(&mut hashi, 2);
    add_bucket(&mut hashi, dkg_key(0), ctx);

    cert_submission::destroy_key_gen_certs(&mut hashi, 0);

    assert!(!hashi.tob_contains(dkg_key(0)));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = cert_submission::ETooEarlyToDestroyKeyGenCerts)]
fun keygen_retention_floor_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 3);
    insert_committee_at(&mut hashi, 5);
    add_bucket(&mut hashi, rotation_key(3), ctx);

    // 10 < 3 + 8: within the break-glass retention window.
    cert_submission::destroy_key_gen_certs(&mut hashi, 3);

    abort
}

#[test]
fun keygen_retention_exact_boundary() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 2);
    insert_committee_at(&mut hashi, 5);
    add_bucket(&mut hashi, rotation_key(2), ctx);

    // 10 == 2 + 8, and the committee at 5 lies strictly between.
    cert_submission::destroy_key_gen_certs(&mut hashi, 2);

    assert!(!hashi.tob_contains(rotation_key(2)));
    std::unit_test::destroy(hashi);
}

#[test]
fun keygen_removes_both_dkg_and_rotation_and_is_idempotent() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 0);
    insert_committee_at(&mut hashi, 2);
    add_bucket(&mut hashi, dkg_key(0), ctx);
    add_bucket(&mut hashi, rotation_key(0), ctx);

    cert_submission::destroy_key_gen_certs(&mut hashi, 0);
    assert!(!hashi.tob_contains(dkg_key(0)));
    assert!(!hashi.tob_contains(rotation_key(0)));

    // Second call finds nothing and must not abort.
    cert_submission::destroy_key_gen_certs(&mut hashi, 0);

    std::unit_test::destroy(hashi);
}

/// A pending committee's epoch is above the current epoch, so it can never
/// stand in for "a committee strictly between the bucket and now".
#[test]
#[expected_failure(abort_code = cert_submission::EKeyGenCertsStillNeeded)]
fun keygen_pending_committee_not_a_guard_satisfier() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 2);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(committee_at(12));
    add_bucket(&mut hashi, rotation_key(2), ctx);

    cert_submission::destroy_key_gen_certs(&mut hashi, 2);

    abort
}

/// A bucket being written for a pending epoch (mid-reconfig) sits above the
/// current epoch and is untouchable by the retention floor.
#[test]
#[expected_failure(abort_code = cert_submission::ETooEarlyToDestroyKeyGenCerts)]
fun keygen_pending_epoch_bucket_protected() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(committee_at(12));
    add_bucket(&mut hashi, rotation_key(12), ctx);

    cert_submission::destroy_key_gen_certs(&mut hashi, 12);

    abort
}

// ~~~~~~~ Bucket Draining ~~~~~~~

#[test]
fun destroy_drains_populated_bucket() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);

    let key = nonce_key(8, 0);
    let sig = hashi::committee::new_committee_signature(8, vector[], vector[]);
    let dealers = vector[VOTER1, VOTER2, VOTER3];
    dealers.do!(|dealer| {
        let epoch_certs = hashi.epoch_certs(key, ctx);
        hashi::tob::submit_cert_with_signature(epoch_certs, 8, dealer, vector[1u8, 2, 3], &sig);
    });
    add_bucket(&mut hashi, nonce_key(8, 1), ctx);
    assert!(hashi.epoch_certs_ref(key).num_certs() == 3);

    cert_submission::destroy_nonce_certs(&mut hashi, 8, 0);

    assert!(!hashi.tob_contains(key));
    assert!(hashi.tob_contains(nonce_key(8, 1)));
    std::unit_test::destroy(hashi);
}

// ~~~~~~~ Committee Walk ~~~~~~~

#[test]
fun is_before_previous_committee_walk() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, CURRENT_EPOCH);
    let mut hashi = hashi_at_current_epoch(ctx);
    insert_committee_at(&mut hashi, 0);
    insert_committee_at(&mut hashi, 2);

    // Committees at {0, 2, 10}: epochs 0 and 1 have the committee at 2
    // strictly between them and now; everything from 2 upward does not.
    let committee_set = hashi.committee_set();
    assert!(committee_set.is_before_previous_committee(0));
    assert!(committee_set.is_before_previous_committee(1));
    let mut e = 2;
    while (e <= CURRENT_EPOCH) {
        assert!(!committee_set.is_before_previous_committee(e));
        e = e + 1;
    };

    std::unit_test::destroy(hashi);
}
