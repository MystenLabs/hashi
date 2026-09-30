// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, unused_const)]
module hashi::mpc_signing_tests;

use hashi::mpc_signing::{
    Self,
    EZeroInputs,
    EIndexOutOfRange,
    ELengthMismatch,
    ENotStale,
    EAllocationMismatch,
    ENotComplete,
};

fun sig(byte: u8): vector<u8> {
    vector[byte]
}

/// A fresh batch for `num_inputs` inputs on presigs starting at `base`.
fun batch(num_inputs: u64, base: u64, epoch: u64): mpc_signing::SigningBatch {
    mpc_signing::new(num_inputs, mpc_signing::presigs_for_testing(base, num_inputs), epoch)
}

#[test]
fun test_allocate_mints_disjoint_contiguous_presigs() {
    let mut allocator = mpc_signing::new_allocator();
    assert!(allocator.num_consumed() == 0);
    let b1 = mpc_signing::new(2, allocator.allocate(2), 1);
    assert!(allocator.num_consumed() == 2);
    let b2 = mpc_signing::new(1, allocator.allocate(1), 1);
    assert!(allocator.num_consumed() == 3);
    // consecutive allocations never overlap
    assert!(b1.pending_index(0) == option::some(0));
    assert!(b1.pending_index(1) == option::some(1));
    assert!(b2.pending_index(0) == option::some(2));
    b1.destroy_for_testing();
    b2.destroy_for_testing();
    allocator.destroy_allocator_for_testing();
}

#[test]
fun test_allocate_zero_consumes_nothing() {
    let mut allocator = mpc_signing::new_allocator_for_testing(6);
    assert!(allocator.allocate(0).is_empty());
    assert!(allocator.num_consumed() == 6);
    allocator.destroy_allocator_for_testing();
}

#[test]
fun test_reset_restarts_numbering() {
    let mut allocator = mpc_signing::new_allocator();
    let _ = allocator.allocate(3);
    allocator.reset();
    assert!(allocator.num_consumed() == 0);
    let b = mpc_signing::new(1, allocator.allocate(1), 2);
    assert!(b.pending_index(0) == option::some(0));
    b.destroy_for_testing();
    allocator.destroy_allocator_for_testing();
}

#[test]
#[expected_failure(abort_code = EAllocationMismatch)]
fun test_new_too_few_presigs_aborts() {
    let b = mpc_signing::new(3, mpc_signing::presigs_for_testing(0, 2), 7);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EAllocationMismatch)]
fun test_new_too_many_presigs_aborts() {
    let b = mpc_signing::new(3, mpc_signing::presigs_for_testing(0, 4), 7);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EAllocationMismatch)]
fun test_reallocate_too_many_presigs_aborts() {
    let mut b = batch(2, 0, 7);
    b.reallocate(mpc_signing::presigs_for_testing(100, 3), 8);
    b.destroy_for_testing();
}

#[test]
fun test_new_initializes_pending() {
    let b = batch(3, 100, 7);
    assert!(b.num_inputs() == 3);
    assert!(b.signed_count() == 0);
    assert!(b.pending_count() == 3);
    assert!(!b.is_complete());
    assert!(b.epoch() == 7);
    assert!(b.pending_index(0) == option::some(100));
    assert!(b.pending_index(1) == option::some(101));
    assert!(b.pending_index(2) == option::some(102));
    b.destroy_for_testing();
}

#[test]
fun test_record_out_of_order() {
    let mut b = batch(3, 100, 7);
    // sign inputs 2 then 0; leave 1 pending
    b.record(vector[2, 0], vector[sig(0xCC), sig(0xAA)]);
    assert!(b.signed_count() == 2);
    assert!(b.pending_count() == 1);
    assert!(!b.is_complete());
    assert!(b.is_signed(0));
    assert!(!b.is_signed(1));
    assert!(b.is_signed(2));
    // pending slot keeps its original presig index
    assert!(b.pending_index(1) == option::some(101));
    b.destroy_for_testing();
}

#[test]
fun test_first_writer_wins() {
    let mut b = batch(2, 0, 1);
    b.record(vector[0], vector[sig(0xAA)]);
    // a second write to the same slot is ignored, count unchanged
    b.record(vector[0], vector[sig(0xBB)]);
    assert!(b.signed_count() == 1);
    b.record(vector[1], vector[sig(0xDD)]);
    assert!(b.is_complete());
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(0xAA)); // original kept, not overwritten
    assert!(*sigs.borrow(1) == sig(0xDD));
    b.destroy_for_testing();
}

#[test]
fun test_to_signatures_order() {
    let mut b = batch(3, 0, 1);
    b.record(vector[0, 1, 2], vector[sig(1), sig(2), sig(3)]);
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(1));
    assert!(*sigs.borrow(1) == sig(2));
    assert!(*sigs.borrow(2) == sig(3));
    b.destroy_for_testing();
}

#[test]
fun test_reallocate_only_pending_tail() {
    let mut b = batch(4, 100, 7); // presigs 100,101,102,103
    // sign inputs 1 and 3 in the old epoch
    b.record(vector[1, 3], vector[sig(0x11), sig(0x33)]);
    // reconfig: reallocate pending inputs (0, 2) from a fresh block at 200
    b.reallocate(mpc_signing::presigs_for_testing(200, 2), 8);
    assert!(b.epoch() == 8);
    assert!(b.signed_count() == 2);
    assert!(b.pending_count() == 2);
    // signed slots untouched (bytes preserved)
    assert!(b.is_signed(1));
    assert!(b.is_signed(3));
    // pending slots got fresh, distinct indices in ascending input order
    assert!(b.pending_index(0) == option::some(200));
    assert!(b.pending_index(2) == option::some(201));
    // finish in the new epoch and confirm signed bytes survived the realloc
    b.record(vector[0, 2], vector[sig(0x00), sig(0x22)]);
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(0x00));
    assert!(*sigs.borrow(1) == sig(0x11));
    assert!(*sigs.borrow(2) == sig(0x22));
    assert!(*sigs.borrow(3) == sig(0x33));
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = ENotStale)]
fun test_reallocate_same_epoch_aborts() {
    let mut b = batch(2, 0, 7);
    b.reallocate(mpc_signing::presigs_for_testing(100, 2), 7); // same epoch -> abort
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EAllocationMismatch)]
fun test_reallocate_wrong_allocated_count_aborts() {
    let mut b = batch(3, 0, 7);
    b.record(vector[0], vector[sig(0xAA)]); // 2 still pending
    b.reallocate(mpc_signing::presigs_for_testing(100, 1), 8); // 2 still pending -> abort
    b.destroy_for_testing();
}

#[test]
fun test_reallocate_multiple_epochs_keeps_signed_count() {
    let mut b = batch(3, 100, 7);
    b.record(vector[0], vector[sig(0x00)]);
    b.reallocate(mpc_signing::presigs_for_testing(200, 2), 8); // inputs 1,2 pending
    assert!(b.signed_count() == 1);
    assert!(b.pending_index(1) == option::some(200));
    assert!(b.pending_index(2) == option::some(201));
    b.record(vector[1], vector[sig(0x11)]);
    b.reallocate(mpc_signing::presigs_for_testing(300, 1), 9); // only input 2 pending
    assert!(b.signed_count() == 2);
    assert!(b.pending_index(2) == option::some(300));
    b.record(vector[2], vector[sig(0x22)]);
    assert!(b.is_complete());
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(0x00));
    assert!(*sigs.borrow(1) == sig(0x11));
    assert!(*sigs.borrow(2) == sig(0x22));
    b.destroy_for_testing();
}

#[test]
fun test_duplicate_index_in_single_call_first_wins() {
    let mut b = batch(2, 0, 1);
    // duplicate index in one call: first-writer-wins, no double count
    b.record(vector[0, 0], vector[sig(0xAA), sig(0xBB)]);
    assert!(b.signed_count() == 1);
    assert!(b.is_signed(0));
    assert!(!b.is_signed(1));
    b.record(vector[1], vector[sig(0xCC)]);
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(0xAA)); // first write kept
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EZeroInputs)]
fun test_new_zero_inputs_aborts() {
    let b = mpc_signing::new(0, vector[], 1);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EIndexOutOfRange)]
fun test_pending_index_out_of_bounds_aborts() {
    let b = batch(2, 0, 1);
    let _ = b.pending_index(5);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = ENotComplete)]
fun test_to_signatures_incomplete_aborts() {
    let b = batch(2, 0, 1);
    let _ = b.to_signatures();
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EIndexOutOfRange)]
fun test_record_index_out_of_range_aborts() {
    let mut b = batch(2, 0, 1);
    b.record(vector[5], vector[sig(0xAA)]);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = ELengthMismatch)]
fun test_record_length_mismatch_aborts() {
    let mut b = batch(2, 0, 1);
    b.record(vector[0, 1], vector[sig(0xAA)]);
    b.destroy_for_testing();
}
