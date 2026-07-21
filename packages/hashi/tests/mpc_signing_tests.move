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
    ENotComplete
};

fun sig(byte: u8): vector<u8> {
    vector[byte]
}

#[test]
fun test_new_initializes_pending() {
    let b = mpc_signing::new(3, 100, 7);
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
    let mut b = mpc_signing::new(3, 100, 7);
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
    let mut b = mpc_signing::new(2, 0, 1);
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
    let mut b = mpc_signing::new(3, 0, 1);
    b.record(vector[0, 1, 2], vector[sig(1), sig(2), sig(3)]);
    let sigs = b.to_signatures();
    assert!(*sigs.borrow(0) == sig(1));
    assert!(*sigs.borrow(1) == sig(2));
    assert!(*sigs.borrow(2) == sig(3));
    b.destroy_for_testing();
}

#[test]
fun test_reallocate_only_pending_tail() {
    let mut b = mpc_signing::new(4, 100, 7); // presigs 100,101,102,103
    // sign inputs 1 and 3 in the old epoch
    b.record(vector[1, 3], vector[sig(0x11), sig(0x33)]);
    // reconfig: reallocate pending inputs (0, 2) from a fresh block at 200
    b.reallocate(200, 8, 2);
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
    let mut b = mpc_signing::new(2, 0, 7);
    b.reallocate(100, 7, 2); // same epoch -> abort (before the count check)
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EAllocationMismatch)]
fun test_reallocate_wrong_allocated_count_aborts() {
    let mut b = mpc_signing::new(3, 0, 7);
    b.record(vector[0], vector[sig(0xAA)]); // 2 still pending
    b.reallocate(100, 8, 1); // under-allocated: should be 2 -> abort
    b.destroy_for_testing();
}

#[test]
fun test_reallocate_multiple_epochs_keeps_signed_count() {
    let mut b = mpc_signing::new(3, 100, 7);
    b.record(vector[0], vector[sig(0x00)]);
    b.reallocate(200, 8, 2); // inputs 1,2 pending
    assert!(b.signed_count() == 1);
    assert!(b.pending_index(1) == option::some(200));
    assert!(b.pending_index(2) == option::some(201));
    b.record(vector[1], vector[sig(0x11)]);
    b.reallocate(300, 9, 1); // only input 2 pending
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
    let mut b = mpc_signing::new(2, 0, 1);
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
    let b = mpc_signing::new(0, 0, 1);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EIndexOutOfRange)]
fun test_pending_index_out_of_bounds_aborts() {
    let b = mpc_signing::new(2, 0, 1);
    let _ = b.pending_index(5);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = ENotComplete)]
fun test_to_signatures_incomplete_aborts() {
    let b = mpc_signing::new(2, 0, 1);
    let _ = b.to_signatures();
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = EIndexOutOfRange)]
fun test_record_index_out_of_range_aborts() {
    let mut b = mpc_signing::new(2, 0, 1);
    b.record(vector[5], vector[sig(0xAA)]);
    b.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = ELengthMismatch)]
fun test_record_length_mismatch_aborts() {
    let mut b = mpc_signing::new(2, 0, 1);
    b.record(vector[0, 1], vector[sig(0xAA)]);
    b.destroy_for_testing();
}
