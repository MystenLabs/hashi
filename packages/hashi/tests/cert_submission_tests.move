// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::cert_submission_tests;

use hashi::test_utils;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
fun test_dkg_and_rotation_certs_use_separate_buckets() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();

    let rot_cert = hashi::committee::new_committee_signature(epoch, vector[], vector[]);
    hashi::cert_submission::submit_rotation_cert(
        &mut hashi,
        epoch,
        VOTER1,
        vector[1u8, 2, 3],
        rot_cert,
        ctx,
    );

    let ctx2 = &mut sui::tx_context::new_from_hint(VOTER2, 1, 0, 0, 0);
    let dkg_cert = hashi::committee::new_committee_signature(epoch, vector[], vector[]);
    hashi::cert_submission::submit_dkg_cert(
        &mut hashi,
        epoch,
        VOTER2,
        vector[1u8, 2, 3],
        dkg_cert,
        ctx2,
    );

    let dkg_key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg());
    let rot_key = hashi::tob::tob_key(
        epoch,
        option::none(),
        hashi::tob::protocol_type_key_rotation(),
    );
    assert!(hashi.tob_contains(dkg_key));
    assert!(hashi.tob_contains(rot_key));
    assert!(hashi.epoch_certs_ref(dkg_key).num_certs() == 1);
    assert!(hashi.epoch_certs_ref(rot_key).num_certs() == 1);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_nonce_cert_is_stamped_with_clock() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    let nonce_cert = hashi::committee::new_committee_signature(epoch, vector[], vector[]);
    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        nonce_cert,
        &clock,
        ctx,
    );

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    assert!(hashi.tob_contains(nonce_key));
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).num_stamped_certs() == 1);
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).submission_timestamp_ms(VOTER1) == 123);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_destroy_all_stamped_drains_nonce_bucket() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut bucket = hashi::tob::create_stamped(
        0,
        hashi::tob::protocol_type_nonce_generation(),
        ctx,
    );
    let sig = hashi::committee::new_committee_signature(0, vector[], vector[]);
    hashi::tob::submit_stamped_cert_with_signature(
        &mut bucket,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        &sig,
        123,
    );
    assert!(bucket.num_stamped_certs() == 1);
    hashi::tob::destroy_all_stamped(bucket, 2);
}

#[test]
#[expected_failure]
fun test_destroy_all_stamped_before_two_epochs_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let bucket = hashi::tob::create_stamped(0, hashi::tob::protocol_type_nonce_generation(), ctx);
    hashi::tob::destroy_all_stamped(bucket, 1);
}
