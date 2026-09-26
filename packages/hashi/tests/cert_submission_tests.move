// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::cert_submission_tests;

use hashi::test_utils;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const RANDOMNESS: vector<u8> = x"0101010101010101010101010101010101010101010101010101010101010101";
const RANDOMNESS2: vector<u8> = x"0202020202020202020202020202020202020202020202020202020202020202";

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
fun test_nonce_cert_is_stamped_with_clock_and_randomness() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    let nonce_cert = hashi::committee::new_committee_signature(epoch, vector[], vector[]);
    hashi::cert_submission::submit_nonce_cert_with_randomness(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        nonce_cert,
        &clock,
        RANDOMNESS,
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
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).submission_randomness(VOTER1) == RANDOMNESS);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_submit_nonce_cert_draws_randomness() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut scenario = sui::test_scenario::begin(@0x0);
    sui::random::create_for_testing(scenario.ctx());
    scenario.next_tx(@0x0);
    let mut random = scenario.take_shared<sui::random::Random>();
    random.update_randomness_state_for_testing(0, RANDOMNESS, scenario.ctx());
    scenario.next_tx(VOTER1);
    let mut hashi = test_utils::create_hashi_with_committee(voters, scenario.ctx());
    let epoch = scenario.ctx().epoch();
    let clock = sui::clock::create_for_testing(scenario.ctx());

    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        &random,
        scenario.ctx(),
    );
    scenario.next_tx(VOTER2);
    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER2,
        vector[4u8, 5, 6],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        &random,
        scenario.ctx(),
    );

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    let certs = hashi.epoch_certs_stamped_ref(nonce_key);
    let drawn = certs.submission_randomness(VOTER1);
    assert!(drawn.length() == 32);
    assert!(drawn != RANDOMNESS);
    assert!(drawn != certs.submission_randomness(VOTER2));

    clock.destroy_for_testing();
    sui::test_scenario::return_shared(random);
    std::unit_test::destroy(hashi);
    scenario.end();
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
        RANDOMNESS,
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

#[test]
#[expected_failure(abort_code = sui::dynamic_field::EFieldTypeMismatch)]
fun test_nonce_cert_into_a_bare_bucket_aborts() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    hashi.epoch_certs(nonce_key, ctx);
    assert!(hashi.cert_bucket_is_bare(nonce_key));

    hashi::cert_submission::submit_nonce_cert_with_randomness(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        RANDOMNESS,
        ctx,
    );

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_stamped_bucket_takes_a_second_writer() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    hashi::cert_submission::submit_nonce_cert_with_randomness(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        RANDOMNESS,
        ctx,
    );

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    assert!(!hashi.cert_bucket_is_bare(nonce_key));
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).num_stamped_certs() == 1);

    clock.set_for_testing(456);
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::cert_submission::submit_nonce_cert_with_randomness(
        &mut hashi,
        epoch,
        0,
        VOTER2,
        vector[4u8, 5, 6],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        RANDOMNESS2,
        ctx2,
    );

    assert!(!hashi.cert_bucket_is_bare(nonce_key));
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).num_stamped_certs() == 2);
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).submission_timestamp_ms(VOTER2) == 456);
    assert!(hashi.epoch_certs_stamped_ref(nonce_key).submission_randomness(VOTER2) == RANDOMNESS2);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
