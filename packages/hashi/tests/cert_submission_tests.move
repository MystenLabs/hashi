// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::cert_submission_tests;

use hashi::test_utils;
use std::bcs;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const VOTER4: address = @0x4;
const DIGEST: vector<u8> = x"d1d1";
const OTHER_DIGEST: vector<u8> = x"d2d2";
const SEED_1: vector<u8> = x"0101";
const SEED_2: vector<u8> = x"0202";
const RANDOMNESS_SEED: vector<u8> =
    x"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";

#[test]
fun test_dkg_and_rotation_certs_use_separate_buckets() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch() + 1;
    set_pending_committee(&mut hashi, epoch, voters);
    let clock = sui::clock::create_for_testing(ctx);

    let rot_cert = hashi::committee::new_committee_signature(epoch, vector[], vector[]);
    hashi::cert_submission::submit_rotation_cert(
        &mut hashi,
        epoch,
        VOTER1,
        vector[1u8, 2, 3],
        rot_cert,
        &clock,
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
        &clock,
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

    clock.destroy_for_testing();
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
    assert!(hashi.epoch_certs_ref(nonce_key).num_certs() == 1);
    assert!(hashi.epoch_certs_ref(nonce_key).submission_timestamp_ms(VOTER1) == 123);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_dkg_and_rotation_certs_are_stamped_with_clock() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch() + 1;
    set_pending_committee(&mut hashi, epoch, voters);
    let mut clock = sui::clock::create_for_testing(ctx);

    clock.set_for_testing(123);
    hashi::cert_submission::submit_dkg_cert(
        &mut hashi,
        epoch,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    clock.set_for_testing(456);
    let ctx2 = &mut sui::tx_context::new_from_hint(VOTER2, 1, 0, 0, 0);
    hashi::cert_submission::submit_rotation_cert(
        &mut hashi,
        epoch,
        VOTER2,
        vector[4u8, 5, 6],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx2,
    );

    let dkg_key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg());
    let rot_key = hashi::tob::tob_key(
        epoch,
        option::none(),
        hashi::tob::protocol_type_key_rotation(),
    );
    assert!(hashi.epoch_certs_ref(dkg_key).submission_timestamp_ms(VOTER1) == 123);
    assert!(hashi.epoch_certs_ref(rot_key).submission_timestamp_ms(VOTER2) == 456);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_rotation_cert_from_a_departing_dealer_is_accepted() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VOTER1, VOTER2, VOTER3],
        vector[VOTER1, VOTER2, VOTER3, VOTER4],
        ctx,
    );
    let epoch = ctx.epoch() + 1;
    set_pending_committee(&mut hashi, epoch, vector[VOTER2, VOTER3, VOTER4]);
    let clock = sui::clock::create_for_testing(ctx);

    hashi::cert_submission::submit_rotation_cert(
        &mut hashi,
        epoch,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    let rot_key = hashi::tob::tob_key(
        epoch,
        option::none(),
        hashi::tob::protocol_type_key_rotation(),
    );
    assert!(hashi.epoch_certs_ref(rot_key).num_certs() == 1);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::cert_submission::EDealerNotInCommittee)]
fun test_nonce_cert_from_a_member_outside_the_committee_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER4, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VOTER1, VOTER2, VOTER3],
        vector[VOTER1, VOTER2, VOTER3, VOTER4],
        ctx,
    );
    let epoch = ctx.epoch();
    let clock = sui::clock::create_for_testing(ctx);

    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER4,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// First submission wins: a dealer's second submission changes neither the
/// stored certificate count nor the timestamp recorded by the first.
#[test]
fun test_resubmission_keeps_the_first_cert_and_timestamp() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    clock.set_for_testing(456);
    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[4u8, 5, 6],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    assert!(hashi.epoch_certs_ref(nonce_key).num_certs() == 1);
    assert!(hashi.epoch_certs_ref(nonce_key).submission_timestamp_ms(VOTER1) == 123);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_destroy_all_drains_nonce_bucket() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut bucket = hashi::tob::create(
        0,
        hashi::tob::protocol_type_nonce_generation(),
        ctx,
    );
    let sig = hashi::committee::new_committee_signature(0, vector[], vector[]);
    hashi::tob::submit_cert_with_signature(
        &mut bucket,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        &sig,
        123,
    );
    assert!(bucket.num_certs() == 1);
    hashi::tob::destroy_all(bucket, 2);
}

#[test]
#[expected_failure(abort_code = hashi::tob::ETooEarlyToDestroy)]
fun test_destroy_all_before_two_epochs_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let bucket = hashi::tob::create(0, hashi::tob::protocol_type_nonce_generation(), ctx);
    hashi::tob::destroy_all(bucket, 1);
}

#[test]
#[expected_failure(abort_code = hashi::tob::EWrongEpoch)]
fun test_submit_to_a_bucket_of_another_epoch_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut bucket = hashi::tob::create(0, hashi::tob::protocol_type_dkg(), ctx);
    let sig = hashi::committee::new_committee_signature(1, vector[], vector[]);
    hashi::tob::submit_cert_with_signature(&mut bucket, 1, VOTER1, vector[1u8, 2, 3], &sig, 123);

    abort
}

#[test]
fun test_nonce_bucket_takes_a_second_writer() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let mut clock = sui::clock::create_for_testing(ctx);
    clock.set_for_testing(123);

    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx,
    );

    let nonce_key = hashi::tob::tob_key(
        epoch,
        option::some(0),
        hashi::tob::protocol_type_nonce_generation(),
    );
    assert!(hashi.epoch_certs_ref(nonce_key).num_certs() == 1);

    clock.set_for_testing(456);
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::cert_submission::submit_nonce_cert(
        &mut hashi,
        epoch,
        0,
        VOTER2,
        vector[4u8, 5, 6],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        &clock,
        ctx2,
    );

    assert!(hashi.epoch_certs_ref(nonce_key).num_certs() == 2);
    assert!(hashi.epoch_certs_ref(nonce_key).submission_timestamp_ms(VOTER1) == 123);
    assert!(hashi.epoch_certs_ref(nonce_key).submission_timestamp_ms(VOTER2) == 456);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

fun build_cert_message<T: copy + drop + store>(
    hashi_id: address,
    epoch: u64,
    intent: u16,
    message: &T,
): vector<u8> {
    let mut bytes = bcs::to_bytes(&intent);
    bytes.append(bcs::to_bytes(&hashi_id));
    bytes.append(bcs::to_bytes(&epoch));
    bytes.append(bcs::to_bytes(message));
    bytes
}

fun set_pending_committee(hashi: &mut hashi::hashi::Hashi, epoch: u64, voters: vector<address>) {
    let sk = test_utils::bls_sk_for_testing();
    let public_key = sui::bls12381::g1_to_uncompressed_g1(
        &sui::bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let members = voters.map!(
        |voter| hashi::committee::new_committee_member(voter, public_key, sk, 1),
    );
    hashi
        .committee_set_mut()
        .set_pending_reconfig_for_testing(
            hashi::committee::new_committee(
                epoch,
                members,
                hashi::mpc_config::new_for_testing(800, 3333, 0),
            ),
        );
}

fun nonce_key(epoch: u64): hashi::tob::TobKey {
    hashi::tob::tob_key(epoch, option::some(0), hashi::tob::protocol_type_nonce_generation())
}

fun submit_one_nonce_cert(
    hashi: &mut hashi::hashi::Hashi,
    epoch: u64,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    hashi::cert_submission::submit_nonce_cert(
        hashi,
        epoch,
        0,
        VOTER1,
        vector[1u8, 2, 3],
        hashi::committee::new_committee_signature(epoch, vector[], vector[]),
        clock,
        ctx,
    );
}

fun presig_dealer_set_cert(
    hashi: &hashi::hashi::Hashi,
    epoch: u64,
    digest: vector<u8>,
): hashi::committee::CommitteeSignature {
    let message = hashi::cert_submission::new_presig_dealer_set_message(epoch, 0, digest);
    let bytes = build_cert_message(
        object::id_address(hashi),
        epoch,
        hashi::intent::presig_dealer_set(),
        &message,
    );
    test_utils::sign_certificate(epoch, &bytes, 3)
}

#[test]
fun test_only_the_first_presig_dealer_set_seals_the_batch() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let clock = sui::clock::create_for_testing(ctx);
    submit_one_nonce_cert(&mut hashi, epoch, &clock, ctx);

    let first = presig_dealer_set_cert(&hashi, epoch, DIGEST);
    hashi::cert_submission::submit_presig_dealer_set_for_testing(
        &mut hashi,
        0,
        DIGEST,
        first,
        SEED_1,
    );
    let second = presig_dealer_set_cert(&hashi, epoch, OTHER_DIGEST);
    hashi::cert_submission::submit_presig_dealer_set_for_testing(
        &mut hashi,
        0,
        OTHER_DIGEST,
        second,
        SEED_2,
    );

    let bucket = hashi.epoch_certs_ref(nonce_key(epoch));
    assert!(
        bucket.seal_randomness() == sui::random::new_generator_from_seed_for_testing(SEED_1).generate_bytes(32),
    );
    assert!(bucket.seal_dealer_set_digest() == DIGEST);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee::ESigVerification)]
fun test_presig_dealer_set_with_a_bad_certificate_aborts() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let epoch = ctx.epoch();
    let clock = sui::clock::create_for_testing(ctx);
    submit_one_nonce_cert(&mut hashi, epoch, &clock, ctx);

    let wrong = test_utils::sign_certificate(epoch, &bcs::to_bytes(&epoch), 3);
    hashi::cert_submission::submit_presig_dealer_set_for_testing(
        &mut hashi,
        0,
        DIGEST,
        wrong,
        SEED_1,
    );

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_submit_presig_dealer_set_draws_randomness() {
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut scenario = sui::test_scenario::begin(@0x0);
    sui::random::create_for_testing(scenario.ctx());
    scenario.next_tx(@0x0);
    let mut random = scenario.take_shared<sui::random::Random>();
    random.update_randomness_state_for_testing(0, RANDOMNESS_SEED, scenario.ctx());
    scenario.next_tx(VOTER1);
    let mut hashi = test_utils::create_hashi_with_committee(voters, scenario.ctx());
    let epoch = scenario.ctx().epoch();
    let clock = sui::clock::create_for_testing(scenario.ctx());
    submit_one_nonce_cert(&mut hashi, epoch, &clock, scenario.ctx());

    let cert = presig_dealer_set_cert(&hashi, epoch, DIGEST);
    hashi::cert_submission::submit_presig_dealer_set(
        &mut hashi,
        0,
        DIGEST,
        cert,
        &random,
        scenario.ctx(),
    );

    let drawn = hashi.epoch_certs_ref(nonce_key(epoch)).seal_randomness();
    assert!(drawn.length() == 32);
    assert!(drawn != RANDOMNESS_SEED);

    clock.destroy_for_testing();
    sui::test_scenario::return_shared(random);
    std::unit_test::destroy(hashi);
    scenario.end();
}
