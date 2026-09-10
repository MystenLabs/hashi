// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::tls_key_registration_tests;

use hashi::{committee_set, test_utils};

const VALIDATOR1: address = @0x1;
const VALIDATOR2: address = @0x2;
const VALIDATOR3: address = @0x3;
const STRANGER: address = @0x999;

const KEY_A: vector<u8> = x"1111111111111111111111111111111111111111111111111111111111111111";
const KEY_B: vector<u8> = x"2222222222222222222222222222222222222222222222222222222222222222";

const POP_HASHI_ID: address = @0xabababababababababababababababababababababababababababababababab;
const POP_ADDRESS: address = @0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd;
const POP_PUBLIC_KEY: vector<u8> =
    x"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const POP_SIGNATURE: vector<u8> =
    x"440c4f5d01b811edf09afc277eebbcfff5f6c732887dd8ea4acf3aa54119a3dbc24255993e8074390b3c43aa256ab5c47750322ec1f07696a6f1339454a7cc0d";

#[test]
fun test_proof_of_possession_verifies_against_rust_vectors() {
    assert!(
        committee_set::verify_tls_proof_of_possession(
            POP_HASHI_ID,
            &POP_ADDRESS,
            &POP_PUBLIC_KEY,
            &POP_SIGNATURE,
        ),
    );
}

#[test]
fun test_proof_of_possession_is_bound_to_key_address_and_deployment() {
    assert!(
        !committee_set::verify_tls_proof_of_possession(
            POP_HASHI_ID,
            &POP_ADDRESS,
            &KEY_A,
            &POP_SIGNATURE,
        ),
    );
    assert!(
        !committee_set::verify_tls_proof_of_possession(
            POP_HASHI_ID,
            &VALIDATOR1,
            &POP_PUBLIC_KEY,
            &POP_SIGNATURE,
        ),
    );
    assert!(
        !committee_set::verify_tls_proof_of_possession(
            @0xdead,
            &POP_ADDRESS,
            &POP_PUBLIC_KEY,
            &POP_SIGNATURE,
        ),
    );
}

#[test]
fun test_setter_accepts_a_valid_proof() {
    let ctx = &mut test_utils::new_tx_context(POP_ADDRESS, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[POP_ADDRESS, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c = &test_utils::new_tx_context(POP_ADDRESS, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key(keys, POP_HASHI_ID, POP_ADDRESS, POP_PUBLIC_KEY, POP_SIGNATURE, c);

    let (_, keys) = hashi.committee_set_and_tls_keys_mut();
    assert!(
        committee_set::tls_key_holder_for_testing(keys, POP_PUBLIC_KEY)
            == option::some(POP_ADDRESS),
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = committee_set::EInvalidTlsProofOfPossession)]
fun test_setter_rejects_a_proof_for_another_deployment() {
    let ctx = &mut test_utils::new_tx_context(POP_ADDRESS, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[POP_ADDRESS, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c = &test_utils::new_tx_context(POP_ADDRESS, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key(keys, @0xdead, POP_ADDRESS, POP_PUBLIC_KEY, POP_SIGNATURE, c);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = committee_set::EInvalidTlsPublicKeyLength)]
fun test_setter_rejects_a_key_of_the_wrong_length() {
    let ctx = &mut test_utils::new_tx_context(POP_ADDRESS, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[POP_ADDRESS, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c = &test_utils::new_tx_context(POP_ADDRESS, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key(keys, POP_HASHI_ID, POP_ADDRESS, x"1122", POP_SIGNATURE, c);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = committee_set::ENotAuthorized)]
fun test_setter_rejects_an_unauthorized_sender() {
    let ctx = &mut test_utils::new_tx_context(POP_ADDRESS, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[POP_ADDRESS, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c = &test_utils::new_tx_context(STRANGER, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key(keys, POP_HASHI_ID, POP_ADDRESS, POP_PUBLIC_KEY, POP_SIGNATURE, c);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = committee_set::ETlsPublicKeyInUse)]
fun test_second_member_cannot_take_a_registered_key() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[VALIDATOR1, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_A, c1);

    let c2 = &test_utils::new_tx_context(VALIDATOR2, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR2, KEY_A, c2);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_reregistering_own_key_is_a_noop() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[VALIDATOR1, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_A, c1);

    let c2 = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_A, c2);

    let (_, keys) = hashi.committee_set_and_tls_keys_mut();
    assert!(committee_set::tls_key_holder_for_testing(keys, KEY_A) == option::some(VALIDATOR1));

    std::unit_test::destroy(hashi);
}

#[test]
fun test_rotating_frees_the_previous_key() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(
        vector[VALIDATOR1, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_A, c1);

    let c1b = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_B, c1b);

    let c2 = &test_utils::new_tx_context(VALIDATOR2, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR2, KEY_A, c2);

    let (_, keys) = hashi.committee_set_and_tls_keys_mut();
    assert!(committee_set::tls_key_holder_for_testing(keys, KEY_A) == option::some(VALIDATOR2));
    assert!(committee_set::tls_key_holder_for_testing(keys, KEY_B) == option::some(VALIDATOR1));

    std::unit_test::destroy(hashi);
}

#[test]
fun test_removing_a_member_frees_its_key() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VALIDATOR1, VALIDATOR2],
        vector[VALIDATOR1, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    let c3 = &test_utils::new_tx_context(VALIDATOR3, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR3, KEY_A, c3);

    hashi::validator::remove_inactive_member_for_testing(&mut hashi, VALIDATOR3, false);

    let (_, keys) = hashi.committee_set_and_tls_keys_mut();
    assert!(committee_set::tls_key_holder_for_testing(keys, KEY_A) == option::none());

    let c1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    let (cs, keys) = hashi.committee_set_and_tls_keys_mut();
    cs.set_tls_public_key_unproven_for_testing(keys, VALIDATOR1, KEY_A, c1);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_removing_a_member_that_never_set_a_key_does_not_abort() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VALIDATOR1, VALIDATOR2],
        vector[VALIDATOR1, VALIDATOR2, VALIDATOR3],
        ctx,
    );

    hashi::validator::remove_inactive_member_for_testing(&mut hashi, VALIDATOR3, false);

    assert!(!hashi.committee_set().has_member(VALIDATOR3));

    std::unit_test::destroy(hashi);
}
