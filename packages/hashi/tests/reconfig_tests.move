// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::reconfig_tests;

use hashi::{reconfig, test_utils};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
#[expected_failure(abort_code = reconfig::EGenesisNotAuthorized)]
fun test_genesis_gate_requires_upgrade_cap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_genesis_gate_passes_with_cap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.versioning_mut().set_upgrade_cap(sui::package::test_publish(@0x42.to_id(), ctx));

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_genesis_gate_skipped_after_bootstrap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.committee_set_mut().set_mpc_public_key_for_testing(vector[1]);

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}

fun pending_committee_for_testing(epoch: u64): hashi::committee::Committee {
    use hashi::{committee, mpc_config};
    use sui::bls12381;

    let sk = test_utils::bls_sk_for_testing();
    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let members = vector[
        committee::new_committee_member(VOTER1, public_key, sk, 1),
        committee::new_committee_member(VOTER2, public_key, sk, 1),
        committee::new_committee_member(VOTER3, public_key, sk, 1),
    ];
    committee::new_committee(epoch, members, mpc_config::new_for_testing(3334, 800, 3333, 0, 0))
}

fun cert_message<T: copy + drop + store>(epoch: u64, intent: u16, message: &T): vector<u8> {
    use sui::bcs;

    let mut bytes = bcs::to_bytes(&intent);
    bytes.append(bcs::to_bytes(&epoch));
    bytes.append(bcs::to_bytes(message));
    bytes
}

#[test]
fun test_end_reconfig_stores_committee_handoff() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1, 2, 3];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(0, hashi::intent::committee_transition(), &handoff_message),
        3,
    );

    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, ctx);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, ctx);

    assert!(hashi.committee_set().epoch() == next_epoch);
    assert!(hashi.committee_set().has_committee_handoff_for_testing(0));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_end_reconfig_requires_committee_handoff_after_initial_reconfig() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );

    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EInitialReconfig)]
fun test_submit_committee_handoff_rejects_initial_reconfig() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(0, hashi::intent::committee_transition(), &handoff_message),
        3,
    );

    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_submit_committee_handoff_rejects_handoff_signed_by_wrong_committee() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::committee_transition(), &handoff_message),
        3,
    );

    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, ctx);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, ctx);
    std::unit_test::destroy(hashi);
}
