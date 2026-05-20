// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::update_config_multikey_tests;

use hashi::{config_value, mpc_config, test_utils, update_config};
use sui::{clock, vec_map};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

fun mpc_threshold_key(): std::string::String {
    b"mpc_threshold_in_basis_points".to_string()
}

fun mpc_max_faulty_key(): std::string::String {
    b"mpc_max_faulty_in_basis_points".to_string()
}

fun mpc_allowed_delta_key(): std::string::String {
    b"mpc_weight_reduction_allowed_delta".to_string()
}

#[test]
fun test_single_key_update_via_multikey_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    assert!(mpc_config::threshold_in_basis_points(hashi.config()) == 3334);

    let mut entries = vec_map::empty();
    entries.insert(mpc_threshold_key(), config_value::new_u64(5200));

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);

    assert!(mpc_config::threshold_in_basis_points(hashi.config()) == 5200);
    assert!(mpc_config::max_faulty_in_basis_points(hashi.config()) == 3333);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.config()) == 800);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_multi_key_update_applies_atomically() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_threshold_key(), config_value::new_u64(5200));
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));
    entries.insert(mpc_allowed_delta_key(), config_value::new_u64(1500));

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);

    assert!(mpc_config::threshold_in_basis_points(hashi.config()) == 5200);
    assert!(mpc_config::max_faulty_in_basis_points(hashi.config()) == 2000);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.config()) == 1500);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_mixed_domain_multi_key_update() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_threshold_key(), config_value::new_u64(5200));
    entries.insert(
        b"bitcoin_deposit_minimum".to_string(),
        config_value::new_u64(50_000),
    );

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);

    assert!(mpc_config::threshold_in_basis_points(hashi.config()) == 5200);
    assert!(hashi::btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::ENoEntriesProvided)]
fun test_empty_entries_aborts_at_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let _ = update_config::propose(
        &mut hashi,
        vec_map::empty(),
        vec_map::empty(),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_unknown_key_aborts_at_execute() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(b"does_not_exist".to_string(), config_value::new_u64(42));

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_wrong_value_type_aborts_at_execute() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // mpc_threshold_in_basis_points is u64; passing a bool should be rejected.
    let mut entries = vec_map::empty();
    entries.insert(mpc_threshold_key(), config_value::new_bool(true));

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_propose_vote_execute_through_quorum() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    let mut entries = vec_map::empty();
    entries.insert(mpc_threshold_key(), config_value::new_u64(5200));
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));

    let proposal_id = update_config::propose(
        &mut hashi,
        entries,
        vec_map::empty(),
        &clock,
        ctx1,
    );

    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::proposal::vote<update_config::UpdateConfig>(&mut hashi, proposal_id, &clock, ctx2);

    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    hashi::proposal::vote<update_config::UpdateConfig>(&mut hashi, proposal_id, &clock, ctx3);

    update_config::execute(&mut hashi, proposal_id, &clock);

    assert!(mpc_config::threshold_in_basis_points(hashi.config()) == 5200);
    assert!(mpc_config::max_faulty_in_basis_points(hashi.config()) == 2000);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.config()) == 800);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
