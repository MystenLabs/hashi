// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_keys_tests;

use hashi::{config_keys, config_registry, config_value, test_utils, update_config};
use sui::{clock::{Self, Clock}, vec_map};

const VOTER1: address = @0x1;

fun setup(ctx: &mut TxContext): hashi::hashi::Hashi {
    test_utils::create_hashi_with_committee(vector[VOTER1], ctx)
}

fun add_key(
    hashi: &mut hashi::hashi::Hashi,
    key: vector<u8>,
    value: config_value::Value,
    updatable: bool,
    removable: bool,
    max: Option<u64>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = config_keys::propose_add(
        hashi,
        VOTER1,
        key.to_string(),
        value,
        false,
        updatable,
        removable,
        option::none(),
        max,
        option::none(),
        vec_map::empty(),
        clock,
        ctx,
    );
    config_keys::execute_add(hashi, proposal_id, clock);
}

fun update_value(
    hashi: &mut hashi::hashi::Hashi,
    key: vector<u8>,
    value: config_value::Value,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = test_utils::create_update_config_proposal(
        hashi,
        VOTER1,
        key,
        value,
        clock,
        ctx,
    );
    update_config::execute(hashi, proposal_id, clock);
}

#[test]
fun test_added_key_is_present_and_updatable() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"example_knob",
        config_value::new_u64(7),
        true,
        true,
        option::some(10),
        &clock,
        ctx,
    );
    assert!(hashi.config().get(b"example_knob").as_u64() == 7);

    update_value(&mut hashi, b"example_knob", config_value::new_u64(9), &clock, ctx);
    assert!(hashi.config().get(b"example_knob").as_u64() == 9);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_keys::EKeyAlreadyExists)]
fun test_add_rejects_existing_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"paused",
        config_value::new_bool(true),
        true,
        false,
        option::none(),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_registry::EWriteOnceMustNotBeRemovable)]
fun test_add_rejects_write_once_removable_spec() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"example_knob",
        config_value::new_u64(7),
        false,
        true,
        option::none(),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_keys::EValueViolatesSpec)]
fun test_add_rejects_value_violating_own_spec() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"example_knob",
        config_value::new_u64(11),
        true,
        true,
        option::some(10),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_update_spec_widens_range_admitting_new_value() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    // Seeded spec caps the nonce protocol at 1 (commit-1 tests pin the
    // rejection of 2); widening the spec is what admits a future protocol.
    let proposal_id = config_keys::propose_update_spec(
        &mut hashi,
        VOTER1,
        b"mpc_nonce_generation_protocol".to_string(),
        true,
        true,
        false,
        option::none(),
        option::some(2),
        option::none(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_update_spec(&mut hashi, proposal_id, &clock);

    update_value(&mut hashi, b"mpc_nonce_generation_protocol", config_value::new_u64(2), &clock, ctx);
    assert!(hashi::mpc_config::nonce_generation_protocol(hashi.config()) == 2);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_registry::EKeyNotRegistered)]
fun test_update_spec_rejects_unregistered_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    let proposal_id = config_keys::propose_update_spec(
        &mut hashi,
        VOTER1,
        b"no_such_key".to_string(),
        false,
        true,
        false,
        option::none(),
        option::none(),
        option::none(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_update_spec(&mut hashi, proposal_id, &clock);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_removed_key_is_gone_and_no_longer_updatable() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"example_knob",
        config_value::new_u64(7),
        true,
        true,
        option::none(),
        &clock,
        ctx,
    );
    let proposal_id = config_keys::propose_remove(
        &mut hashi,
        VOTER1,
        b"example_knob".to_string(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_remove(&mut hashi, proposal_id, &clock);
    assert!(!hashi.config().contains(b"example_knob"));

    update_value(&mut hashi, b"example_knob", config_value::new_u64(9), &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_registry::EKeyNotRemovable)]
fun test_remove_rejects_non_removable_seeded_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    let proposal_id = config_keys::propose_remove(
        &mut hashi,
        VOTER1,
        b"mpc_threshold_in_basis_points".to_string(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_remove(&mut hashi, proposal_id, &clock);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_added_write_once_key_rejects_updates() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    add_key(
        &mut hashi,
        b"example_pin",
        config_value::new_bytes(vector[1, 2, 3]),
        false,
        false,
        option::none(),
        &clock,
        ctx,
    );

    update_value(&mut hashi, b"example_pin", config_value::new_bytes(vector[4]), &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
