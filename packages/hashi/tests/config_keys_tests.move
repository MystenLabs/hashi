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

fun schedule(
    hashi: &mut hashi::hashi::Hashi,
    key: vector<u8>,
    value: config_value::Value,
    activate_at_epoch: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = config_keys::propose_schedule(
        hashi,
        VOTER1,
        key.to_string(),
        value,
        activate_at_epoch,
        vec_map::empty(),
        clock,
        ctx,
    );
    config_keys::execute_schedule(hashi, proposal_id, clock);
}

#[test]
fun test_schedule_commits_exactly_at_activation_epoch() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"mpc_nonce_generation_protocol", config_value::new_u64(1), 2, &clock, ctx);
    assert!(hashi.pending_config_updates().size() == 1);

    hashi.commit_pending_config_updates(1);
    assert!(hashi::mpc_config::nonce_generation_protocol(hashi.config()) == 0);
    assert!(hashi.pending_config_updates().size() == 1);

    hashi.commit_pending_config_updates(2);
    assert!(hashi::mpc_config::nonce_generation_protocol(hashi.config()) == 1);
    assert!(hashi.pending_config_updates().size() == 0);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_schedule_replaces_on_repropose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"mpc_threshold_in_basis_points", config_value::new_u64(4000), 2, &clock, ctx);
    schedule(&mut hashi, b"mpc_threshold_in_basis_points", config_value::new_u64(5000), 3, &clock, ctx);
    assert!(hashi.pending_config_updates().size() == 1);

    hashi.commit_pending_config_updates(2);
    assert!(hashi::mpc_config::threshold_in_basis_points(hashi.config()) == 3334);

    hashi.commit_pending_config_updates(3);
    assert!(hashi::mpc_config::threshold_in_basis_points(hashi.config()) == 5000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_keys::ENotPinnedKey)]
fun test_schedule_rejects_non_pinned_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"bitcoin_deposit_minimum", config_value::new_u64(40_000), 2, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_keys::EActivationNotInFuture)]
fun test_schedule_rejects_activation_at_current_epoch() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"mpc_nonce_generation_protocol", config_value::new_u64(1), 0, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_keys::EInvalidScheduledEntry)]
fun test_schedule_rejects_out_of_range_value() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"mpc_nonce_generation_protocol", config_value::new_u64(5), 2, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_commit_drops_entry_invalidated_by_later_spec_narrowing() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    schedule(&mut hashi, b"mpc_threshold_in_basis_points", config_value::new_u64(9000), 2, &clock, ctx);
    let proposal_id = config_keys::propose_update_spec(
        &mut hashi,
        VOTER1,
        b"mpc_threshold_in_basis_points".to_string(),
        true,
        true,
        false,
        option::some(1),
        option::some(5000),
        option::none(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_update_spec(&mut hashi, proposal_id, &clock);

    hashi.commit_pending_config_updates(2);

    // Fail closed toward the narrowed spec: dropped, not applied.
    assert!(hashi::mpc_config::threshold_in_basis_points(hashi.config()) == 3334);
    assert!(hashi.pending_config_updates().size() == 0);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_remove_clears_pending_schedule() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    let clock = clock::create_for_testing(ctx);

    let proposal_id = config_keys::propose_add(
        &mut hashi,
        VOTER1,
        b"example_knob".to_string(),
        config_value::new_u64(7),
        true,
        true,
        true,
        option::none(),
        option::none(),
        option::none(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_add(&mut hashi, proposal_id, &clock);
    schedule(&mut hashi, b"example_knob", config_value::new_u64(9), 2, &clock, ctx);

    let proposal_id = config_keys::propose_remove(
        &mut hashi,
        VOTER1,
        b"example_knob".to_string(),
        vec_map::empty(),
        &clock,
        ctx,
    );
    config_keys::execute_remove(&mut hashi, proposal_id, &clock);

    assert!(hashi.pending_config_updates().size() == 0);
    hashi.commit_pending_config_updates(2);
    assert!(!hashi.config().contains(b"example_knob"));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
