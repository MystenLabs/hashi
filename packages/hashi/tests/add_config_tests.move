// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// `add_config` semantics: new keys land in exactly the store selected by
/// `epoch`, existing keys abort, epoch keys ride the wholesale pin, and an
/// added key's type is stable under the update proposals.
#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::add_config_tests;

use hashi::{
    add_config::{Self, AddConfig},
    config_value,
    mpc_config,
    test_utils,
    update_config,
    update_epoch_config
};
use sui::{clock, vec_map};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

const NEW_KEY: vector<u8> = b"node_signing_batch_size";
const OTHER_KEY: vector<u8> = b"node_gc_interval_ms";

fun add_and_execute(
    hashi: &mut hashi::hashi::Hashi,
    epoch: bool,
    key: vector<u8>,
    value: config_value::Value,
    clock: &clock::Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = test_utils::create_add_config_proposal(
        hashi,
        VOTER1,
        epoch,
        key,
        value,
        clock,
        ctx,
    );
    add_config::execute(hashi, proposal_id, clock);
}

#[test]
fun test_add_instant_key_is_readable_immediately_and_never_pinned() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, false, NEW_KEY, config_value::new_u64(64), &clock, ctx);

    assert!(hashi.config().get(NEW_KEY).as_u64() == 64);
    assert!(!hashi.epoch_config().contains(NEW_KEY));
    let pinned = *hashi.epoch_config();
    assert!(!pinned.contains(NEW_KEY));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_add_epoch_key_rides_the_wholesale_pin() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, true, NEW_KEY, config_value::new_u64(64), &clock, ctx);

    assert!(hashi.epoch_config().get(NEW_KEY).as_u64() == 64);
    assert!(!hashi.config().contains(NEW_KEY));

    let pinned = *hashi.epoch_config();
    assert!(pinned.get(NEW_KEY).as_u64() == 64);
    // The MPC parameters are still in the snapshot alongside the new key.
    assert!(mpc_config::max_faulty_in_basis_points(&pinned) == 3333);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_add_multiple_keys_in_one_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(NEW_KEY.to_string(), config_value::new_u64(64));
    entries.insert(OTHER_KEY.to_string(), config_value::new_bool(true));
    let proposal_id = add_config::propose(
        &mut hashi,
        VOTER1,
        true,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    add_config::execute(&mut hashi, proposal_id, &clock);

    assert!(hashi.epoch_config().get(NEW_KEY).as_u64() == 64);
    assert!(hashi.epoch_config().get(OTHER_KEY).as_bool());

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// A key name is scoped to its store: adding it to both is two independent
/// entries, each reachable only through its own update proposal.
#[test]
fun test_same_key_may_live_in_both_stores_independently() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, false, NEW_KEY, config_value::new_u64(1), &clock, ctx);
    add_and_execute(&mut hashi, true, NEW_KEY, config_value::new_u64(2), &clock, ctx);

    assert!(hashi.config().get(NEW_KEY).as_u64() == 1);
    assert!(hashi.epoch_config().get(NEW_KEY).as_u64() == 2);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::EKeyAlreadyExists)]
fun test_add_existing_instant_key_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(
        &mut hashi,
        false,
        b"bitcoin_deposit_minimum",
        config_value::new_u64(1),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::EKeyAlreadyExists)]
fun test_add_existing_epoch_key_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(
        &mut hashi,
        true,
        b"mpc_max_faulty_in_basis_points",
        config_value::new_u64(2000),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::EKeyAlreadyExists)]
fun test_add_same_key_twice_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, true, NEW_KEY, config_value::new_u64(64), &clock, ctx);
    add_and_execute(&mut hashi, true, NEW_KEY, config_value::new_u64(65), &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// The retired threshold key can never re-enter the epoch config, not even
/// as a fresh insert.
#[test]
#[expected_failure(abort_code = add_config::EInvalidConfigEntry)]
fun test_add_reserved_threshold_key_to_epoch_config_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(
        &mut hashi,
        true,
        b"mpc_threshold_in_basis_points",
        config_value::new_u64(3334),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::ENoEntriesProvided)]
fun test_empty_entries_aborts_at_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let _ = add_config::propose(
        &mut hashi,
        VOTER1,
        false,
        vec_map::empty(),
        vec_map::empty(),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_added_instant_key_is_updatable_with_the_same_type() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, false, NEW_KEY, config_value::new_u64(64), &clock, ctx);

    let mut entries = vec_map::empty();
    entries.insert(NEW_KEY.to_string(), config_value::new_u64(128));
    let proposal_id = update_config::propose(
        &mut hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi.config().get(NEW_KEY).as_u64() == 128);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_added_key_type_is_fixed_by_its_first_value() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, false, NEW_KEY, config_value::new_u64(64), &clock, ctx);

    let mut entries = vec_map::empty();
    entries.insert(NEW_KEY.to_string(), config_value::new_bool(true));
    let proposal_id = update_config::propose(
        &mut hashi,
        VOTER1,
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
fun test_added_epoch_key_is_updatable_via_update_epoch_config() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(&mut hashi, true, NEW_KEY, config_value::new_u64(64), &clock, ctx);

    let proposal_id = test_utils::create_update_epoch_config_proposal(
        &mut hashi,
        VOTER1,
        NEW_KEY,
        config_value::new_u64(128),
        &clock,
        ctx,
    );
    update_epoch_config::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi.epoch_config().get(NEW_KEY).as_u64() == 128);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_propose_vote_execute_through_quorum() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    let proposal_id = test_utils::create_add_config_proposal(
        &mut hashi,
        VOTER1,
        true,
        NEW_KEY,
        config_value::new_u64(64),
        &clock,
        ctx1,
    );

    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::proposal::vote<AddConfig>(&mut hashi, VOTER2, proposal_id, &clock, ctx2);
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    hashi::proposal::vote<AddConfig>(&mut hashi, VOTER3, proposal_id, &clock, ctx3);

    add_config::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi.epoch_config().get(NEW_KEY).as_u64() == 64);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::EProtectedConfigKey)]
/// A pinned key name cannot be introduced into the epoch store.
fun test_pinned_key_cannot_be_added_to_epoch_store() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(
        &mut hashi,
        true,
        b"guardian_btc_public_key",
        config_value::new_bytes(vector::tabulate!(32, |i| i as u8)),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = add_config::EProtectedConfigKey)]
/// Nor into the instant store, where it would otherwise abort as an existing
/// key: the pinned-key rule is checked first.
fun test_pinned_key_cannot_be_added_to_instant_store() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    add_and_execute(
        &mut hashi,
        false,
        b"bitcoin_chain_id",
        config_value::new_bytes(vector::tabulate!(32, |i| i as u8)),
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
