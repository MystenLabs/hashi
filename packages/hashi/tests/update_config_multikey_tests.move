// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// `update_config` semantics on the instant config: multi-key batches apply
/// atomically, unknown keys and type changes abort, and the MPC parameters
/// (which live in the epoch config) are not reachable from here.
#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::update_config_multikey_tests;

use hashi::{btc_config, config_value, test_utils, update_config};
use sui::{clock, vec_map};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

fun deposit_minimum_key(): std::string::String {
    b"bitcoin_deposit_minimum".to_string()
}

fun withdrawal_minimum_key(): std::string::String {
    b"bitcoin_withdrawal_minimum".to_string()
}

fun propose_and_execute(
    hashi: &mut hashi::hashi::Hashi,
    entries: vec_map::VecMap<std::string::String, config_value::Value>,
    clock: &clock::Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = update_config::propose(
        hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        clock,
        ctx,
    );
    update_config::execute(hashi, proposal_id, clock);
}

#[test]
fun test_single_key_update_via_multikey_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 30_000);

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);
    // Untouched by the update above.
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 30_000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_multi_key_update_applies_atomically() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    entries.insert(withdrawal_minimum_key(), config_value::new_u64(60_000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 60_000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_instant_update_never_touches_the_epoch_config() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(!hashi.epoch_config().contains(b"bitcoin_deposit_minimum"));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::ENoEntriesProvided)]
fun test_empty_entries_aborts_at_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let _ = update_config::propose(
        &mut hashi,
        VOTER1,
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
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(b"does_not_exist".to_string(), config_value::new_u64(42));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// The MPC parameters live in the epoch config; naming one here is an
/// unknown key for the instant store, not a silent no-op.
#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_mpc_key_aborts_at_execute() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(b"mpc_max_faulty_in_basis_points".to_string(), config_value::new_u64(2000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_wrong_value_type_aborts_at_execute() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_bool(true));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_batch_with_unknown_entry_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    entries.insert(b"does_not_exist".to_string(), config_value::new_u64(42));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

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
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    entries.insert(withdrawal_minimum_key(), config_value::new_u64(60_000));

    let proposal_id = update_config::propose(
        &mut hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        &clock,
        ctx1,
    );

    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::proposal::vote<update_config::UpdateConfig>(
        &mut hashi,
        VOTER2,
        proposal_id,
        &clock,
        ctx2,
    );

    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    hashi::proposal::vote<update_config::UpdateConfig>(
        &mut hashi,
        VOTER3,
        proposal_id,
        &clock,
        ctx3,
    );

    update_config::execute(&mut hashi, proposal_id, &clock);

    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 60_000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
