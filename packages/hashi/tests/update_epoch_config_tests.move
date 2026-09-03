// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// `update_epoch_config` semantics on the epoch config: the MPC parameters
/// are tuned here (with range validation), batches apply atomically, unknown
/// keys and type changes abort, and `pin` normalizes then snapshots the store.
#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::update_epoch_config_tests;

use hashi::{config_value, mpc_config, test_utils, update_epoch_config};
use sui::{clock, vec_map};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

const MAX_BPS: u64 = 10000;
const MAX_FAULTY_BPS: u64 = 3333;
const DEFAULT_MAX_FAULTY_BPS: u64 = 3333;
const MAX_NONCE_ACCUMULATION_WINDOW_MS: u64 = 10000;

fun mpc_max_faulty_key(): std::string::String {
    b"mpc_max_faulty_in_basis_points".to_string()
}

fun mpc_allowed_delta_key(): std::string::String {
    b"mpc_weight_reduction_allowed_delta".to_string()
}

fun mpc_nonce_generation_protocol_key(): std::string::String {
    b"mpc_nonce_generation_protocol".to_string()
}

fun mpc_nonce_accumulation_window_key(): std::string::String {
    b"mpc_nonce_accumulation_window_ms".to_string()
}

fun propose_and_execute(
    hashi: &mut hashi::hashi::Hashi,
    entries: vec_map::VecMap<std::string::String, config_value::Value>,
    clock: &clock::Clock,
    ctx: &mut TxContext,
) {
    let proposal_id = update_epoch_config::propose(
        hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        clock,
        ctx,
    );
    update_epoch_config::execute(hashi, proposal_id, clock);
}

fun reject_single(key: std::string::String, value: config_value::Value) {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(key, value);
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_single_key_update() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 3333);

    let mut entries = vec_map::empty();
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 2000);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == 800);
    // Seeded by init_defaults and untouched by the update above.
    assert!(mpc_config::nonce_generation_protocol(hashi.epoch_config()) == 0);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_update_nonce_generation_protocol() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    assert!(mpc_config::nonce_generation_protocol(hashi.epoch_config()) == 0);

    let mut entries = vec_map::empty();
    entries.insert(mpc_nonce_generation_protocol_key(), config_value::new_u64(1));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(mpc_config::nonce_generation_protocol(hashi.epoch_config()) == 1);
    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 3333);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_multi_key_update_applies_atomically() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));
    entries.insert(mpc_allowed_delta_key(), config_value::new_u64(1500));
    entries.insert(mpc_nonce_accumulation_window_key(), config_value::new_u64(5000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 2000);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == 1500);
    assert!(mpc_config::nonce_accumulation_window_ms(hashi.epoch_config()) == 5000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_epoch_update_never_touches_the_instant_config() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(!hashi.config().contains(b"mpc_max_faulty_in_basis_points"));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_epoch_config::ENoEntriesProvided)]
fun test_empty_entries_aborts_at_propose() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let _ = update_epoch_config::propose(
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
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_unknown_key_aborts_at_execute() {
    reject_single(b"does_not_exist".to_string(), config_value::new_u64(42));
}

/// Instant keys are not reachable through the epoch store.
#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_instant_key_aborts_at_execute() {
    reject_single(b"bitcoin_deposit_minimum".to_string(), config_value::new_u64(50_000));
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_wrong_value_type_aborts_at_execute() {
    reject_single(mpc_max_faulty_key(), config_value::new_bool(true));
}

#[test]
fun test_propose_vote_execute_through_quorum() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    let mut entries = vec_map::empty();
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(2000));
    entries.insert(mpc_allowed_delta_key(), config_value::new_u64(1500));

    let proposal_id = update_epoch_config::propose(
        &mut hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        &clock,
        ctx1,
    );

    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    hashi::proposal::vote<update_epoch_config::UpdateEpochConfig>(
        &mut hashi,
        VOTER2,
        proposal_id,
        &clock,
        ctx2,
    );

    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    hashi::proposal::vote<update_epoch_config::UpdateEpochConfig>(
        &mut hashi,
        VOTER3,
        proposal_id,
        &clock,
        ctx3,
    );

    update_epoch_config::execute(&mut hashi, proposal_id, &clock);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 2000);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == 1500);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_max_faulty_above_max() {
    reject_single(mpc_max_faulty_key(), config_value::new_u64(MAX_FAULTY_BPS + 1));
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_allowed_delta_above_max() {
    reject_single(mpc_allowed_delta_key(), config_value::new_u64(MAX_BPS + 1));
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_nonce_protocol_above_one() {
    reject_single(mpc_nonce_generation_protocol_key(), config_value::new_u64(2));
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_nonce_window_above_max() {
    reject_single(
        mpc_nonce_accumulation_window_key(),
        config_value::new_u64(MAX_NONCE_ACCUMULATION_WINDOW_MS + 1),
    );
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_max_faulty_zero() {
    reject_single(mpc_max_faulty_key(), config_value::new_u64(0));
}

/// Max-faulty at its cap and the delta one below it: the largest pair the
/// per-entry ranges and the cross-key rule both accept.
#[test]
fun test_accept_upper_boundary_values() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(MAX_FAULTY_BPS));
    entries.insert(mpc_allowed_delta_key(), config_value::new_u64(MAX_FAULTY_BPS - 1));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == MAX_FAULTY_BPS);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == MAX_FAULTY_BPS - 1);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_batch_with_out_of_range_entry_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(mpc_allowed_delta_key(), config_value::new_u64(1500));
    entries.insert(mpc_max_faulty_key(), config_value::new_u64(MAX_BPS + 1));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// The retired threshold key is rejected even when a test has planted it,
/// so it can never be tuned back into a pinned config.
#[test]
#[expected_failure(abort_code = update_epoch_config::EInvalidConfigEntry)]
fun test_reject_removed_threshold_key_even_when_present() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    hashi.epoch_config_mut().upsert(b"mpc_threshold_in_basis_points", config_value::new_u64(3334));

    let mut entries = vec_map::empty();
    entries.insert(b"mpc_threshold_in_basis_points".to_string(), config_value::new_u64(5200));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// The per-entry range checks cannot see the cross-key rule (the delta must
/// stay below max-faulty), so it is enforced on the store a proposal leaves
/// behind: lowering max-faulty to the current delta is refused.
#[test]
#[expected_failure(abort_code = update_epoch_config::EInconsistentMpcConfig)]
fun test_reject_max_faulty_at_or_below_delta() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == 800);

    let mut entries = vec_map::empty();
    entries.insert(b"mpc_max_faulty_in_basis_points".to_string(), config_value::new_u64(800));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EInconsistentMpcConfig)]
fun test_reject_delta_at_or_above_max_faulty() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);
    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == DEFAULT_MAX_FAULTY_BPS);

    let mut entries = vec_map::empty();
    entries.insert(
        b"mpc_weight_reduction_allowed_delta".to_string(),
        config_value::new_u64(DEFAULT_MAX_FAULTY_BPS),
    );
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

/// Both coupled keys may drop below the other's old value in one proposal:
/// the rule is judged on the resulting store, not per entry, so the entry
/// order (max-faulty first here, while the old delta still exceeds it) does
/// not matter.
#[test]
fun test_joint_update_of_both_coupled_keys_is_judged_on_the_result() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    let clock = clock::create_for_testing(ctx);

    let mut entries = vec_map::empty();
    entries.insert(b"mpc_max_faulty_in_basis_points".to_string(), config_value::new_u64(500));
    entries.insert(b"mpc_weight_reduction_allowed_delta".to_string(), config_value::new_u64(400));
    propose_and_execute(&mut hashi, entries, &clock, ctx);

    assert!(mpc_config::max_faulty_in_basis_points(hashi.epoch_config()) == 500);
    assert!(mpc_config::weight_reduction_allowed_delta(hashi.epoch_config()) == 400);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_epoch_config::EProtectedConfigKey)]
/// The keys the package pins for the deployment's lifetime are refused on the
/// epoch path too, before the store is even consulted.
fun test_pinned_key_is_refused() {
    reject_single(
        b"guardian_btc_public_key".to_string(),
        config_value::new_bytes(vector::tabulate!(32, |i| i as u8)),
    );
}
