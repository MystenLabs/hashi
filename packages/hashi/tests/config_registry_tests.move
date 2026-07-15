// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_registry_tests;

use hashi::{config_registry, config_value, test_utils, update_config};
use sui::clock;

const VOTER1: address = @0x1;

// Single-voter committee: proposing auto-votes 100% weight, so execute has
// quorum immediately (the pattern from proposal_tests).
fun setup(ctx: &mut TxContext): hashi::hashi::Hashi {
    test_utils::create_hashi_with_committee(vector[VOTER1], ctx)
}

fun execute_update(
    hashi: &mut hashi::hashi::Hashi,
    key: vector<u8>,
    value: config_value::Value,
    ctx: &mut TxContext,
) {
    let clock = clock::create_for_testing(ctx);
    let proposal_id = test_utils::create_update_config_proposal(
        hashi,
        VOTER1,
        key,
        value,
        &clock,
        ctx,
    );
    update_config::execute(hashi, proposal_id, &clock);
    clock::destroy_for_testing(clock);
}

#[test]
fun test_update_config_valid_update_applies() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(&mut hashi, b"mpc_threshold_in_basis_points", config_value::new_u64(4000), ctx);

    assert!(hashi::mpc_config::threshold_in_basis_points(hashi.config()) == 4000);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_write_once_guardian_btc_public_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    // Key present and registered (as after finish_publish); the registry
    // marks it non-updatable, so governance must not be able to overwrite it.
    hashi.register_launch_keys_for_testing();
    hashi.config_mut().set_guardian_btc_public_key(test_bytes32(1));

    execute_update(
        &mut hashi,
        b"guardian_btc_public_key",
        config_value::new_bytes(test_bytes32(2)),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_write_once_bitcoin_chain_id() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);
    hashi.register_launch_keys_for_testing();
    hashi::btc_config::set_bitcoin_chain_id(hashi.config_mut(), @0x1);

    execute_update(&mut hashi, b"bitcoin_chain_id", config_value::new_address(@0x2), ctx);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_threshold_of_zero() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(&mut hashi, b"mpc_threshold_in_basis_points", config_value::new_u64(0), ctx);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_threshold_above_max_bps() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(
        &mut hashi,
        b"mpc_threshold_in_basis_points",
        config_value::new_u64(10001),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_nonce_protocol_above_max() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(&mut hashi, b"mpc_nonce_generation_protocol", config_value::new_u64(2), ctx);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_emergency_threshold_above_max_bps() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(
        &mut hashi,
        b"governance_emergency_pause_threshold_bps",
        config_value::new_u64(10001),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EInvalidConfigEntry)]
fun test_update_config_rejects_unknown_key() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = setup(ctx);

    execute_update(&mut hashi, b"mpc_threshold_in_basis_pointz", config_value::new_u64(4000), ctx);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = config_registry::EWriteOnceMustNotBeRemovable)]
fun test_new_spec_rejects_write_once_removable() {
    let _spec = config_registry::new_spec(
        false,
        false,
        true,
        option::none(),
        option::none(),
        option::none(),
    );
}

fun test_bytes32(fill: u8): vector<u8> {
    let mut bytes = vector[];
    32u64.do!(|_| bytes.push_back(fill));
    bytes
}
