// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Keys the `UpdateConfig` governance path refuses to write.
#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::update_config_protected_keys_tests;

use hashi::{
    btc_config,
    config,
    config_value::{Self, Value},
    hashi::Hashi,
    test_utils,
    update_config
};
use std::string::String;
use sui::{clock, vec_map::{Self, VecMap}};

const VOTER1: address = @0x1;

fun guardian_btc_public_key_key(): String { b"guardian_btc_public_key".to_string() }

fun guardian_url_key(): String { b"guardian_url".to_string() }

fun bitcoin_chain_id_key(): String { b"bitcoin_chain_id".to_string() }

fun deposit_minimum_key(): String { b"bitcoin_deposit_minimum".to_string() }

fun new_hashi(ctx: &mut TxContext): Hashi {
    test_utils::create_hashi_with_committee(vector[VOTER1], ctx)
}

fun single(key: String, value: Value): VecMap<String, Value> {
    let mut entries = vec_map::empty();
    entries.insert(key, value);
    entries
}

/// Proposes `entries` from the single-member committee (whose creator vote
/// meets quorum) and executes the proposal.
fun propose_and_execute(hashi: &mut Hashi, entries: VecMap<String, Value>, ctx: &mut TxContext) {
    let clock = clock::create_for_testing(ctx);
    let proposal_id = update_config::propose(
        hashi,
        VOTER1,
        entries,
        vec_map::empty(),
        &clock,
        ctx,
    );
    update_config::execute(hashi, proposal_id, &clock);
    clock::destroy_for_testing(clock);
}

fun guardian_key(seed: u8): vector<u8> {
    vector::tabulate!(32, |i| ((i as u8) + seed))
}

#[test]
#[expected_failure(abort_code = update_config::EProtectedConfigKey)]
fun test_guardian_btc_public_key_cannot_be_rotated() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);
    config::set_guardian_btc_public_key(hashi.config_mut(), guardian_key(0));

    propose_and_execute(
        &mut hashi,
        single(guardian_btc_public_key_key(), config_value::new_bytes(guardian_key(1))),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EProtectedConfigKey)]
fun test_guardian_btc_public_key_cannot_be_rewritten_with_same_value() {
    // The key is refused outright, not compared: governance has no business
    // writing it at all.
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);
    config::set_guardian_btc_public_key(hashi.config_mut(), guardian_key(0));

    propose_and_execute(
        &mut hashi,
        single(guardian_btc_public_key_key(), config_value::new_bytes(guardian_key(0))),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EProtectedConfigKey)]
fun test_bitcoin_chain_id_cannot_be_changed() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);
    btc_config::set_bitcoin_chain_id(hashi.config_mut(), @0xA);

    propose_and_execute(
        &mut hashi,
        single(bitcoin_chain_id_key(), config_value::new_address(@0xB)),
        ctx,
    );

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = update_config::EProtectedConfigKey)]
fun test_protected_key_aborts_the_whole_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);
    config::set_guardian_btc_public_key(hashi.config_mut(), guardian_key(0));

    let mut entries = vec_map::empty();
    entries.insert(deposit_minimum_key(), config_value::new_u64(50_000));
    entries.insert(guardian_btc_public_key_key(), config_value::new_bytes(guardian_key(1)));
    propose_and_execute(&mut hashi, entries, ctx);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_guardian_url_stays_governable() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);
    config::set_guardian_url(hashi.config_mut(), b"https://old.example".to_string());

    propose_and_execute(
        &mut hashi,
        single(guardian_url_key(), config_value::new_string(b"https://new.example".to_string())),
        ctx,
    );
    assert!(
        config::guardian_url(hashi.config()).destroy_some() == b"https://new.example".to_string(),
    );

    std::unit_test::destroy(hashi);
}

#[test]
fun test_other_keys_stay_governable() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = new_hashi(ctx);

    propose_and_execute(
        &mut hashi,
        single(deposit_minimum_key(), config_value::new_u64(50_000)),
        ctx,
    );
    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);

    std::unit_test::destroy(hashi);
}
