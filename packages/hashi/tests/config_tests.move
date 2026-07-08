// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_tests;

use hashi::{btc_config, config, config_value, test_utils};
use std::string;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
fun test_withdrawal_minimum_with_defaults() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Default config: bitcoin_withdrawal_minimum=30_000
    // worst_case_network_fee = 30_000 - 546 = 29_454
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 30_000);
    assert!(btc_config::worst_case_network_fee(hashi.config()) == 29_454);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_deposit_minimum_with_defaults() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Default config: bitcoin_deposit_minimum=30_000
    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 30_000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_bitcoin_deposit_minimum_floors_at_dust() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set below the floor (DUST_RELAY_MIN_VALUE = 546).
    btc_config::set_bitcoin_deposit_minimum(hashi.config_mut(), 100);
    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 546);

    // Set above the floor.
    btc_config::set_bitcoin_deposit_minimum(hashi.config_mut(), 50_000);
    assert!(btc_config::bitcoin_deposit_minimum(hashi.config()) == 50_000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_bitcoin_withdrawal_minimum_floors() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Floor is DUST_RELAY_MIN_VALUE + 1 = 547.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 100);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 547);

    // Set above the floor.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 10_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 10_000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_set_guardian_url_stores_url() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let url = string::utf8(b"http://guardian.example:3000");
    config::set_guardian_url(hashi.config_mut(), url);

    assert!(config::guardian_url(hashi.config()).borrow() == url);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_set_guardian_btc_public_key_stores_value() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    assert!(config::guardian_btc_public_key(hashi.config()).is_none());

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    config::set_guardian_btc_public_key(hashi.config_mut(), btc_pk);
    assert!(config::guardian_btc_public_key(hashi.config()).destroy_some() == btc_pk);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_set_guardian_btc_public_key_is_idempotent() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    config::set_guardian_btc_public_key(hashi.config_mut(), btc_pk);
    // Re-setting with the same value succeeds (idempotent).
    config::set_guardian_btc_public_key(hashi.config_mut(), btc_pk);
    assert!(config::guardian_btc_public_key(hashi.config()).destroy_some() == btc_pk);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::config::EBadGuardianBtcPublicKeyLength)]
fun test_set_guardian_btc_public_key_rejects_wrong_length() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let bad_pk = vector::tabulate!(31, |i| (i as u8));
    config::set_guardian_btc_public_key(hashi.config_mut(), bad_pk);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::config::EGuardianBtcPublicKeyImmutable)]
fun test_set_guardian_btc_public_key_rejects_rotation() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let first = vector::tabulate!(32, |i| (i as u8));
    let second = vector::tabulate!(32, |i| ((i + 1) as u8));
    config::set_guardian_btc_public_key(hashi.config_mut(), first);
    config::set_guardian_btc_public_key(hashi.config_mut(), second);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_bitcoin_withdrawal_minimum_updates() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let baseline = btc_config::bitcoin_withdrawal_minimum(hashi.config());

    // Increasing bitcoin_withdrawal_minimum should increase it.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 50_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) > baseline);

    // Decreasing it should decrease it.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 2_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) < baseline);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_config_value_wide_integers_round_trip() {
    let mut config = config::empty();

    // Values that cannot fit the next-smaller integer width.
    let big_u128 = 1u128 << 100;
    config.upsert(b"test_u128", config_value::new_u128(big_u128));
    assert!(config.get(b"test_u128").as_u128() == big_u128);

    let big_u256 = 1u256 << 200;
    config.upsert(b"test_u256", config_value::new_u256(big_u256));
    assert!(config.get(b"test_u256").as_u256() == big_u256);
}

#[test]
fun test_config_value_same_variant_distinguishes_integer_widths() {
    let u64_value = config_value::new_u64(1);
    let u128_value = config_value::new_u128(1);
    let u256_value = config_value::new_u256(1);

    assert!(u128_value.same_variant(&config_value::new_u128(2)));
    assert!(u256_value.same_variant(&config_value::new_u256(2)));
    assert!(!u64_value.same_variant(&u128_value));
    assert!(!u128_value.same_variant(&u256_value));
    assert!(!u256_value.same_variant(&u64_value));
}
