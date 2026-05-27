// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_tests;

use hashi::{btc_config, config, test_utils};
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
fun test_set_guardian_stores_url_and_key() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let url = string::utf8(b"http://guardian.example:3000");
    let pk = vector::tabulate!(32, |i| (i as u8));
    config::set_guardian(hashi.config_mut(), url, pk);

    assert!(config::guardian_url(hashi.config()).borrow() == url);
    let stored = config::guardian_public_key(hashi.config()).destroy_some();
    assert!(stored.length() == 32);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::config::EBadGuardianPublicKeyLength)]
fun test_set_guardian_rejects_wrong_length_key() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let url = string::utf8(b"http://guardian.example:3000");
    let bad_pk = vector::tabulate!(31, |i| (i as u8));
    config::set_guardian(hashi.config_mut(), url, bad_pk);

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
fun test_set_deployer_stores_address() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    assert!(config::deployer(hashi.config()).is_none());

    config::set_deployer(hashi.config_mut(), @0xDE);
    assert!(config::deployer(hashi.config()).destroy_some() == @0xDE);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::config::EDeployerAlreadySet)]
fun test_set_deployer_rejects_overwrite() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    config::set_deployer(hashi.config_mut(), @0xDE);
    config::set_deployer(hashi.config_mut(), @0xDE);

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
