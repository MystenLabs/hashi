// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_tests;

use hashi::{btc_config, test_utils};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
fun test_withdrawal_minimum_with_defaults() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Default config: bitcoin_withdrawal_minimum=30_000, withdrawal_fee_btc=546
    // worst_case_network_fee = 30_000 - 546 - 546 = 28_908
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 30_000);
    assert!(btc_config::worst_case_network_fee(hashi.config()) == 28_908);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_deposit_minimum_with_defaults() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Default config: bitcoin_deposit_minimum=30_000
    assert!(btc_config::deposit_minimum(hashi.config()) == 30_000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_fee_btc_floors_at_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set fee below dust minimum.
    btc_config::set_withdrawal_fee_btc(hashi.config_mut(), 100);
    // Should return the dust floor (546), not the configured value (100).
    assert!(btc_config::withdrawal_fee_btc(hashi.config()) == 546);

    // Set fee above dust minimum.
    btc_config::set_withdrawal_fee_btc(hashi.config_mut(), 1000);
    assert!(btc_config::withdrawal_fee_btc(hashi.config()) == 1000);

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

    // Floor is withdrawal_fee_btc + DUST_RELAY_MIN_VALUE + 1.
    // With default withdrawal_fee_btc=546: floor = 546 + 546 + 1 = 1093.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 100);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 1093);

    // Set above the floor.
    btc_config::set_bitcoin_withdrawal_minimum(hashi.config_mut(), 10_000);
    assert!(btc_config::bitcoin_withdrawal_minimum(hashi.config()) == 10_000);

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
