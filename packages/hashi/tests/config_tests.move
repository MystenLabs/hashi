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

    // Default config: bitcoin_min_withdrawal=27_971, withdrawal_fee_btc=546
    // worst_case_network_fee = 27_971 - 546 = 27_425
    // withdrawal_minimum = 27_971 + 546 = 28_517
    assert!(btc_config::worst_case_network_fee(hashi.config()) == 27_425);
    assert!(btc_config::withdrawal_minimum(hashi.config()) == 28_517);

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
fun test_bitcoin_min_withdrawal_floors_at_dust_plus_one() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set below the floor (DUST_RELAY_MIN_VALUE * 2 = 1092).
    btc_config::set_bitcoin_min_withdrawal(hashi.config_mut(), 100);
    assert!(btc_config::bitcoin_min_withdrawal(hashi.config()) == 1092);

    // Set above the floor.
    btc_config::set_bitcoin_min_withdrawal(hashi.config_mut(), 10_000);
    assert!(btc_config::bitcoin_min_withdrawal(hashi.config()) == 10_000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_minimum_updates_with_config_changes() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let baseline = btc_config::withdrawal_minimum(hashi.config());

    // Increasing bitcoin_min_withdrawal should increase the minimum.
    btc_config::set_bitcoin_min_withdrawal(hashi.config_mut(), 50_000);
    assert!(btc_config::withdrawal_minimum(hashi.config()) > baseline);

    // Decreasing it should decrease the minimum.
    btc_config::set_bitcoin_min_withdrawal(hashi.config_mut(), 1_000);
    assert!(btc_config::withdrawal_minimum(hashi.config()) < baseline);

    std::unit_test::destroy(hashi);
}
