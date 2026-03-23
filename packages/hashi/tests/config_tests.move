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

    // Default config: max_fee_rate=25, input_budget=10, withdrawal_fee_btc=546
    // tx_vbytes = 11 + (10 * 100) + (2 * 43) = 1,097 vB
    // worst_case_fee = 25 * 1,097 = 27,425 sats
    // minimum = 546 + 27,425 + 546 = 28,517 sats
    assert!(btc_config::withdrawal_minimum(hashi.config()) == 28_517);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_fee_btc_floors_at_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set fee below dust minimum
    btc_config::set_withdrawal_fee_btc(hashi.config_mut(), 100);
    // Should return the dust floor (546), not the configured value (100)
    assert!(btc_config::withdrawal_fee_btc(hashi.config()) == 546);

    // Set fee above dust minimum
    btc_config::set_withdrawal_fee_btc(hashi.config_mut(), 1000);
    assert!(btc_config::withdrawal_fee_btc(hashi.config()) == 1000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_max_fee_rate_floors_at_min_relay_fee() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set fee rate to zero
    btc_config::set_max_fee_rate(hashi.config_mut(), 0);
    // Should return the relay fee floor (1), not 0
    assert!(btc_config::max_fee_rate(hashi.config()) == 1);

    // Set fee rate above floor
    btc_config::set_max_fee_rate(hashi.config_mut(), 50);
    assert!(btc_config::max_fee_rate(hashi.config()) == 50);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_input_budget_floors_at_one() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set input_budget to zero
    btc_config::set_input_budget(hashi.config_mut(), 0);
    // Should return 1, not 0
    assert!(btc_config::input_budget(hashi.config()) == 1);

    // Set input_budget above floor
    btc_config::set_input_budget(hashi.config_mut(), 20);
    assert!(btc_config::input_budget(hashi.config()) == 20);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_minimum_updates_with_config_changes() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let baseline = btc_config::withdrawal_minimum(hashi.config());

    // Increasing max_fee_rate should increase the minimum
    btc_config::set_max_fee_rate(hashi.config_mut(), 50);
    assert!(btc_config::withdrawal_minimum(hashi.config()) > baseline);

    // Reset and increase input_budget instead
    btc_config::set_max_fee_rate(hashi.config_mut(), 25);
    btc_config::set_input_budget(hashi.config_mut(), 20);
    assert!(btc_config::withdrawal_minimum(hashi.config()) > baseline);

    std::unit_test::destroy(hashi);
}
