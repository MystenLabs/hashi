// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::config_tests;

use hashi::test_utils;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
fun test_withdrawal_minimum_with_defaults() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Default config: max_fee_rate=25, max_inputs=10, withdrawal_fee_btc=546
    // tx_vbytes = 11 + (10 * 100) + (2 * 43) = 1,097 vB
    // worst_case_fee = 25 * 1,097 = 27,425 sats
    // minimum = 546 + 27,425 + 546 = 28,517 sats
    assert!(hashi.config().withdrawal_minimum() == 28_517);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_fee_btc_floors_at_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set fee below dust minimum
    hashi.config_mut().set_withdrawal_fee_btc(100);
    // Should return the dust floor (546), not the configured value (100)
    assert!(hashi.config().withdrawal_fee_btc() == 546);

    // Set fee above dust minimum
    hashi.config_mut().set_withdrawal_fee_btc(1000);
    assert!(hashi.config().withdrawal_fee_btc() == 1000);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_max_fee_rate_floors_at_min_relay_fee() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set fee rate to zero
    hashi.config_mut().set_max_fee_rate(0);
    // Should return the relay fee floor (1), not 0
    assert!(hashi.config().max_fee_rate() == 1);

    // Set fee rate above floor
    hashi.config_mut().set_max_fee_rate(50);
    assert!(hashi.config().max_fee_rate() == 50);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_max_inputs_floors_at_one() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    // Set max_inputs to zero
    hashi.config_mut().set_max_inputs(0);
    // Should return 1, not 0
    assert!(hashi.config().max_inputs() == 1);

    // Set max_inputs above floor
    hashi.config_mut().set_max_inputs(20);
    assert!(hashi.config().max_inputs() == 20);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_withdrawal_minimum_updates_with_config_changes() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let baseline = hashi.config().withdrawal_minimum();

    // Increasing max_fee_rate should increase the minimum
    hashi.config_mut().set_max_fee_rate(50);
    assert!(hashi.config().withdrawal_minimum() > baseline);

    // Reset and increase max_inputs instead
    hashi.config_mut().set_max_fee_rate(25);
    hashi.config_mut().set_max_inputs(20);
    assert!(hashi.config().withdrawal_minimum() > baseline);

    std::unit_test::destroy(hashi);
}
