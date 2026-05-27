// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::hashi_tests;

use hashi::{config, hashi as hashi_mod, test_utils};

const DEPLOYER: address = @0xDE;
const OTHER: address = @0xBAD;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

#[test]
fun test_set_guardian_btc_public_key_stores_value() {
    let ctx = &mut test_utils::new_tx_context(DEPLOYER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);
    config::set_deployer(hashi.config_mut(), DEPLOYER);

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    hashi_mod::set_guardian_btc_public_key(&mut hashi, btc_pk, ctx);

    assert!(config::guardian_btc_public_key(hashi.config()).destroy_some() == btc_pk);

    std::unit_test::destroy(hashi);
}

#[test]
fun test_set_guardian_btc_public_key_is_idempotent() {
    let ctx = &mut test_utils::new_tx_context(DEPLOYER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);
    config::set_deployer(hashi.config_mut(), DEPLOYER);

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    hashi_mod::set_guardian_btc_public_key(&mut hashi, btc_pk, ctx);
    hashi_mod::set_guardian_btc_public_key(&mut hashi, btc_pk, ctx);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::hashi::ENotDeployer)]
fun test_set_guardian_btc_public_key_rejects_wrong_sender() {
    let ctx = &mut test_utils::new_tx_context(OTHER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);
    config::set_deployer(hashi.config_mut(), DEPLOYER);

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    hashi_mod::set_guardian_btc_public_key(&mut hashi, btc_pk, ctx);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::hashi::ENotDeployer)]
fun test_set_guardian_btc_public_key_rejects_unset_deployer() {
    let ctx = &mut test_utils::new_tx_context(DEPLOYER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let btc_pk = vector::tabulate!(32, |i| (i as u8));
    hashi_mod::set_guardian_btc_public_key(&mut hashi, btc_pk, ctx);

    std::unit_test::destroy(hashi);
}

#[test, expected_failure(abort_code = ::hashi::config::EGuardianBtcPublicKeyImmutable)]
fun test_set_guardian_btc_public_key_rejects_rotation() {
    let ctx = &mut test_utils::new_tx_context(DEPLOYER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);
    config::set_deployer(hashi.config_mut(), DEPLOYER);

    let first = vector::tabulate!(32, |i| (i as u8));
    let second = vector::tabulate!(32, |i| ((i + 1) as u8));
    hashi_mod::set_guardian_btc_public_key(&mut hashi, first, ctx);
    hashi_mod::set_guardian_btc_public_key(&mut hashi, second, ctx);

    std::unit_test::destroy(hashi);
}
