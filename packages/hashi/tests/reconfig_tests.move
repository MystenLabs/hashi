// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::reconfig_tests;

use hashi::{reconfig, test_utils};

const VOTER1: address = @0x1;

#[test]
#[expected_failure(abort_code = reconfig::EGenesisNotAuthorized)]
fun test_genesis_gate_requires_upgrade_cap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_genesis_gate_passes_with_cap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.versioning_mut().set_upgrade_cap(sui::package::test_publish(@0x42.to_id(), ctx));

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}

#[test]
fun test_genesis_gate_skipped_after_bootstrap() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.committee_set_mut().set_mpc_public_key_for_testing(vector[1]);

    reconfig::assert_genesis_launch_authorized(&hashi);
    std::unit_test::destroy(hashi);
}
