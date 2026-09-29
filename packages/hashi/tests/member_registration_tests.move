// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::member_registration_tests;

use hashi::{committee_set, test_utils};

const VALIDATOR1: address = @0x1;
const VALIDATOR2: address = @0x2;

#[test]
/// An active Sui validator registers, and each address gets its own entry.
fun test_register_member() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut members = committee_set::create(ctx);
    assert!(!members.has_member(VALIDATOR1));

    members.register_member_for_testing(VALIDATOR1, true);
    assert!(members.has_member(VALIDATOR1));
    assert!(!members.has_member(VALIDATOR2));

    members.register_member_for_testing(VALIDATOR2, true);
    assert!(members.has_member(VALIDATOR2));

    members.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = committee_set::EMemberAlreadyRegistered)]
/// Registering an address that already holds a registration aborts with the
/// named error rather than the bag's duplicate-key abort.
fun test_register_member_twice_aborts() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut members = committee_set::create(ctx);

    members.register_member_for_testing(VALIDATOR1, true);
    members.register_member_for_testing(VALIDATOR1, true);

    members.destroy_for_testing();
}

#[test]
#[expected_failure(abort_code = committee_set::ENotAnActiveSuiValidator)]
/// An address outside Sui's active validator set cannot register.
fun test_register_member_outside_sui_validator_set_aborts() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut members = committee_set::create(ctx);

    members.register_member_for_testing(VALIDATOR1, false);

    members.destroy_for_testing();
}

#[test]
/// The duplicate guard follows the registry, not history: once a registration
/// has been removed, the same address can register again.
fun test_register_member_again_after_removal() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    let mut members = committee_set::create(ctx);

    members.register_member_for_testing(VALIDATOR1, true);
    members.remove_inactive_member(VALIDATOR1, false);
    assert!(!members.has_member(VALIDATOR1));

    members.register_member_for_testing(VALIDATOR1, true);
    assert!(members.has_member(VALIDATOR1));

    members.destroy_for_testing();
}
