// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::pause_proposal_tests;

use hashi::{emergency_pause, test_utils};
use sui::clock;

// ======== Test Addresses ========
const VOTER1: address = @0x1;

// ======== Pause Tests ========

#[test]
/// Test basic emergency pause: propose, execute, verify paused
fun test_emergency_pause_basic() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Verify not paused initially
    assert!(!hashi.config().paused());

    // Create emergency pause proposal
    let proposal_id = test_utils::create_emergency_pause_proposal(
        &mut hashi,
        true,
        &clock,
        ctx,
    );

    // Execute the proposal
    emergency_pause::execute(&mut hashi, proposal_id, &clock);

    // Verify paused
    assert!(hashi.config().paused());

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Unpause Tests ========

#[test]
/// Test unpause: pause first, then propose unpause, execute
fun test_unpause_basic() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // First, pause the system
    let pause_id = test_utils::create_emergency_pause_proposal(
        &mut hashi,
        true,
        &clock,
        ctx,
    );
    emergency_pause::execute(&mut hashi, pause_id, &clock);
    assert!(hashi.config().paused());

    // Now propose unpause
    let unpause_id = test_utils::create_emergency_pause_proposal(
        &mut hashi,
        false,
        &clock,
        ctx,
    );

    // Execute unpause
    emergency_pause::execute(&mut hashi, unpause_id, &clock);

    // Verify unpaused
    assert!(!hashi.config().paused());

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
