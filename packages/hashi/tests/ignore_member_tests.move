// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::ignore_member_tests;

use hashi::{committee, ignore_member::{Self, IgnoreMember}, mpc_config, proposal, test_utils};
use sui::{clock, vec_map};

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const NON_MEMBER: address = @0x999;

// ======== Helpers ========

/// Propose ignoring (or un-ignoring) `target` as VOTER1, vote with VOTER2 and
/// VOTER3 to reach quorum, and execute. `nonce` must be unique per call
/// within a test so each proposal object gets a distinct ID.
fun ignore_through_quorum(
    hashi: &mut hashi::hashi::Hashi,
    target: address,
    ignored: bool,
    clock: &clock::Clock,
    nonce: u64,
) {
    let ctx1 = &mut tx_context::new_from_hint(VOTER1, nonce, 0, 0, 0);
    let proposal_id = test_utils::create_ignore_member_proposal(
        hashi,
        VOTER1,
        target,
        ignored,
        clock,
        ctx1,
    );
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<IgnoreMember>(hashi, VOTER2, proposal_id, clock, ctx2);
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<IgnoreMember>(hashi, VOTER3, proposal_id, clock, ctx3);
    ignore_member::execute(hashi, proposal_id, clock);
}

/// The voting-power map for the standard three test voters, in reverse order
/// so that VecMap::pop yields VOTER1 first (matching registration order).
fun voting_powers(w1: u64, w2: u64, w3: u64): sui::vec_map::VecMap<address, u64> {
    let mut powers = vec_map::empty();
    powers.insert(VOTER3, w3);
    powers.insert(VOTER2, w2);
    powers.insert(VOTER1, w1);
    powers
}

// ======== Proposal Lifecycle ========

#[test]
/// A quorum-approved ignore proposal sets the flag; the current epoch's
/// committee is unchanged.
fun test_execute_ignore_sets_flag() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    ignore_through_quorum(&mut hashi, VOTER3, true, &clock, 1);

    assert!(hashi.committee_set().is_member_ignored(VOTER3));
    // The current committee snapshot is untouched: VOTER3 still in it with
    // full weight.
    let current = hashi.committee_set().current_committee();
    assert!(current.has_member(&VOTER3));
    assert!(current.total_weight() == 3);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// Un-ignore through the same proposal type restores the member for future
/// formations.
fun test_execute_unignore_clears_flag() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    ignore_through_quorum(&mut hashi, VOTER3, true, &clock, 1);
    assert!(hashi.committee_set().is_member_ignored(VOTER3));

    ignore_through_quorum(&mut hashi, VOTER3, false, &clock, 2);
    assert!(!hashi.committee_set().is_member_ignored(VOTER3));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = ignore_member::EMemberNotRegistered)]
/// Proposing to ignore an address with no registered member aborts.
fun test_propose_unregistered_target_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let _id = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        NON_MEMBER,
        true,
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = ignore_member::EAlreadyInRequestedState)]
/// Proposing a no-op (member already in the requested state) aborts at
/// propose time.
fun test_propose_noop_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let _id = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        VOTER3,
        false,
        &clock,
        ctx,
    );

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// Two racing proposals for the same member: executing the second (now a
/// no-op) is harmless and idempotent — drift degrades to a repeated write,
/// never an abort.
fun test_execute_after_drift_is_idempotent() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Both proposals created while VOTER3 is not ignored.
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    let first = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        VOTER3,
        true,
        &clock,
        ctx1,
    );
    let ctx1b = &mut tx_context::new_from_hint(VOTER1, 1, 0, 0, 0);
    let second = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        VOTER3,
        true,
        &clock,
        ctx1b,
    );

    // Reach quorum on both.
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<IgnoreMember>(&mut hashi, VOTER2, first, &clock, ctx2);
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<IgnoreMember>(&mut hashi, VOTER3, first, &clock, ctx3);
    let ctx2b = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<IgnoreMember>(&mut hashi, VOTER2, second, &clock, ctx2b);
    let ctx3b = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<IgnoreMember>(&mut hashi, VOTER3, second, &clock, ctx3b);

    ignore_member::execute(&mut hashi, first, &clock);
    assert!(hashi.committee_set().is_member_ignored(VOTER3));
    // Second execute re-applies the same flag without aborting.
    ignore_member::execute(&mut hashi, second, &clock);
    assert!(hashi.committee_set().is_member_ignored(VOTER3));

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Committee Formation ========

#[test]
/// Formation skips an ignored member and total weight re-sums without them.
fun test_formation_skips_ignored_member() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_weighted_committee(
        voters,
        vector[1, 2, 3],
        ctx,
    );
    let clock = clock::create_for_testing(ctx);

    ignore_through_quorum(&mut hashi, VOTER2, true, &clock, 1);

    let next = hashi
        .committee_set()
        .new_committee_from_voting_powers_for_testing(
            1,
            voting_powers(1, 2, 3),
            mpc_config::new_for_testing(800, 3333, 0, 0),
        );
    assert!(next.n_members() == 2);
    assert!(!next.has_member(&VOTER2));
    assert!(next.has_member(&VOTER1));
    assert!(next.has_member(&VOTER3));
    assert!(next.total_weight() == 4);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// After un-ignoring, the next formation includes the member again.
fun test_formation_includes_unignored_member() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    ignore_through_quorum(&mut hashi, VOTER2, true, &clock, 1);
    ignore_through_quorum(&mut hashi, VOTER2, false, &clock, 2);

    let next = hashi
        .committee_set()
        .new_committee_from_voting_powers_for_testing(
            1,
            voting_powers(1, 1, 1),
            mpc_config::new_for_testing(800, 3333, 0, 0),
        );
    assert!(next.n_members() == 3);
    assert!(next.has_member(&VOTER2));
    assert!(next.total_weight() == 3);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// A flag flip executed while a pending committee exists does not alter that
/// pending committee — it only affects the NEXT formation ("takes effect at
/// the next committee formation" semantics).
fun test_ignore_mid_reconfig_affects_next_formation_only() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // A pending committee (epoch 1) is already formed, including VOTER3.
    let sk = test_utils::bls_sk_for_testing();
    let public_key = sui::bls12381::g1_to_uncompressed_g1(
        &sui::bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let members = vector[
        committee::new_committee_member(VOTER1, public_key, sk, 1),
        committee::new_committee_member(VOTER2, public_key, sk, 1),
        committee::new_committee_member(VOTER3, public_key, sk, 1),
    ];
    let pending = committee::new_committee(
        1,
        members,
        mpc_config::new_for_testing(800, 3333, 0, 0),
    );
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending);

    // Ignore VOTER3 while the reconfig is in flight.
    ignore_through_quorum(&mut hashi, VOTER3, true, &clock, 1);

    // The pending committee is immutable: VOTER3 is still in it.
    let pending_ref = hashi.committee_set().get_committee(1);
    assert!(pending_ref.has_member(&VOTER3));
    assert!(pending_ref.total_weight() == 3);

    // The next formation (epoch 2) skips them.
    let next = hashi
        .committee_set()
        .new_committee_from_voting_powers_for_testing(
            2,
            voting_powers(1, 1, 1),
            mpc_config::new_for_testing(800, 3333, 0, 0),
        );
    assert!(!next.has_member(&VOTER3));
    assert!(next.total_weight() == 2);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
