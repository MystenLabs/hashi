// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, deprecated_usage, unused_variable)]
module hashi::proposal_tests;

use hashi::{proposal, test_utils, update_deposit_fee::UpdateDepositFee};
use sui::clock;

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const NON_VOTER: address = @0x999;

// ======== Constants ========
const MAX_PROPOSAL_DURATION_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days

// ======== Proposal Creation Tests ========

#[test]
/// Test that a committee member can create a proposal
fun test_create_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Create a proposal - should succeed since VOTER1 is a member
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Verify proposal exists
    assert!(hashi.proposals().contains(proposal_id));

    // Verify the creator voted automatically
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(prop.votes().length() == 1);
    assert!(prop.votes().contains(&VOTER1));

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EUnauthorizedCaller)]
/// Test that a non-committee member cannot create a proposal
fun test_create_proposal_fails_for_non_member() {
    let ctx = &mut test_utils::new_tx_context(NON_VOTER, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Try to create a proposal as non-member - should fail
    let _proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Voting Tests ========

#[test]
/// Test that a committee member can vote on a proposal
fun test_vote_on_proposal() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // VOTER2 votes
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx2);

    // Verify vote count is now 2
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(prop.votes().length() == 2);
    assert!(prop.votes().contains(&VOTER1));
    assert!(prop.votes().contains(&VOTER2));

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EVoteAlreadyCounted)]
/// Test that voting twice on the same proposal fails
fun test_double_vote_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // VOTER1 creates proposal (auto-votes)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // VOTER1 tries to vote again - should fail
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EUnauthorizedCaller)]
/// Test that a non-member cannot vote
fun test_vote_by_non_member_fails() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // NON_VOTER tries to vote - should fail
    let ctx_non = &mut test_utils::new_tx_context(NON_VOTER, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx_non);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Remove Vote Tests ========

#[test]
/// Test that a voter can remove their vote
fun test_remove_vote() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // VOTER1 creates proposal (auto-votes)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Verify vote exists
    {
        let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
        assert!(prop.votes().length() == 1);
    };

    // VOTER1 removes vote
    proposal::remove_vote<UpdateDepositFee>(&mut hashi, proposal_id, ctx);

    // Verify vote was removed
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(prop.votes().length() == 0);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::ENoVoteFound)]
/// Test that removing a non-existent vote fails
fun test_remove_nonexistent_vote_fails() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // VOTER2 tries to remove vote without having voted - should fail
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::remove_vote<UpdateDepositFee>(&mut hashi, proposal_id, ctx2);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Proposal Execution Tests ========

#[test]
/// Test executing a proposal with quorum reached
fun test_execute_proposal_with_quorum() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    // Single voter = 100% quorum with one vote
    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Verify initial deposit fee is 0
    assert!(hashi.config().deposit_fee() == 0);

    // VOTER1 creates proposal (auto-votes = 100% weight)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Execute the proposal
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id, &clock);

    // Verify the deposit fee was updated
    assert!(hashi.config().deposit_fee() == 1000);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EQuorumNotReached)]
/// Test that executing without quorum fails
fun test_execute_without_quorum_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    // 3 voters with equal weight - need 100% for quorum
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // VOTER1 creates proposal (auto-votes = 33% weight)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Try to execute without quorum - should fail
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id, &clock);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// Test executing after gathering enough votes
fun test_execute_after_gathering_votes() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal (33% weight)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // VOTER2 votes (66% weight)
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx2);

    // VOTER3 votes (100% weight)
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx3);

    // Now execute with 100% quorum
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id, &clock);

    // Verify the deposit fee was updated
    assert!(hashi.config().deposit_fee() == 1000);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Proposal Expiration Tests ========

#[test]
#[expected_failure(abort_code = proposal::EProposalExpired)]
/// Test that voting on an expired proposal fails
fun test_vote_on_expired_proposal_fails() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx1);
    let mut clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // Advance clock past expiration (7 days + 1 ms)
    clock::increment_for_testing(&mut clock, MAX_PROPOSAL_DURATION_MS + 1);

    // VOTER2 tries to vote on expired proposal - should fail
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx2);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EProposalExpired)]
/// Test that executing an expired proposal fails
fun test_execute_expired_proposal_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // VOTER1 creates proposal (100% weight)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Advance clock past expiration
    clock::increment_for_testing(&mut clock, MAX_PROPOSAL_DURATION_MS + 1);

    // Try to execute expired proposal - should fail
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id, &clock);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// Test deleting an expired proposal
fun test_delete_expired_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let mut clock = clock::create_for_testing(ctx);

    // Create proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Advance clock past expiration
    clock::increment_for_testing(&mut clock, MAX_PROPOSAL_DURATION_MS + 1);

    // Delete expired proposal - should succeed
    let data = proposal::delete_expired<UpdateDepositFee>(&mut hashi, proposal_id, &clock);
    std::unit_test::destroy(data);

    // Verify proposal no longer exists
    assert!(!hashi.proposals().contains(proposal_id));

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EProposalNotExpired)]
/// Test that deleting a non-expired proposal fails
fun test_delete_non_expired_proposal_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Create proposal
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Try to delete non-expired proposal - should fail
    let data = proposal::delete_expired<UpdateDepositFee>(&mut hashi, proposal_id, &clock);

    // Won't reach here
    std::unit_test::destroy(data);
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Weighted Voting Tests ========

#[test]
/// Test quorum calculation with weighted committee
fun test_weighted_quorum() {
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);

    // Create committee with weights: VOTER1=3, VOTER2=2, VOTER3=1 (total=6)
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let weights = vector[3u64, 2u64, 1u64];
    let mut hashi = test_utils::create_hashi_with_weighted_committee(voters, weights, ctx1);
    let clock = clock::create_for_testing(ctx1);

    // VOTER1 creates proposal (3/6 = 50% weight)
    let proposal_id = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx1,
    );

    // 50% is not enough for 100% quorum - verify we need more votes
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(!proposal::quorum_reached(prop, &hashi));

    // VOTER2 votes (now 5/6 = 83% total weight)
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx2);

    // Still not enough for 100% quorum
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(!proposal::quorum_reached(prop, &hashi));

    // VOTER3 votes (now 6/6 = 100% total weight)
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<UpdateDepositFee>(&mut hashi, proposal_id, &clock, ctx3);

    // Now we have quorum
    let prop: &proposal::Proposal<UpdateDepositFee> = hashi.proposals().borrow(proposal_id);
    assert!(proposal::quorum_reached(prop, &hashi));

    // Execute should succeed
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi.config().deposit_fee() == 1000);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Multiple Proposals Tests ========

#[test]
/// Test handling multiple concurrent proposals
fun test_multiple_concurrent_proposals() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Create first proposal
    let proposal_id_1 = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        1000,
        &clock,
        ctx,
    );

    // Create second proposal
    let proposal_id_2 = test_utils::create_deposit_fee_proposal(
        &mut hashi,
        2000,
        &clock,
        ctx,
    );

    // Both proposals should exist
    assert!(hashi.proposals().contains(proposal_id_1));
    assert!(hashi.proposals().contains(proposal_id_2));

    // Execute first proposal
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id_1, &clock);
    assert!(hashi.config().deposit_fee() == 1000);

    // Execute second proposal (overwrites first)
    hashi::update_deposit_fee::execute(&mut hashi, proposal_id_2, &clock);
    assert!(hashi.config().deposit_fee() == 2000);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Enable/Disable Version Tests ========

#[test]
/// Test creating and executing an enable version proposal
fun test_enable_version_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Create enable version proposal for version 2
    let proposal_id = test_utils::create_enable_version_proposal(
        &mut hashi,
        2,
        &clock,
        ctx,
    );

    // Execute the proposal
    hashi::enable_version::execute(&mut hashi, proposal_id, &clock);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
/// Test creating and executing a disable version proposal
fun test_disable_version_proposal() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // First enable version 2
    let enable_id = test_utils::create_enable_version_proposal(
        &mut hashi,
        2,
        &clock,
        ctx,
    );
    hashi::enable_version::execute(&mut hashi, enable_id, &clock);

    // Now disable version 2 (not the current version)
    let disable_id = test_utils::create_disable_version_proposal(
        &mut hashi,
        2,
        &clock,
        ctx,
    );
    hashi::disable_version::execute(&mut hashi, disable_id, &clock);

    // Clean up
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::config::EDisableCurrentVersion)]
/// Test that disabling the current package version fails (anti-bricking protection)
fun test_disable_current_version_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Try to disable version 1 (current version) - should fail
    let proposal_id = test_utils::create_disable_version_proposal(
        &mut hashi,
        1, // current package version
        &clock,
        ctx,
    );
    hashi::disable_version::execute(&mut hashi, proposal_id, &clock);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = sui::vec_set::EKeyAlreadyExists)]
/// Test that enabling an already-enabled version fails
fun test_enable_already_enabled_version_fails() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);

    let voters = vector[VOTER1];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Try to enable version 1 (already enabled by default) - should fail
    let proposal_id = test_utils::create_enable_version_proposal(
        &mut hashi,
        1, // already enabled
        &clock,
        ctx,
    );
    hashi::enable_version::execute(&mut hashi, proposal_id, &clock);

    // Won't reach here
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
