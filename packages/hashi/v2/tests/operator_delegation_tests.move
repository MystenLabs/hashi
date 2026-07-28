// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy, unused_variable)]
module hashi::operator_delegation_tests;

use hashi::{proposal, test_utils, update_config::UpdateConfig};
use sui::clock;

// ======== Test Addresses ========
const VALIDATOR1: address = @0x1;
const VALIDATOR2: address = @0x2;
const VALIDATOR3: address = @0x3;
const OPERATOR1: address = @0xA1;
const STRANGER: address = @0x999;

// ======== member_authorized Tests ========

#[test]
/// A validator authorizes itself; an undelegated operator and a stranger do not;
/// after delegation the operator is authorized while the validator stays authorized.
fun test_member_authorized() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    // Each context is created and used immediately: a `&mut` to a temporary reuses
    // one slot, so holding several at once would all observe the last sender.

    // The validator's own key is always authorized for itself.
    let cv = &test_utils::new_tx_context(VALIDATOR1, 0);
    assert!(hashi.committee_set().member_authorized(VALIDATOR1, cv));

    // No operator delegated yet: operator and stranger are not authorized.
    let co = &test_utils::new_tx_context(OPERATOR1, 0);
    assert!(!hashi.committee_set().member_authorized(VALIDATOR1, co));
    let cs = &test_utils::new_tx_context(STRANGER, 0);
    assert!(!hashi.committee_set().member_authorized(VALIDATOR1, cs));

    // A non-member validator address is never authorized.
    let cs2 = &test_utils::new_tx_context(STRANGER, 0);
    assert!(!hashi.committee_set().member_authorized(STRANGER, cs2));

    // VALIDATOR1 delegates to OPERATOR1.
    let cd = &test_utils::new_tx_context(VALIDATOR1, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, OPERATOR1, cd);

    // Now the operator is authorized, and the validator key still is too.
    let co2 = &test_utils::new_tx_context(OPERATOR1, 0);
    assert!(hashi.committee_set().member_authorized(VALIDATOR1, co2));
    let cv2 = &test_utils::new_tx_context(VALIDATOR1, 0);
    assert!(hashi.committee_set().member_authorized(VALIDATOR1, cv2));

    std::unit_test::destroy(hashi);
}

// ======== Operator Acting On Behalf Of Validator ========

#[test]
/// A delegated operator can create a proposal *for* the validator and the vote
/// is recorded under the validator's address. Quorum then completes normally.
fun test_operator_can_create_and_vote() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Delegate V1 -> OPERATOR1.
    let ctx_v1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, OPERATOR1, ctx_v1);

    // OPERATOR1 creates a proposal on behalf of VALIDATOR1.
    let ctx_op = &mut test_utils::new_tx_context(OPERATOR1, 0);
    let proposal_id = test_utils::create_deposit_minimum_proposal(
        &mut hashi,
        VALIDATOR1,
        1000,
        &clock,
        ctx_op,
    );

    // The auto-vote is recorded under VALIDATOR1, not OPERATOR1.
    let prop: &proposal::Proposal<UpdateConfig> = hashi.proposals().active().borrow(proposal_id);
    assert!(prop.votes().length() == 1);
    assert!(prop.votes().contains(&VALIDATOR1));
    assert!(!prop.votes().contains(&OPERATOR1));

    // VALIDATOR2 and VALIDATOR3 vote to reach quorum.
    let ctx_v2 = &mut test_utils::new_tx_context(VALIDATOR2, 0);
    proposal::vote<UpdateConfig>(&mut hashi, VALIDATOR2, proposal_id, &clock, ctx_v2);
    let ctx_v3 = &mut test_utils::new_tx_context(VALIDATOR3, 0);
    proposal::vote<UpdateConfig>(&mut hashi, VALIDATOR3, proposal_id, &clock, ctx_v3);

    hashi::update_config::execute(&mut hashi, proposal_id, &clock);
    assert!(hashi::btc_config::bitcoin_deposit_minimum(hashi.config()) == 1000);

    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EVoteAlreadyCounted)]
/// The operator's create auto-votes under VALIDATOR1; the validator then voting
/// for itself is a double vote since both resolve to the same VALIDATOR1 slot.
fun test_operator_and_validator_single_vote() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Delegate V1 -> OPERATOR1.
    let ctx_v1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, OPERATOR1, ctx_v1);

    // OPERATOR1 creates the proposal for VALIDATOR1 (auto-votes under VALIDATOR1).
    let ctx_op = &mut test_utils::new_tx_context(OPERATOR1, 0);
    let proposal_id = test_utils::create_deposit_minimum_proposal(
        &mut hashi,
        VALIDATOR1,
        1000,
        &clock,
        ctx_op,
    );

    // VALIDATOR1 itself now votes for VALIDATOR1 - already counted, must abort.
    let ctx_v1b = &mut test_utils::new_tx_context(VALIDATOR1, 0);
    proposal::vote<UpdateConfig>(&mut hashi, VALIDATOR1, proposal_id, &clock, ctx_v1b);

    // Won't reach here.
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

// ======== Delegation Authorization Tests ========

#[test]
#[expected_failure]
/// A sender that is neither the validator nor its delegated operator may not set
/// the operator address.
fun test_set_operator_address_rejects_unauthorized() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    // STRANGER is neither VALIDATOR1 nor its operator (none delegated) -> aborts.
    let ctx_stranger = &test_utils::new_tx_context(STRANGER, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, @0xBEEF, ctx_stranger);

    // Won't reach here.
    std::unit_test::destroy(hashi);
}

#[test]
/// Reverted behavior: a delegated operator key may itself re-point the operator
/// address (validator OR operator may delegate; the validator always retains it).
fun test_operator_can_set_operator_address() {
    let ctx = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    // VALIDATOR1 delegates to OPERATOR1.
    let ctx_v1 = &test_utils::new_tx_context(VALIDATOR1, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, OPERATOR1, ctx_v1);

    // OPERATOR1 (the operator) re-points the operator address to @0xBEEF.
    let ctx_op = &test_utils::new_tx_context(OPERATOR1, 0);
    hashi.committee_set_mut().set_operator_address(VALIDATOR1, @0xBEEF, ctx_op);

    // @0xBEEF is the authorized operator now; OPERATOR1 no longer is.
    let ctx_beef = &test_utils::new_tx_context(@0xBEEF, 0);
    assert!(hashi.committee_set().member_authorized(VALIDATOR1, ctx_beef));
    let ctx_op2 = &test_utils::new_tx_context(OPERATOR1, 0);
    assert!(!hashi.committee_set().member_authorized(VALIDATOR1, ctx_op2));

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EUnauthorizedCaller)]
/// A validator cannot create a proposal claiming to be a *different* validator:
/// member_authorized(VALIDATOR2, VALIDATOR1) is false, so create aborts.
fun test_unauthorized_validator_arg_fails() {
    let ctx_v1 = &mut test_utils::new_tx_context(VALIDATOR1, 0);

    let voters = vector[VALIDATOR1, VALIDATOR2, VALIDATOR3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx_v1);
    let clock = clock::create_for_testing(ctx_v1);

    // VALIDATOR1 (sender) tries to propose as VALIDATOR2 - unauthorized.
    let _proposal_id = test_utils::create_deposit_minimum_proposal(
        &mut hashi,
        VALIDATOR2,
        1000,
        &clock,
        ctx_v1,
    );

    // Won't reach here.
    clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
