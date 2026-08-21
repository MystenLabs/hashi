// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::resignation_tests;

use hashi::{committee, mpc_config, proposal, reconfig, test_utils, validator};
use sui::bls12381;

// ======== Test Addresses ========
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const OPERATOR: address = @0x77;
const STRANGER: address = @0x999;

// ======== Helpers ========

fun committee_for_testing(epoch: u64, voters: vector<address>): committee::Committee {
    let sk = test_utils::bls_sk_for_testing();
    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let mut members = vector[];
    voters.do!(|voter| {
        members.push_back(committee::new_committee_member(voter, public_key, sk, 1));
    });
    committee::new_committee(epoch, members, mpc_config::new_for_testing(3334, 800, 3333, 0, 0))
}

fun cert_message<T: copy + drop + store>(epoch: u64, intent: u16, message: &T): vector<u8> {
    let mut bytes = sui::bcs::to_bytes(&intent);
    bytes.append(sui::bcs::to_bytes(&epoch));
    bytes.append(sui::bcs::to_bytes(message));
    bytes
}

/// Drive a full epoch transition to `next_epoch` with `next_voters` as the
/// pending committee, signing the handoff with the 3-member current
/// committee and the completion cert with the pending committee.
fun run_epoch_transition(
    hashi: &mut hashi::hashi::Hashi,
    next_epoch: u64,
    next_voters: vector<address>,
    ctx: &mut TxContext,
) {
    let next_committee = committee_for_testing(next_epoch, next_voters);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1, 2, 3];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        next_voters.length(),
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        hashi.committee_set().epoch(),
        &cert_message(
            hashi.committee_set().epoch(),
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );

    reconfig::submit_committee_handoff_for_testing(hashi, committee_handoff_cert, ctx);
    reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);
}

// ======== Flag + Formation ========

#[test]
/// Resigning while serving sets the flag (no removal), and the next
/// formation skips the member with total weight re-summed.
fun test_resign_sets_flag_and_formation_skips() {
    let ctx = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx);

    assert!(hashi.committee_set().has_member(VOTER3));
    assert!(hashi.committee_set().is_member_resigned(VOTER3));

    let mut powers = sui::vec_map::empty();
    powers.insert(VOTER3, 1);
    powers.insert(VOTER2, 1);
    powers.insert(VOTER1, 1);
    let next = hashi
        .committee_set()
        .new_committee_from_voting_powers_for_testing(
            1,
            powers,
            mpc_config::new_for_testing(3334, 800, 3333, 0, 0),
        );
    assert!(next.n_members() == 2);
    assert!(!next.has_member(&VOTER3));
    assert!(next.total_weight() == 2);

    std::unit_test::destroy(hashi);
}

#[test]
/// A duty-free member (registered but in no committee) is removed
/// immediately on resign.
fun test_resign_without_duties_removes_immediately() {
    let ctx = &mut test_utils::new_tx_context(VOTER3, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VOTER1, VOTER2],
        vector[VOTER1, VOTER2, VOTER3],
        ctx,
    );

    validator::resign_for_testing(&mut hashi, VOTER3, ctx);

    assert!(!hashi.committee_set().has_member(VOTER3));
    std::unit_test::destroy(hashi);
}

#[test]
/// Pre-genesis (no committee exists yet): resign is immediate removal.
fun test_resign_pre_genesis_removes_immediately() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let sk = test_utils::bls_sk_for_testing();
    let pub_key = bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk));
    let mut committee_set = hashi::committee_set::create_pre_genesis_for_testing(
        vector[VOTER1, VOTER2],
        *pub_key.bytes(),
        sk,
        ctx,
    );

    let removed = committee_set.request_resignation(VOTER1, ctx);

    assert!(removed);
    assert!(!committee_set.has_member(VOTER1));
    assert!(committee_set.has_member(VOTER2));
    hashi::committee_set::destroy_for_testing(committee_set);
}

// ======== Withdrawal ========

#[test]
/// withdraw_resignation clears the flag and the next formation includes the
/// member again.
fun test_withdraw_resignation_clears_flag() {
    let ctx = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx);
    assert!(hashi.committee_set().is_member_resigned(VOTER3));

    validator::withdraw_resignation_for_testing(&mut hashi, VOTER3, ctx);
    assert!(!hashi.committee_set().is_member_resigned(VOTER3));

    let mut powers = sui::vec_map::empty();
    powers.insert(VOTER3, 1);
    powers.insert(VOTER2, 1);
    powers.insert(VOTER1, 1);
    let next = hashi
        .committee_set()
        .new_committee_from_voting_powers_for_testing(
            1,
            powers,
            mpc_config::new_for_testing(3334, 800, 3333, 0, 0),
        );
    assert!(next.n_members() == 3);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::ENotResigned)]
/// Withdrawing with no pending resignation aborts.
fun test_withdraw_without_resignation_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::withdraw_resignation_for_testing(&mut hashi, VOTER3, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::EAlreadyResigned)]
/// Resigning twice aborts.
fun test_resign_twice_aborts() {
    let ctx = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx);
    validator::resign_for_testing(&mut hashi, VOTER3, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::EMemberNotRegistered)]
/// Resigning an unregistered address aborts.
fun test_resign_unregistered_aborts() {
    let ctx = &mut test_utils::new_tx_context(STRANGER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::resign_for_testing(&mut hashi, STRANGER, ctx);
    std::unit_test::destroy(hashi);
}

// ======== Authorization ========

#[test]
/// The delegated operator key can resign and withdraw for the validator.
fun test_operator_can_resign_for_validator() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx3);
    hashi.committee_set_mut().set_operator_address(VOTER3, OPERATOR, ctx3);

    let ctx_op = &mut test_utils::new_tx_context(OPERATOR, 0);
    validator::resign_for_testing(&mut hashi, VOTER3, ctx_op);
    assert!(hashi.committee_set().is_member_resigned(VOTER3));

    validator::withdraw_resignation_for_testing(&mut hashi, VOTER3, ctx_op);
    assert!(!hashi.committee_set().is_member_resigned(VOTER3));

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
/// A stranger cannot resign someone else.
fun test_stranger_cannot_resign_member() {
    let ctx = &mut test_utils::new_tx_context(STRANGER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx);
    std::unit_test::destroy(hashi);
}

// ======== Last-member guard ========

#[test]
#[expected_failure(abort_code = hashi::committee_set::ELastActiveMember)]
/// The sole remaining active current-committee member cannot resign.
fun test_last_active_member_cannot_resign() {
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    let voters = vector[VOTER1, VOTER2];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx2);

    validator::resign_for_testing(&mut hashi, VOTER2, ctx2);

    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    validator::resign_for_testing(&mut hashi, VOTER1, ctx1);
    std::unit_test::destroy(hashi);
}

// ======== Finalization at the epoch transition ========

#[test]
/// The canonical flow: resign while serving, epoch transition excludes the
/// member, finalize removes the registration atomically with end_reconfig.
fun test_finalize_removes_resigned_member_at_end_reconfig() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx3);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx3);

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    run_epoch_transition(&mut hashi, 1, vector[VOTER1, VOTER2], ctx);

    assert!(hashi.committee_set().epoch() == 1);
    assert!(!hashi.committee_set().has_member(VOTER3));
    assert!(hashi.committee_set().has_member(VOTER1));
    assert!(hashi.committee_set().has_member(VOTER2));

    std::unit_test::destroy(hashi);
}

#[test]
/// Resigning mid-reconfig while included in the PENDING committee: the
/// member survives this boundary (they hold the new epoch's shares) and is
/// removed at the following one.
fun test_resign_mid_reconfig_survives_one_boundary() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx3);

    // Reconfig in flight; pending committee (epoch 1) includes VOTER3.
    let next_committee = committee_for_testing(1, vector[VOTER1, VOTER2, VOTER3]);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    // Resign now: flag only (they are in the pending committee).
    validator::resign_for_testing(&mut hashi, VOTER3, ctx3);
    assert!(hashi.committee_set().has_member(VOTER3));

    // Complete the in-flight transition: VOTER3 is in the NEW committee, so
    // finalize must NOT remove them — they serve epoch 1.
    let mpc_public_key = vector[1, 2, 3];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(1, mpc_public_key);
    let mpc_cert = test_utils::sign_certificate(
        1,
        &cert_message(1, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );
    let next_committee = committee_for_testing(1, vector[VOTER1, VOTER2, VOTER3]);
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(0, hashi::intent::committee_transition(), &handoff_message),
        3,
    );
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, ctx);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, ctx);

    assert!(hashi.committee_set().epoch() == 1);
    assert!(hashi.committee_set().has_member(VOTER3));
    assert!(hashi.committee_set().is_member_resigned(VOTER3));

    // The FOLLOWING transition (epoch 2, formed without them) removes them.
    run_epoch_transition(&mut hashi, 2, vector[VOTER1, VOTER2], ctx);
    assert!(hashi.committee_set().epoch() == 2);
    assert!(!hashi.committee_set().has_member(VOTER3));

    std::unit_test::destroy(hashi);
}

#[test]
/// A pending-only member (new joiner mid-reconfig) who resigns and then
/// sees abort_reconfig is removed by the abort sweep — no registry leak.
fun test_abort_reconfig_sweeps_pending_only_resigned_member() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let mut hashi = test_utils::create_hashi_with_committee_and_registry(
        vector[VOTER1, VOTER2],
        vector[VOTER1, VOTER2, VOTER3],
        ctx3,
    );

    // Pending committee (epoch 1) includes the new joiner VOTER3.
    let next_committee = committee_for_testing(1, vector[VOTER1, VOTER2, VOTER3]);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    // Resign: pending-only membership → flag, not immediate removal.
    validator::resign_for_testing(&mut hashi, VOTER3, ctx3);
    assert!(hashi.committee_set().has_member(VOTER3));

    let (aborted_epoch, removed) = hashi.committee_set_mut().abort_reconfig(ctx3);
    assert!(aborted_epoch == 1);
    assert!(removed == vector[VOTER3]);
    assert!(!hashi.committee_set().has_member(VOTER3));

    std::unit_test::destroy(hashi);
}

#[test]
/// A CURRENT-committee member who resigned keeps their registration (and
/// flag) through an abort — they still serve the current epoch.
fun test_abort_reconfig_retains_current_member() {
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx2);

    let next_committee = committee_for_testing(1, vector[VOTER1, VOTER2, VOTER3]);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    validator::resign_for_testing(&mut hashi, VOTER2, ctx2);

    let (aborted_epoch, removed) = hashi.committee_set_mut().abort_reconfig(ctx2);
    assert!(aborted_epoch == 1);
    assert!(removed.is_empty());
    assert!(hashi.committee_set().has_member(VOTER2));
    assert!(hashi.committee_set().is_member_resigned(VOTER2));

    std::unit_test::destroy(hashi);
}

// ======== Interaction with ignore + governance ========

#[test]
/// Resigned AND ignored coexist; removal keys off resigned only — an
/// ignored-but-not-resigned member keeps their registration through the
/// transition.
fun test_resigned_and_ignored_coexist() {
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx2);

    // VOTER2: ignored + resigned. VOTER3: ignored only.
    hashi.committee_set_mut().set_member_ignored(VOTER2, true);
    hashi.committee_set_mut().set_member_ignored(VOTER3, true);
    validator::resign_for_testing(&mut hashi, VOTER2, ctx2);

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    run_epoch_transition(&mut hashi, 1, vector[VOTER1], ctx);

    // Resigned member removed; ignored-only member retained (reversible).
    assert!(!hashi.committee_set().has_member(VOTER2));
    assert!(hashi.committee_set().has_member(VOTER3));
    assert!(hashi.committee_set().is_member_ignored(VOTER3));

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = proposal::EUnauthorizedCaller)]
/// After finalization, the ex-member can no longer vote on proposals.
fun test_ex_member_cannot_vote() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx3);
    let clock = sui::clock::create_for_testing(ctx3);

    validator::resign_for_testing(&mut hashi, VOTER3, ctx3);
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    run_epoch_transition(&mut hashi, 1, vector[VOTER1, VOTER2], ctx);
    assert!(!hashi.committee_set().has_member(VOTER3));

    let proposal_id = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        VOTER2,
        true,
        &clock,
        ctx,
    );
    let ctx3b = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<hashi::ignore_member::IgnoreMember>(
        &mut hashi,
        VOTER3,
        proposal_id,
        &clock,
        ctx3b,
    );

    sui::clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::EMemberNotRegistered)]
/// An approved ignore proposal whose target resigned and was removed aborts
/// at execute (the setter re-asserts registration).
fun test_ignore_execute_aborts_after_target_deregistered() {
    let ctx3 = &mut test_utils::new_tx_context(VOTER3, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx3);
    let clock = sui::clock::create_for_testing(ctx3);

    // Approve ignoring VOTER3 (proposal reaches quorum but is not executed).
    let ctx1 = &mut test_utils::new_tx_context(VOTER1, 0);
    let proposal_id = test_utils::create_ignore_member_proposal(
        &mut hashi,
        VOTER1,
        VOTER3,
        true,
        &clock,
        ctx1,
    );
    let ctx2 = &mut test_utils::new_tx_context(VOTER2, 0);
    proposal::vote<hashi::ignore_member::IgnoreMember>(
        &mut hashi,
        VOTER2,
        proposal_id,
        &clock,
        ctx2,
    );
    let ctx3b = &mut test_utils::new_tx_context(VOTER3, 0);
    proposal::vote<hashi::ignore_member::IgnoreMember>(
        &mut hashi,
        VOTER3,
        proposal_id,
        &clock,
        ctx3b,
    );

    // Target resigns and is removed at the transition.
    validator::resign_for_testing(&mut hashi, VOTER3, ctx3);
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    run_epoch_transition(&mut hashi, 1, vector[VOTER1, VOTER2], ctx);
    assert!(!hashi.committee_set().has_member(VOTER3));

    // Executing the approved proposal now aborts.
    hashi::ignore_member::execute(&mut hashi, proposal_id, &clock);

    sui::clock::destroy_for_testing(clock);
    std::unit_test::destroy(hashi);
}
