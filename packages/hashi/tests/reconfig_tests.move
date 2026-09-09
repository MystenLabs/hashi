// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::reconfig_tests;

use hashi::{committee::CommitteeSignature, reconfig, test_utils};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const OUTSIDER: address = @0x999;

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

fun pending_committee_for_testing(epoch: u64): hashi::committee::Committee {
    use hashi::{committee, mpc_config};
    use sui::bls12381;

    let sk = test_utils::bls_sk_for_testing();
    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk)),
    );
    let members = vector[
        committee::new_committee_member(VOTER1, public_key, sk, 1),
        committee::new_committee_member(VOTER2, public_key, sk, 1),
        committee::new_committee_member(VOTER3, public_key, sk, 1),
    ];
    committee::new_committee(epoch, members, mpc_config::new_for_testing(800, 3333, 0))
}

fun cert_message<T: copy + drop + store>(
    hashi_id: address,
    epoch: u64,
    intent: u16,
    message: &T,
): vector<u8> {
    use sui::bcs;

    let mut bytes = bcs::to_bytes(&intent);
    bytes.append(bcs::to_bytes(&hashi_id));
    bytes.append(bcs::to_bytes(&epoch));
    bytes.append(bcs::to_bytes(message));
    bytes
}

#[test]
fun test_end_reconfig_stores_committee_handoff() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1, 2, 3];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            object::id_address(&hashi),
            next_epoch,
            hashi::intent::reconfig_completion(),
            &mpc_message,
        ),
        3,
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            object::id_address(&hashi),
            0,
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );

    let in_window = &test_utils::new_tx_context(VOTER1, next_epoch);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, in_window);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, in_window);

    assert!(hashi.committee_set().epoch() == next_epoch);
    assert!(hashi.committee_set().has_committee_handoff_for_testing(0));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_end_reconfig_requires_committee_handoff_after_initial_reconfig() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            object::id_address(&hashi),
            next_epoch,
            hashi::intent::reconfig_completion(),
            &mpc_message,
        ),
        3,
    );

    let in_window = &test_utils::new_tx_context(VOTER1, next_epoch);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, in_window);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EInitialReconfig)]
fun test_submit_committee_handoff_rejects_initial_reconfig() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            object::id_address(&hashi),
            0,
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );

    let in_window = &test_utils::new_tx_context(VOTER1, next_epoch);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, in_window);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_submit_committee_handoff_rejects_handoff_signed_by_wrong_committee() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            object::id_address(&hashi),
            next_epoch,
            hashi::intent::reconfig_completion(),
            &mpc_message,
        ),
        3,
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(next_committee);
    let committee_handoff_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            object::id_address(&hashi),
            next_epoch,
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );

    let in_window = &test_utils::new_tx_context(VOTER1, next_epoch);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, in_window);
    reconfig::end_reconfig_for_testing(&mut hashi, mpc_public_key, mpc_cert, in_window);
    std::unit_test::destroy(hashi);
}

// ======== abort_reconfig ========

/// Hashi at epoch 0 with a pending epoch-1 committee and a set MPC key, i.e.
/// a non-initial reconfiguration in flight.
fun hashi_with_pending_reconfig(ctx: &mut TxContext): hashi::hashi::Hashi {
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(1));
    hashi.committee_set_mut().set_mpc_public_key_for_testing(vector[1, 2, 3]);
    hashi
}

#[test]
/// Once Sui's epoch has moved past the pending epoch, the abort tears down
/// only the pending state: the current epoch, committee, and MPC key stay.
fun test_abort_reconfig_clears_pending_state_once_sui_epoch_moves_on() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    assert!(hashi.committee_set().pending_epoch_change().destroy_some() == 1);
    assert!(hashi.committee_set().has_committee(1));

    let later_ctx = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, later_ctx);

    assert!(hashi.committee_set().pending_epoch_change().is_none());
    assert!(!hashi.committee_set().has_committee(1));
    assert!(hashi.committee_set().has_committee(0));
    assert!(hashi.committee_set().epoch() == 0);
    assert!(hashi.committee_set().mpc_public_key() == vector[1, 2, 3]);

    let aborted = sui::event::events_by_type<reconfig::ReconfigAborted>();
    assert!(aborted.length() == 1);
    assert!(aborted[0] == reconfig::reconfig_aborted_for_testing(1));

    std::unit_test::destroy(hashi);
}

#[test]
/// No signer check: an address that is neither a member nor a validator can
/// abort a stale reconfiguration.
fun test_abort_reconfig_is_permissionless() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);

    let outsider_ctx = &test_utils::new_tx_context(OUTSIDER, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, outsider_ctx);

    assert!(hashi.committee_set().pending_epoch_change().is_none());
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::EPendingEpochStillCurrent)]
/// While the pending epoch is still Sui's current epoch the reconfiguration
/// is inside its window and cannot be aborted, by anyone.
fun test_abort_reconfig_rejects_pending_epoch_still_current() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);

    let same_epoch_ctx = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, same_epoch_ctx);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::ENotReconfiguring)]
/// Nothing to abort when no reconfiguration is pending, whatever Sui's epoch.
fun test_abort_reconfig_rejects_when_not_reconfiguring() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1, VOTER2, VOTER3], ctx);

    let later_ctx = &test_utils::new_tx_context(VOTER1, 5);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, later_ctx);

    std::unit_test::destroy(hashi);
}

#[test]
/// A handoff certificate the outgoing committee already submitted is
/// discarded with the pending committee: nothing is recorded for the
/// aborted transition.
fun test_abort_reconfig_discards_submitted_handoff_cert() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let handoff_message = reconfig::committee_transition_request_for_testing(
        pending_committee_for_testing(1),
    );
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            object::id_address(&hashi),
            0,
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );
    let in_window = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, committee_handoff_cert, in_window);

    let later_ctx = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, later_ctx);

    assert!(hashi.committee_set().pending_epoch_change().is_none());
    assert!(!hashi.committee_set().has_committee(1));
    assert!(!hashi.committee_set().has_committee_handoff_for_testing(0));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::ENotReconfiguring)]
/// After an abort the pending state is gone, so a second abort has nothing
/// to act on.
fun test_abort_reconfig_twice_fails_second_time() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);

    let later_ctx = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, later_ctx);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, later_ctx);

    std::unit_test::destroy(hashi);
}

// ======== abort_reconfig during genesis ========

/// Pre-genesis Hashi: members registered, no committee for epoch 0, empty
/// MPC key, and the launch switch (upgrade cap) already thrown.
fun pre_genesis_hashi(ctx: &mut TxContext): hashi::hashi::Hashi {
    use sui::bls12381;

    let sk = test_utils::bls_sk_for_testing();
    let pub_key = bls12381::g1_from_bytes(&test_utils::bls_min_pk_from_sk(&sk));
    let committee_set = hashi::committee_set::create_pre_genesis_for_testing(
        vector[VOTER1, VOTER2, VOTER3],
        *pub_key.bytes(),
        sk,
        ctx,
    );
    let mut config = hashi::config::create();
    hashi::btc_config::init_defaults(&mut config);
    let mut epoch_config = hashi::config::empty();
    hashi::mpc_config::init_defaults(&mut epoch_config);
    let mut hashi = hashi::hashi::create_for_testing(
        committee_set,
        config,
        epoch_config,
        hashi::versioning::create(),
        hashi::treasury::create(ctx),
        hashi::proposals::create(ctx),
        sui::bag::new(ctx),
        ctx,
    );
    hashi.versioning_mut().set_upgrade_cap(sui::package::test_publish(@0x42.to_id(), ctx));
    hashi
}

#[test]
/// A genesis DKG that overran its Sui epoch is abortable even though no
/// committee exists yet to vote, and the abort restores the pre-genesis
/// state exactly: epoch 0, no committee, no MPC key, launch switch still
/// thrown. Everything a fresh genesis `start_reconfig` checks at the new Sui
/// epoch then holds.
fun test_abort_reconfig_during_genesis_dkg_returns_to_pre_genesis() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 7);
    let mut hashi = pre_genesis_hashi(ctx);
    // Genesis start_reconfig at Sui epoch 7 pins the initial committee to 7.
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(7));
    assert!(!hashi.committee_set().has_committee(0));
    assert!(hashi.committee_set().mpc_public_key().is_empty());

    let later_ctx = &test_utils::new_tx_context(OUTSIDER, 8);
    reconfig::abort_reconfig_for_testing(&mut hashi, 7, later_ctx);

    assert!(hashi.committee_set().pending_epoch_change().is_none());
    assert!(!hashi.committee_set().has_committee(7));
    assert!(hashi.committee_set().epoch() == 0);
    assert!(!hashi.committee_set().has_committee(0));
    assert!(hashi.committee_set().mpc_public_key().is_empty());
    assert!(!hashi.committee_set().is_reconfiguring());
    assert!(!hashi.committee_set().has_committee(8));
    reconfig::assert_genesis_launch_authorized(&hashi);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee_set::EPendingEpochStillCurrent)]
/// Genesis on a fresh network starts at Sui epoch 0, so the pending epoch
/// equals the Hashi epoch (both 0). The gate keys on Sui's epoch, not on
/// Hashi's, so the in-window genesis DKG still cannot be aborted.
fun test_abort_reconfig_genesis_at_sui_epoch_zero_rejected_while_current() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = pre_genesis_hashi(ctx);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(0));

    reconfig::abort_reconfig_for_testing(&mut hashi, 0, ctx);

    std::unit_test::destroy(hashi);
}

#[test]
/// The same epoch-0 genesis becomes abortable once Sui reaches epoch 1, and
/// removing the pending epoch-0 committee returns Hashi to pre-genesis.
fun test_abort_reconfig_genesis_at_sui_epoch_zero_once_sui_moves_on() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = pre_genesis_hashi(ctx);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(0));

    let later_ctx = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::abort_reconfig_for_testing(&mut hashi, 0, later_ctx);

    assert!(hashi.committee_set().pending_epoch_change().is_none());
    assert!(!hashi.committee_set().has_committee(0));
    assert!(hashi.committee_set().epoch() == 0);
    assert!(hashi.committee_set().mpc_public_key().is_empty());

    std::unit_test::destroy(hashi);
}

// ======== Completion window and race classification ========

/// Certificates for the transition 0 -> `next_epoch` over `mpc_public_key`:
/// the completion cert signed by the pending committee and the handoff cert
/// signed by the current (epoch 0) committee.
fun transition_certs(
    hashi: &hashi::hashi::Hashi,
    next_epoch: u64,
    mpc_public_key: vector<u8>,
): (CommitteeSignature, CommitteeSignature) {
    let mpc_message = reconfig::reconfig_completion_message_for_testing(
        next_epoch,
        mpc_public_key,
    );
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            object::id_address(hashi),
            next_epoch,
            hashi::intent::reconfig_completion(),
            &mpc_message,
        ),
        3,
    );
    let handoff_message = reconfig::committee_transition_request_for_testing(
        pending_committee_for_testing(next_epoch),
    );
    let handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            object::id_address(hashi),
            0,
            hashi::intent::committee_transition(),
            &handoff_message,
        ),
        3,
    );
    (mpc_cert, handoff_cert)
}

#[test]
#[expected_failure(abort_code = reconfig::EReconfigWindowClosed)]
/// Once Sui's epoch has moved past the pending epoch a valid completion is
/// refused: from then on the reconfiguration can only be aborted.
fun test_end_reconfig_rejects_closed_window() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (mpc_cert, handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    let in_window = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, in_window);

    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, late);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EReconfigWindowClosed)]
fun test_submit_committee_handoff_rejects_closed_window() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (_mpc_cert, handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);

    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, late);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EReconfigAlreadyCompleted)]
/// A second completion for a target that already activated is reported as
/// the benign race the node treats as success, not as "not reconfiguring".
fun test_end_reconfig_after_completion_reports_already_completed() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (mpc_cert, handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    let in_window = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, in_window);
    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, in_window);
    assert!(hashi.committee_set().epoch() == 1);

    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, in_window);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EReconfigAlreadyCompleted)]
fun test_submit_committee_handoff_after_completion_reports_already_completed() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (mpc_cert, handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    let in_window = &test_utils::new_tx_context(VOTER1, 1);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, in_window);
    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, in_window);
    assert!(hashi.committee_set().epoch() == 1);

    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, in_window);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::ENotReconfiguring)]
/// After an abort the target's committee is gone, so a late completion is
/// "not reconfiguring" and never mistaken for "already completed".
fun test_end_reconfig_after_abort_is_not_reconfiguring() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (mpc_cert, _handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, late);

    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, late);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::ENotReconfiguring)]
fun test_submit_committee_handoff_after_abort_is_not_reconfiguring() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (_mpc_cert, handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, late);

    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, late);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EWrongReconfigEpoch)]
/// The abort names its target, so a stale transaction cannot tear down a
/// different pending reconfiguration.
fun test_abort_reconfig_rejects_wrong_epoch() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);

    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 2, late);

    std::unit_test::destroy(hashi);
}

/// Aborts the pending epoch-1 reconfiguration at Sui epoch 2 and pends a
/// replacement for epoch 2, i.e. the abort-and-restart cycle from the same
/// source epoch 0.
fun abort_and_pend_replacement(hashi: &mut hashi::hashi::Hashi) {
    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(hashi, 1, late);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(2));
}

#[test]
#[expected_failure(abort_code = hashi::committee::ESigVerification)]
/// A handoff certificate binds its target inside the signed message (the
/// incoming committee, epoch included), so one for an aborted target cannot
/// verify against the replacement now pending from the same source epoch.
fun test_submit_committee_handoff_rejects_aborted_target_while_replacement_pending() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (_mpc_cert, stale_handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    abort_and_pend_replacement(&mut hashi);

    let in_window = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, stale_handoff_cert, in_window);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = reconfig::EWrongReconfigEpoch)]
fun test_end_reconfig_rejects_aborted_target_while_replacement_pending() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (stale_mpc_cert, _handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    abort_and_pend_replacement(&mut hashi);

    let in_window = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], stale_mpc_cert, in_window);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = hashi::committee::ESigVerification)]
/// Handoffs are stored by source epoch, so once the replacement (0 -> 2) has
/// activated a handoff for the aborted target (0 -> 1) must not read that
/// record as its own completion. The certificate is verified against the
/// stored transition before the benign race is reported, and a certificate
/// over the aborted committee fails that verification.
fun test_submit_committee_handoff_for_aborted_target_after_replacement_completed() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let (_mpc_cert, stale_handoff_cert) = transition_certs(&hashi, 1, vector[1, 2, 3]);
    abort_and_pend_replacement(&mut hashi);
    let (mpc_cert, handoff_cert) = transition_certs(&hashi, 2, vector[1, 2, 3]);
    let in_window = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::submit_committee_handoff_for_testing(&mut hashi, handoff_cert, in_window);
    reconfig::end_reconfig_for_testing(&mut hashi, vector[1, 2, 3], mpc_cert, in_window);
    assert!(hashi.committee_set().epoch() == 2);
    assert!(hashi.committee_set().has_committee_handoff_for_testing(0));

    reconfig::submit_committee_handoff_for_testing(&mut hashi, stale_handoff_cert, in_window);

    std::unit_test::destroy(hashi);
}

// ======== Restart after abort ========

fun equal_voting_powers(): sui::vec_map::VecMap<address, u64> {
    let mut powers = sui::vec_map::empty();
    powers.insert(VOTER1, 1);
    powers.insert(VOTER2, 1);
    powers.insert(VOTER3, 1);
    powers
}

#[test]
/// What the design rests on: after an abort, a fresh start_reconfig at the
/// new Sui epoch forms a replacement committee and pends it.
fun test_start_reconfig_succeeds_after_abort() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = hashi_with_pending_reconfig(ctx);
    let late = &test_utils::new_tx_context(VOTER1, 2);
    reconfig::abort_reconfig_for_testing(&mut hashi, 1, late);

    let epoch = hashi
        .committee_set_mut()
        .start_reconfig_from_voting_powers_for_testing(
            equal_voting_powers(),
            hashi::mpc_config::new_for_testing(800, 3333, 0),
            late,
        );

    assert!(epoch == 2);
    assert!(hashi.committee_set().pending_epoch_change().destroy_some() == 2);
    assert!(hashi.committee_set().has_committee(2));
    assert!(hashi.committee_set().get_committee(2).n_members() == 3);
    assert!(hashi.committee_set().epoch() == 0);
    std::unit_test::destroy(hashi);
}

#[test]
/// The same cycle at genesis: the aborted initial committee is replaced by
/// a fresh one at the new Sui epoch, still behind the launch switch.
fun test_start_reconfig_succeeds_after_genesis_abort() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 7);
    let mut hashi = pre_genesis_hashi(ctx);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(pending_committee_for_testing(7));
    let late = &test_utils::new_tx_context(VOTER1, 8);
    reconfig::abort_reconfig_for_testing(&mut hashi, 7, late);

    reconfig::assert_genesis_launch_authorized(&hashi);
    let epoch = hashi
        .committee_set_mut()
        .start_reconfig_from_voting_powers_for_testing(
            equal_voting_powers(),
            hashi::mpc_config::new_for_testing(800, 3333, 0),
            late,
        );

    assert!(epoch == 8);
    assert!(hashi.committee_set().pending_epoch_change().destroy_some() == 8);
    assert!(hashi.committee_set().has_committee(8));
    assert!(hashi.committee_set().get_committee(8).n_members() == 3);
    assert!(hashi.committee_set().epoch() == 0);
    assert!(hashi.committee_set().mpc_public_key().is_empty());
    std::unit_test::destroy(hashi);
}
