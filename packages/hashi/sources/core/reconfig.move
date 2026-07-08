// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: reconfig
module hashi::reconfig;

use hashi::{committee::CommitteeSignature, hashi::Hashi};

const ENotReconfiguring: u64 = 0;
const EInitialReconfig: u64 = 1;
const EGenesisNotAuthorized: u64 = 2;

/// Message that committee members sign to confirm successful key rotation.
public struct ReconfigCompletionMessage has copy, drop, store {
    /// The epoch of the new committee.
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

public struct CommitteeTransitionRequest has copy, drop, store {
    new_committee: hashi::committee::Committee,
}

entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    // Assert that we are not already reconfiguring
    assert!(!self.committee_set().is_reconfiguring());
    assert_genesis_launch_authorized(self);
    // Pin the current MPC parameters so they stay fixed for the new epoch even
    // if governance changes them mid-epoch.
    let config = hashi::mpc_config::pin(self.config());
    let epoch = self
        .committee_set_mut()
        .start_reconfig(
            sui_system,
            config,
            ctx,
        );
    sui::event::emit(StartReconfigEvent { epoch });
}

entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    let from_epoch = self.committee_set().epoch();
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let next_committee = self.committee_set().get_committee(next_epoch);
    let message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    self.verify_with_committee(
        next_committee,
        hashi::intent::reconfig_completion(),
        message,
        mpc_cert,
    );
    let is_initial_reconfig = self.committee_set().mpc_public_key().is_empty();

    self.reset_num_consumed_presigs();
    let (epoch, committee_handoff_cert) = self
        .committee_set_mut()
        .end_reconfig(mpc_public_key, ctx);
    if (is_initial_reconfig) {
        committee_handoff_cert.destroy_none();
    } else {
        self
            .committee_set_mut()
            .insert_committee_handoff(
                from_epoch,
                epoch,
                committee_handoff_cert.destroy_some(),
            );
    };
    sui::event::emit(EndReconfigEvent { from_epoch, epoch, mpc_public_key });
}

entry fun submit_committee_handoff(
    self: &mut Hashi,
    committee_handoff_cert: CommitteeSignature,
    _ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    assert!(!self.committee_set().mpc_public_key().is_empty(), EInitialReconfig);
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let next_committee = self.committee_set().get_committee(next_epoch);
    let new_committee = *next_committee;
    let message = CommitteeTransitionRequest { new_committee };
    self.verify_with_committee(
        self.current_committee(),
        hashi::intent::committee_transition(),
        message,
        committee_handoff_cert,
    );
    self.committee_set_mut().set_pending_committee_handoff_cert(committee_handoff_cert);
}

/// At genesis bootstrap (no MPC key yet) the initial committee may only form
/// after the publisher hands the package `UpgradeCap` into on-chain custody
/// via `hashi::finish_publish` -- the launch switch. After bootstrap this is
/// never consulted; Hashi follows Sui's validator set unconditionally --
/// enforcing a floor on a normal reconfig would let validators brick
/// reconfiguration (and with it all deposits/withdrawals) by withholding
/// registration.
public(package) fun assert_genesis_launch_authorized(self: &Hashi) {
    if (self.committee_set().mpc_public_key().is_empty()) {
        assert!(self.versioning().has_upgrade_cap(), EGenesisNotAuthorized);
    }
}

public struct StartReconfigEvent has copy, drop {
    epoch: u64,
}

public struct EndReconfigEvent has copy, drop {
    from_epoch: u64,
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

#[test_only]
const VOTER1: address = @0x1;
#[test_only]
const VOTER2: address = @0x2;
#[test_only]
const VOTER3: address = @0x3;

#[test_only]
fun pending_committee_for_testing(epoch: u64): hashi::committee::Committee {
    use hashi::{committee, mpc_config, test_utils};
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
    committee::new_committee(epoch, members, mpc_config::new_for_testing(3334, 800, 3333, 0))
}

#[test_only]
fun cert_message<T: copy + drop + store>(epoch: u64, intent: u16, message: &T): vector<u8> {
    use sui::bcs;

    let mut bytes = bcs::to_bytes(&intent);
    bytes.append(bcs::to_bytes(&epoch));
    bytes.append(bcs::to_bytes(message));
    bytes
}

#[test]
fun test_end_reconfig_stores_committee_handoff() {
    use hashi::test_utils;

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1, 2, 3];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );
    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            0,
            hashi::intent::committee_transition(),
            &CommitteeTransitionRequest { new_committee: next_committee },
        ),
        3,
    );

    submit_committee_handoff(&mut hashi, committee_handoff_cert, ctx);
    end_reconfig(&mut hashi, mpc_public_key, mpc_cert, ctx);

    assert!(hashi.committee_set().epoch() == next_epoch);
    assert!(hashi.committee_set().has_committee_handoff_for_testing(0));
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_end_reconfig_requires_committee_handoff_after_initial_reconfig() {
    use hashi::test_utils;

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );

    end_reconfig(&mut hashi, mpc_public_key, mpc_cert, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure(abort_code = EInitialReconfig)]
fun test_submit_committee_handoff_rejects_initial_reconfig() {
    use hashi::test_utils;

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let committee_handoff_cert = test_utils::sign_certificate(
        0,
        &cert_message(
            0,
            hashi::intent::committee_transition(),
            &CommitteeTransitionRequest { new_committee: next_committee },
        ),
        3,
    );

    submit_committee_handoff(&mut hashi, committee_handoff_cert, ctx);
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_submit_committee_handoff_rejects_handoff_signed_by_wrong_committee() {
    use hashi::test_utils;

    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let next_epoch = 1;
    let next_committee = pending_committee_for_testing(next_epoch);
    hashi.committee_set_mut().set_pending_reconfig_for_testing(next_committee);

    let mpc_public_key = vector[1];
    hashi.committee_set_mut().set_mpc_public_key_for_testing(mpc_public_key);
    let mpc_message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    let mpc_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(next_epoch, hashi::intent::reconfig_completion(), &mpc_message),
        3,
    );
    let committee_handoff_cert = test_utils::sign_certificate(
        next_epoch,
        &cert_message(
            next_epoch,
            hashi::intent::committee_transition(),
            &CommitteeTransitionRequest { new_committee: next_committee },
        ),
        3,
    );

    submit_committee_handoff(&mut hashi, committee_handoff_cert, ctx);
    end_reconfig(&mut hashi, mpc_public_key, mpc_cert, ctx);
    std::unit_test::destroy(hashi);
}
