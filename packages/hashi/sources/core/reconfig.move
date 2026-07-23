// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Committee reconfiguration entry points. `start_reconfig` forms the next
/// committee from Sui's active validator set (pinning the governed MPC
/// parameters for the new epoch), `submit_committee_handoff` records the
/// outgoing committee's certificate approving the incoming committee, and
/// `end_reconfig` verifies the new committee's certificate over the MPC
/// threshold public key and activates the epoch. The initial (genesis)
/// reconfig skips the handoff — no prior committee exists — and is gated on
/// the publisher's launch switch (`hashi::finish_publish`).
module hashi::reconfig;

use hashi::{committee::CommitteeSignature, hashi::Hashi};

// ~~~~~~~ Errors ~~~~~~~

// NOTE: `ENotReconfiguring` is matched BY NAME in the node's reconfig-abort
// classifier (crates/hashi/src/mpc/service.rs) to detect the benign
// "end_reconfig already completed by another node" race — keep the name.
#[error]
const ENotReconfiguring: vector<u8> = b"No reconfiguration is in progress";
#[error]
const EInitialReconfig: vector<u8> =
    b"Not allowed during the initial reconfig (no committee handoff exists yet)";
#[error]
const EGenesisNotAuthorized: vector<u8> =
    b"Genesis is locked until the publisher sends finish_publish (the launch switch)";

// ~~~~~~~ Structs ~~~~~~~

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

// ~~~~~~~ Events ~~~~~~~

public struct ReconfigStarted has copy, drop {
    epoch: u64,
}

public struct ReconfigEnded has copy, drop {
    from_epoch: u64,
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

// ~~~~~~~ Entry Functions ~~~~~~~

entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    // Assert that we are not already reconfiguring
    assert!(!self.committee_set().is_reconfiguring());
    assert_genesis_launch_authorized(self);
    // Commit due scheduled updates before the snapshot so the epoch's
    // committee pins the values active for that epoch.
    self.commit_pending_config_updates(ctx.epoch());
    // Pin the governed epoch parameters so mid-epoch governance changes don't
    // affect the active committee.
    let config = self.config().pin(self.config_registry());
    let version_ceiling = hashi::protocol_version::ceiling(self.config());
    let version_buffer_bps = hashi::protocol_version::buffer_bps(self.config());
    let epoch = self
        .committee_set_mut()
        .start_reconfig(
            sui_system,
            config,
            version_ceiling,
            version_buffer_bps,
            ctx,
        );
    // The advance rule wrote only the pinned copy; mirror it back so the next
    // reconfig's pin starts from the advanced version.
    let pinned_version = hashi::protocol_version::current(self
        .committee_set()
        .get_committee(epoch)
        .config());
    if (pinned_version != hashi::protocol_version::current(self.config())) {
        hashi::protocol_version::set(self.config_mut(), pinned_version);
    };
    sui::event::emit(ReconfigStarted { epoch });
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
    sui::event::emit(ReconfigEnded { from_epoch, epoch, mpc_public_key });
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

// ~~~~~~~ Package Functions ~~~~~~~

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

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
/// Forwards to `end_reconfig` so it can be exercised from
/// `hashi::reconfig_tests` (non-public entry functions are not callable from
/// other modules).
public fun end_reconfig_for_testing(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    end_reconfig(self, mpc_public_key, mpc_cert, ctx)
}

#[test_only]
/// Forwards to `submit_committee_handoff` so it can be exercised from
/// `hashi::reconfig_tests` (non-public entry functions are not callable from
/// other modules).
public fun submit_committee_handoff_for_testing(
    self: &mut Hashi,
    committee_handoff_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    submit_committee_handoff(self, committee_handoff_cert, ctx)
}

#[test_only]
/// Constructs a `ReconfigCompletionMessage` (private fields) for tests that
/// need to sign one.
public fun reconfig_completion_message_for_testing(
    epoch: u64,
    mpc_public_key: vector<u8>,
): ReconfigCompletionMessage {
    ReconfigCompletionMessage { epoch, mpc_public_key }
}

#[test_only]
/// Constructs a `CommitteeTransitionRequest` (private fields) for tests that
/// need to sign one.
public fun committee_transition_request_for_testing(
    new_committee: hashi::committee::Committee,
): CommitteeTransitionRequest {
    CommitteeTransitionRequest { new_committee }
}
