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
///
/// A reconfiguration must complete within the Sui epoch it was formed in:
/// `start_reconfig` pins the pending committee to Sui's epoch, and
/// `submit_committee_handoff` and `end_reconfig` refuse to land once Sui's
/// epoch has moved past it. From then on only `abort_reconfig`, the
/// permissionless escape hatch, can resolve it, and it is refused while the
/// epochs still match. Completion and abort are therefore mutually exclusive
/// by Sui epoch and can never race each other.
module hashi::reconfig;

use hashi::{committee::CommitteeSignature, hashi::Hashi};

// ~~~~~~~ Errors ~~~~~~~

// NOTE: the node's reconfig-submission classifier
// (crates/hashi/src/mpc/service.rs) matches `ENotReconfiguring`,
// `EReconfigAlreadyCompleted`, and `EReconfigWindowClosed` BY NAME to tell the
// benign "another node already completed it" race from a dead target — keep
// the names.
#[error]
const ENotReconfiguring: vector<u8> = b"No reconfiguration is in progress";
#[error]
const EReconfigAlreadyCompleted: vector<u8> =
    b"This reconfiguration has already completed; nothing is pending";
#[error]
const EReconfigWindowClosed: vector<u8> =
    b"The pending reconfiguration's Sui epoch has passed; it can only be aborted now";
#[error]
const EWrongReconfigEpoch: vector<u8> = b"Epoch does not match the pending reconfiguration";
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

public struct ReconfigAborted has copy, drop {
    /// The pending epoch that was torn down; the current epoch is unchanged.
    epoch: u64,
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
    // Copy the epoch config verbatim onto the new committee so it stays fixed
    // for the epoch even if governance changes the store mid-epoch. The
    // proposals that write the store keep it valid; nothing is repaired here.
    let epoch_config = *self.epoch_config();
    let epoch = self
        .committee_set_mut()
        .start_reconfig(
            sui_system,
            epoch_config,
            ctx,
        );
    sui::event::emit(ReconfigStarted { epoch });
}

entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    // The certificate is signed by the incoming committee, so its epoch is
    // this submission's target. An activated target is the current epoch and
    // still has its committee; an aborted one has neither.
    let target = mpc_cert.signature_epoch();
    let already_completed =
        self.committee_set().epoch() == target && self.committee_set().has_committee(target);
    let next_epoch = pending_epoch_in_window(self, already_completed, ctx);
    let from_epoch = self.committee_set().epoch();
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
    ctx: &TxContext,
) {
    self.versioning().assert_version_enabled();
    // The certificate is signed by the outgoing committee, so its epoch is
    // the handoff's source epoch, and a stored handoff for that epoch means
    // the transition it approved already activated.
    let from_epoch = committee_handoff_cert.signature_epoch();
    let already_completed = self.committee_set().has_committee_handoff(from_epoch);
    let next_epoch = pending_epoch_in_window(self, already_completed, ctx);
    assert!(!self.committee_set().mpc_public_key().is_empty(), EInitialReconfig);
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

/// Abort a reconfiguration that has overrun its Sui epoch. Callable by
/// anyone, with no vote. The conditions are that a reconfiguration is in
/// flight, that `epoch` names it (so a stale transaction cannot tear down a
/// different one), and that its epoch is no longer Sui's current epoch (see
/// `committee_set::abort_reconfig`). `end_reconfig` is gated on the opposite
/// condition, so an abort can never race a completion.
///
/// Deliberately not a governance proposal. The committees that could vote on
/// one are exactly the parties a stalled reconfiguration puts in doubt: the
/// pending committee may never finish DKG or key rotation, and a proposal
/// gated on the outgoing committee's quorum can be stranded by the same
/// offline stake that stalled the reconfiguration. Binding the abort to an
/// objective on-chain fact instead keeps the escape hatch usable precisely
/// when it is needed.
///
/// The launch switch applies exactly as it does to `start_reconfig`, so the
/// pre-launch state machine is the same at both ends of a reconfiguration.
entry fun abort_reconfig(self: &mut Hashi, epoch: u64, ctx: &TxContext) {
    self.versioning().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    assert!(
        self.committee_set().pending_epoch_change().destroy_some() == epoch,
        EWrongReconfigEpoch,
    );
    assert_genesis_launch_authorized(self);
    let aborted = self.committee_set_mut().abort_reconfig(ctx);
    sui::event::emit(ReconfigAborted { epoch: aborted });
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

// ~~~~~~~ Private Functions ~~~~~~~

/// The pending epoch, provided the reconfiguration can still complete.
///
/// Aborts with `EReconfigAlreadyCompleted` when nothing is pending because
/// this transaction's target already activated (another node won the
/// `end_reconfig` race; the node treats this as success), with
/// `ENotReconfiguring` when nothing is pending for any other reason (the
/// target was aborted), and with `EReconfigWindowClosed` once Sui's epoch has
/// moved past the pending epoch, from which point only `abort_reconfig` can
/// resolve it. The node keys its retry/give-up decision on which of these
/// fires, so the distinction is load-bearing.
fun pending_epoch_in_window(self: &Hashi, already_completed: bool, ctx: &TxContext): u64 {
    if (!self.committee_set().is_reconfiguring()) {
        if (already_completed) abort EReconfigAlreadyCompleted;
        abort ENotReconfiguring
    };
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    assert!(next_epoch == ctx.epoch(), EReconfigWindowClosed);
    next_epoch
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
/// Forwards to `abort_reconfig` so it can be exercised from
/// `hashi::reconfig_tests` (non-public entry functions are not callable from
/// other modules).
public fun abort_reconfig_for_testing(self: &mut Hashi, epoch: u64, ctx: &TxContext) {
    abort_reconfig(self, epoch, ctx)
}

#[test_only]
/// Constructs a `ReconfigAborted` (private fields) so tests can assert the
/// emitted payload.
public fun reconfig_aborted_for_testing(epoch: u64): ReconfigAborted {
    ReconfigAborted { epoch }
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
