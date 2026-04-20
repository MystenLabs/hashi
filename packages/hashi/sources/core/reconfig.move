// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: reconfig
module hashi::reconfig;

use hashi::{committee::CommitteeSignature, hashi::Hashi};

const ENotReconfiguring: u64 = 0;
const EAbortReconfigDisabled: u64 = 1;

/// Message that committee members sign to confirm successful key rotation.
public struct ReconfigCompletionMessage has copy, drop, store {
    /// The epoch of the new committee.
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.config().assert_version_enabled();
    // Assert that we are not already reconfiguring
    assert!(!self.committee_set().is_reconfiguring());
    let mpc_threshold_in_basis_points = hashi::mpc_config::threshold_in_basis_points(self.config());
    let mpc_weight_reduction_allowed_delta = hashi::mpc_config::weight_reduction_allowed_delta(self.config());
    let mpc_max_faulty_in_basis_points = hashi::mpc_config::max_faulty_in_basis_points(self.config());
    let epoch = self
        .committee_set_mut()
        .start_reconfig(
            sui_system,
            mpc_threshold_in_basis_points,
            mpc_weight_reduction_allowed_delta,
            mpc_max_faulty_in_basis_points,
            ctx,
        );
    sui::event::emit(StartReconfigEvent { epoch });
}

entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    cert: CommitteeSignature,
    ctx: &TxContext,
) {
    self.config().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let next_committee = self.committee_set().get_committee(next_epoch);
    let message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    self.verify_with_committee(next_committee, message, cert);
    self.reset_num_consumed_presigs();
    let epoch = self.committee_set_mut().end_reconfig(mpc_public_key, ctx);
    sui::event::emit(EndReconfigEvent { epoch, mpc_public_key });
}

// TODO: Re-enable with committee certificate verification.
entry fun abort_reconfig(_self: &mut Hashi, _ctx: &TxContext) {
    abort EAbortReconfigDisabled
}

public struct StartReconfigEvent has copy, drop {
    epoch: u64,
}

public struct EndReconfigEvent has copy, drop {
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

#[allow(unused_field)]
public struct AbortReconfigEvent has copy, drop {
    epoch: u64,
}
