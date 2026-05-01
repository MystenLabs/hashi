// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for aborting a pending Hashi reconfiguration.
///
/// This is intentionally governed by the current committee. If the pending
/// next committee cannot complete DKG/key rotation or cannot produce the
/// `end_reconfig` certificate, the last committed committee is the only
/// committee with stable on-chain voting power.
module hashi::abort_reconfig;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 6667;
const ENotReconfiguring: u64 = 0;
const EWrongReconfigEpoch: u64 = 1;

public struct AbortReconfig has copy, drop, store {
    epoch: u64,
}

public fun propose(
    hashi: &mut Hashi,
    epoch: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    assert!(hashi.committee_set().is_reconfiguring(), ENotReconfiguring);
    assert!(
        hashi.committee_set().pending_epoch_change().destroy_some() == epoch,
        EWrongReconfigEpoch,
    );
    proposal::create(hashi, AbortReconfig { epoch }, THRESHOLD_BPS, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &TxContext) {
    let AbortReconfig { epoch } = proposal::execute(hashi, proposal_id, clock);
    hashi.config().assert_version_enabled();
    assert!(hashi.committee_set().is_reconfiguring(), ENotReconfiguring);
    assert!(
        hashi.committee_set().pending_epoch_change().destroy_some() == epoch,
        EWrongReconfigEpoch,
    );
    let aborted_epoch = hashi.committee_set_mut().abort_reconfig(ctx);
    assert!(aborted_epoch == epoch, EWrongReconfigEpoch);
}
