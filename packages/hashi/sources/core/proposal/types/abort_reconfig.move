// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for aborting a pending Hashi reconfiguration.
///
/// This is intentionally governed by the current committee. If the pending
/// next committee cannot complete DKG/key rotation or cannot produce the
/// `end_reconfig` certificate, the last committed committee is the only
/// committee with stable on-chain voting power.
module hashi::abort_reconfig;

use hashi::{hashi::Hashi, proposal, reconfig};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 6667;

public struct AbortReconfig has drop, store {}

public fun propose(
    hashi: &mut Hashi,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, AbortReconfig {}, THRESHOLD_BPS, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &TxContext) {
    let AbortReconfig {} = proposal::execute(hashi, proposal_id, clock);
    reconfig::abort_reconfig(hashi, ctx);
}
