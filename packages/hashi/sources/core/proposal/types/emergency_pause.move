// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Emergency pause/unpause governance module.
///
/// A single proposal type that can either pause or unpause the bridge.
/// Pausing requires 51% quorum; unpausing requires ~67% quorum.
module hashi::emergency_pause;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

public struct EmergencyPause has copy, drop, store {
    pause: bool,
}

public fun propose(
    hashi: &mut Hashi,
    pause: bool,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    let threshold = if (pause) {
        hashi.config().emergency_pause_threshold_bps()
    } else {
        hashi.config().emergency_unpause_threshold_bps()
    };
    proposal::create(hashi, EmergencyPause { pause }, threshold, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi.config().assert_version_enabled();
    let EmergencyPause { pause } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().set_paused(pause);
}
