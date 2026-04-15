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

const PAUSE_THRESHOLD_BPS: u64 = 5100; // 51% - low quorum for emergencies
const UNPAUSE_THRESHOLD_BPS: u64 = 6667; // ~2/3 - higher bar for resuming

public struct EmergencyPause has drop, store {
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
    let threshold = if (pause) { PAUSE_THRESHOLD_BPS } else { UNPAUSE_THRESHOLD_BPS };
    proposal::create(hashi, EmergencyPause { pause }, threshold, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi.config().assert_version_enabled();
    let EmergencyPause { pause } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().set_paused(pause);
}
