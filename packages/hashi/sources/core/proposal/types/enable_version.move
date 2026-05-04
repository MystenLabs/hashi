// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::enable_version;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 10000;

public struct EnableVersion has copy, drop, store {
    version: u64,
}

public fun propose(
    hashi: &mut Hashi,
    version: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, EnableVersion { version }, THRESHOLD_BPS, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let EnableVersion { version } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().enable_version(version);
}
