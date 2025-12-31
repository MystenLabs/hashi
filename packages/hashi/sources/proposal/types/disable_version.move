// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::disable_version;

use hashi::{hashi::Hashi, proposal::{Self, Proposal}};
use std::string::String;
use sui::vec_map::VecMap;

const THRESHOLD_BPS: u64 = 10000;

public struct DisableVersion has drop, store {
    version: u64,
}

public fun propose(
    hashi: &mut Hashi,
    version: u64,
    metadata: VecMap<String, String>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, DisableVersion { version }, THRESHOLD_BPS, metadata, ctx)
}

public fun execute(hashi: &mut Hashi, proposal: Proposal<DisableVersion>) {
    let DisableVersion { version } = proposal.execute(hashi);
    hashi.config_mut().disable_version(version);
}
