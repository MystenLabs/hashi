// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::enable_version;

use hashi::{hashi::Hashi, proposal::{Self, Proposal}};
use std::string::String;
use sui::vec_map::VecMap;

const THRESHOLD_BPS: u64 = 10000;

public struct EnableVersion has drop, store {
    version: u64,
}

public fun propose(
    hashi: &mut Hashi,
    version: u64,
    metadata: VecMap<String, String>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, EnableVersion { version }, THRESHOLD_BPS, metadata, ctx)
}

public fun execute(hashi: &mut Hashi, proposal: Proposal<EnableVersion>) {
    let EnableVersion { version } = proposal.execute(hashi);
    hashi.config_mut().enable_version(version);
}
