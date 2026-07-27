// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for disabling a package version. Once quorum is
/// reached, `execute` marks the proposed version as disabled in `versioning`,
/// so every entry point guarded by `assert_version_enabled` stops serving
/// calls made through that version — the recovery lever if an upgraded
/// package turns out to be broken.
module hashi::disable_version;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Structs ~~~~~~~

public struct DisableVersion has copy, drop, store {
    version: u64,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    version: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    proposal::create(
        hashi,
        validator_address,
        DisableVersion { version },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let DisableVersion { version } = proposal::execute(hashi, proposal_id, clock);
    hashi.versioning_mut().disable_version(version);
}
