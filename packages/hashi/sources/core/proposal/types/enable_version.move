// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for enabling a package version. Once quorum is
/// reached, `execute` marks the proposed version as enabled in `versioning`,
/// re-admitting calls made through that version at entry points guarded by
/// `assert_version_enabled` — the counterpart to `disable_version` for
/// re-activating a previously disabled version.
module hashi::enable_version;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Structs ~~~~~~~

public struct EnableVersion has copy, drop, store {
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
        EnableVersion { version },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let EnableVersion { version } = proposal::execute(hashi, proposal_id, clock);
    hashi.versioning_mut().enable_version(version);
}
