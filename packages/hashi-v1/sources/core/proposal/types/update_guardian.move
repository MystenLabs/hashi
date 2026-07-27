// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for updating the guardian's URL in the global config.
/// Only the URL is governable: the guardian's BTC public key is immutable once
/// set (rotating it would invalidate derived deposit addresses), and the
/// ephemeral signing key is intentionally not pinned on-chain — nodes
/// authenticate the guardian over TLS plus the immutable BTC key.
module hashi::update_guardian;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Structs ~~~~~~~

public struct UpdateGuardian has copy, drop, store {
    url: String,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    url: String,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    proposal::create(
        hashi,
        validator_address,
        UpdateGuardian { url },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let UpdateGuardian { url } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().set_guardian_url(url);
}
