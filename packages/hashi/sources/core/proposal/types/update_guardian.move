// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::update_guardian;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 6667;

public struct UpdateGuardian has copy, drop, store {
    url: String,
}

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    url: String,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
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
