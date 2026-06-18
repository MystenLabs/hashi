// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::update_guardian;

use hashi::{config, hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 6667;

public struct UpdateGuardian has copy, drop, store {
    url: String,
    git_revision: String,
    pcr0: vector<u8>,
}

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    url: String,
    git_revision: String,
    pcr0: vector<u8>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    config::assert_valid_pcr0(&pcr0);
    proposal::create(
        hashi,
        validator_address,
        UpdateGuardian { url, git_revision, pcr0 },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let UpdateGuardian { url, git_revision, pcr0 } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().set_guardian(url, git_revision, pcr0);
}
