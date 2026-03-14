// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::update_config;

use hashi::{config_value::Value, hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 6667;

public struct UpdateConfig has drop, store {
    key: String,
    value: Value,
}

public fun propose(
    hashi: &mut Hashi,
    key: String,
    value: Value,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, UpdateConfig { key, value }, THRESHOLD_BPS, metadata, clock, ctx)
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let UpdateConfig { key, value } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().upsert_checked(key, value);
}
