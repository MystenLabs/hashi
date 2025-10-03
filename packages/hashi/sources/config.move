// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::config;
use std::type_name::TypeName;
use sui::package::{UpgradeCap, UpgradeTicket};
use sui::vec_map::VecMap;

public struct Config has store {
    proposal_thresholds: VecMap<TypeName, u64>,
    upgrade_cap: UpgradeCap,
}

public fun proposal_threshold(self: &Config, proposal_type: &TypeName): u64 {
    *self.proposal_thresholds.get(proposal_type)
}

public(package) fun authorize_upgrade(
    self: &mut Config,
    digest: vector<u8>,
): UpgradeTicket {
    let policy = sui::package::upgrade_policy(&self.upgrade_cap);
    sui::package::authorize_upgrade(
        &mut self.upgrade_cap,
        policy,
        digest,
    )
}

public(package) fun register_proposal_type(
    self: &mut Config,
    proposal_type: TypeName,
    threshold: u64,
) {
    self.proposal_thresholds.insert(proposal_type, threshold);
}
