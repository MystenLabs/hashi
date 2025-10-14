// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::config;
use std::type_name::{Self, TypeName};
use sui::package::{UpgradeCap, UpgradeTicket};
use sui::vec_map::VecMap;

// TODO: do we want to store all seq_num for each proposal type separately?
// or use a global seq_num for all proposal types?
public struct Config has store {
    proposal_thresholds: VecMap<TypeName, u64>,
    proposal_sequential_execution: VecMap<TypeName, bool>,
    latest_proposal_executed: VecMap<TypeName, u64>,
    upgrade_cap: UpgradeCap,
    seq_num: u64,
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
    sequential_execution: bool,
) {
    self.proposal_thresholds.insert(proposal_type, threshold);
    self
        .proposal_sequential_execution
        .insert(proposal_type, sequential_execution);
}

public(package) fun seq_num(self: &Config): u64 {
    self.seq_num
}

public(package) fun increment_seq_num<T>(self: &mut Config) {
    self.seq_num = self.seq_num + 1;
    self
        .latest_proposal_executed
        .insert(type_name::with_defining_ids<T>(), self.seq_num);
}
