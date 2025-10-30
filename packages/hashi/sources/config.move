// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::config;
use std::type_name::{Self, TypeName};
use sui::package::{UpgradeCap, UpgradeTicket};
use sui::vec_map::VecMap;

#[error]
const EProposalThresholdNotSet: vector<u8> = b"Proposal threshold not set";

// TODO: do we want to store all seq_num for each proposal type separately?
// or use a global seq_num for all proposal types?
// TODO: enable future config options to be added via dynamic fields
public struct Config has store {
    proposal_threshold_bps: VecMap<TypeName, u64>,
    upgrade_cap: UpgradeCap,
    seq_num: u64,
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

public(package) fun seq_num(self: &Config): u64 {
    self.seq_num
}

public(package) fun set_proposal_threshold<T>(self: &mut Config, bps: u64) {
    self.proposal_threshold_bps.insert(type_name::with_defining_ids<T>(), bps);
}

public(package) fun proposal_threshold_for<T>(self: &Config): u64 {
    let t = type_name::with_defining_ids<T>();
    assert!(self.proposal_threshold_bps.contains(&t), EProposalThresholdNotSet);
    *self.proposal_threshold_bps.get(&t)
}
