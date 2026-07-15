// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposals for the config-key lifecycle: adding a key (with its
/// spec), replacing a key's spec, and removing a key. One module for the
/// three actions because they share one object of governance — the key
/// registry — while `update_config` (changing values of existing keys) stays
/// separate so its unknown-key typo-guard is untouched: adding a key is never
/// a side effect of updating one.
module hashi::config_keys;

use hashi::{config_registry::{Self, ConfigKeySpec}, config_value::Value, hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EKeyAlreadyExists: vector<u8> = b"Config key already exists";
#[error]
const EValueViolatesSpec: vector<u8> = b"Proposed value violates the key's spec";

// ~~~~~~~ Structs ~~~~~~~

public struct AddConfigKey has copy, drop, store {
    key: String,
    value: Value,
    spec: ConfigKeySpec,
}

public struct UpdateConfigKeySpec has copy, drop, store {
    key: String,
    spec: ConfigKeySpec,
}

public struct RemoveConfigKey has copy, drop, store {
    key: String,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose_add(
    hashi: &mut Hashi,
    validator_address: address,
    key: String,
    value: Value,
    pinned: bool,
    updatable: bool,
    removable: bool,
    min: Option<u64>,
    max: Option<u64>,
    max_len: Option<u64>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    // Specs only exist via `new_spec`, so the write-once/removable invariant
    // holds for every spec that can reach `execute_add`.
    let spec = config_registry::new_spec(pinned, updatable, removable, min, max, max_len);
    assert!(spec.value_in_constraints(&value), EValueViolatesSpec);
    proposal::create(
        hashi,
        validator_address,
        AddConfigKey { key, value, spec },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute_add(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let AddConfigKey { key, value, spec } = proposal::execute(hashi, proposal_id, clock);
    // Both stores must agree the key is new (registered => present).
    assert!(!hashi.config().contains(*key.as_bytes()), EKeyAlreadyExists);
    hashi.config_registry_mut().register(*key.as_bytes(), spec);
    hashi.config_mut().upsert(*key.as_bytes(), value);
}

public fun propose_update_spec(
    hashi: &mut Hashi,
    validator_address: address,
    key: String,
    pinned: bool,
    updatable: bool,
    removable: bool,
    min: Option<u64>,
    max: Option<u64>,
    max_len: Option<u64>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    let spec = config_registry::new_spec(pinned, updatable, removable, min, max, max_len);
    proposal::create(
        hashi,
        validator_address,
        UpdateConfigKeySpec { key, spec },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute_update_spec(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let UpdateConfigKeySpec { key, spec } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_registry_mut().update_spec(&key, spec);
}

public fun propose_remove(
    hashi: &mut Hashi,
    validator_address: address,
    key: String,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    proposal::create(
        hashi,
        validator_address,
        RemoveConfigKey { key },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute_remove(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let RemoveConfigKey { key } = proposal::execute(hashi, proposal_id, clock);
    // Registry-side asserts registered + removable; config-side removal then
    // cannot miss (registered => present). Past epochs' pinned snapshots are
    // immutable and unaffected.
    hashi.config_registry_mut().remove(&key);
    hashi.config_mut().remove(&key);
}
