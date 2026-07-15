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
#[error]
const EInvalidScheduledEntry: vector<u8> =
    b"Scheduled entry must satisfy the same checks as an immediate update";
#[error]
const ENotPinnedKey: vector<u8> =
    b"Only epoch-pinned keys can be scheduled: a global key has no epoch boundary to anchor to";
#[error]
const EActivationNotInFuture: vector<u8> = b"Activation epoch must be after the current epoch";

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

public struct ScheduleConfigUpdate has copy, drop, store {
    key: String,
    value: Value,
    activate_at_epoch: u64,
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
    // A scheduled update for a removed key must not resurrect it at commit.
    if (hashi.pending_config_updates().contains(&key)) {
        hashi.pending_config_updates_mut().remove(&key);
    };
}

public fun propose_schedule(
    hashi: &mut Hashi,
    validator_address: address,
    key: String,
    value: Value,
    activate_at_epoch: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    proposal::create(
        hashi,
        validator_address,
        ScheduleConfigUpdate { key, value, activate_at_epoch },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute_schedule(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let ScheduleConfigUpdate { key, value, activate_at_epoch } = proposal::execute(
        hashi,
        proposal_id,
        clock,
    );
    // Validated at execute time (state may drift between propose and quorum),
    // with the same gates as an immediate update.
    assert!(
        hashi.config().is_valid_config_update(&key, &value)
            && hashi.config_registry().is_valid_update(&key, &value),
        EInvalidScheduledEntry,
    );
    assert!(hashi.config_registry().is_pinned(&key), ENotPinnedKey);
    assert!(activate_at_epoch > hashi.committee_set().epoch(), EActivationNotInFuture);
    // Re-proposing replaces any earlier schedule for the key.
    if (hashi.pending_config_updates().contains(&key)) {
        hashi.pending_config_updates_mut().remove(&key);
    };
    hashi
        .pending_config_updates_mut()
        .insert(key, config_registry::new_pending_update(value, activate_at_epoch));
}
