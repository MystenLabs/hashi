// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governed metadata about config keys: whether a key is epoch-pinned onto
/// committees, whether governance may update or remove it, and data-driven
/// value constraints. The registry is the single source of truth for
/// config-update validation — a key without a registry entry cannot be
/// updated by governance at all — so adding a parameter is a data change,
/// not a package change.
module hashi::config_registry;

use hashi::config_value::Value;
use std::string::String;
use sui::vec_map::{Self, VecMap};

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EWriteOnceMustNotBeRemovable: vector<u8> =
    b"A non-updatable (write-once) key must not be removable: remove + re-add would bypass write-once";
#[error]
const EKeyAlreadyRegistered: vector<u8> = b"Config key is already registered";
#[error]
const EKeyNotRegistered: vector<u8> = b"Config key is not registered";
#[error]
const EKeyNotRemovable: vector<u8> = b"Config key is not removable";

// ~~~~~~~ Structs ~~~~~~~

public struct ConfigKeySpec has copy, drop, store {
    /// Snapshot this key into every epoch's committee config at start_reconfig.
    pinned: bool,
    /// Governance (update_config) may change this key's value; false = write-once.
    updatable: bool,
    /// Governance may remove this key from the config and registry.
    removable: bool,
    /// Inclusive range, enforced only for U64 values.
    min: Option<u64>,
    max: Option<u64>,
    /// Maximum length, enforced only for Bytes/String values.
    max_len: Option<u64>,
    /// Extension slot for future validation metadata; the spec shape itself is
    /// frozen at publish, so it carries its own open-keys escape hatch.
    extensions: VecMap<String, Value>,
}

public struct ConfigRegistry has copy, drop, store {
    specs: VecMap<String, ConfigKeySpec>,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun empty(): ConfigRegistry {
    ConfigRegistry { specs: vec_map::empty() }
}

public(package) fun new_spec(
    pinned: bool,
    updatable: bool,
    removable: bool,
    min: Option<u64>,
    max: Option<u64>,
    max_len: Option<u64>,
): ConfigKeySpec {
    assert!(updatable || !removable, EWriteOnceMustNotBeRemovable);
    ConfigKeySpec {
        pinned,
        updatable,
        removable,
        min,
        max,
        max_len,
        extensions: vec_map::empty(),
    }
}

public(package) fun register(self: &mut ConfigRegistry, key: vector<u8>, spec: ConfigKeySpec) {
    let key = key.to_string();
    assert!(!self.specs.contains(&key), EKeyAlreadyRegistered);
    self.specs.insert(key, spec);
}

/// Replace a registered key's spec. The value's type cannot change through
/// this path (specs carry no type; the entry's `Value` variant stays), and a
/// narrowed range does not retro-invalidate the current value — constraints
/// are checked at update time only.
public(package) fun update_spec(self: &mut ConfigRegistry, key: &String, spec: ConfigKeySpec) {
    assert!(self.specs.contains(key), EKeyNotRegistered);
    // In place: the registry's insertion order is the pinned snapshot's
    // canonical order, so a spec update must not move the key.
    *self.specs.get_mut(key) = spec;
}

/// Deregister a key. Requires `removable`, which `new_spec` guarantees is
/// never set on a write-once key — so remove-then-re-add cannot bypass
/// write-once.
public(package) fun remove(self: &mut ConfigRegistry, key: &String) {
    assert!(self.specs.contains(key), EKeyNotRegistered);
    assert!(self.specs.get(key).removable, EKeyNotRemovable);
    self.specs.remove(key);
}

public(package) fun contains(self: &ConfigRegistry, key: &String): bool {
    self.specs.contains(key)
}

/// Whether governance may set `key` to `value`: the key must be registered
/// and updatable, and the value must satisfy the spec's constraints. The
/// value's type-stability against the existing entry is enforced separately
/// (`config::is_valid_config_update`).
public(package) fun is_valid_update(self: &ConfigRegistry, key: &String, value: &Value): bool {
    if (!self.specs.contains(key)) return false;
    let spec = self.specs.get(key);
    spec.updatable && spec.value_in_constraints(value)
}

// ~~~~~~~ Spec Accessors ~~~~~~~

public(package) fun pinned(spec: &ConfigKeySpec): bool {
    spec.pinned
}

public(package) fun updatable(spec: &ConfigKeySpec): bool {
    spec.updatable
}

public(package) fun removable(spec: &ConfigKeySpec): bool {
    spec.removable
}

public(package) fun value_in_constraints(spec: &ConfigKeySpec, value: &Value): bool {
    if (spec.min.is_some() || spec.max.is_some()) {
        if (!value.is_u64()) return false;
        let v = (*value).as_u64();
        if (spec.min.is_some() && v < *spec.min.borrow()) return false;
        if (spec.max.is_some() && v > *spec.max.borrow()) return false;
    };
    if (spec.max_len.is_some()) {
        let max_len = *spec.max_len.borrow();
        if (value.is_bytes()) {
            if ((*value).as_bytes().length() > max_len) return false;
        } else if (value.is_string()) {
            if ((*value).as_string().length() > max_len) return false;
        };
    };
    true
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun specs(self: &ConfigRegistry): &VecMap<String, ConfigKeySpec> {
    &self.specs
}
