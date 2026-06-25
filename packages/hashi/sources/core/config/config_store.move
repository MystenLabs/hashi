// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A general-purpose, typed key-value store. This is the reusable core of the
/// package's configuration: a map from string keys to `config_value::Value`s,
/// with no policy of its own (no versioning, no upgrade authority, no
/// domain-specific keys).
///
/// It is deliberately self-contained and has `copy, drop, store` so it can be
/// embedded by value in other structs that need a pinned bag of settings
/// (e.g. the per-epoch MPC parameters carried on a `Committee`), in addition
/// to backing the package's global `config::Config`.
///
/// Note on serialization: a struct wrapping a single field is BCS-transparent
/// (a struct is just the concatenation of its fields, with no wrapper bytes),
/// so a `ConfigStore` serializes identically to the bare `VecMap` it wraps.
/// When a `ConfigStore` is embedded in a signed struct, the BCS bytes depend
/// on the entries' insertion order, so callers that pin a snapshot must insert
/// a fixed key set in a fixed, canonical order (see `mpc_config`).
module hashi::config_store;

use hashi::config_value::Value;
use std::string::String;
use sui::vec_map::{Self, VecMap};

public struct ConfigStore has copy, drop, store {
    entries: VecMap<String, Value>,
}

/// Create an empty store.
public(package) fun empty(): ConfigStore {
    ConfigStore { entries: vec_map::empty() }
}

/// Read a config value by key. Aborts if the key is absent.
public(package) fun get(self: &ConfigStore, key: vector<u8>): Value {
    *self.entries.get(&key.to_string())
}

/// Read a config value by key, or `none` if absent.
public(package) fun try_get(self: &ConfigStore, key: vector<u8>): Option<Value> {
    let key = key.to_string();
    if (self.entries.contains(&key)) {
        option::some(*self.entries.get(&key))
    } else {
        option::none()
    }
}

/// Returns true if `key` is present.
public(package) fun contains(self: &ConfigStore, key: vector<u8>): bool {
    self.entries.contains(&key.to_string())
}

/// Insert or update a config value.
public(package) fun upsert(self: &mut ConfigStore, key: vector<u8>, value: Value) {
    let key = key.to_string();

    if (self.entries.contains(&key)) {
        self.entries.remove(&key);
    };

    self.entries.insert(key, value);
}

/// Returns true when `key` exists in the store and `value` has the
/// same type as the existing entry.
public(package) fun is_valid_update(self: &ConfigStore, key: &String, value: &Value): bool {
    if (!self.entries.contains(key)) return false;
    self.entries.get(key).same_variant(value)
}
