// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A general-purpose, typed key-value configuration store: a map from string
/// keys to `config_value::Value`s, with domain-specific accessors layered on
/// top (pause state, guardian, emergency thresholds). Chain-specific
/// configuration (e.g. BTC fee parameters) lives in separate modules that use
/// get/upsert.
///
/// `Config` has `copy, drop, store` and carries no policy of its own (no
/// versioning, no upgrade authority — those live in `versioning`), so it can be
/// embedded by value wherever a bag of settings is needed: it backs the
/// package's global config and is also pinned per-epoch onto a `Committee`.
module hashi::config;

use hashi::{config_registry::{Self, ConfigRegistry}, config_value::{Self, Value}};
use std::string::String;
use sui::vec_map::{Self, VecMap};

// ~~~~~~~ Constants ~~~~~~~

const PAUSED_KEY: vector<u8> = b"paused";
const GUARDIAN_URL_KEY: vector<u8> = b"guardian_url";
const GUARDIAN_BTC_PUBLIC_KEY_KEY: vector<u8> = b"guardian_btc_public_key";
const GUARDIAN_BTC_PUBLIC_KEY_LEN: u64 = 32;
const EMERGENCY_PAUSE_THRESHOLD_BPS_KEY: vector<u8> = b"governance_emergency_pause_threshold_bps";
const EMERGENCY_UNPAUSE_THRESHOLD_BPS_KEY: vector<u8> =
    b"governance_emergency_unpause_threshold_bps";

// ~~~~~~~ Errors ~~~~~~~

#[error(code = 3)]
const EBadGuardianBtcPublicKeyLength: vector<u8> = b"Guardian BTC public key must be 32 bytes";
#[error(code = 4)]
const EGuardianBtcPublicKeyImmutable: vector<u8> =
    b"Guardian BTC public key cannot be changed once set";

// ~~~~~~~ Structs ~~~~~~~

public struct Config has copy, drop, store {
    config: VecMap<String, Value>,
}

// ~~~~~~~ Package Functions ~~~~~~~

/// Create the global config with core defaults only. Chain-specific defaults
/// (e.g. BTC fees) are initialized separately via btc_config::init_defaults.
public(package) fun create(): Config {
    let mut config = empty();

    // Core defaults
    config.upsert(PAUSED_KEY, config_value::new_bool(false));
    config.upsert(EMERGENCY_PAUSE_THRESHOLD_BPS_KEY, config_value::new_u64(500));
    config.upsert(EMERGENCY_UNPAUSE_THRESHOLD_BPS_KEY, config_value::new_u64(6667));

    config
}

/// Create an empty store. Used to build a pinned snapshot (e.g. a `Committee`'s
/// MPC parameters); the global config is built via `create`.
public(package) fun empty(): Config {
    Config { config: vec_map::empty() }
}

/// Register the specs for the keys `create` seeds. `paused` is non-removable
/// because `paused()` reads it with `get` (removal would abort every
/// `assert_unpaused`); the emergency thresholds are basis points.
public(package) fun register_core_keys(registry: &mut ConfigRegistry) {
    registry.register(
        PAUSED_KEY,
        config_registry::new_spec(false, true, false, option::none(), option::none(), option::none()),
    );
    registry.register(
        EMERGENCY_PAUSE_THRESHOLD_BPS_KEY,
        config_registry::new_spec(
            false,
            true,
            false,
            option::none(),
            option::some(10000),
            option::none(),
        ),
    );
    registry.register(
        EMERGENCY_UNPAUSE_THRESHOLD_BPS_KEY,
        config_registry::new_spec(
            false,
            true,
            false,
            option::none(),
            option::some(10000),
            option::none(),
        ),
    );
}

/// Register the specs for the guardian keys `finish_publish` sets. The BTC
/// public key is write-once at the registry layer too: `update_config` must
/// never bypass `set_guardian_btc_public_key`'s immutability or length check.
public(package) fun register_guardian_keys(registry: &mut ConfigRegistry) {
    registry.register(
        GUARDIAN_URL_KEY,
        config_registry::new_spec(false, true, false, option::none(), option::none(), option::none()),
    );
    registry.register(
        GUARDIAN_BTC_PUBLIC_KEY_KEY,
        config_registry::new_spec(
            false,
            false,
            false,
            option::none(),
            option::none(),
            option::some(GUARDIAN_BTC_PUBLIC_KEY_LEN),
        ),
    );
}

/// Read a config value by key. Exposed to other modules in the package
/// (e.g. btc_config) so they can define domain-specific accessors.
public(package) fun get(self: &Config, key: vector<u8>): Value {
    *self.config.get(&key.to_string())
}

public(package) fun try_get(self: &Config, key: vector<u8>): Option<Value> {
    let key = key.to_string();
    if (self.config.contains(&key)) {
        option::some(*self.config.get(&key))
    } else {
        option::none()
    }
}

/// Returns true if `key` is present.
public(package) fun contains(self: &Config, key: vector<u8>): bool {
    self.config.contains(&key.to_string())
}

/// Insert or update a config value. Exposed to other modules in the package
/// (e.g. btc_config) so they can define domain-specific setters.
public(package) fun upsert(self: &mut Config, key: vector<u8>, value: Value) {
    let key = key.to_string();

    if (self.config.contains(&key)) {
        self.config.remove(&key);
    };

    self.config.insert(key, value);
}

/// Remove a key. Aborts if absent — callers guard existence via the registry
/// (registered => present).
public(package) fun remove(self: &mut Config, key: &String) {
    self.config.remove(key);
}

/// Returns true when `key` exists in the config and `value` has the
/// same type as the existing entry.
public(package) fun is_valid_config_update(self: &Config, key: &String, value: &Value): bool {
    if (!self.config.contains(key)) return false;
    self.config.get(key).same_variant(value)
}

// === Core Accessors ===

public(package) fun paused(self: &Config): bool {
    self.get(PAUSED_KEY).as_bool()
}

public(package) fun set_paused(self: &mut Config, paused: bool) {
    self.upsert(PAUSED_KEY, config_value::new_bool(paused))
}

public(package) fun guardian_url(self: &Config): Option<String> {
    self.try_get(GUARDIAN_URL_KEY).map!(|v| v.as_string())
}

public(package) fun guardian_btc_public_key(self: &Config): Option<vector<u8>> {
    self.try_get(GUARDIAN_BTC_PUBLIC_KEY_KEY).map!(|v| v.as_bytes())
}

/// Set the guardian's URL. The ephemeral signing key is intentionally not pinned
/// onchain; the node authenticates the guardian over TLS + the immutable BTC key.
public(package) fun set_guardian_url(self: &mut Config, url: String) {
    self.upsert(GUARDIAN_URL_KEY, config_value::new_string(url));
}

/// Pin the guardian's x-only BTC pubkey (32 bytes). Immutable once set —
/// rotating it would invalidate every 2-of-2 deposit address derived against it.
public(package) fun set_guardian_btc_public_key(self: &mut Config, btc_public_key: vector<u8>) {
    assert!(btc_public_key.length() == GUARDIAN_BTC_PUBLIC_KEY_LEN, EBadGuardianBtcPublicKeyLength);
    let existing = self.guardian_btc_public_key();
    if (existing.is_some()) {
        assert!(existing.destroy_some() == btc_public_key, EGuardianBtcPublicKeyImmutable);
    } else {
        existing.destroy_none();
    };
    self.upsert(GUARDIAN_BTC_PUBLIC_KEY_KEY, config_value::new_bytes(btc_public_key));
}

public(package) fun emergency_pause_threshold_bps(self: &Config): u64 {
    self.try_get(EMERGENCY_PAUSE_THRESHOLD_BPS_KEY).map!(|v| v.as_u64()).destroy_or!(500)
}

public(package) fun emergency_unpause_threshold_bps(self: &Config): u64 {
    self.try_get(EMERGENCY_UNPAUSE_THRESHOLD_BPS_KEY).map!(|v| v.as_u64()).destroy_or!(6667)
}
