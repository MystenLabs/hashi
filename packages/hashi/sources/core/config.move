// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Core configuration: versioning, pause state, upgrade management, and
/// generic key-value config store. Chain-specific configuration (e.g. BTC
/// fee parameters) lives in separate modules that use get/upsert.
module hashi::config;

use hashi::config_value::{Self, Value};
use std::string::String;
use sui::{
    package::{Self, UpgradeCap, UpgradeTicket, UpgradeReceipt},
    vec_map::{Self, VecMap},
    vec_set::{Self, VecSet}
};

const PACKAGE_VERSION: u64 = 1;

#[error(code = 0)]
const EVersionDisabled: vector<u8> = b"Version disabled";
#[error(code = 1)]
const EDisableCurrentVersion: vector<u8> = b"Cannot disable current version";
#[error(code = 2)]
const EInvalidConfigEntry: vector<u8> = b"Unknown config key or wrong value type";

//
// Config keys (core)
//

const PAUSED_KEY: vector<u8> = b"paused";

//
// Config keys (BTC) — kept here for is_valid_config_entry validation.
// Accessors and calculation functions live in btc_config.move.
//

const DEPOSIT_FEE_KEY: vector<u8> = b"deposit_fee";
const WITHDRAWAL_FEE_BTC_KEY: vector<u8> = b"withdrawal_fee_btc";
const MAX_FEE_RATE_KEY: vector<u8> = b"max_fee_rate";
const INPUT_BUDGET_KEY: vector<u8> = b"input_budget";
const BITCOIN_CONFIRMATION_THRESHOLD_KEY: vector<u8> = b"bitcoin_confirmation_threshold";
const WITHDRAWAL_CANCELLATION_COOLDOWN_KEY: vector<u8> = b"withdrawal_cancellation_cooldown_ms";

public struct Config has store {
    config: VecMap<String, Value>,
    enabled_versions: VecSet<u64>,
    upgrade_cap: Option<UpgradeCap>,
}

/// Read a config value by key. Exposed to other modules in the package
/// (e.g. btc_config) so they can define domain-specific accessors.
public(package) fun get(self: &Config, key: vector<u8>): Value {
    *self.config.get(&key.to_string())
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

/// Validated upsert: accepts a key string and a Value, validates that
/// known keys receive the expected value type, and rejects unknown keys.
/// This is the entry point used by the generic `UpdateConfig` proposal.
public(package) fun upsert_checked(self: &mut Config, key: String, value: Value) {
    assert!(is_valid_config_entry(&key, &value), EInvalidConfigEntry);
    let bytes = *key.as_bytes();
    self.upsert(bytes, value);
}

/// Returns true when `key` is a recognised config key and `value`
/// carries the type that key expects.
#[allow(implicit_const_copy)]
fun is_valid_config_entry(key: &String, value: &Value): bool {
    let k = key.as_bytes();
    // Core keys
    if (k == &PAUSED_KEY) {
        value.is_bool()
    } else if (k == &DEPOSIT_FEE_KEY) {
        // BTC bridge keys (accessors live in btc_config.move)
        value.is_u64()
    } else if (k == &WITHDRAWAL_FEE_BTC_KEY) {
        value.is_u64()
    } else if (k == &MAX_FEE_RATE_KEY) {
        value.is_u64()
    } else if (k == &INPUT_BUDGET_KEY) {
        value.is_u64()
    } else if (k == &BITCOIN_CONFIRMATION_THRESHOLD_KEY) {
        value.is_u64()
    } else if (k == &WITHDRAWAL_CANCELLATION_COOLDOWN_KEY) {
        value.is_u64()
    } else {
        false
    }
}

// ======== Core Accessors ========

/// Assert that the package version is the current version.
#[allow(implicit_const_copy)]
public(package) fun assert_version_enabled(self: &Config) {
    assert!(self.enabled_versions.contains(&PACKAGE_VERSION), EVersionDisabled);
}

public(package) fun paused(self: &Config): bool {
    self.get(PAUSED_KEY).as_bool()
}

public(package) fun set_paused(self: &mut Config, paused: bool) {
    self.upsert(PAUSED_KEY, config_value::new_bool(paused))
}

// ======== Version Management ========

public(package) fun disable_version(self: &mut Config, version: u64) {
    assert!(version != PACKAGE_VERSION, EDisableCurrentVersion);
    self.enabled_versions.remove(&version);
}

public(package) fun enable_version(self: &mut Config, version: u64) {
    self.enabled_versions.insert(version);
}

// ======== Upgrade Management ========

public(package) fun authorize_upgrade(self: &mut Config, digest: vector<u8>): UpgradeTicket {
    let policy = sui::package::upgrade_policy(self.upgrade_cap.borrow());
    sui::package::authorize_upgrade(
        self.upgrade_cap.borrow_mut(),
        policy,
        digest,
    )
}

public(package) fun commit_upgrade(self: &mut Config, receipt: UpgradeReceipt) {
    package::commit_upgrade(self.upgrade_cap.borrow_mut(), receipt);
    let version = self.upgrade_cap.borrow().version();
    self.enabled_versions.insert(version);
}

public(package) fun set_upgrade_cap(self: &mut Config, upgrade_cap: UpgradeCap) {
    self.upgrade_cap.fill(upgrade_cap);
}

public(package) fun upgrade_cap(self: &Config): &UpgradeCap {
    self.upgrade_cap.borrow()
}

// ======== Constructor ========

/// Create a Config with core defaults only. Chain-specific defaults
/// (e.g. BTC fees) are initialized separately via btc_config::init_defaults.
public(package) fun create(): Config {
    let mut config = Config {
        config: vec_map::empty(),
        enabled_versions: vec_set::from_keys(vector[PACKAGE_VERSION]),
        upgrade_cap: option::none(),
    };

    // Core defaults
    config.upsert(PAUSED_KEY, config_value::new_bool(false));

    config
}
