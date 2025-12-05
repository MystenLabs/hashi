// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::config;

use hashi::config_value::{Self, Value};
use std::string::String;
use sui::vec_map::{Self, VecMap};

const PACKAGE_VERSION: u64 = 1;

//
// Config Key's
//

const VERSION_KEY: vector<u8> = b"version";
const DEPOSIT_FEE_KEY: vector<u8> = b"deposit_fee";
const PAUSED_KEY: vector<u8> = b"paused";

public struct Config has store {
    config: VecMap<String, Value>,
}

fun get(self: &Config, key: vector<u8>): Value {
    *self.config.get(&key.to_string())
}

/// Inserts or updates a configuration in the config map.
/// If a configuration with the same key already exists, it is replaced.
fun upsert(self: &mut Config, key: vector<u8>, value: Value) {
    let key = key.to_string();

    if (self.config.contains(&key)) {
        self.config.remove(&key);
    };

    self.config.insert(key, value);
}

public(package) fun version(self: &Config): u64 {
    self.get(VERSION_KEY).as_u64()
}

/// Assert that the package version is the current version.
/// Used to disallow usage with old contract versions.
public(package) fun assert_version(self: &Config) {
    assert!(self.version() == PACKAGE_VERSION)
}

public(package) fun deposit_fee(self: &Config): u64 {
    self.get(DEPOSIT_FEE_KEY).as_u64()
}

public(package) fun set_deposit_fee(self: &mut Config, fee: u64) {
    self.upsert(DEPOSIT_FEE_KEY, config_value::new_u64(fee))
}

public(package) fun paused(self: &Config): bool {
    self.get(PAUSED_KEY).as_bool()
}

public(package) fun set_paused(self: &mut Config, paused: bool) {
    self.upsert(PAUSED_KEY, config_value::new_bool(paused))
}

//
// Constructor
//

public(package) fun create(): Config {
    let mut config = Config {
        config: vec_map::empty(),
    };

    // Set initial config values
    config.upsert(VERSION_KEY, config_value::new_u64(PACKAGE_VERSION));
    config.upsert(PAUSED_KEY, config_value::new_bool(true));
    config.upsert(DEPOSIT_FEE_KEY, config_value::new_u64(0));

    config
}
