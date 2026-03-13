// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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

//
// Config Key's
//

const BITCOIN_CHAIN_ID_KEY: vector<u8> = b"bitcoin_chain_id";
const DEPOSIT_FEE_KEY: vector<u8> = b"deposit_fee";
const WITHDRAWAL_FEE_BTC_KEY: vector<u8> = b"withdrawal_fee_btc";
const WITHDRAWAL_MINIMUM_KEY: vector<u8> = b"withdrawal_minimum";
const BITCOIN_CONFIRMATION_THRESHOLD_KEY: vector<u8> = b"bitcoin_confirmation_threshold";
const PAUSED_KEY: vector<u8> = b"paused";
const WITHDRAWAL_CANCELLATION_COOLDOWN_KEY: vector<u8> = b"withdrawal_cancellation_cooldown_ms";

public struct Config has store {
    config: VecMap<String, Value>,
    enabled_versions: VecSet<u64>,
    upgrade_cap: Option<UpgradeCap>,
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

/// Assert that the package version is the current version.
/// Used to disallow usage with old contract versions.
#[allow(implicit_const_copy)]
public(package) fun assert_version_enabled(self: &Config) {
    assert!(self.enabled_versions.contains(&PACKAGE_VERSION), EVersionDisabled);
}

public(package) fun bitcoin_chain_id(self: &Config): address {
    self.get(BITCOIN_CHAIN_ID_KEY).as_address()
}

public(package) fun set_bitcoin_chain_id(self: &mut Config, bitcoin_chain_id: address) {
    self.upsert(BITCOIN_CHAIN_ID_KEY, config_value::new_address(bitcoin_chain_id))
}

public(package) fun deposit_fee(self: &Config): u64 {
    self.get(DEPOSIT_FEE_KEY).as_u64()
}

public(package) fun set_deposit_fee(self: &mut Config, fee: u64) {
    self.upsert(DEPOSIT_FEE_KEY, config_value::new_u64(fee))
}

public(package) fun withdrawal_fee_btc(self: &Config): u64 {
    self.get(WITHDRAWAL_FEE_BTC_KEY).as_u64()
}

public(package) fun set_withdrawal_fee_btc(self: &mut Config, fee: u64) {
    self.upsert(WITHDRAWAL_FEE_BTC_KEY, config_value::new_u64(fee))
}

public(package) fun withdrawal_minimum(self: &Config): u64 {
    self.get(WITHDRAWAL_MINIMUM_KEY).as_u64()
}

public(package) fun set_withdrawal_minimum(self: &mut Config, fee: u64) {
    self.upsert(WITHDRAWAL_MINIMUM_KEY, config_value::new_u64(fee))
}

public(package) fun bitcoin_confirmation_threshold(self: &Config): u64 {
    self.get(BITCOIN_CONFIRMATION_THRESHOLD_KEY).as_u64()
}

public(package) fun set_bitcoin_confirmation_threshold(self: &mut Config, confirmations: u64) {
    self.upsert(
        BITCOIN_CONFIRMATION_THRESHOLD_KEY,
        config_value::new_u64(confirmations),
    )
}

public(package) fun paused(self: &Config): bool {
    self.get(PAUSED_KEY).as_bool()
}

public(package) fun set_paused(self: &mut Config, paused: bool) {
    self.upsert(PAUSED_KEY, config_value::new_bool(paused))
}

public(package) fun withdrawal_cancellation_cooldown_ms(self: &Config): u64 {
    self.get(WITHDRAWAL_CANCELLATION_COOLDOWN_KEY).as_u64()
}

public(package) fun set_withdrawal_cancellation_cooldown_ms(self: &mut Config, cooldown_ms: u64) {
    self.upsert(WITHDRAWAL_CANCELLATION_COOLDOWN_KEY, config_value::new_u64(cooldown_ms))
}

public(package) fun disable_version(self: &mut Config, version: u64) {
    // Can not disable current version (anti package bricking)
    assert!(version != PACKAGE_VERSION, EDisableCurrentVersion);
    self.enabled_versions.remove(&version);
}

public(package) fun enable_version(self: &mut Config, version: u64) {
    self.enabled_versions.insert(version);
}

/// Step 1 of upgrade: Authorizes an upgrade with the given package digest.
///
/// Called by `upgrade::execute()` after the `Proposal<Upgrade>` reaches quorum.
/// The returned `UpgradeTicket` must be consumed by `sui::package::upgrade()`
/// in the same transaction to publish the new package version.
public(package) fun authorize_upgrade(self: &mut Config, digest: vector<u8>): UpgradeTicket {
    let policy = sui::package::upgrade_policy(self.upgrade_cap.borrow());
    sui::package::authorize_upgrade(
        self.upgrade_cap.borrow_mut(),
        policy,
        digest,
    )
}

/// Step 2 of upgrade: Commits the upgrade and enables the new version.
///
/// Called after `sui::package::upgrade()` returns an `UpgradeReceipt`.
/// This finalizes the upgrade by:
/// 1. Committing the receipt to the `UpgradeCap` (incrementing the version)
/// 2. Auto-enabling the new version so the package can be used immediately
public(package) fun commit_upgrade(self: &mut Config, receipt: UpgradeReceipt) {
    package::commit_upgrade(self.upgrade_cap.borrow_mut(), receipt);
    let version = self.upgrade_cap.borrow().version();
    self.enabled_versions.insert(version);
}

//
// Constructor
//

public(package) fun create(): Config {
    let mut config = Config {
        config: vec_map::empty(),
        enabled_versions: vec_set::from_keys(vector[PACKAGE_VERSION]),
        upgrade_cap: option::none(),
    };

    // Set initial config values
    config.upsert(PAUSED_KEY, config_value::new_bool(false));
    config.upsert(DEPOSIT_FEE_KEY, config_value::new_u64(0));
    config.upsert(WITHDRAWAL_FEE_BTC_KEY, config_value::new_u64(500)); // 500 satoshis
    config.upsert(WITHDRAWAL_MINIMUM_KEY, config_value::new_u64(0));
    config.upsert(BITCOIN_CONFIRMATION_THRESHOLD_KEY, config_value::new_u64(1)); // TODO: set to 6 before mainnet
    config.upsert(WITHDRAWAL_CANCELLATION_COOLDOWN_KEY, config_value::new_u64(1000 * 60 * 60)); // 1 hour

    config
}

public(package) fun set_upgrade_cap(self: &mut Config, upgrade_cap: UpgradeCap) {
    self.upgrade_cap.fill(upgrade_cap);
}

public(package) fun upgrade_cap(self: &Config): &UpgradeCap {
    self.upgrade_cap.borrow()
}
