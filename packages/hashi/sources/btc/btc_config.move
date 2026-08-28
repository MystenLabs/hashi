// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Bitcoin-specific configuration accessors and fee calculation functions.
/// Operates on the shared Config store via public(package) get/upsert.
#[allow(implicit_const_copy)]
module hashi::btc_config;

use hashi::{config::Config, config_value};
use std::string::String;

// ~~~~~~~ Constants ~~~~~~~

/// Minimum value (satoshis) for a Bitcoin output to be relayed (dust threshold).
/// Uses the highest threshold (P2PKH 546 sats) as a conservative floor.
const DUST_RELAY_MIN_VALUE: u64 = 546;

const KEY_BITCOIN_CHAIN_ID: vector<u8> = b"bitcoin_chain_id";
const KEY_BITCOIN_DEPOSIT_TIME_DELAY_MS: vector<u8> = b"bitcoin_deposit_time_delay_ms";
const KEY_BITCOIN_DEPOSIT_MINIMUM: vector<u8> = b"bitcoin_deposit_minimum";
const KEY_BITCOIN_WITHDRAWAL_MINIMUM: vector<u8> = b"bitcoin_withdrawal_minimum";
const KEY_BITCOIN_CONFIRMATION_THRESHOLD: vector<u8> = b"bitcoin_confirmation_threshold";
const KEY_WITHDRAWAL_CANCELLATION_COOLDOWN_MS: vector<u8> = b"withdrawal_cancellation_cooldown_ms";

// ~~~~~~~ Package Functions ~~~~~~~

// === Initialization ===

/// Initialize BTC-specific config defaults. Called after config::create().
public(package) fun init_defaults(config: &mut Config) {
    config.upsert(KEY_BITCOIN_DEPOSIT_TIME_DELAY_MS, config_value::new_u64(10 * 60 * 1_000)); // 10 minutes
    config.upsert(KEY_BITCOIN_DEPOSIT_MINIMUM, config_value::new_u64(30_000));
    config.upsert(KEY_BITCOIN_WITHDRAWAL_MINIMUM, config_value::new_u64(30_000));
    config.upsert(KEY_BITCOIN_CONFIRMATION_THRESHOLD, config_value::new_u64(6));
    config.upsert(KEY_WITHDRAWAL_CANCELLATION_COOLDOWN_MS, config_value::new_u64(1000 * 60 * 60)); // 1 hour
}

// === Governance ===

/// Whether `UpdateConfig` may write `key`. The chain id is pinned at
/// `finish_publish` and verified by every node at startup; changing it
/// on-chain would only desynchronize the fleet from the object.
public(package) fun is_governable_key(key: &String): bool {
    key.as_bytes() != &KEY_BITCOIN_CHAIN_ID
}

// === Accessors ===

public(package) fun bitcoin_chain_id(self: &Config): address {
    self.get(KEY_BITCOIN_CHAIN_ID).as_address()
}

public(package) fun set_bitcoin_chain_id(self: &mut Config, bitcoin_chain_id: address) {
    self.upsert(KEY_BITCOIN_CHAIN_ID, config_value::new_address(bitcoin_chain_id))
}

/// Minimum total withdrawal amount (satoshis). The worst-case network
/// fee is derived from this value minus the dust threshold. The floor
/// ensures the worst-case network fee is always at least 1 sat.
public(package) fun bitcoin_withdrawal_minimum(self: &Config): u64 {
    self.get(KEY_BITCOIN_WITHDRAWAL_MINIMUM).as_u64().max(DUST_RELAY_MIN_VALUE + 1)
}

public(package) fun set_bitcoin_withdrawal_minimum(self: &mut Config, min_withdrawal: u64) {
    self.upsert(KEY_BITCOIN_WITHDRAWAL_MINIMUM, config_value::new_u64(min_withdrawal))
}

/// The dust relay minimum value as a pure constant accessor.
public(package) fun dust_relay_min_value(): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Minimum deposit amount (satoshis). Returns the greater of configured
/// value or DUST_RELAY_MIN_VALUE, ensuring deposits are never below dust.
public(package) fun bitcoin_deposit_minimum(self: &Config): u64 {
    self.get(KEY_BITCOIN_DEPOSIT_MINIMUM).as_u64().max(DUST_RELAY_MIN_VALUE)
}

public(package) fun set_bitcoin_deposit_minimum(self: &mut Config, min_deposit: u64) {
    self.upsert(KEY_BITCOIN_DEPOSIT_MINIMUM, config_value::new_u64(min_deposit))
}

/// Minimum time (milliseconds) that must elapse between a deposit being
/// approved by the committee and being confirmed. Provides a window in
/// which a fraudulent or erroneous approval can be detected and the
/// service paused before funds are minted.
public(package) fun bitcoin_deposit_time_delay_ms(self: &Config): u64 {
    self.get(KEY_BITCOIN_DEPOSIT_TIME_DELAY_MS).as_u64()
}

public(package) fun set_bitcoin_deposit_time_delay_ms(self: &mut Config, time_delay_ms: u64) {
    self.upsert(KEY_BITCOIN_DEPOSIT_TIME_DELAY_MS, config_value::new_u64(time_delay_ms))
}

/// Worst-case Bitcoin miner fee for a withdrawal transaction, derived
/// from `bitcoin_withdrawal_minimum` minus the dust threshold. This
/// caps the per-user miner fee deduction.
public(package) fun worst_case_network_fee(self: &Config): u64 {
    bitcoin_withdrawal_minimum(self) - DUST_RELAY_MIN_VALUE
}

public(package) fun bitcoin_confirmation_threshold(self: &Config): u64 {
    self.get(KEY_BITCOIN_CONFIRMATION_THRESHOLD).as_u64()
}

public(package) fun set_bitcoin_confirmation_threshold(self: &mut Config, confirmations: u64) {
    self.upsert(KEY_BITCOIN_CONFIRMATION_THRESHOLD, config_value::new_u64(confirmations))
}

public(package) fun withdrawal_cancellation_cooldown_ms(self: &Config): u64 {
    self.get(KEY_WITHDRAWAL_CANCELLATION_COOLDOWN_MS).as_u64()
}

public(package) fun set_withdrawal_cancellation_cooldown_ms(self: &mut Config, cooldown_ms: u64) {
    self.upsert(KEY_WITHDRAWAL_CANCELLATION_COOLDOWN_MS, config_value::new_u64(cooldown_ms))
}
