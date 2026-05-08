// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Bitcoin-specific configuration accessors and fee calculation functions.
/// Operates on the shared Config store via public(package) get/upsert.
module hashi::btc_config;

use hashi::{config::Config, config_value};

/// Minimum value (satoshis) for a Bitcoin output to be relayed (dust threshold).
/// Uses the highest threshold (P2PKH 546 sats) as a conservative floor.
const DUST_RELAY_MIN_VALUE: u64 = 546;

// ======== Accessors ========

public(package) fun bitcoin_chain_id(self: &Config): address {
    self.get(b"bitcoin_chain_id").as_address()
}

public(package) fun set_bitcoin_chain_id(self: &mut Config, bitcoin_chain_id: address) {
    self.upsert(b"bitcoin_chain_id", config_value::new_address(bitcoin_chain_id))
}

/// Minimum total withdrawal amount (satoshis). The worst-case network
/// fee is derived from this value minus the dust threshold. The floor
/// ensures the worst-case network fee is always at least 1 sat.
public(package) fun bitcoin_withdrawal_minimum(self: &Config): u64 {
    self.get(b"bitcoin_withdrawal_minimum").as_u64().max(DUST_RELAY_MIN_VALUE + 1)
}

public(package) fun set_bitcoin_withdrawal_minimum(self: &mut Config, min_withdrawal: u64) {
    self.upsert(b"bitcoin_withdrawal_minimum", config_value::new_u64(min_withdrawal))
}

/// The dust relay minimum value as a pure constant accessor.
public(package) fun dust_relay_min_value(): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Minimum deposit amount (satoshis). Returns the greater of configured
/// value or DUST_RELAY_MIN_VALUE, ensuring deposits are never below dust.
public(package) fun bitcoin_deposit_minimum(self: &Config): u64 {
    self.get(b"bitcoin_deposit_minimum").as_u64().max(DUST_RELAY_MIN_VALUE)
}

public(package) fun set_bitcoin_deposit_minimum(self: &mut Config, min_deposit: u64) {
    self.upsert(b"bitcoin_deposit_minimum", config_value::new_u64(min_deposit))
}

/// Minimum time (milliseconds) that must elapse between a deposit being
/// approved by the committee and being confirmed. Provides a window in
/// which a fraudulent or erroneous approval can be detected and the
/// service paused before funds are minted.
public(package) fun bitcoin_deposit_time_delay_ms(self: &Config): u64 {
    self.get(b"bitcoin_deposit_time_delay_ms").as_u64()
}

public(package) fun set_bitcoin_deposit_time_delay_ms(self: &mut Config, time_delay_ms: u64) {
    self.upsert(b"bitcoin_deposit_time_delay_ms", config_value::new_u64(time_delay_ms))
}

/// Worst-case Bitcoin miner fee for a withdrawal transaction, derived
/// from `bitcoin_withdrawal_minimum` minus the dust threshold. This
/// caps the per-user miner fee deduction.
public(package) fun worst_case_network_fee(self: &Config): u64 {
    bitcoin_withdrawal_minimum(self) - DUST_RELAY_MIN_VALUE
}

public(package) fun bitcoin_confirmation_threshold(self: &Config): u64 {
    self.get(b"bitcoin_confirmation_threshold").as_u64()
}

public(package) fun set_bitcoin_confirmation_threshold(self: &mut Config, confirmations: u64) {
    self.upsert(b"bitcoin_confirmation_threshold", config_value::new_u64(confirmations))
}

public(package) fun withdrawal_cancellation_cooldown_ms(self: &Config): u64 {
    self.get(b"withdrawal_cancellation_cooldown_ms").as_u64()
}

public(package) fun set_withdrawal_cancellation_cooldown_ms(self: &mut Config, cooldown_ms: u64) {
    self.upsert(b"withdrawal_cancellation_cooldown_ms", config_value::new_u64(cooldown_ms))
}

// ======== Initialization ========

/// Initialize BTC-specific config defaults. Called after config::create().
public(package) fun init_defaults(config: &mut Config) {
    config.upsert(b"bitcoin_deposit_time_delay_ms", config_value::new_u64(10 * 60 * 1_000)); // 15 minutes
    config.upsert(b"bitcoin_deposit_minimum", config_value::new_u64(30_000));
    config.upsert(b"bitcoin_withdrawal_minimum", config_value::new_u64(30_000));
    config.upsert(b"bitcoin_confirmation_threshold", config_value::new_u64(6));
    config.upsert(b"withdrawal_cancellation_cooldown_ms", config_value::new_u64(1000 * 60 * 60)); // 1 hour
}
