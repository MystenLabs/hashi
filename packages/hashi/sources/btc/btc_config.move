// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Bitcoin-specific configuration accessors and fee calculation functions.
/// Operates on the shared Config store via public(package) get/upsert.
module hashi::btc_config;

use hashi::{config::Config, config_value};

// ======== Bitcoin Network Constants ========

/// Minimum value (satoshis) for a Bitcoin output to be relayed (dust threshold).
/// Uses the highest threshold (P2PKH 546 sats) as a conservative floor.
const DUST_RELAY_MIN_VALUE: u64 = 546;

// ======== Config Validation ========

/// Returns true when `key` is a recognised BTC config key and `value`
/// carries the type that key expects.
#[allow(implicit_const_copy)]
public(package) fun is_valid_config_entry(
    key: &std::string::String,
    value: &config_value::Value,
): bool {
    let k = key.as_bytes();
    if (k == &b"deposit_fee") {
        value.is_u64()
    } else if (k == &b"withdrawal_fee_btc") {
        value.is_u64()
    } else if (k == &b"bitcoin_min_withdrawal") {
        value.is_u64()
    } else if (k == &b"bitcoin_confirmation_threshold") {
        value.is_u64()
    } else if (k == &b"withdrawal_cancellation_cooldown_ms") {
        value.is_u64()
    } else {
        false
    }
}

// ======== Accessors ========

public(package) fun bitcoin_chain_id(self: &Config): address {
    self.get(b"bitcoin_chain_id").as_address()
}

public(package) fun set_bitcoin_chain_id(self: &mut Config, bitcoin_chain_id: address) {
    self.upsert(b"bitcoin_chain_id", config_value::new_address(bitcoin_chain_id))
}

public(package) fun deposit_fee(self: &Config): u64 {
    self.get(b"deposit_fee").as_u64()
}

public(package) fun set_deposit_fee(self: &mut Config, fee: u64) {
    self.upsert(b"deposit_fee", config_value::new_u64(fee))
}

/// Protocol fee (satoshis) deducted from the user's withdrawal amount.
/// Returns the greater of configured value or DUST_RELAY_MIN_VALUE.
public(package) fun withdrawal_fee_btc(self: &Config): u64 {
    self.get(b"withdrawal_fee_btc").as_u64().max(DUST_RELAY_MIN_VALUE)
}

public(package) fun set_withdrawal_fee_btc(self: &mut Config, fee: u64) {
    self.upsert(b"withdrawal_fee_btc", config_value::new_u64(fee))
}

/// Minimum net withdrawal amount (satoshis) after the protocol fee.
/// This is the amount that must cover the worst-case miner fee plus
/// the dust threshold for the user's output. Returns the greater of
/// configured value or DUST_RELAY_MIN_VALUE * 2, ensuring the
/// worst-case network fee is always at least DUST_RELAY_MIN_VALUE.
public(package) fun bitcoin_min_withdrawal(self: &Config): u64 {
    self.get(b"bitcoin_min_withdrawal").as_u64().max(DUST_RELAY_MIN_VALUE * 2)
}

public(package) fun set_bitcoin_min_withdrawal(self: &mut Config, min_withdrawal: u64) {
    self.upsert(b"bitcoin_min_withdrawal", config_value::new_u64(min_withdrawal))
}

/// The dust relay minimum value as a pure constant accessor.
public(package) fun dust_relay_min_value(): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Minimum deposit amount (satoshis). Below this, the UTXO is dust.
public(package) fun deposit_minimum(_self: &Config): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Worst-case Bitcoin miner fee for a withdrawal transaction, derived
/// from the flat `bitcoin_min_withdrawal` config minus the dust
/// threshold. This caps the per-user miner fee deduction.
public(package) fun worst_case_network_fee(self: &Config): u64 {
    bitcoin_min_withdrawal(self) - DUST_RELAY_MIN_VALUE
}

/// Minimum withdrawal amount (satoshis) the user must provide,
/// covering the protocol fee plus the net minimum withdrawal.
public(package) fun withdrawal_minimum(self: &Config): u64 {
    bitcoin_min_withdrawal(self) + withdrawal_fee_btc(self)
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
    config.upsert(b"deposit_fee", config_value::new_u64(0));
    config.upsert(b"withdrawal_fee_btc", config_value::new_u64(DUST_RELAY_MIN_VALUE));
    config.upsert(b"bitcoin_min_withdrawal", config_value::new_u64(27_971));
    config.upsert(b"bitcoin_confirmation_threshold", config_value::new_u64(1)); // TODO: set to 6 before mainnet
    config.upsert(b"withdrawal_cancellation_cooldown_ms", config_value::new_u64(1000 * 60 * 60)); // 1 hour
}
