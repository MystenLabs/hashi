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

/// Minimum fee rate (sat/vB) for Bitcoin relay. Bitcoin Core default.
const MIN_RELAY_FEE_RATE: u64 = 1;

/// Virtual bytes per input for 2-of-2 taproot script-path spend.
/// ceil((164 WU non-witness + 234 WU witness) / 4) = 100 vB.
const INPUT_VB: u64 = 100;

/// Virtual bytes per P2TR output. ceil(172 WU / 4) = 43 vB.
const OUTPUT_VB: u64 = 43;

/// Number of outputs assumed per withdrawal: recipient + change.
const OUTPUT_BUDGET: u64 = 2;

/// Fixed virtual bytes overhead per Bitcoin transaction.
/// ceil((32 + 4 + 6) WU / 4) = 11 vB.
const TX_FIXED_VB: u64 = 11;

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

/// Worst-case fee rate (sat/vB) for withdrawal minimum calculation.
/// Returns the greater of configured value or MIN_RELAY_FEE_RATE.
public(package) fun max_fee_rate(self: &Config): u64 {
    self.get(b"max_fee_rate").as_u64().max(MIN_RELAY_FEE_RATE)
}

public(package) fun set_max_fee_rate(self: &mut Config, fee_rate: u64) {
    self.upsert(b"max_fee_rate", config_value::new_u64(fee_rate))
}

/// Worst-case number of UTXO inputs assumed per withdrawal for fee estimation.
/// Returns the greater of configured value or 1.
public(package) fun input_budget(self: &Config): u64 {
    self.get(b"input_budget").as_u64().max(1)
}

public(package) fun set_input_budget(self: &mut Config, input_budget: u64) {
    self.upsert(b"input_budget", config_value::new_u64(input_budget))
}

/// The dust relay minimum value as a pure constant accessor.
public(package) fun dust_relay_min_value(): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Minimum deposit amount (satoshis). Below this, the UTXO is dust.
public(package) fun deposit_minimum(_self: &Config): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Worst-case Bitcoin miner fee for a withdrawal transaction,
/// assuming input_budget inputs and OUTPUT_BUDGET outputs at max_fee_rate.
public(package) fun worst_case_network_fee(self: &Config): u64 {
    let tx_vbytes =
        TX_FIXED_VB
        + (input_budget(self) * INPUT_VB)
        + (OUTPUT_BUDGET * OUTPUT_VB);
    max_fee_rate(self) * tx_vbytes
}

/// Minimum withdrawal amount (satoshis) to cover protocol fee + miner fee + dust.
public(package) fun withdrawal_minimum(self: &Config): u64 {
    withdrawal_fee_btc(self) + worst_case_network_fee(self) + DUST_RELAY_MIN_VALUE
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
    config.upsert(b"max_fee_rate", config_value::new_u64(25));
    config.upsert(b"input_budget", config_value::new_u64(10));
    config.upsert(b"bitcoin_confirmation_threshold", config_value::new_u64(1)); // TODO: set to 6 before mainnet
    config.upsert(b"withdrawal_cancellation_cooldown_ms", config_value::new_u64(1000 * 60 * 60)); // 1 hour
}
