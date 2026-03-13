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

/// The minimum value (in satoshis) that a Bitcoin transaction output must carry
/// to be relayed by nodes using Bitcoin Core's default dust relay fee rate
/// (3 sat/vB). Outputs below this threshold are considered "dust" -- they cost
/// more in fees to spend than they are worth -- and are rejected by the network's
/// relay policy.
///
/// The exact dust threshold depends on the spend path because each path has a
/// different input weight:
///
///   - P2PKH (legacy):             546 sats  (148 vB input)
///   - P2WPKH (segwit v0):         294 sats  (68 vB input)
///   - P2TR keypath (taproot):     330 sats  (58 vB input)
///   - P2TR script-path 1-of-1:    369 sats  (75 vB input)
///   - P2TR script-path 2-of-2:    429 sats  (100 vB input)
///
/// We use 546 sats -- the highest of these thresholds -- as a conservative floor
/// that is safe regardless of the output's eventual spend path.
const DUST_RELAY_MIN_VALUE: u64 = 546;

/// The minimum fee rate (in sat/vB) required for a Bitcoin transaction to be
/// relayed by nodes on the network. This is Bitcoin Core's default
/// `-minrelaytxfee` expressed in sat/vB.
const MIN_RELAY_FEE_RATE: u64 = 1;

/// Virtual bytes (vB) for a single transaction input spent via a 2-of-2 taproot
/// script-path. This is the heaviest input type we support.
///
/// Derived from weight units (WU), where vB = ceil(WU / 4):
///
///   Non-witness data (x4 multiplier):
///     outpoint(32+4) + script_sig_len(1) + script_sig(0) + sequence(4) = 41 bytes
///     41 x 4 = 164 WU
///
///   Witness data (x1 multiplier):
///     items_count(1) + sig1_len(1) + sig1(64) + sig2_len(1) + sig2(64)
///     + script_len(1) + script(68) + control_block_len(1) + control_block(33) = 234 WU
///
///     Where the script is: <pk1> OP_CHECKSIGVERIFY <pk2> OP_CHECKSIG (68 bytes)
///     and the control block is: leaf_version|parity(1) + internal_key(32) = 33 bytes
///     (single-leaf tree, no merkle siblings)
///
///   Total: ceil((164 + 234) / 4) = ceil(398 / 4) = 100 vB
const INPUT_VB: u64 = 100;

/// Virtual bytes (vB) for a single P2TR transaction output. We use P2TR as it is
/// the heaviest segwit output type we support, making this a conservative
/// worst-case assumption.
///
/// Derived from weight units (WU):
///   value(8) + script_len(1) = 9 bytes base (x 4 = 36 WU)
///   OP_1(1) + push_32(1) + x_only_pubkey(32) = 34 bytes script (x 4 = 136 WU)
///
///   Total: ceil((36 + 136) / 4) = ceil(172 / 4) = 43 vB
///
/// For comparison, P2WPKH outputs are ceil(124 / 4) = 31 vB.
const OUTPUT_VB: u64 = 43;

/// Number of outputs assumed for withdrawal minimum calculation:
/// one recipient output + one change output.
const NUM_OUTPUTS: u64 = 2;

/// Fixed virtual bytes (vB) overhead per Bitcoin transaction, independent of the
/// number of inputs and outputs.
///
/// Derived from weight units (WU):
///   Non-witness (x4 multiplier):
///     version(4) + locktime(4) = 8 bytes x 4 = 32 WU
///
///   Witness (x1 multiplier):
///     segwit_marker(1) + segwit_flag(1) + input_count(1) + output_count(1)
///     = 4 bytes x 1 = 4 WU
///
///   Adjustment: +6 WU for compact size encoding overhead.
///
///   Total: ceil((32 + 4 + 6) / 4) = ceil(42 / 4) = 11 vB
const TX_FIXED_VB: u64 = 11;

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
const MAX_FEE_RATE_KEY: vector<u8> = b"max_fee_rate";
const MAX_INPUTS_KEY: vector<u8> = b"max_inputs";
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

/// The protocol fee (in satoshis) deducted from the user's withdrawal amount.
/// Returns the greater of the configured value or DUST_RELAY_MIN_VALUE, ensuring
/// the fee is always at least economically meaningful regardless of governance
/// misconfiguration.
public(package) fun withdrawal_fee_btc(self: &Config): u64 {
    self.get(WITHDRAWAL_FEE_BTC_KEY).as_u64().max(DUST_RELAY_MIN_VALUE)
}

public(package) fun set_withdrawal_fee_btc(self: &mut Config, fee: u64) {
    self.upsert(WITHDRAWAL_FEE_BTC_KEY, config_value::new_u64(fee))
}

/// The worst-case fee rate (in sat/vB) used to compute the withdrawal minimum.
/// This represents the highest sustained fee environment we expect to operate in
/// without pausing withdrawals. Governance-updatable to adapt to changing network
/// conditions.
///
/// Returns the greater of the configured value or MIN_RELAY_FEE_RATE (1 sat/vB),
/// ensuring the assumed fee rate is never below the minimum required for a
/// transaction to be relayed by Bitcoin nodes.
public(package) fun max_fee_rate(self: &Config): u64 {
    self.get(MAX_FEE_RATE_KEY).as_u64().max(MIN_RELAY_FEE_RATE)
}

public(package) fun set_max_fee_rate(self: &mut Config, fee_rate: u64) {
    self.upsert(MAX_FEE_RATE_KEY, config_value::new_u64(fee_rate))
}

/// The worst-case number of UTXO inputs assumed per withdrawal transaction.
/// More inputs means a heavier transaction and higher fees. Governance-updatable
/// to account for changes in UTXO pool fragmentation.
///
/// Returns the greater of the configured value or 1, since a transaction
/// requires at least one input.
public(package) fun max_inputs(self: &Config): u64 {
    self.get(MAX_INPUTS_KEY).as_u64().max(1)
}

public(package) fun set_max_inputs(self: &mut Config, max_inputs: u64) {
    self.upsert(MAX_INPUTS_KEY, config_value::new_u64(max_inputs))
}

/// Minimum deposit amount (in satoshis). Deposits below the Bitcoin
/// network's dust relay threshold are rejected because the resulting UTXO
/// would cost more in fees to spend than it is worth.
public(package) fun deposit_minimum(_self: &Config): u64 {
    DUST_RELAY_MIN_VALUE
}

/// Computes the minimum withdrawal amount (in satoshis) required for a
/// withdrawal request to be accepted. This ensures the withdrawal is large
/// enough to produce a valid Bitcoin transaction even under worst-case fee
/// conditions.
///
/// The minimum is the sum of three components:
///   1. withdrawal_fee_btc -- the protocol fee deducted from the user's amount
///   2. worst_case_network_fee -- estimated miner fee at max_fee_rate with
///      max_inputs inputs and NUM_OUTPUTS outputs
///   3. DUST_RELAY_MIN_VALUE -- the user's output must be at least this large
///      to be relayed by Bitcoin nodes
///
/// Formula:
///   tx_vbytes = TX_FIXED_VB + (max_inputs * INPUT_VB) + (NUM_OUTPUTS * OUTPUT_VB)
///   worst_case_fee = max_fee_rate * tx_vbytes
///   minimum = withdrawal_fee_btc + worst_case_fee + DUST_RELAY_MIN_VALUE
public(package) fun withdrawal_minimum(self: &Config): u64 {
    let tx_vbytes = TX_FIXED_VB
        + (self.max_inputs() * INPUT_VB)
        + (NUM_OUTPUTS * OUTPUT_VB);
    let worst_case_fee = self.max_fee_rate() * tx_vbytes;

    self.withdrawal_fee_btc() + worst_case_fee + DUST_RELAY_MIN_VALUE
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
    config.upsert(WITHDRAWAL_FEE_BTC_KEY, config_value::new_u64(DUST_RELAY_MIN_VALUE));
    // Worst-case fee rate in sat/vB for withdrawal minimum calculation.
    // 25 sat/vB covers historically sustained congestion periods; brief spikes
    // above this are handled by pausing withdrawals.
    config.upsert(MAX_FEE_RATE_KEY, config_value::new_u64(25));
    // Worst-case number of inputs per withdrawal transaction.
    config.upsert(MAX_INPUTS_KEY, config_value::new_u64(10));
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
