// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const SUI_MAINNET_CHAIN_ID: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
pub const SUI_TESTNET_CHAIN_ID: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";

pub fn is_production_sui_chain(chain_id: &str) -> bool {
    chain_id == SUI_MAINNET_CHAIN_ID || chain_id == SUI_TESTNET_CHAIN_ID
}

/// Trigger presignature refill when remaining presignatures drop to
/// `initial_pool_size / PRESIG_REFILL_DIVISOR`.
pub const PRESIG_REFILL_DIVISOR: usize = 2;
