// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Sui mainnet genesis checkpoint digest (Base58).
pub const SUI_MAINNET_CHAIN_ID: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
/// Sui testnet genesis checkpoint digest (Base58).
pub const SUI_TESTNET_CHAIN_ID: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";

/// Bitcoin mainnet genesis block hash.
pub const BITCOIN_MAINNET_CHAIN_ID: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
/// Bitcoin testnet4 genesis block hash.
pub const BITCOIN_TESTNET4_CHAIN_ID: &str =
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
/// Bitcoin signet genesis block hash.
pub const BITCOIN_SIGNET_CHAIN_ID: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
/// Bitcoin regtest genesis block hash.
pub const BITCOIN_REGTEST_CHAIN_ID: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Trigger presignature refill when remaining presignatures drop to
/// `initial_pool_size / PRESIG_REFILL_DIVISOR`.
pub const PRESIG_REFILL_DIVISOR: usize = 2;

pub fn is_production_sui_chain(chain_id: &str) -> bool {
    chain_id == SUI_MAINNET_CHAIN_ID || chain_id == SUI_TESTNET_CHAIN_ID
}

/// Epoch at which the privacy-threshold presignature extraction activates;
/// earlier epochs use the legacy.
/// All validators must agree on this value for every epoch they serve,
/// so flipping testnet means shipping a release with a concrete epoch,
/// chosen at least one epoch ahead and only after the whole fleet
/// verifiably runs it.
pub fn presignature_derivation_activation_epoch(chain_id: &str) -> u64 {
    if chain_id == SUI_TESTNET_CHAIN_ID {
        20
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_monitor::config::Network;
    use crate::btc_monitor::config::network_from_chain_id;

    #[test]
    fn presignature_derivation_activation_epoch_per_chain() {
        assert_eq!(
            presignature_derivation_activation_epoch(SUI_TESTNET_CHAIN_ID),
            20,
            "the scheduled testnet flip; every validator must update before this epoch"
        );
        assert_eq!(
            presignature_derivation_activation_epoch(SUI_MAINNET_CHAIN_ID),
            0,
            "mainnet must never derive with the legacy extraction"
        );
        assert_eq!(presignature_derivation_activation_epoch("localnet"), 0);
    }

    #[test]
    fn mainnet_chain_id_matches_network() {
        assert_eq!(
            network_from_chain_id(BITCOIN_MAINNET_CHAIN_ID),
            Some(Network::Bitcoin),
        );
    }

    #[test]
    fn testnet4_chain_id_matches_network() {
        assert_eq!(
            network_from_chain_id(BITCOIN_TESTNET4_CHAIN_ID),
            Some(Network::Testnet4),
        );
    }

    #[test]
    fn signet_chain_id_matches_network() {
        assert_eq!(
            network_from_chain_id(BITCOIN_SIGNET_CHAIN_ID),
            Some(Network::Signet),
        );
    }

    #[test]
    fn regtest_chain_id_matches_network() {
        assert_eq!(
            network_from_chain_id(BITCOIN_REGTEST_CHAIN_ID),
            Some(Network::Regtest),
        );
    }
}
