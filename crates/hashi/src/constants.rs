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

/// The `hashi::versioning` package versions whose on-chain semantics this
/// binary implements.
///
/// The node computes an *active* version as
/// `max(enabled_versions ∩ published_versions ∩ SUPPORTED_PACKAGE_VERSIONS)`
/// and gates autonomous work on it (see `onchain::version`). If every
/// enabled+published on-chain version is beyond this set — the chain has moved
/// ahead of this binary — the node halts autonomous mutations and signals for
/// an upgrade rather than acting on data it cannot interpret.
///
/// Add the next version here in the same change that teaches this binary to
/// run it (e.g. a package upgrade); never list a version whose semantics this
/// build does not implement.
///
/// Version-dependent calls (e.g. `start_reconfig`) execute the active
/// version's code through `SuiTxExecutor::active_call_package_id` instead of
/// the original publish id, and shared inputs are pre-resolved so
/// upgrade-introduced modules never trip the fullnode's simulate-time linkage
/// check. The testnet squash restarted the sequence: the whole feature set
/// (stamped nonce certs, deferred archival, TOB pruning) ships as v1.
pub const SUPPORTED_PACKAGE_VERSIONS: &[u64] = &[1];

pub fn is_production_sui_chain(chain_id: &str) -> bool {
    chain_id == SUI_MAINNET_CHAIN_ID || chain_id == SUI_TESTNET_CHAIN_ID
}

/// Refuse a Sui chain / Bitcoin chain pairing the protocol never deploys:
/// Bitcoin mainnet if and only if Sui mainnet. On Sui mainnet anything but
/// Bitcoin mainnet would mint a real `hashi::btc` against free signet or
/// regtest deposits; on any other Sui network Bitcoin mainnet would lock real
/// Bitcoin behind a non-mainnet package (SEC-510, audit D-13).
///
/// Move cannot enforce this (`finish_publish` stores whichever id it is
/// handed and the Sui framework exposes no chain identifier to Move), so it
/// runs in every Rust path that produces or consumes the pair. The Bitcoin
/// side is decided by the network the hash resolves to, as every consumer of
/// the id does, not by string equality, so letter case cannot dodge it. An
/// empty or unrecognised id fails closed.
pub fn check_sui_bitcoin_chain_pairing(
    sui_chain_id: &str,
    bitcoin_chain_id: &str,
) -> anyhow::Result<()> {
    use crate::btc_monitor::config::Network;
    use crate::btc_monitor::config::network_from_chain_id;

    anyhow::ensure!(
        !sui_chain_id.is_empty(),
        "Sui chain ID is empty; refusing to pair it with Bitcoin chain {bitcoin_chain_id}"
    );
    let network = network_from_chain_id(bitcoin_chain_id)
        .ok_or_else(|| anyhow::anyhow!("unrecognized bitcoin chain id: {bitcoin_chain_id}"))?;
    let sui_is_mainnet = sui_chain_id == SUI_MAINNET_CHAIN_ID;
    let bitcoin_is_mainnet = network == Network::Bitcoin;
    anyhow::ensure!(
        !sui_is_mainnet || bitcoin_is_mainnet,
        "refusing Bitcoin {network:?} ({bitcoin_chain_id}) on Sui mainnet: \
         Sui mainnet requires Bitcoin mainnet"
    );
    anyhow::ensure!(
        !bitcoin_is_mainnet || sui_is_mainnet,
        "refusing Bitcoin mainnet ({bitcoin_chain_id}) on Sui chain {sui_chain_id}: \
         Bitcoin mainnet is allowed on Sui mainnet only; every other Sui network \
         needs a non-mainnet bitcoin_chain_id, which defaults to mainnet when unset"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_monitor::config::Network;
    use crate::btc_monitor::config::network_from_chain_id;

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
