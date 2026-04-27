// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Bitcoin monitor.

use std::path::PathBuf;
use std::str::FromStr;

pub use bitcoin::BlockHash;
pub use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
pub use corepc_client;

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Bitcoin network to connect to
    pub network: Network,

    /// Peers for P2P connections, identified by hostname (or IP) and port.
    /// Hostnames are resolved at connection time; the monitor's supervisor
    /// rebuilds the kyoto node on disconnect, which re-resolves them so IP
    /// changes (e.g. Kubernetes pod rotation) are followed.
    pub trusted_peers: Vec<kyoto::TrustedPeer>,

    /// Starting block height for synchronization
    pub start_height: u32,

    /// bitcoind JSON-RPC server URL to connect to
    pub bitcoind_rpc_url: String,

    /// bitcoind JSON-RPC server auth config
    pub bitcoind_rpc_auth: corepc_client::client_sync::Auth,

    /// Directory for storing BTC light client data
    pub data_dir: Option<PathBuf>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            trusted_peers: Vec::new(),
            start_height: 800_000,
            bitcoind_rpc_url: "http://localhost:8332".to_string(),
            bitcoind_rpc_auth: corepc_client::client_sync::Auth::None,
            data_dir: None,
        }
    }
}

impl MonitorConfig {
    /// Create a new configuration builder.
    pub fn builder() -> MonitorConfigBuilder {
        MonitorConfigBuilder::default()
    }
}

/// Builder for constructing monitor configuration.
#[derive(Debug, Default)]
pub struct MonitorConfigBuilder {
    network: Option<Network>,
    trusted_peers: Vec<kyoto::TrustedPeer>,
    start_height: u32,
    bitcoind_rpc_url: Option<String>,
    bitcoind_rpc_auth: Option<corepc_client::client_sync::Auth>,
    data_dir: Option<PathBuf>,
}

impl MonitorConfigBuilder {
    /// Set the Bitcoin network.
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Set peers for P2P connections. Accepts hostnames or IPs with port.
    /// Hostnames are resolved at connection time.
    pub fn trusted_peers(mut self, peers: Vec<kyoto::TrustedPeer>) -> Self {
        self.trusted_peers = peers;
        self
    }

    /// Set the starting block height for synchronization.
    pub fn start_height(mut self, height: u32) -> Self {
        self.start_height = height;
        self
    }

    /// Set the bitcoind JSON-RPC server config.
    pub fn bitcoind_rpc_config(
        mut self,
        url: String,
        auth: corepc_client::client_sync::Auth,
    ) -> Self {
        self.bitcoind_rpc_url = Some(url);
        self.bitcoind_rpc_auth = Some(auth);
        self
    }

    /// Set the directory for storing BTC light client data.
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    pub fn build(self) -> MonitorConfig {
        let default = MonitorConfig::default();

        MonitorConfig {
            network: self.network.unwrap_or(default.network),
            trusted_peers: self.trusted_peers,
            start_height: self.start_height,
            bitcoind_rpc_url: self.bitcoind_rpc_url.unwrap_or(default.bitcoind_rpc_url),
            bitcoind_rpc_auth: self.bitcoind_rpc_auth.unwrap_or(default.bitcoind_rpc_auth),
            data_dir: self.data_dir,
        }
    }
}

/// Wrapper around corepc_client::client_sync::Auth that we can serialize/deserialize from configs
#[derive(Clone, Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum BtcRpcAuth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl BtcRpcAuth {
    pub fn to_corepc_auth(&self) -> corepc_client::client_sync::Auth {
        match self {
            BtcRpcAuth::None => corepc_client::client_sync::Auth::None,
            BtcRpcAuth::UserPass(user, pass) => {
                corepc_client::client_sync::Auth::UserPass(user.clone(), pass.clone())
            }
            BtcRpcAuth::CookieFile(path) => {
                corepc_client::client_sync::Auth::CookieFile(path.clone())
            }
        }
    }
}

/// Create a `corepc_client` RPC client, handling the `Auth::None` case
/// (where `Client::new_with_auth` would error with `MissingUserPassword`).
pub fn new_rpc_client(
    url: &str,
    auth: corepc_client::client_sync::Auth,
) -> corepc_client::client_sync::Result<corepc_client::client_sync::v29::Client> {
    match auth {
        corepc_client::client_sync::Auth::None => {
            Ok(corepc_client::client_sync::v29::Client::new(url))
        }
        auth => corepc_client::client_sync::v29::Client::new_with_auth(url, auth),
    }
}

/// Parse a human-readable network name into a [`Network`].
///
/// Recognised values: `"mainnet"`, `"testnet4"`, `"regtest"`.
/// Returns [`Network::Regtest`] when `name` is `None`.
/// Returns an error for unrecognised network names.
pub fn parse_btc_network(name: Option<&str>) -> anyhow::Result<Network> {
    match name {
        Some("mainnet") => Ok(Network::Bitcoin),
        Some("testnet4") => Ok(Network::Testnet4),
        Some("signet") => Ok(Network::Signet),
        Some("regtest") | None => Ok(Network::Regtest),
        Some(other) => anyhow::bail!(
            "Unknown BTC network '{}'. Use mainnet, testnet4, signet, or regtest",
            other
        ),
    }
}

pub fn network_from_chain_id(chain_id: &str) -> Option<Network> {
    let hash = BlockHash::from_str(chain_id).ok()?;

    [
        Network::Bitcoin,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ]
    .into_iter()
    .find(|&net| genesis_block(net).block_hash() == hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_mapping() {
        let network = network_from_chain_id(crate::constants::BITCOIN_MAINNET_CHAIN_ID);
        assert_eq!(network, Some(Network::Bitcoin));
    }

    #[test]
    fn test_testnet4_genesis_mapping() {
        let network = network_from_chain_id(crate::constants::BITCOIN_TESTNET4_CHAIN_ID);
        assert_eq!(network, Some(Network::Testnet4));
    }

    #[test]
    fn test_signet_genesis_mapping() {
        let network = network_from_chain_id(crate::constants::BITCOIN_SIGNET_CHAIN_ID);
        assert_eq!(network, Some(Network::Signet));
    }

    #[test]
    fn test_regtest_genesis_mapping() {
        let network = network_from_chain_id(crate::constants::BITCOIN_REGTEST_CHAIN_ID);
        assert_eq!(network, Some(Network::Regtest));
    }
}
