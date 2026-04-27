// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Bitcoin monitor.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

pub use bitcoin::BlockHash;
pub use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
pub use corepc_client;

/// Live source of the BTC confirmation threshold, read on every deposit
/// evaluation so on-chain governance changes (`update_config` for
/// `bitcoin_confirmation_threshold`) take effect without a validator
/// restart.
///
/// Implemented by `OnchainState` for production and by `StaticThreshold`
/// for tests/examples that don't need live updates.
pub trait ConfirmationThresholdSource: Send + Sync {
    fn current(&self) -> u32;
}

/// Fixed-value implementation of `ConfirmationThresholdSource` for use
/// in tests, the standalone `testnet_monitor` example, and as the
/// fallback when no live source is wired in.
#[derive(Debug, Clone, Copy)]
pub struct StaticThreshold(pub u32);

impl ConfirmationThresholdSource for StaticThreshold {
    fn current(&self) -> u32 {
        self.0
    }
}

#[derive(Clone)]
pub struct MonitorConfig {
    /// Bitcoin network to connect to
    pub network: Network,

    /// Live source of the number of confirmations required for a
    /// transaction to be considered canonical. Read at every deposit
    /// evaluation so governance updates are picked up immediately.
    pub confirmation_threshold: Arc<dyn ConfirmationThresholdSource>,

    /// Peers for P2P connections, identified by hostname (or IP) and port.
    /// Re-resolved via DNS on each connection attempt, so IP changes
    /// (e.g., Kubernetes pod rotation) are followed automatically.
    pub dns_peers: Vec<kyoto::DnsPeer>,

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
            confirmation_threshold: Arc::new(StaticThreshold(6)),
            dns_peers: Vec::new(),
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
#[derive(Default)]
pub struct MonitorConfigBuilder {
    network: Option<Network>,
    confirmation_threshold: Option<Arc<dyn ConfirmationThresholdSource>>,
    dns_peers: Vec<kyoto::DnsPeer>,
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

    /// Set a fixed confirmation threshold for deposits. Useful for tests
    /// and standalone tools that don't have a live governance source.
    /// Production validators should use
    /// [`Self::confirmation_threshold_source`] instead so on-chain
    /// `update_config` actions take effect without a restart.
    pub fn confirmation_threshold(mut self, confirmations: u32) -> Self {
        self.confirmation_threshold = Some(Arc::new(StaticThreshold(confirmations)));
        self
    }

    /// Set a live source for the confirmation threshold, read at every
    /// deposit evaluation.
    pub fn confirmation_threshold_source(
        mut self,
        source: Arc<dyn ConfirmationThresholdSource>,
    ) -> Self {
        self.confirmation_threshold = Some(source);
        self
    }

    /// Set peers for P2P connections. Accepts hostnames or IPs with port.
    /// Hostnames are re-resolved via DNS on each connection attempt.
    pub fn dns_peers(mut self, peers: Vec<kyoto::DnsPeer>) -> Self {
        self.dns_peers = peers;
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
            confirmation_threshold: self
                .confirmation_threshold
                .unwrap_or(default.confirmation_threshold),
            dns_peers: self.dns_peers,
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
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    /// Test fake whose threshold can be mutated post-construction so we
    /// can verify the monitor reads the value live, not at boot.
    struct AtomicThreshold(AtomicU32);

    impl ConfirmationThresholdSource for AtomicThreshold {
        fn current(&self) -> u32 {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn static_threshold_returns_stored_value() {
        let source = StaticThreshold(6);
        assert_eq!(source.current(), 6);
    }

    #[test]
    fn builder_with_u32_wraps_in_static_source() {
        let config = MonitorConfig::builder().confirmation_threshold(3).build();
        assert_eq!(config.confirmation_threshold.current(), 3);
    }

    #[test]
    fn live_source_picks_up_updates() {
        let live = Arc::new(AtomicThreshold(AtomicU32::new(6)));
        let config = MonitorConfig::builder()
            .confirmation_threshold_source(live.clone())
            .build();
        assert_eq!(config.confirmation_threshold.current(), 6);

        live.0.store(3, Ordering::Relaxed);
        assert_eq!(config.confirmation_threshold.current(), 3);
    }

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
