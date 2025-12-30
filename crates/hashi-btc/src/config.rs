//! Configuration for the Bitcoin monitor.

use std::path::PathBuf;
use std::str::FromStr;

pub use bitcoin::BlockHash;
pub use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
pub use bitcoincore_rpc;

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Bitcoin network to connect to
    pub network: Network,

    /// Number of confirmations required for a transaction to be considered canonical
    pub confirmation_threshold: u32,

    /// Initial peer addresses for P2P connections
    pub trusted_peers: Vec<kyoto::TrustedPeer>,

    /// Starting block height for synchronization
    pub start_height: u32,

    /// bitcoind JSON-RPC server URL to connect to
    pub bitcoind_rpc_url: String,

    /// bitcoind JSON-RPC server auth config
    pub bitcoind_rpc_auth: bitcoincore_rpc::Auth,

    /// Directory for storing BTC light client data
    pub data_dir: Option<PathBuf>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            confirmation_threshold: 6,
            trusted_peers: Vec::new(),
            start_height: 800_000,
            bitcoind_rpc_url: "http://localhost:8332".to_string(),
            bitcoind_rpc_auth: bitcoincore_rpc::Auth::None,
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
    confirmation_threshold: Option<u32>,
    trusted_peers: Vec<kyoto::TrustedPeer>,
    start_height: u32,
    bitcoind_rpc_url: Option<String>,
    bitcoind_rpc_auth: Option<bitcoincore_rpc::Auth>,
    data_dir: Option<PathBuf>,
}

impl MonitorConfigBuilder {
    /// Set the Bitcoin network.
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Set the confirmation threshold for deposits.
    pub fn confirmation_threshold(mut self, confirmations: u32) -> Self {
        self.confirmation_threshold = Some(confirmations);
        self
    }

    /// Set peer addresses for P2P connections.
    pub fn trusted_peers(mut self, addresses: Vec<kyoto::TrustedPeer>) -> Self {
        self.trusted_peers = addresses;
        self
    }

    /// Set the starting block height for synchronization.
    pub fn start_height(mut self, height: u32) -> Self {
        self.start_height = height;
        self
    }

    /// Set the bitcoind JSON-RPC server config.
    pub fn bitcoind_rpc_config(mut self, url: String, auth: bitcoincore_rpc::Auth) -> Self {
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
            trusted_peers: if self.trusted_peers.is_empty() {
                default.trusted_peers
            } else {
                self.trusted_peers
            },
            start_height: self.start_height,
            bitcoind_rpc_url: self.bitcoind_rpc_url.unwrap_or(default.bitcoind_rpc_url),
            bitcoind_rpc_auth: self.bitcoind_rpc_auth.unwrap_or(default.bitcoind_rpc_auth),
            data_dir: self.data_dir,
        }
    }
}

/// Wrapper around bitcoincore_rpc::Auth that we can serialize/deserialize from configs
#[derive(Clone, Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum BtcRpcAuth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl BtcRpcAuth {
    pub fn to_bitcoincore_rpc_auth(&self) -> bitcoincore_rpc::Auth {
        match self {
            BtcRpcAuth::None => bitcoincore_rpc::Auth::None,
            BtcRpcAuth::UserPass(user, pass) => {
                bitcoincore_rpc::Auth::UserPass(user.clone(), pass.clone())
            }
            BtcRpcAuth::CookieFile(path) => bitcoincore_rpc::Auth::CookieFile(path.clone()),
        }
    }
}

pub fn network_from_chain_id(chain_id: &str) -> Option<Network> {
    let hash = BlockHash::from_str(chain_id).ok()?;

    [
        Network::Bitcoin,
        Network::Testnet,
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
        let mainnet_id = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let network = network_from_chain_id(mainnet_id);
        assert_eq!(network, Some(Network::Bitcoin));
    }

    #[test]
    fn test_testnet_genesis_mapping() {
        let mainnet_id = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
        let network = network_from_chain_id(mainnet_id);
        assert_eq!(network, Some(Network::Testnet));
    }

    #[test]
    fn test_regtest_genesis_mapping() {
        let mainnet_id = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
        let network = network_from_chain_id(mainnet_id);
        assert_eq!(network, Some(Network::Regtest));
    }
}
