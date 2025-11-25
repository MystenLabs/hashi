//! Configuration for the Bitcoin monitor.

use bitcoin::Network;

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
        }
    }
}
