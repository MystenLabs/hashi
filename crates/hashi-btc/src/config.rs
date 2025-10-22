//! Configuration for the Bitcoin monitor.

use bitcoin::Network;

#[derive(Debug, Clone)]
pub struct MontiorConfig {
    /// Bitcoin network to connect to
    pub network: Network,

    /// Number of confirmations required for a transaction to be considered canonical
    pub confirmation_threshold: u32,

    /// Initial peer addresses for P2P connections
    pub trusted_peers: Vec<kyoto::TrustedPeer>,

    /// Starting block height for synchronization
    pub start_height: u32,
}

impl Default for MontiorConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            confirmation_threshold: 6,
            trusted_peers: Vec::new(),
            start_height: 800_000,
        }
    }
}

impl MontiorConfig {
    /// Create a new configuration builder.
    pub fn builder() -> MonitorConfigBuilder {
        MonitorConfigBuilder::default()
    }
}

/// Builder for constructing pool configuration.
#[derive(Debug, Default)]
pub struct MonitorConfigBuilder {
    network: Option<Network>,
    confirmation_threshold: Option<u32>,
    trusted_peers: Vec<kyoto::TrustedPeer>,
    start_height: u32,
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

    /// Build the pool configuration.
    pub fn build(self) -> MontiorConfig {
        let default = MontiorConfig::default();

        MontiorConfig {
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
        }
    }
}
