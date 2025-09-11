use anyhow::Result;
use test_cluster::{TestCluster, TestClusterBuilder};

pub mod bitcoin_network;
pub mod hashi_network;

pub use bitcoin_network::{BitcoinNetwork, BitcoinNetworkBuilder};
pub use hashi_network::{HashiNetwork, HashiNetworkBuilder, HashiNodeHandle};

pub struct TestNetworks {
    pub sui_network: TestCluster,
    pub hashi_network: HashiNetwork,
    pub bitcoin_network: BitcoinNetwork,
}

impl TestNetworks {
    pub async fn new() -> Result<Self> {
        let sui_network = TestClusterBuilder::new().build().await;
        let hashi_network = HashiNetworkBuilder::new().build().await?;
        let bitcoin_network = BitcoinNetworkBuilder::new().build().await?;
        let test_networks = Self {
            sui_network,
            hashi_network,
            bitcoin_network,
        };
        Ok(test_networks)
    }

    pub fn builder() -> TestNetworksBuilder {
        TestNetworksBuilder::new()
    }

    pub fn sui_network(&self) -> &TestCluster {
        &self.sui_network
    }

    pub fn hashi_network(&self) -> &HashiNetwork {
        &self.hashi_network
    }

    pub fn bitcoin_network(&self) -> &BitcoinNetwork {
        &self.bitcoin_network
    }
}

pub struct TestNetworksBuilder {
    sui_builder: TestClusterBuilder,
    hashi_builder: HashiNetworkBuilder,
    bitcoin_builder: BitcoinNetworkBuilder,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        Self {
            sui_builder: TestClusterBuilder::new(),
            hashi_builder: HashiNetworkBuilder::new(),
            bitcoin_builder: BitcoinNetworkBuilder::new(),
        }
    }

    pub fn with_sui_hashi_nodes(mut self, num_nodes: usize) -> Self {
        self = self.with_hashi_nodes(num_nodes);
        self = self.with_sui_validators(num_nodes);
        self
    }

    pub fn with_hashi_nodes(mut self, num_nodes: usize) -> Self {
        self.hashi_builder = self.hashi_builder.with_num_nodes(num_nodes);
        self
    }

    pub fn with_sui_validators(mut self, num_validators: usize) -> Self {
        self.sui_builder = self.sui_builder.with_num_validators(num_validators);
        self
    }

    pub fn with_sui_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.sui_builder = self.sui_builder.with_epoch_duration_ms(epoch_duration_ms);
        self
    }

    pub async fn build(self) -> Result<TestNetworks> {
        let sui_network = self.sui_builder.build().await;
        let hashi_network = self.hashi_builder.build().await?;
        let bitcoin_network = self.bitcoin_builder.build().await?;
        let test_networks = TestNetworks {
            sui_network,
            hashi_network,
            bitcoin_network,
        };
        Ok(test_networks)
    }
}

impl Default for TestNetworksBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_networks_setup() -> Result<()> {
        const NUM_SUI_HASHI_NODES: usize = 4;

        let test_networks = TestNetworksBuilder::new()
            .with_sui_hashi_nodes(NUM_SUI_HASHI_NODES)
            .build()
            .await?;

        assert_eq!(
            test_networks.hashi_network().nodes().len(),
            NUM_SUI_HASHI_NODES
        );
        assert_eq!(
            test_networks.sui_network().get_validator_pubkeys().len(),
            NUM_SUI_HASHI_NODES
        );
        assert!(!test_networks.bitcoin_network().node().rpc_url().is_empty());

        Ok(())
    }
}
