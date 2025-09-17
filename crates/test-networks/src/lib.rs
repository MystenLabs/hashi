use anyhow::Result;

pub mod bitcoin_node;
pub mod hashi_network;
pub mod sui_network;

pub use bitcoin_node::{BitcoinNodeBuilder, BitcoinNodeHandle};
pub use hashi_network::{HashiNetwork, HashiNetworkBuilder, HashiNodeHandle};
pub use sui_network::{SuiNetworkBuilder, SuiNetworkHandle};

pub struct TestNetworks {
    pub sui_network: SuiNetworkHandle,
    pub hashi_network: HashiNetwork,
    pub bitcoin_node: BitcoinNodeHandle,
}

impl TestNetworks {
    pub async fn new() -> Result<Self> {
        let sui_network = SuiNetworkBuilder::default().build().await?;
        let hashi_network = HashiNetworkBuilder::new().build().await?;
        let bitcoin_node = BitcoinNodeBuilder::new().build().await?;
        let test_networks = Self {
            sui_network,
            hashi_network,
            bitcoin_node,
        };
        Ok(test_networks)
    }

    pub fn builder() -> TestNetworksBuilder {
        TestNetworksBuilder::new()
    }

    pub fn sui_network(&self) -> &SuiNetworkHandle {
        &self.sui_network
    }

    pub fn hashi_network(&self) -> &HashiNetwork {
        &self.hashi_network
    }

    pub fn bitcoin_node(&self) -> &BitcoinNodeHandle {
        &self.bitcoin_node
    }
}

pub struct TestNetworksBuilder {
    sui_builder: SuiNetworkBuilder,
    hashi_builder: HashiNetworkBuilder,
    bitcoin_builder: BitcoinNodeBuilder,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        Self {
            sui_builder: SuiNetworkBuilder::default(),
            hashi_builder: HashiNetworkBuilder::new(),
            bitcoin_builder: BitcoinNodeBuilder::new(),
        }
    }

    pub fn with_nodes(mut self, num_nodes: usize) -> Self {
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
        let sui_network = self.sui_builder.build().await?;
        let hashi_network = self.hashi_builder.build().await?;
        let bitcoin_node = self.bitcoin_builder.build().await?;
        let test_networks = TestNetworks {
            sui_network,
            hashi_network,
            bitcoin_node,
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
    async fn test_with_nodes_sets_same_num_of_nodes() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        assert_eq!(test_networks.hashi_network().nodes().len(), TEST_NUM_NODES);
        assert_eq!(test_networks.sui_network().num_validators, TEST_NUM_NODES);
        assert!(!test_networks.bitcoin_node().rpc_url().is_empty());

        Ok(())
    }
}
