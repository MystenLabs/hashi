use anyhow::Result;
use test_cluster::{TestCluster, TestClusterBuilder};

pub mod hashi_network;
pub use hashi_network::{
    DEFAULT_BASE_GRPC_PORT, DEFAULT_BASE_HTTP_PORT, HashiNetwork, HashiNetworkBuilder,
    HashiNodeHandle, LOCALHOST,
};

// TODO: Add bitcoin network.
pub struct TestNetworks {
    pub sui_network: TestCluster,
    pub hashi_network: HashiNetwork,
}

impl TestNetworks {
    pub async fn new() -> Result<Self> {
        let sui_network = TestClusterBuilder::new().build().await;
        let hashi_network = HashiNetworkBuilder::new().build().await?;
        let test_networks = Self {
            sui_network,
            hashi_network,
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
}

pub struct TestNetworksBuilder {
    sui_builder: TestClusterBuilder,
    hashi_builder: HashiNetworkBuilder,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        Self {
            sui_builder: TestClusterBuilder::new(),
            hashi_builder: HashiNetworkBuilder::new(),
        }
    }

    pub fn with_hashi_nodes(mut self, num_nodes: usize) -> Self {
        self.hashi_builder = self.hashi_builder.with_num_nodes(num_nodes);
        self
    }

    pub fn with_sui_validators(mut self, num_validators: usize) -> Self {
        self.sui_builder = self.sui_builder.with_num_validators(num_validators);
        self
    }

    pub async fn build(self) -> Result<TestNetworks> {
        let sui_network = self.sui_builder.build().await;
        let hashi_network = self.hashi_builder.build().await?;
        let test_networks = TestNetworks {
            sui_network,
            hashi_network,
        };
        Ok(test_networks)
    }
}

impl Default for TestNetworksBuilder {
    fn default() -> Self {
        Self::new()
    }
}
