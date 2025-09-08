use anyhow::Result;
use test_cluster::{TestCluster, TestClusterBuilder};

// TODO: Add hashi and bitcoin networks.
pub struct TestNetworks {
    pub sui_network: TestCluster,
}

impl TestNetworks {
    pub async fn new() -> Result<Self> {
        let sui_network = TestClusterBuilder::new().build().await;
        Ok(Self { sui_network })
    }

    pub fn builder() -> TestNetworksBuilder {
        TestNetworksBuilder::new()
    }

    pub fn sui_network(&self) -> &TestCluster {
        &self.sui_network
    }
}

pub struct TestNetworksBuilder {
    sui_builder: TestClusterBuilder,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        Self {
            sui_builder: TestClusterBuilder::new(),
        }
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
        Ok(TestNetworks { sui_network })
    }
}

impl Default for TestNetworksBuilder {
    fn default() -> Self {
        Self::new()
    }
}
