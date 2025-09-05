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

    pub fn with_validators(mut self, sui_num_validators: usize) -> Self {
        self.sui_builder = self.sui_builder.with_num_validators(sui_num_validators);
        self
    }

    pub fn with_epoch_duration_ms(mut self, sui_epoch_duration_ms: u64) -> Self {
        self.sui_builder = self
            .sui_builder
            .with_epoch_duration_ms(sui_epoch_duration_ms);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_test_networks_creation() -> Result<()> {
        let test_networks = TestNetworks::new().await?;
        assert!(!test_networks.sui_network().get_addresses().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_test_networks_with_custom_validators() -> Result<()> {
        let test_networks = TestNetworksBuilder::new()
            .with_validators(5)
            .build()
            .await?;

        assert_eq!(test_networks.sui_network().get_validator_pubkeys().len(), 5);
        Ok(())
    }

    #[tokio::test]
    async fn test_test_networks_with_epoch_duration() -> Result<()> {
        let test_networks = TestNetworksBuilder::new()
            .with_validators(4)
            .with_epoch_duration_ms(10000)
            .build()
            .await?;

        // Network should be created successfully with custom epoch duration
        assert!(!test_networks.sui_network().get_addresses().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_test_networks_builder_default() -> Result<()> {
        let test_networks = TestNetworksBuilder::default().build().await?;

        // Should use default configuration (4 validators)
        assert_eq!(test_networks.sui_network().get_validator_pubkeys().len(), 4);
        Ok(())
    }
}
