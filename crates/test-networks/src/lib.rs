//! Test infrastructure to stand up a Sui localnet, a bitcoin regtest, and hashi nodes.
//!
//! The general bootstrapping process is as follows:
//! 1. Stand up a Bitcoin regtest
//! 2. Stand up a Sui Network leveraging `sui start`.
//! 3. Ensure that the SuiSystemState object has been upgraded from v1 to v2.
//! 4. Ensure that each sui validator address is properly funded.
//! 5. Publish the Hashi package.
//! 6. Build configs for each Hashi node (one for each validator).
//! 7. Register each validator with the Hashi system object
//! 8. Initialize the first hashi committee once all validators have been registered.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

pub mod bitcoin_node;
pub mod hashi_network;
mod publish;
pub mod sui_network;

pub use bitcoin_node::BitcoinNodeBuilder;
pub use bitcoin_node::BitcoinNodeHandle;
pub use hashi_network::HashiNetwork;
pub use hashi_network::HashiNetworkBuilder;
pub use hashi_network::HashiNodeHandle;
pub use sui_network::SuiNetworkBuilder;
pub use sui_network::SuiNetworkHandle;
use tempfile::TempDir;

use crate::publish::publish;
use crate::sui_network::sui_binary;

pub struct TestNetworks {
    #[allow(unused)]
    dir: TempDir,
    pub sui_network: SuiNetworkHandle,
    pub hashi_network: HashiNetwork,
    pub bitcoin_node: BitcoinNodeHandle,
}

impl TestNetworks {
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
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

    fn _sui_client_command(&self) -> Command {
        let client_config = self.dir.path().join("sui/client.yaml");
        let mut cmd = Command::new(sui_binary());
        cmd.arg("client").arg("--client.config").arg(client_config);
        cmd
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
        let dir = tempfile::Builder::new()
            .prefix("hashi-test-env-")
            .tempdir()?;

        println!("test env: {}", dir.path().display());

        let bitcoin_node = self.bitcoin_builder.dir(dir.as_ref()).build().await?;

        let mut sui_network = self
            .sui_builder
            .dir(&dir.path().join("sui"))
            .build()
            .await?;
        Self::cp_packages(dir.as_ref())?;

        let hashi_ids = publish(
            dir.as_ref(),
            &mut sui_network.client,
            sui_network.user_keys.first().unwrap(),
        )
        .await?;

        let hashi_network = self
            .hashi_builder
            .build(&sui_network, &bitcoin_node, hashi_ids)
            .await?;

        let test_networks = TestNetworks {
            dir,
            sui_network,
            hashi_network,
            bitcoin_node,
        };

        println!("rpc url: {}", test_networks.sui_network().rpc_url);

        Ok(test_networks)
    }

    pub fn cp_packages(dir: &Path) -> Result<()> {
        const PACKAGES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages");

        // Copy packages over to the scratch space
        let output = Command::new("cp")
            .arg("-r")
            .arg(PACKAGES_DIR)
            .arg(dir)
            .output()?;
        if !output.status.success() {
            anyhow::bail!("unable to run 'cp -r {PACKAGES_DIR} {}", dir.display());
        }

        Ok(())
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

        // loop {
        //     tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        // }

        Ok(())
    }

    #[tokio::test]
    async fn test_onchain_state_scraping() -> Result<()> {
        const TEST_NUM_NODES: usize = 1;

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;
        let sui_rpc_url = &test_networks.sui_network().rpc_url;
        let ids = test_networks.hashi_network().ids();

        let state = hashi::onchain::OnchainState::new(sui_rpc_url, ids, None).await?;

        assert_eq!(state.state().hashi().committees.committees().len(), 1);
        assert_eq!(state.state().hashi().committees.members().len(), 1);
        assert_eq!(state.state().hashi().treasury.treasury_caps.len(), 1);
        assert_eq!(state.state().hashi().treasury.metadata_caps.len(), 1);
        assert!(state.state().hashi().treasury.coins.is_empty());

        // println!("{state:#?}");

        Ok(())
    }
}
