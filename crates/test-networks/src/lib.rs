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
pub use hashi_network::HashiProcessHandle;
pub use hashi_network::HashiProcessNetwork;
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

pub struct TestProcessNetworks {
    #[allow(unused)]
    dir: TempDir,
    pub sui_network: SuiNetworkHandle,
    pub hashi_network: HashiProcessNetwork,
    pub bitcoin_node: BitcoinNodeHandle,
}

impl TestProcessNetworks {
    pub fn sui_network(&self) -> &SuiNetworkHandle {
        &self.sui_network
    }

    pub fn hashi_network(&self) -> &HashiProcessNetwork {
        &self.hashi_network
    }

    pub fn hashi_network_mut(&mut self) -> &mut HashiProcessNetwork {
        &mut self.hashi_network
    }

    pub fn bitcoin_node(&self) -> &BitcoinNodeHandle {
        &self.bitcoin_node
    }
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

    pub fn with_auto_start(mut self, auto_start: bool) -> Self {
        self.hashi_builder = self.hashi_builder.with_auto_start(auto_start);
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
            .build(
                &dir.path().join("hashi"),
                &sui_network,
                &bitcoin_node,
                hashi_ids,
            )
            .await?;

        let test_networks = TestNetworks {
            dir,
            sui_network,
            hashi_network,
            bitcoin_node,
        };
        Ok(test_networks)
    }

    pub async fn build_process(self) -> Result<TestProcessNetworks> {
        let dir = tempfile::Builder::new()
            .prefix("hashi-test-env-")
            .tempdir()?;
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
            .build_process_network(
                &dir.path().join("hashi"),
                &sui_network,
                &bitcoin_node,
                hashi_ids,
            )
            .await?;
        let test_networks = TestProcessNetworks {
            dir,
            sui_network,
            hashi_network,
            bitcoin_node,
        };
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
    use std::time::Duration;

    // TODO: Add more integration tests for DKG.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_dkg_e2e() -> Result<()> {
        hashi::init_crypto_provider();
        // Using 3 nodes: threshold=2, max_faulty=0, required_weight=2
        // This means each dealer needs 2 signatures (including own), so 1 from others
        const NUM_NODES: usize = 3;
        let status = Command::new("cargo")
            .args(["build", "-p", "hashi", "--release"])
            .status()?;
        if !status.success() {
            anyhow::bail!("Failed to build hashi binary");
        }
        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(NUM_NODES)
            .with_auto_start(false) // We'll start manually after verification
            .build_process()
            .await?;
        assert_eq!(test_networks.hashi_network().nodes().len(), NUM_NODES);
        test_networks.hashi_network_mut().start_all()?;
        // Give nodes time to initialize and start their HTTP servers
        tokio::time::sleep(Duration::from_secs(10)).await;
        // Test connectivity by checking each node's RPC service
        for (i, node) in test_networks.hashi_network().nodes().iter().enumerate() {
            let tls_config = hashi::tls::make_client_config(&node.tls_public_key()?);
            let client = hashi::grpc::Client::new(node.https_url(), tls_config)?;
            // Retry up to 20 times (10 seconds total) as the node may still be starting
            for attempt in 1..=20 {
                match client.get_service_info().await {
                    Ok(_) => {
                        break;
                    }
                    Err(e) if attempt == 20 => {
                        anyhow::bail!("Node {} failed to start after 20 attempts: {}", i, e);
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }
        let sui_rpc_url = &test_networks.sui_network().rpc_url;
        let ids = test_networks.hashi_network().ids();
        let state = hashi::onchain::OnchainState::new(sui_rpc_url, ids, None).await?;
        let epoch = state.state().hashi().committees.epoch();
        let expected_certs = NUM_NODES;
        const DEADLINE_SECS: u64 = 3600;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(DEADLINE_SECS);
        loop {
            let certs = state.fetch_dkg_certs(epoch).await?;
            if certs.len() >= expected_certs {
                // All certificates are present - DKG completed successfully.
                // The certificates are validated on-chain by the Move contract when they're published.
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!(
                    "DKG timeout: only {} / {} certificates on TOB after {}s",
                    certs.len(),
                    expected_certs,
                    DEADLINE_SECS
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

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

        // Validate subscribing to checkpoints functions
        let ckpt = state.latest_checkpoint();
        let mut checkpoint_subscriber = state.subscribe_checkpoint();
        checkpoint_subscriber.changed().await.unwrap();
        assert!(*checkpoint_subscriber.borrow_and_update() > ckpt);

        // Validate subscribing works by just updating a validator's onchain info
        let mut reciever = state.subscribe();

        let client = test_networks.sui_network().client.clone();
        let v1_config = &test_networks.hashi_network().nodes()[0].0.config;
        super::hashi_network::update_tls_public_key(client, v1_config)
            .await
            .unwrap();

        #[allow(irrefutable_let_patterns)]
        if let hashi::onchain::Notification::ValidatorInfoUpdated(validator) =
            reciever.recv().await.unwrap()
        {
            assert_eq!(validator, v1_config.validator_address().unwrap());
        } else {
            panic!("unexpected notification");
        }

        Ok(())
    }
}
