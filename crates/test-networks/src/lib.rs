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
pub mod deposit_flow;
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

    pub fn hashi_network_mut(&mut self) -> &mut HashiNetwork {
        &mut self.hashi_network
    }

    pub fn bitcoin_node(&self) -> &BitcoinNodeHandle {
        &self.bitcoin_node
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.hashi_network.restart().await
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
    use fastcrypto::groups::GroupElement;
    use fastcrypto::groups::Scalar;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::S;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
    use fastcrypto_tbls::types::ShareIndex;

    const DKG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    const ROTATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(480);
    const SIGNING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    fn assert_nodes_agree_on_mpc_key(nodes: &[HashiNodeHandle]) {
        let pk = nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap();
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let node_pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(pk, node_pk, "Node {i} public key differs from node 0");
        }
    }

    /// Wait for all nodes to reach at least `target_epoch`.
    /// Returns the actual epoch of `nodes[0]` after the wait (may exceed `target_epoch`).
    async fn wait_for_rotation(nodes: &[HashiNodeHandle], target_epoch: u64) -> u64 {
        let futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_epoch(target_epoch, ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target_epoch}: {e}"));
        }
        nodes[0].current_epoch().unwrap()
    }

    async fn force_rotate_and_assert_key_agreement(
        test_networks: &mut TestNetworks,
        target_epoch: u64,
    ) -> u64 {
        test_networks.sui_network.force_close_epoch().await.unwrap();
        let epoch = wait_for_rotation(test_networks.hashi_network().nodes(), target_epoch).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());
        epoch
    }

    struct MockDealerNonces {
        public_keys: Vec<G>,
        /// `nonce_shares[l][i]` = share of nonce `l` for share-index `i` (0-indexed).
        nonce_shares: Vec<Vec<S>>,
    }

    fn mock_nonces_for_dealers(
        rng: &mut rand::rngs::ThreadRng,
        num_dealers: u16,
        batch_size_per_weight: u16,
        t: u16,
        n: u16,
    ) -> Vec<MockDealerNonces> {
        (0..num_dealers)
            .map(|_| {
                let nonces: Vec<S> = (0..batch_size_per_weight).map(|_| S::rand(rng)).collect();
                let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(rng, nonce, t, n)
                            .iter()
                            .map(|e| e.value)
                            .collect()
                    })
                    .collect();
                MockDealerNonces {
                    public_keys,
                    nonce_shares,
                }
            })
            .collect()
    }

    fn mock_presignatures(
        nonces_for_dealer: &[MockDealerNonces],
        share_ids: &[ShareIndex],
        batch_size_per_weight: u16,
        f: usize,
    ) -> Presignatures {
        let receiver_outputs: Vec<batch_avss::ReceiverOutput> = nonces_for_dealer
            .iter()
            .map(|dealer| {
                let shares: Vec<batch_avss::ShareBatch> = share_ids
                    .iter()
                    .map(|&sid| {
                        let share_idx = u16::from(sid) as usize - 1;
                        batch_avss::ShareBatch {
                            index: sid,
                            batch: (0..batch_size_per_weight as usize)
                                .map(|l| dealer.nonce_shares[l][share_idx])
                                .collect(),
                            blinding_share: Default::default(),
                        }
                    })
                    .collect();
                batch_avss::ReceiverOutput {
                    my_shares: batch_avss::SharesForNode { shares },
                    public_keys: dealer.public_keys.clone(),
                }
            })
            .collect();
        Presignatures::new(receiver_outputs, batch_size_per_weight, f).unwrap()
    }

    fn mock_shares(
        rng: &mut rand::rngs::ThreadRng,
        secret: S,
        t: u16,
        n: u16,
    ) -> Vec<fastcrypto_tbls::types::IndexedValue<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect()
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

        let (state, _service) = hashi::onchain::OnchainState::new(sui_rpc_url, ids, None).await?;

        assert_eq!(state.state().hashi().committees.committees().len(), 1);
        assert_eq!(state.state().hashi().committees.members().len(), 1);
        assert_eq!(state.state().hashi().treasury.treasury_caps.len(), 1);
        assert_eq!(state.state().hashi().treasury.metadata_caps.len(), 1);
        assert!(state.state().hashi().treasury.coins.is_empty());

        // Validate subscribing to checkpoints functions
        let ckpt = state.latest_checkpoint_height();
        let mut checkpoint_subscriber = state.subscribe_checkpoint();
        checkpoint_subscriber.changed().await.unwrap();
        assert!(checkpoint_subscriber.borrow_and_update().height > ckpt);

        // Wait for DKG to complete before modifying shared state to avoid lock conflicts
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(DKG_TIMEOUT)
            .await?;

        // Validate subscribing works by just updating a validator's onchain info
        let mut reciever = state.subscribe();

        let client = test_networks.sui_network().client.clone();
        let v1_config = &test_networks.hashi_network().nodes()[0].hashi().config;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_completes() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        assert_nodes_agree_on_mpc_key(nodes);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_recovery_after_restart() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // Wait for DKG to complete on all nodes
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();

        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        // Save the public key before restart
        let pk_before = test_networks.hashi_network().nodes()[0]
            .hashi()
            .mpc_handle()
            .unwrap()
            .public_key()
            .expect("public key should be set after DKG");

        // Restart the first node
        test_networks.hashi_network_mut().nodes_mut()[0]
            .restart()
            .await?;

        // Wait for the restarted node to recover DKG state
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(DKG_TIMEOUT)
            .await
            .expect("DKG recovery should complete within timeout");

        // Verify the recovered key matches the original
        let pk_after = test_networks.hashi_network().nodes()[0]
            .hashi()
            .mpc_handle()
            .unwrap()
            .public_key()
            .expect("public key should be set after recovery");

        assert_eq!(
            pk_before, pk_after,
            "Recovered DKG key should match original"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node_restart_stress() -> Result<()> {
        const TEST_NUM_NODES: usize = 3;
        const RESTART_ITERATIONS: usize = 3;

        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // Wait for initial DKG completion on all nodes
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} initial DKG failed: {e}"));
        }

        // Verify all nodes are reachable via RPC before restart cycles
        for (i, node) in test_networks.hashi_network().nodes().iter().enumerate() {
            let client = hashi::grpc::Client::new_no_auth(node.https_url())?;
            client
                .get_service_info()
                .await
                .unwrap_or_else(|e| panic!("Node {i} initial RPC failed: {e}"));
        }

        // Restart all nodes multiple times
        for iteration in 0..RESTART_ITERATIONS {
            tracing::info!(
                "Starting restart iteration {}/{}",
                iteration + 1,
                RESTART_ITERATIONS
            );

            // Restart all nodes
            test_networks.hashi_network_mut().restart().await?;

            // Wait for DKG recovery on all nodes after restart
            let nodes = test_networks.hashi_network().nodes();
            let mpc_key_futures: Vec<_> = nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| {
                    panic!(
                        "Node {i} DKG failed after restart iteration {}: {e}",
                        iteration + 1
                    )
                });
            }

            // Verify all nodes are reachable via RPC after restart
            for (i, node) in test_networks.hashi_network().nodes().iter().enumerate() {
                let client = hashi::grpc::Client::new_no_auth(node.https_url())?;
                client.get_service_info().await.unwrap_or_else(|e| {
                    panic!(
                        "Node {i} RPC failed after restart iteration {}: {e}",
                        iteration + 1
                    )
                });
            }

            tracing::info!(
                "Restart iteration {}/{} completed successfully",
                iteration + 1,
                RESTART_ITERATIONS
            );
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_key_rotation() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // Wait for initial DKG completion on all nodes (epoch 1)
        {
            let nodes = test_networks.hashi_network().nodes();
            let mpc_key_futures: Vec<_> = nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
            assert_nodes_agree_on_mpc_key(nodes);
        }

        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // First key rotation
        let epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;

        // Second key rotation
        force_rotate_and_assert_key_agreement(&mut test_networks, epoch + 1).await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_key_rotation_restart_recovery_across_two_rounds() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // Wait for initial DKG completion on all nodes
        {
            let nodes = test_networks.hashi_network().nodes();
            let mpc_key_futures: Vec<_> = nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
        }

        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // Round 1: restart after DKG, then rotate
        test_networks.hashi_network_mut().nodes_mut()[0]
            .restart()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(DKG_TIMEOUT)
            .await
            .expect("Node 0 should recover MPC key after restart");
        let epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;

        // Round 2: restart after rotation, then rotate again
        test_networks.hashi_network_mut().nodes_mut()[0]
            .restart()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(DKG_TIMEOUT)
            .await
            .expect("Node 0 should recover MPC key after restart");
        force_rotate_and_assert_key_agreement(&mut test_networks, epoch + 1).await;

        Ok(())
    }

    // TODO: Replace presigning simulation after presigning is completed.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing_e2e() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // Wait for DKG so gRPC servers and onchain state are fully initialized.
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        // Read DKG config from each node's DkgManager.
        let mut node_infos: Vec<(
            /* party_id */ u16,
            /* address */ sui_sdk_types::Address,
            /* share_ids */ Vec<ShareIndex>,
        )> = Vec::new();
        let (threshold, max_faulty, total_weight) = {
            let dkg_mgr = nodes[0].hashi().dkg_manager();
            let mgr = dkg_mgr.read().unwrap();
            (
                mgr.dkg_config.threshold,
                mgr.dkg_config.max_faulty,
                mgr.dkg_config.nodes.total_weight(),
            )
        };
        for node in nodes {
            let dkg_mgr = node.hashi().dkg_manager();
            let mgr = dkg_mgr.read().unwrap();
            let share_ids = mgr.dkg_config.nodes.share_ids_of(mgr.party_id).unwrap();
            node_infos.push((mgr.party_id, mgr.address, share_ids));
        }

        let n = total_weight;
        let t = threshold;
        let f = max_faulty as usize;
        let batch_size_per_weight: u16 = 5;
        let mut rng = rand::thread_rng();

        // Fake signing key shares.
        let sk = S::rand(&mut rng);
        let vk = G::generator() * sk;
        let all_sk_shares = mock_shares(&mut rng, sk, t, n);

        // Fake nonce shares for presigning.
        let nonces_for_dealer = mock_nonces_for_dealers(&mut rng, n, batch_size_per_weight, t, n);

        // Build ReceiverOutputs per node and create Presignatures + SigningManager.
        let epoch = nodes[0].hashi().onchain_state().epoch();
        for (node_idx, node) in nodes.iter().enumerate() {
            let (_party_id, address, ref share_ids) = node_infos[node_idx];
            let key_shares = avss::SharesForNode {
                shares: share_ids
                    .iter()
                    .map(|&sid| {
                        // ShareIndex is 1-based; all_sk_shares is 0-indexed by share index - 1.
                        all_sk_shares[u16::from(sid) as usize - 1].clone()
                    })
                    .collect(),
            };
            let presignatures =
                mock_presignatures(&nonces_for_dealer, share_ids, batch_size_per_weight, f);
            let committee = {
                let dkg_mgr = node.hashi().dkg_manager();
                let mgr = dkg_mgr.read().unwrap();
                mgr.committee.clone()
            };
            let signing_manager = hashi::mpc::SigningManager::new(
                address,
                committee,
                t,
                key_shares,
                vk,
                presignatures,
            );
            node.hashi().init_signing_manager(signing_manager);
        }

        // All nodes call sign() concurrently.
        let message = b"Hello, Hashi signing!";
        let beacon_value = S::rand(&mut rng);
        let sui_request_id = sui_sdk_types::Address::ZERO;
        let sign_futures: Vec<_> = nodes
            .iter()
            .map(|node| {
                let signing_manager = node.hashi().signing_manager();
                let onchain_state = node.hashi().onchain_state().clone();
                let p2p_channel = hashi::mpc::rpc::RpcP2PChannel::new(onchain_state, epoch);
                let beacon = beacon_value;
                async move {
                    hashi::mpc::SigningManager::sign(
                        &signing_manager,
                        &p2p_channel,
                        sui_request_id,
                        message,
                        &beacon,
                        None,
                        SIGNING_TIMEOUT,
                    )
                    .await
                }
            })
            .collect();

        let results = futures::future::join_all(sign_futures).await;
        let mut signatures = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            let sig = result.unwrap_or_else(|e| panic!("Node {i} signing failed: {e}"));
            signatures.push(sig);
        }

        // All nodes should produce the same signature.
        let sig0_bytes = signatures[0].to_byte_array();
        for (i, sig) in signatures.iter().enumerate().skip(1) {
            assert_eq!(
                sig0_bytes,
                sig.to_byte_array(),
                "Node {i} signature differs from node 0"
            );
        }
        Ok(())
    }
}
