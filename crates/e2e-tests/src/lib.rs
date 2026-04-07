// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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

pub mod backup_restore;
pub mod bitcoin_node;
pub mod e2e_flow;
pub mod hashi_network;
mod publish;
pub mod sui_network;
pub mod test_helpers;
pub mod upgrade_flow;

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

    pub fn dir(&self) -> &Path {
        self.dir.path()
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
    /// On-chain config overrides applied after DKG completes, before `build()`
    /// returns. Each entry is run through the full propose/vote/execute flow.
    onchain_config_overrides: Vec<(String, hashi_types::move_types::ConfigValue)>,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        Self {
            sui_builder: SuiNetworkBuilder::default(),
            hashi_builder: HashiNetworkBuilder::new(),
            bitcoin_builder: BitcoinNodeBuilder::new(),
            onchain_config_overrides: Vec::new(),
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

    pub fn with_initially_active_nodes(mut self, initially_active: usize) -> Self {
        self.hashi_builder = self.hashi_builder.with_initially_active(initially_active);
        self
    }

    pub fn with_sui_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.sui_builder = self.sui_builder.with_epoch_duration_ms(epoch_duration_ms);
        self
    }

    pub fn with_sui_rpc_port(mut self, port: u16) -> Self {
        self.sui_builder = self.sui_builder.with_rpc_port(port);
        self
    }

    pub fn with_btc_rpc_port(mut self, port: u16) -> Self {
        self.bitcoin_builder = self.bitcoin_builder.with_rpc_port(port);
        self
    }

    pub fn with_batch_size_per_weight(mut self, batch_size_per_weight: u16) -> Self {
        self.hashi_builder = self
            .hashi_builder
            .with_batch_size_per_weight(batch_size_per_weight);
        self
    }

    pub fn with_corrupt_shares_target(mut self, target_node_index: usize) -> Self {
        self.hashi_builder = self
            .hashi_builder
            .with_corrupt_shares_target(target_node_index);
        self
    }

    pub fn with_full_voting_power(mut self) -> Self {
        self.hashi_builder = self.hashi_builder.with_full_voting_power();
        self
    }

    /// Queue an on-chain config override to be applied after the network
    /// initializes. Each call adds one key/value pair; multiple overrides
    /// are applied in order, one proposal per entry.
    ///
    /// Example:
    /// ```ignore
    /// TestNetworksBuilder::new()
    ///     .with_nodes(4)
    ///     .with_onchain_config("bitcoin_confirmation_threshold", ConfigValue::U64(6))
    ///     .build()
    ///     .await?
    /// ```
    pub fn with_onchain_config(
        mut self,
        key: impl Into<String>,
        value: hashi_types::move_types::ConfigValue,
    ) -> Self {
        self.onchain_config_overrides.push((key.into(), value));
        self
    }

    pub fn with_withdrawal_batching_delay_ms(mut self, ms: u64) -> Self {
        self.hashi_builder = self.hashi_builder.with_withdrawal_batching_delay_ms(ms);
        self
    }

    pub fn with_withdrawal_max_batch_size(mut self, size: usize) -> Self {
        self.hashi_builder = self.hashi_builder.with_withdrawal_max_batch_size(size);
        self
    }

    pub fn with_max_mempool_chain_depth(mut self, depth: usize) -> Self {
        self.hashi_builder = self.hashi_builder.with_max_mempool_chain_depth(depth);
        self
    }

    pub async fn build(self) -> Result<TestNetworks> {
        let dir = tempfile::Builder::new()
            .prefix("hashi-test-env-")
            .tempdir()?;

        tracing::info!("test env: {}", dir.path().display());

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

        let mut test_networks = TestNetworks {
            dir,
            sui_network,
            hashi_network,
            bitcoin_node,
        };

        tracing::info!("rpc url: {}", test_networks.sui_network().rpc_url);

        if !self.onchain_config_overrides.is_empty() {
            apply_onchain_config_overrides(&mut test_networks, &self.onchain_config_overrides)
                .await?;
        }

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

/// Apply on-chain config overrides by running the full propose/vote/execute
/// cycle for each `(key, value)` pair. Called from `TestNetworksBuilder::build`
/// when overrides are present.
///
/// Waits for DKG to complete first so the committee is ready to vote.
/// All nodes vote on every proposal, ensuring quorum is always reached
/// regardless of the number of nodes or their weight distribution.
pub(crate) async fn apply_onchain_config_overrides(
    networks: &mut TestNetworks,
    overrides: &[(String, hashi_types::move_types::ConfigValue)],
) -> Result<()> {
    use hashi::cli::client::CreateProposalParams;
    use hashi::cli::client::build_create_proposal_transaction;
    use hashi::cli::client::build_vote_transaction;
    use hashi::cli::upgrade::build_execute_proposal_transaction;
    use hashi::cli::upgrade::extract_proposal_id_from_response;
    use hashi::sui_tx_executor::SuiTxExecutor;
    use sui_sdk_types::Identifier;
    use sui_sdk_types::StructTag;
    use sui_sdk_types::TypeTag;

    let nodes = networks.hashi_network.nodes();

    // The committee is only available after DKG. Wait on the first node; the
    // others are guaranteed to be ready too once DKG completes.
    nodes[0]
        .wait_for_mpc_key(std::time::Duration::from_secs(120))
        .await?;

    let hashi_ids = networks.hashi_network.ids();

    // Build one executor per node, reused across all overrides.
    let mut executors: Vec<SuiTxExecutor> = nodes
        .iter()
        .map(|node| {
            let hashi = node.hashi();
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
        })
        .collect::<anyhow::Result<_>>()?;

    // Updated to the checkpoint of each execute response; used after the loop
    // to wait for all nodes to catch up to the last applied override.
    let mut exec_checkpoint: u64 = 0;

    let update_config_type_tag = TypeTag::Struct(Box::new(StructTag::new(
        hashi_ids.package_id,
        Identifier::from_static("update_config"),
        Identifier::from_static("UpdateConfig"),
        vec![],
    )));

    //TODO could we build the proposals and vote/execute on them all at the same time vs doing them
    //one at a time?
    for (key, value) in overrides {
        tracing::info!("applying on-chain config override: {key} = {value:?}");

        // 1. Node 0 creates the proposal (and automatically casts its own vote).
        let create_tx = build_create_proposal_transaction(
            hashi_ids,
            CreateProposalParams::UpdateConfig {
                key: key.clone(),
                value: value.clone(),
                metadata: vec![],
            },
        );
        let response = executors[0].execute(create_tx).await?;
        anyhow::ensure!(
            response.transaction().effects().status().success(),
            "create UpdateConfig proposal for '{key}' failed"
        );

        let proposal_id = extract_proposal_id_from_response(&response)?;
        tracing::info!("proposal {proposal_id} created for '{key}'; collecting votes");

        // 2. All remaining nodes vote. This gives 100% of total weight,
        //    guaranteeing the 66.67% quorum threshold is met.
        for executor in &mut executors[1..] {
            let vote_tx =
                build_vote_transaction(hashi_ids, proposal_id, update_config_type_tag.clone());
            let vote_resp = executor.execute(vote_tx).await?;
            anyhow::ensure!(
                vote_resp.transaction().effects().status().success(),
                "vote on UpdateConfig proposal {proposal_id} for '{key}' failed"
            );
        }

        // 3. Node 0 executes the proposal now that quorum is reached.
        let execute_tx = build_execute_proposal_transaction(
            hashi_ids,
            proposal_id,
            hashi_ids.package_id,
            "update_config",
        )?;
        let exec_resp = executors[0].execute(execute_tx).await?;
        anyhow::ensure!(
            exec_resp.transaction().effects().status().success(),
            "execute UpdateConfig proposal {proposal_id} for '{key}' failed"
        );

        exec_checkpoint = exec_resp
            .transaction()
            .checkpoint_opt()
            .ok_or_else(|| anyhow::anyhow!("execute transaction response missing checkpoint"))?;

        tracing::info!("on-chain config override applied: {key} (checkpoint {exec_checkpoint})");
    }

    // Wait for all nodes' watchers to process the checkpoint that contains the
    // last execute transaction. The watcher re-fetches config on each
    // ProposalExecutedEvent<UpdateConfig>, so once a node reaches this
    // checkpoint its in-memory config will reflect the override.
    let futs = networks.hashi_network().nodes().iter().map(|node| {
        let mut subscription = node.hashi().onchain_state().subscribe_checkpoint();
        async move {
            while subscription.borrow().height < exec_checkpoint {
                subscription.changed().await.unwrap();
            }
        }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        futures::future::join_all(futs),
    )
    .await?;

    Ok(())
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

    fn get_mpc_key(nodes: &[HashiNodeHandle]) -> G {
        nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap()
    }

    fn assert_nodes_agree_on_mpc_key(nodes: &[HashiNodeHandle]) {
        let pk = get_mpc_key(nodes);
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
        let key_before = get_mpc_key(test_networks.hashi_network().nodes());
        test_networks.sui_network.force_close_epoch().await.unwrap();
        let epoch = wait_for_rotation(test_networks.hashi_network().nodes(), target_epoch).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());
        let key_after = get_mpc_key(test_networks.hashi_network().nodes());
        assert_eq!(
            key_before, key_after,
            "Public key changed during rotation to epoch {target_epoch}"
        );
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

    struct NodeDkgInfo {
        address: sui_sdk_types::Address,
        share_ids: Vec<ShareIndex>,
    }

    struct DkgConfig {
        threshold: u16,
        max_faulty: usize,
        total_weight: u16,
    }

    fn read_dkg_config(nodes: &[HashiNodeHandle]) -> (Vec<NodeDkgInfo>, DkgConfig) {
        let (threshold, max_faulty, total_weight) = {
            let mpc_mgr = nodes[0].hashi().mpc_manager().unwrap();
            let mgr = mpc_mgr.read().unwrap();
            (
                mgr.mpc_config.threshold,
                mgr.mpc_config.max_faulty,
                mgr.mpc_config.nodes.total_weight(),
            )
        };
        let node_infos: Vec<_> = nodes
            .iter()
            .map(|node| {
                let mpc_mgr = node.hashi().mpc_manager().unwrap();
                let mgr = mpc_mgr.read().unwrap();
                let share_ids = mgr.mpc_config.nodes.share_ids_of(mgr.party_id).unwrap();
                NodeDkgInfo {
                    address: mgr.address,
                    share_ids,
                }
            })
            .collect();
        (
            node_infos,
            DkgConfig {
                threshold,
                max_faulty: max_faulty as usize,
                total_weight,
            },
        )
    }

    /// Override SigningManagers on all nodes with mock key shares and presignatures,
    /// deliberately giving wrong key shares to the specified corrupt nodes.
    fn corrupt_signing_managers(
        nodes: &[HashiNodeHandle],
        node_infos: &[NodeDkgInfo],
        cfg: &DkgConfig,
        corrupt_node_indices: &[usize],
    ) -> G {
        let mut rng = rand::thread_rng();
        let n = cfg.total_weight;
        let t = cfg.threshold;
        let batch_size_per_weight: u16 = 5;

        let sk = S::rand(&mut rng);
        let vk = G::generator() * sk;
        let all_sk_shares = mock_shares(&mut rng, sk, t, n);

        // Wrong key shares for corrupted nodes.
        let wrong_sk = S::rand(&mut rng);
        let wrong_sk_shares = mock_shares(&mut rng, wrong_sk, t, n);

        let nonces_for_dealer = mock_nonces_for_dealers(&mut rng, n, batch_size_per_weight, t, n);

        for (node_idx, node) in nodes.iter().enumerate() {
            let info = &node_infos[node_idx];
            let shares_source = if corrupt_node_indices.contains(&node_idx) {
                &wrong_sk_shares
            } else {
                &all_sk_shares
            };
            let key_shares = avss::SharesForNode {
                shares: info
                    .share_ids
                    .iter()
                    .map(|&sid| shares_source[u16::from(sid) as usize - 1].clone())
                    .collect(),
            };
            let presignatures = mock_presignatures(
                &nonces_for_dealer,
                &info.share_ids,
                batch_size_per_weight,
                cfg.max_faulty,
            );
            let committee = {
                let mpc_mgr = node.hashi().mpc_manager().unwrap();
                let mgr = mpc_mgr.read().unwrap();
                mgr.committee.clone()
            };
            let (refill_tx, _) = tokio::sync::watch::channel(0u32);
            let signing_manager = hashi::mpc::SigningManager::new(
                info.address,
                committee,
                t,
                key_shares,
                vk,
                presignatures,
                0,
                0,
                hashi::constants::PRESIG_REFILL_DIVISOR,
                std::sync::Arc::new(refill_tx),
            );
            node.hashi().set_signing_manager(signing_manager);
        }
        vk
    }

    /// Have all nodes call sign() concurrently, returning per-node results.
    async fn sign_on_all_nodes(
        nodes: &[HashiNodeHandle],
        message: &[u8],
        epoch: u64,
        sui_request_id: sui_sdk_types::Address,
        global_presig_index: u64,
    ) -> Vec<
        hashi::mpc::types::SigningResult<fastcrypto::groups::secp256k1::schnorr::SchnorrSignature>,
    > {
        let beacon_value = S::rand(&mut rand::thread_rng());
        let sign_futures: Vec<_> = nodes
            .iter()
            .map(|node| {
                let signing_manager = node.hashi().signing_manager();
                let onchain_state = node.hashi().onchain_state().clone();
                let p2p_channel = hashi::mpc::rpc::RpcP2PChannel::new(onchain_state, epoch);
                let beacon = beacon_value;
                let message = message.to_vec();
                async move {
                    hashi::mpc::SigningManager::sign(
                        &signing_manager,
                        &p2p_channel,
                        sui_request_id,
                        &message,
                        global_presig_index,
                        &beacon,
                        None,
                        SIGNING_TIMEOUT,
                    )
                    .await
                }
            })
            .collect();
        futures::future::join_all(sign_futures).await
    }

    fn assert_all_signatures_match(
        results: Vec<
            hashi::mpc::types::SigningResult<
                fastcrypto::groups::secp256k1::schnorr::SchnorrSignature,
            >,
        >,
    ) {
        let mut signatures = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            let sig = result.unwrap_or_else(|e| panic!("Node {i} signing failed: {e}"));
            signatures.push(sig);
        }
        let sig0_bytes = signatures[0].to_byte_array();
        for (i, sig) in signatures.iter().enumerate().skip(1) {
            assert_eq!(
                sig0_bytes,
                sig.to_byte_array(),
                "Node {i} signature differs from node 0"
            );
        }
    }

    async fn run_signing_test(num_nodes: usize, corrupt_node_indices: &[usize]) -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(num_nodes)
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

        let epoch = nodes[0].hashi().onchain_state().epoch();
        if !corrupt_node_indices.is_empty() {
            let (node_infos, cfg) = read_dkg_config(nodes);
            corrupt_signing_managers(nodes, &node_infos, &cfg, corrupt_node_indices);
        }

        let message: &[u8] = b"Hello, Hashi signing!";
        let request_id = sui_sdk_types::Address::ZERO;
        let results = sign_on_all_nodes(nodes, message, epoch, request_id, 0).await;
        assert_all_signatures_match(results);

        Ok(())
    }

    /// Shutdown a node, open its DB, delete the first half of messages listed
    /// by `list_fn`, using `delete_fn` to remove each one.
    fn delete_first_half_of_messages(
        node: &HashiNodeHandle,
        _label: &str,
        list_fn: impl FnOnce(&hashi::db::Database) -> Result<Vec<sui_sdk_types::Address>>,
        delete_fn: impl Fn(&hashi::db::Database, &sui_sdk_types::Address) -> anyhow::Result<()>,
    ) -> Result<()> {
        let db = node.open_db()?;
        let dealers = list_fn(&db)?;
        let to_delete = dealers.len() / 2;
        for dealer in &dealers[..to_delete] {
            delete_fn(&db, dealer)?;
        }
        Ok(())
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

        let (state, _service) =
            hashi::onchain::OnchainState::new(sui_rpc_url, ids, None, None, None).await?;

        assert_eq!(state.state().hashi().committees.committees().len(), 1);
        assert_eq!(state.state().hashi().committees.members().len(), 1);
        assert_eq!(state.state().hashi().treasury.treasury_caps.len(), 1);
        assert_eq!(state.state().hashi().treasury.metadata_caps.len(), 1);

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

    /// Verify that rescraping on-chain state correctly deserializes deposit
    /// requests from ObjectBag dynamic fields.
    ///
    /// This catches BCS mismatches between the subscription path (which builds
    /// objects from events) and the scrape path (which reads from ObjectBag
    /// child objects). The subscription path may work while the scrape path
    /// fails if the deserialization code uses the wrong field access method.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_rescrape_with_existing_requests() -> Result<()> {
        let test_networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_full_voting_power()
            .build()
            .await?;

        let nodes = test_networks.hashi_network().nodes();
        nodes[0].wait_for_mpc_key(DKG_TIMEOUT).await?;

        // Submit a deposit request using a dummy UTXO so the ObjectBag has an entry.
        let user_key = test_networks.sui_network.user_keys.first().unwrap();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = nodes[0].hashi().clone();
        let mut executor = hashi::sui_tx_executor::SuiTxExecutor::from_config(
            &hashi.config,
            hashi.onchain_state(),
        )?
        .with_signer(user_key.clone());
        let dummy_txid = sui_sdk_types::Address::new([0xCA; 32]);
        let _request_id = executor
            .execute_create_deposit_request(dummy_txid, 0, 50_000, Some(hbtc_recipient))
            .await?;

        // Wait briefly for the subscription path to pick up the event
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Now rescrape from chain — this exercises the ObjectBag deserialization
        // path that reads child objects, not the subscription/event path.
        hashi.onchain_state().rescrape().await?;

        // Verify the deposit request survived the rescrape.
        let deposit_requests = hashi.onchain_state().deposit_requests();
        assert!(
            !deposit_requests.is_empty(),
            "Rescrape should find the deposit request in the ObjectBag"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        let test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .with_full_voting_power()
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
            let client = hashi::grpc::Client::new_no_auth(node.endpoint_url())?;
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
                let client = hashi::grpc::Client::new_no_auth(node.endpoint_url())?;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_new_member_joins_key_rotation_after_dkg() -> Result<()> {
        const TOTAL_VALIDATORS: usize = 20;
        const INITIAL_NODES: usize = 19; // 19/20 = 95%, meets the registration threshold

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks = TestNetworksBuilder::new()
            .with_sui_validators(TOTAL_VALIDATORS)
            .with_hashi_nodes(TOTAL_VALIDATORS)
            .with_initially_active_nodes(INITIAL_NODES)
            .build()
            .await?;

        // Wait for DKG to complete with 19 nodes
        {
            let active_nodes = &test_networks.hashi_network().nodes()[..INITIAL_NODES];
            let mpc_key_futures: Vec<_> = active_nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
            assert_nodes_agree_on_mpc_key(active_nodes);
        }

        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // Register and start the 20th node (new member)
        let client = test_networks.sui_network.client.clone();
        test_networks
            .hashi_network_mut()
            .register_and_start_pending_node(client)
            .await?;

        // Force epoch change → key rotation 19→20.
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), initial_epoch + 1).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_new_member_joins_key_rotation_after_rotation() -> Result<()> {
        const TOTAL_VALIDATORS: usize = 20;
        const INITIAL_NODES: usize = 19; // 19/20 = 95%, meets the registration threshold

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks = TestNetworksBuilder::new()
            .with_sui_validators(TOTAL_VALIDATORS)
            .with_hashi_nodes(TOTAL_VALIDATORS)
            .with_initially_active_nodes(INITIAL_NODES)
            .build()
            .await?;

        // Wait for DKG to complete with 19 nodes
        {
            let active_nodes = &test_networks.hashi_network().nodes()[..INITIAL_NODES];
            let mpc_key_futures: Vec<_> = active_nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
            assert_nodes_agree_on_mpc_key(active_nodes);
        }

        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // 2. Force epoch change → key rotation with same 19 nodes.
        test_networks.sui_network.force_close_epoch().await?;
        let active_nodes = &test_networks.hashi_network().nodes()[..INITIAL_NODES];
        wait_for_rotation(active_nodes, initial_epoch + 1).await;
        assert_nodes_agree_on_mpc_key(active_nodes);

        // 3. Register and start the 20th node (new member)
        let client = test_networks.sui_network.client.clone();
        test_networks
            .hashi_network_mut()
            .register_and_start_pending_node(client)
            .await?;

        // 4. Force epoch change → key rotation 19→20.
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), initial_epoch + 2).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing_happy_path() -> Result<()> {
        run_signing_test(4, &[]).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing_recovery_max_correctable() -> Result<()> {
        // n=7, t=3, f=2. Two nodes have wrong key shares.
        // Each node collects 7 sigs (2 bad), RS capacity (7-3)/2=2 → corrects 2.
        run_signing_test(7, &[0, 1]).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mid_protocol_restart_recovery() -> Result<()> {
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

        // Wait for DKG completion on all nodes
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        let epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // Phase 1: DKG + nonce recovery with partial state
        let node0 = &mut test_networks.hashi_network_mut().nodes_mut()[0];
        node0.shutdown().await;
        delete_first_half_of_messages(
            node0,
            "dealer",
            |db| {
                Ok(db
                    .list_all_dealer_messages(epoch)?
                    .into_iter()
                    .map(|(addr, _)| addr)
                    .collect())
            },
            |db, dealer| Ok(db.delete_dealer_message(epoch, dealer)?),
        )?;
        delete_first_half_of_messages(
            node0,
            "nonce",
            |db| {
                Ok(db
                    .list_nonce_messages(epoch, 0)?
                    .into_iter()
                    .map(|(addr, _)| addr)
                    .collect())
            },
            |db, dealer| Ok(db.delete_nonce_message(epoch, 0, dealer)?),
        )?;

        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(DKG_TIMEOUT)
            .await
            .expect("DKG + nonce recovery with partial state should complete");
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        // Phase 2: Rotation + nonce recovery with partial state
        let next_epoch = epoch + 1;
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), next_epoch).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        let node0 = &mut test_networks.hashi_network_mut().nodes_mut()[0];
        node0.shutdown().await;
        delete_first_half_of_messages(
            node0,
            "rotation",
            |db| {
                Ok(db
                    .list_all_rotation_messages(next_epoch)?
                    .into_iter()
                    .map(|(addr, _)| addr)
                    .collect())
            },
            |db, dealer| Ok(db.delete_rotation_messages(next_epoch, dealer)?),
        )?;
        delete_first_half_of_messages(
            node0,
            "nonce",
            |db| {
                Ok(db
                    .list_nonce_messages(next_epoch, 0)?
                    .into_iter()
                    .map(|(addr, _)| addr)
                    .collect())
            },
            |db, dealer| Ok(db.delete_nonce_message(next_epoch, 0, dealer)?),
        )?;

        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(std::time::Duration::from_secs(180))
            .await
            .expect("Rotation recovery with partial state should complete");
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_second_rotation_retrieves_missing_previous_rotation_message() -> Result<()> {
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

        // Wait for DKG completion
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

        // First rotation — all nodes participate normally
        let epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;

        // Delete node 1's rotation messages from node 0's DB. Nodes 1, 2, 3 all
        // have this message, guaranteeing retrieval always succeeds.
        let node1_address = test_networks.hashi_network().nodes()[1].validator_address();

        let node0 = &mut test_networks.hashi_network_mut().nodes_mut()[0];
        node0.shutdown().await;
        {
            let db = node0.open_db()?;
            db.delete_rotation_messages(epoch, &node1_address)?;
        }

        // Start node 0 and trigger a second rotation.
        // prepare_previous_output should retrieve the missing messages from peers.
        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(ROTATION_TIMEOUT)
            .await
            .expect("Node 0 should recover MPC key after restart");
        force_rotate_and_assert_key_agreement(&mut test_networks, epoch + 1).await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_refill_presignature_pool() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let test_networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        let epoch = nodes[0].hashi().onchain_state().epoch();

        let signing_manager = nodes[0].hashi().signing_manager();
        let pool_size = signing_manager.read().unwrap().initial_presig_count();
        let refill_trigger_at = pool_size - pool_size / hashi::constants::PRESIG_REFILL_DIVISOR;
        // Sign pool_size + 1 times: exhaust batch 0 and prove batch 1 swap works.
        let num_signings = pool_size + 1;
        // Wait for refill a few signs after the threshold, before exhaustion.
        let wait_at = refill_trigger_at + (pool_size - refill_trigger_at) / 2;

        for i in 0..num_signings {
            let request_id = sui_sdk_types::Address::new([i as u8; 32]);
            let results =
                sign_on_all_nodes(nodes, b"refill test", epoch, request_id, i as u64).await;
            assert_all_signatures_match(results);

            // After crossing the refill threshold, wait for the refill to
            // complete before we exhaust the pool.
            if i == wait_at {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                while !signing_manager.read().unwrap().has_next_batch() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "Timed out waiting for presignature refill"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        assert_eq!(signing_manager.read().unwrap().batch_index(), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_complaint_recovery() -> Result<()> {
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
            .with_corrupt_shares_target(0) // all others corrupt shares for node 0
            .build()
            .await?;

        // 1. DKG with complaint recovery
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

        // 2. Sign to verify nonce generation presigs (built via in-memory complaint recovery) work
        let epoch = nodes[0].hashi().onchain_state().epoch();
        let request_id = sui_sdk_types::Address::ZERO;
        let results = sign_on_all_nodes(nodes, b"complaint test", epoch, request_id, 0).await;
        assert_all_signatures_match(results);

        // 3. First rotation — reconstruct_previous_output hits corrupted DKG
        //    messages → DKG reconstruction complaint recovery via RPC →
        //    rotation dealers also corrupted → complaint recovery → key preserved
        let initial_epoch = nodes[0].current_epoch().unwrap();
        let epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;

        // 4. Second rotation — reconstruct_previous_output hits corrupted
        //    rotation messages → rotation reconstruction complaint recovery
        force_rotate_and_assert_key_agreement(&mut test_networks, epoch + 1).await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nonce_generation_complaint_recovery_after_restart() -> Result<()> {
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
            .with_corrupt_shares_target(0)
            .build()
            .await?;

        // 1. DKG + nonce gen with complaint recovery
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        // 2. Restart — recover_presigning_state hits corrupted nonce messages
        //    in DB → nonce gen complaint recovery via RPC
        test_networks.hashi_network_mut().restart().await?;
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} MPC recovery after restart failed: {e}"));
        }

        // 3. Sign to verify presigs recovered via nonce gen complaint recovery work
        let nodes = test_networks.hashi_network().nodes();
        let epoch = nodes[0].hashi().onchain_state().epoch();
        let request_id = sui_sdk_types::Address::ZERO;
        let results = sign_on_all_nodes(nodes, b"post-restart", epoch, request_id, 0).await;
        assert_all_signatures_match(results);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rotation_reconstruction_complaint_recovery_after_restart() -> Result<()> {
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
            .with_corrupt_shares_target(0)
            .build()
            .await?;

        // 1. DKG + first rotation with complaint recovery
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }
        let initial_epoch = nodes[0].current_epoch().unwrap();
        let epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;

        // 2. Restart — clears dealer_outputs from memory
        test_networks.hashi_network_mut().restart().await?;
        let nodes = test_networks.hashi_network().nodes();
        let mpc_key_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} MPC recovery after restart failed: {e}"));
        }

        // 3. Second rotation — reconstruct_from_rotation_certificates hits
        //    corrupted rotation messages from the first rotation → complaint
        //    recovery via RPC
        force_rotate_and_assert_key_agreement(&mut test_networks, epoch + 1).await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node_2_epochs_behind_rejoins_before_rotation() -> Result<()> {
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

        // 1. DKG completes on all nodes
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
        let initial_epoch = nodes[0].current_epoch().unwrap();

        // 2. Shut down node 0
        test_networks.hashi_network_mut().nodes_mut()[0]
            .shutdown()
            .await;

        // 3. Force 2 epoch changes — nodes 1,2,3 rotate without node 0
        test_networks.sui_network.force_close_epoch().await.unwrap();
        wait_for_rotation(
            &test_networks.hashi_network().nodes()[1..],
            initial_epoch + 1,
        )
        .await;

        test_networks.sui_network.force_close_epoch().await.unwrap();
        wait_for_rotation(
            &test_networks.hashi_network().nodes()[1..],
            initial_epoch + 2,
        )
        .await;

        // 4. Start node 0 and wait for it to initialize before triggering rotation.
        //    Node 0 needs its gRPC server ready to receive SendMessages RPCs
        //    during the next rotation's dealer phase.
        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(ROTATION_TIMEOUT)
            .await
            .ok(); // May fail (no shares yet) — that's expected, we just need the server up

        // 5. Force a 3rd epoch change — node 0 joins this rotation as a new
        //    member (reconstruction fails for stale epoch data, falls back to
        //    fetching public output from quorum, then gets fresh shares)
        test_networks.sui_network.force_close_epoch().await.unwrap();
        let nodes = test_networks.hashi_network().nodes();
        let epoch_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_epoch(initial_epoch + 3, ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(epoch_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| {
                panic!("Node {i} failed to reach epoch {}: {e}", initial_epoch + 3)
            });
        }

        // 6. All nodes agree on key (node 0 got shares from rotation)
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_node_2_epochs_behind_rejoins_after_rotation() -> Result<()> {
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

        // 1. DKG completes on all nodes
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
        let initial_epoch = nodes[0].current_epoch().unwrap();

        // 2. Shut down node 0
        test_networks.hashi_network_mut().nodes_mut()[0]
            .shutdown()
            .await;

        // 3. Force 3 epoch changes — nodes 1,2,3 rotate without node 0
        for target in 1..=3 {
            test_networks.sui_network.force_close_epoch().await.unwrap();
            wait_for_rotation(
                &test_networks.hashi_network().nodes()[1..],
                initial_epoch + target,
            )
            .await;
        }

        // 4. Start node 0 AFTER all rotations are done — must recover via
        //    reconstruct from certs + new-member fallback
        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;

        // 5. Force one more rotation so node 0 can participate and get shares
        test_networks.sui_network.force_close_epoch().await.unwrap();
        let nodes = test_networks.hashi_network().nodes();
        let epoch_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_epoch(initial_epoch + 4, ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(epoch_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| {
                panic!("Node {i} failed to reach epoch {}: {e}", initial_epoch + 4)
            });
        }

        // 6. All nodes agree on key
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        Ok(())
    }
}
