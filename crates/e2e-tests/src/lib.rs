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
pub mod guardian_harness;
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

/// Tail the last 20 lines of each named log file, joined into a one-line diagnostic.
pub(crate) fn tail_logs(files: &[(&str, &Path)]) -> String {
    let mut diagnostics = Vec::new();
    for (label, path) in files {
        let contents = std::fs::read_to_string(path)
            .ok()
            .and_then(|contents| {
                let lines: Vec<_> = contents.lines().rev().take(20).collect();
                if lines.is_empty() {
                    None
                } else {
                    Some(lines.into_iter().rev().collect::<Vec<_>>().join(" | "))
                }
            })
            .unwrap_or_else(|| format!("<empty or unavailable at {}>", path.display()));
        diagnostics.push(format!("{label}: {contents}"));
    }
    diagnostics.join("; ")
}

pub struct TestNetworks {
    #[allow(unused)]
    dir: TempDir,
    pub sui_network: SuiNetworkHandle,
    pub hashi_network: HashiNetwork,
    pub bitcoin_node: BitcoinNodeHandle,
    pub guardian_harness: Option<guardian_harness::GuardianHarness>,
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

/// An externally-run guardian (the dockerized Nitro replica) to publish + point
/// the nodes at, instead of the in-process [`guardian_harness::GuardianHarness`].
/// Provisioned out-of-band (`operator`/`key-provisioner provision`) once the
/// committee forms, so `build()` does not finalize it.
#[derive(Clone)]
pub struct ExternalGuardian {
    /// Endpoint the hashi nodes reach the guardian at (typically its proxy).
    pub url: String,
    /// The guardian's x-only BTC master pubkey, printed by `operator ceremony`.
    pub btc_pubkey: hashi_types::bitcoin::BitcoinPubkey,
}

pub struct TestNetworksBuilder {
    sui_builder: SuiNetworkBuilder,
    hashi_builder: HashiNetworkBuilder,
    bitcoin_builder: BitcoinNodeBuilder,
    /// On-chain config overrides applied after DKG completes, before `build()`
    /// returns. Each entry is run through the full propose/vote/execute flow.
    onchain_config_overrides: Vec<(String, hashi_types::move_types::ConfigValue)>,
    /// When set, publish + point nodes at this external guardian instead of the
    /// in-process harness (and skip its finalize). See [`ExternalGuardian`].
    external_guardian: Option<ExternalGuardian>,
}

impl TestNetworksBuilder {
    pub fn new() -> Self {
        // E2e tests skip the deposit-confirmation delay by default so they
        // don't have to wait through the production-grade window. Tests that
        // need a non-zero delay can override via `with_onchain_config`; later
        // entries win because overrides are applied in insertion order.
        let onchain_config_overrides = vec![(
            "bitcoin_deposit_time_delay_ms".to_string(),
            hashi_types::move_types::ConfigValue::U64(0),
        )];
        Self {
            sui_builder: SuiNetworkBuilder::default(),
            hashi_builder: HashiNetworkBuilder::new(),
            bitcoin_builder: BitcoinNodeBuilder::new(),
            onchain_config_overrides,
            external_guardian: None,
        }
    }

    /// Publish + point the nodes at an externally-run guardian (the dockerized
    /// replica) instead of the in-process test harness. The external guardian is
    /// provisioned out-of-band via the CLI once the committee forms.
    pub fn with_external_guardian(mut self, guardian: ExternalGuardian) -> Self {
        self.external_guardian = Some(guardian);
        self
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

        // The guardian's BTC key must exist BEFORE the launch tx
        // (finish_publish) so the on-chain config pins the right pubkey.
        // External guardian: take its ceremony pubkey + URL (provisioned
        // out-of-band). Otherwise: start the in-process harness and finalize
        // it below once DKG output exists.
        let (guardian_config, guardian_harness) = match &self.external_guardian {
            Some(external) => {
                let guardian_config = hashi::publish::GuardianConfig {
                    url: external.url.clone(),
                    btc_public_key: external.btc_pubkey.serialize().to_vec(),
                };
                tracing::info!(
                    endpoint = %external.url,
                    "using external guardian (dockerized replica); provisioner-init runs out-of-band"
                );
                (guardian_config, None)
            }
            None => {
                let harness =
                    guardian_harness::GuardianHarness::start(bitcoin::Network::Regtest).await?;
                let guardian_btc_pubkey = harness.ensure_btc_pubkey()?;
                let guardian_config = hashi::publish::GuardianConfig {
                    url: harness.endpoint().to_string(),
                    btc_public_key: guardian_btc_pubkey.serialize().to_vec(),
                };
                tracing::info!(
                    endpoint = %harness.endpoint(),
                    "guardian harness started (serving; BTC key set, init deferred to finalize)"
                );
                (guardian_config, Some(harness))
            }
        };

        let hashi_builder = self.hashi_builder;

        // The post-build steps below (on-chain config overrides, guardian
        // provisioner-init) drive transactions through the running committee, so
        // they need at least one validator launched at build time. In
        // manual-bootstrap mode (0 initially-active validators) there are none,
        // so skip them — registration/genesis/guardian-init are driven later.
        let nodes_started = hashi_builder
            .num_initially_active_nodes
            .unwrap_or(hashi_builder.num_nodes)
            > 0;

        let publish_output = publish(
            dir.as_ref(),
            &mut sui_network.client,
            sui_network.user_keys.first().unwrap(),
        )
        .await?;

        let hashi_network = hashi_builder
            .build(
                &dir.path().join("hashi"),
                &sui_network,
                &bitcoin_node,
                publish_output.ids,
                publish_output.upgrade_cap_id,
                guardian_config,
            )
            .await?;

        let mut test_networks = TestNetworks {
            dir,
            sui_network,
            hashi_network,
            bitcoin_node,
            guardian_harness,
        };

        tracing::info!("rpc url: {}", test_networks.sui_network().rpc_url);

        if nodes_started && !self.onchain_config_overrides.is_empty() {
            apply_onchain_config_overrides(&mut test_networks, &self.onchain_config_overrides)
                .await?;
        }

        if nodes_started && test_networks.guardian_harness.is_some() {
            finalize_guardian_harness(&mut test_networks).await?;
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

async fn finalize_guardian_harness(networks: &mut TestNetworks) -> Result<()> {
    use crate::guardian_harness::default_test_limiter_config;
    use hashi_types::guardian::LimiterState;

    let nodes = networks.hashi_network.nodes();
    anyhow::ensure!(
        !nodes.is_empty(),
        "no hashi nodes to provision guardian from"
    );

    nodes[0]
        .wait_for_mpc_key(std::time::Duration::from_secs(120))
        .await?;

    let hashi = nodes[0].hashi();
    let committee = hashi
        .onchain_state()
        .current_committee()
        .ok_or_else(|| anyhow::anyhow!("no current committee after DKG"))?;
    // Pass the raw `G` (with y-parity) so the guardian's child-key
    // derivation matches the MPC's signing path. Using only the x-only
    // projection would force an even-y parent and silently disagree with
    // MPC sigs for half of all DKG outputs.
    let master_pubkey = hashi.onchain_state().onchain_verifying_key_g()?;

    let limiter_config = default_test_limiter_config();
    let limiter_state = LimiterState::genesis(&limiter_config);

    let harness = networks
        .guardian_harness
        .as_ref()
        .expect("guardian_harness set when finalize_guardian_harness is called");
    harness
        .finalize(committee, master_pubkey, limiter_config, limiter_state)
        .await?;
    tracing::info!("guardian harness finalized");

    // Wait for every *running* node's async limiter bootstrap to complete so
    // tests don't race it. Only the initially-active nodes are started here; a
    // pending new-member node (e.g. the key-rotation tests, which start the
    // final validator later via `register_and_start_pending_node`) bootstraps
    // its limiter when it starts, so skip nodes that aren't running yet.
    futures::future::try_join_all(
        networks
            .hashi_network
            .nodes()
            .iter()
            .filter(|node| node.is_running())
            .map(|node| node.wait_for_local_limiter(std::time::Duration::from_secs(60))),
    )
    .await?;
    tracing::info!("running hashi nodes have bootstrapped their local limiter");
    Ok(())
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
    use hashi::sui_tx_executor::SuiTxExecutor;
    use hashi_types::move_types::ConfigValue;
    use sui_sdk_types::Identifier;
    use sui_sdk_types::StructTag;
    use sui_sdk_types::TypeTag;

    let mut mpc_threshold_bps: Option<u64> = None;
    let mut mpc_max_faulty_bps: Option<u64> = None;
    let mut mpc_weight_reduction_allowed_delta: Option<u64> = None;
    let mut other_overrides: Vec<(String, ConfigValue)> = Vec::new();
    for (key, value) in overrides {
        match (key.as_str(), value) {
            ("mpc_threshold_in_basis_points", ConfigValue::U64(v)) => {
                mpc_threshold_bps = Some(*v);
            }
            ("mpc_max_faulty_in_basis_points", ConfigValue::U64(v)) => {
                mpc_max_faulty_bps = Some(*v);
            }
            ("mpc_weight_reduction_allowed_delta", ConfigValue::U64(v)) => {
                mpc_weight_reduction_allowed_delta = Some(*v);
            }
            _ => other_overrides.push((key.clone(), value.clone())),
        }
    }
    let has_mpc_overrides = mpc_threshold_bps.is_some()
        || mpc_max_faulty_bps.is_some()
        || mpc_weight_reduction_allowed_delta.is_some();

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
        .filter(|node| node.is_running())
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

    if has_mpc_overrides {
        tracing::info!(
            "applying MPC config overrides atomically: \
             threshold_bps={mpc_threshold_bps:?}, \
             max_faulty_bps={mpc_max_faulty_bps:?}, \
             weight_reduction_allowed_delta={mpc_weight_reduction_allowed_delta:?}"
        );
        exec_checkpoint = submit_proposal_through_quorum(
            hashi_ids,
            &mut executors,
            CreateProposalParams::UpdateMpcConfig {
                threshold_bps: mpc_threshold_bps,
                max_faulty_bps: mpc_max_faulty_bps,
                weight_reduction_allowed_delta: mpc_weight_reduction_allowed_delta,
                nonce_generation_protocol: None,
                metadata: vec![],
            },
            update_config_type_tag.clone(),
            "update_config",
            "UpdateMpcConfig",
        )
        .await?;
    }

    //TODO could we build the proposals and vote/execute on them all at the same time vs doing them
    //one at a time?
    for (key, value) in &other_overrides {
        tracing::info!("applying on-chain config override: {key} = {value:?}");
        exec_checkpoint = submit_proposal_through_quorum(
            hashi_ids,
            &mut executors,
            CreateProposalParams::UpdateConfig {
                key: key.clone(),
                value: value.clone(),
                metadata: vec![],
            },
            update_config_type_tag.clone(),
            "update_config",
            &format!("UpdateConfig({key})"),
        )
        .await?;
    }

    // Wait for all nodes' watchers to process the checkpoint that contains the
    // last execute transaction. The watcher re-fetches config on each
    // ProposalExecuted<UpdateConfig>, so once a node reaches this
    // checkpoint its in-memory config will reflect the override.
    let futs = networks
        .hashi_network()
        .nodes()
        .iter()
        .filter(|node| node.is_running())
        .map(|node| {
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

async fn submit_proposal_through_quorum(
    hashi_ids: hashi::config::HashiIds,
    executors: &mut [hashi::sui_tx_executor::SuiTxExecutor],
    create_params: hashi::cli::client::CreateProposalParams,
    proposal_type_tag: sui_sdk_types::TypeTag,
    module_name: &str,
    label: &str,
) -> Result<u64> {
    use hashi::cli::client::build_create_proposal_transaction;
    use hashi::cli::client::build_vote_transaction;
    use hashi::cli::upgrade::build_execute_proposal_transaction;
    use hashi::cli::upgrade::extract_proposal_id_from_response;

    let creator = executors[0].sender();
    let create_tx = build_create_proposal_transaction(hashi_ids, creator, create_params);
    let response = executors[0].execute(create_tx).await?;
    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "create {label} proposal failed"
    );
    let proposal_id = extract_proposal_id_from_response(&response)?;
    tracing::info!("{label} proposal {proposal_id} created; collecting votes");
    for executor in &mut executors[1..] {
        let voter = executor.sender();
        let vote_tx =
            build_vote_transaction(hashi_ids, voter, proposal_id, proposal_type_tag.clone());
        let vote_resp = executor.execute(vote_tx).await?;
        anyhow::ensure!(
            vote_resp.transaction().effects().status().success(),
            "vote on {label} proposal {proposal_id} failed"
        );
    }
    let execute_tx = build_execute_proposal_transaction(
        hashi_ids,
        proposal_id,
        hashi_ids.package_id,
        module_name,
    )?;
    let exec_resp = executors[0].execute(execute_tx).await?;
    anyhow::ensure!(
        exec_resp.transaction().effects().status().success(),
        "execute {label} proposal {proposal_id} failed"
    );
    let checkpoint = exec_resp
        .transaction()
        .checkpoint_opt()
        .ok_or_else(|| anyhow::anyhow!("execute transaction response missing checkpoint"))?;
    tracing::info!("{label} proposal applied (checkpoint {checkpoint})");
    Ok(checkpoint)
}

impl Default for TestNetworksBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Witness;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::groups::Scalar;
    use fastcrypto::hash::HashFunction;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::Parameters;
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

    async fn assert_nodes_agree_on_mpc_key(nodes: &[HashiNodeHandle]) {
        // Wait for each node's local rotation to complete before asserting
        // agreement.
        let futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} MPC key not ready: {e}"));
        }

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

    async fn wait_for_signing_manager(
        nodes: &[HashiNodeHandle],
        epoch: u64,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let all_ready = nodes
                .iter()
                .all(|node| node.hashi().signing_manager_for(epoch).is_some());
            if all_ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let statuses: Vec<_> = nodes
                    .iter()
                    .enumerate()
                    .map(|(i, node)| (i, node.hashi().signing_manager_for(epoch).is_some()))
                    .collect();
                return Err(anyhow::anyhow!(
                    "Timed out waiting for SigningManager for epoch {epoch} on all nodes: {statuses:?}"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    async fn force_rotate_and_assert_key_agreement(
        test_networks: &mut TestNetworks,
        target_epoch: u64,
    ) -> u64 {
        let key_before = get_mpc_key(test_networks.hashi_network().nodes());
        test_networks.sui_network.force_close_epoch().await.unwrap();
        let epoch = wait_for_rotation(test_networks.hashi_network().nodes(), target_epoch).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;
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
        params: Parameters,
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
        Presignatures::new(receiver_outputs, batch_size_per_weight, params).unwrap()
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
                Parameters {
                    t,
                    f: cfg.max_faulty as u16,
                },
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
            node.hashi().store_signing_manager(signing_manager);
        }
        vk
    }

    async fn sign_on_all_nodes(
        nodes: &[HashiNodeHandle],
        message: &[u8],
        epoch: u64,
        sui_request_id: sui_sdk_types::Address,
        global_presig_index: u64,
        derivation_address: Option<[u8; 32]>,
    ) -> Vec<
        hashi::mpc::types::SigningResult<fastcrypto::groups::secp256k1::schnorr::SchnorrSignature>,
    > {
        let mut per_input = sign_batch_on_all_nodes(
            nodes,
            epoch,
            &[(
                sui_request_id,
                global_presig_index,
                message.to_vec(),
                derivation_address,
            )],
        )
        .await;
        per_input.pop().expect("one input requested")
    }

    /// One batch input: (signing_id, global_presig_index, message, derivation_address).
    type SignInputSpec = (sui_sdk_types::Address, u64, Vec<u8>, Option<[u8; 32]>);

    async fn sign_batch_on_all_nodes(
        nodes: &[HashiNodeHandle],
        epoch: u64,
        inputs: &[SignInputSpec],
    ) -> Vec<
        Vec<
            hashi::mpc::types::SigningResult<
                fastcrypto::groups::secp256k1::schnorr::SchnorrSignature,
            >,
        >,
    > {
        let beacon_value = {
            let mut hasher = fastcrypto::hash::Blake2b256::default();
            for (signing_id, _, _, _) in inputs {
                hasher.update(signing_id.as_bytes());
            }
            S::from_bytes_mod_order(&hasher.finalize().digest)
        };
        let order: Vec<sui_sdk_types::Address> = inputs.iter().map(|(sid, _, _, _)| *sid).collect();
        let sign_futures: Vec<_> = nodes
            .iter()
            .map(|node| {
                let signing_manager = node
                    .hashi()
                    .signing_manager_for(epoch)
                    .unwrap_or_else(|| panic!("SigningManager not initialized for epoch {epoch}"));
                let p2p_channel = hashi::mpc::rpc::RpcP2PChannel::new(
                    node.hashi().onchain_state().clone(),
                    epoch,
                    hashi::metrics::MPC_LABEL_SIGNING,
                );
                let beacon = beacon_value;
                let metrics = node.hashi().metrics.clone();
                let requests: Vec<hashi::mpc::SignInput> = inputs
                    .iter()
                    .map(|(sid, pidx, msg, deriv)| hashi::mpc::SignInput {
                        signing_id: *sid,
                        message: msg.clone(),
                        global_presig_index: *pidx,
                        derivation_address: *deriv,
                    })
                    .collect();
                let order = order.clone();
                async move {
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    signing_manager
                        .sign(
                            &p2p_channel,
                            requests,
                            &beacon,
                            SIGNING_TIMEOUT,
                            &metrics,
                            tx,
                        )
                        .await;
                    let mut by_id = std::collections::HashMap::new();
                    while let Some((sid, res)) = rx.recv().await {
                        by_id.insert(sid, res);
                    }
                    order
                        .into_iter()
                        .map(|sid| {
                            by_id.remove(&sid).unwrap_or_else(|| {
                                Err(hashi::mpc::types::SigningError::CryptoError(
                                    "sign produced no result for input".to_string(),
                                ))
                            })
                        })
                        .collect::<Vec<_>>()
                }
            })
            .collect();
        // `[node][input]` -> `[input][node]` so each input's per-node results can
        // be checked together.
        let per_node = futures::future::join_all(sign_futures).await;
        let mut per_input: Vec<Vec<_>> = (0..inputs.len())
            .map(|_| Vec::with_capacity(nodes.len()))
            .collect();
        for node_results in per_node {
            for (j, res) in node_results.into_iter().enumerate() {
                per_input[j].push(res);
            }
        }
        per_input
    }

    fn assert_all_signatures_match(
        results: Vec<
            hashi::mpc::types::SigningResult<
                fastcrypto::groups::secp256k1::schnorr::SchnorrSignature,
            >,
        >,
    ) -> fastcrypto::groups::secp256k1::schnorr::SchnorrSignature {
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
        signatures
            .into_iter()
            .next()
            .expect("MPC signing returned no signatures")
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

        let inputs: Vec<SignInputSpec> = (0..3u8)
            .map(|j| {
                (
                    sui_sdk_types::Address::new([0xE0 + j; 32]),
                    j as u64,
                    format!("Hello, Hashi signing! {j}").into_bytes(),
                    None,
                )
            })
            .collect();
        let per_input = sign_batch_on_all_nodes(nodes, epoch, &inputs).await;
        assert_eq!(per_input.len(), inputs.len());
        for input_results in per_input {
            assert_all_signatures_match(input_results);
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mpc_recovery_spend_before_and_after_csv_delay() -> Result<()> {
        crate::test_helpers::init_test_logging();

        // Start a full localnet and wait until all Hashi nodes can participate
        // in MPC signing for the current epoch.
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

        let epoch = nodes[0]
            .current_epoch()
            .context("Hashi epoch not available")?;
        wait_for_signing_manager(nodes, epoch, DKG_TIMEOUT).await?;

        // Create a real Hashi-controlled Bitcoin UTXO by funding a deposit
        // address derived for a test Sui address.
        let hashi = nodes[0].hashi().clone();
        let derivation_path = test_networks
            .sui_network
            .user_keys
            .first()
            .context("test network has no Sui user keys")?
            .public_key()
            .derive_address();
        let deposit_address = hashi.get_deposit_address(Some(&derivation_path))?;
        let deposit_amount = Amount::from_sat(100_000);
        let miner_fee = Amount::from_sat(1_000);

        tracing::info!(%deposit_address, "Funding Hashi-controlled deposit address");
        let funding_txid = test_networks
            .bitcoin_node()
            .send_to_address(&deposit_address, deposit_amount)?;
        test_networks.bitcoin_node().generate_blocks(10)?;
        let vout = crate::test_helpers::lookup_vout(
            &test_networks,
            funding_txid,
            deposit_address.clone(),
            deposit_amount.to_sat(),
        )?;

        // Build a raw Bitcoin transaction that attempts to spend the deposit
        // through the delayed MPC-only recovery path.
        let destination = test_networks.bitcoin_node().get_new_address()?;
        let destination_balance_before = test_networks
            .bitcoin_node()
            .rpc_client()
            .get_received_by_address(&destination)?
            .into_model()?
            .0;
        let mut recovery_tx = hashi_types::bitcoin::construct_tx(
            vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: vout as u32,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: hashi_types::bitcoin::taproot::mpc_recovery_delay_sequence(),
                witness: Witness::new(),
            }],
            vec![TxOut {
                value: deposit_amount - miner_fee,
                script_pubkey: destination.script_pubkey(),
            }],
        );

        // Fetch the delayed MPC-only recovery leaf artifacts used for sighash
        // and witness construction.
        let guardian_pubkey = hashi
            .guardian_btc_pubkey()
            .copied()
            .context("guardian BTC pubkey not pinned")?;
        let mpc_master_g = hashi
            .signing_verifying_key()
            .context("MPC signing verifying key not available")?;
        let (recovery_script, recovery_control_block, recovery_leaf_hash) =
            hashi_types::bitcoin::taproot::taproot_mpc_recovery_witness_artifacts(
                &guardian_pubkey,
                &mpc_master_g,
                &derivation_path,
            );

        // Compute the sighash for the recovery leaf and sign it with the real
        // MPC protocol using the same derivation path as the deposit address.
        let prevout = TxOut {
            value: deposit_amount,
            script_pubkey: deposit_address.script_pubkey(),
        };
        let sighash = hashi_types::bitcoin::taproot_script_spend_sighashes(
            &recovery_tx,
            &[prevout],
            &[recovery_leaf_hash],
        )[0];
        let derivation_address = derivation_path.into_inner();
        // The signing request id just needs to be unique and agreed on by all
        // nodes; a random one keeps it independent of the message being signed.
        let mut request_id_bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut request_id_bytes);
        let results = sign_on_all_nodes(
            nodes,
            &sighash,
            epoch,
            sui_sdk_types::Address::new(request_id_bytes),
            0,
            Some(derivation_address),
        )
        .await;
        let mpc_signature = assert_all_signatures_match(results);

        // Attach the delayed-path witness: one MPC signature plus the recovery
        // script and control block. There is deliberately no guardian signature.
        let mut witness = Witness::new();
        witness.push(mpc_signature.to_byte_array());
        witness.push(recovery_script.to_bytes());
        witness.push(recovery_control_block.serialize());
        recovery_tx.input[0].witness = witness;

        // Before the relative CSV delay has elapsed, Bitcoin should reject the
        // otherwise valid recovery spend as non-final.
        let before = test_networks
            .bitcoin_node()
            .rpc_client()
            .test_mempool_accept(&[recovery_tx.clone()])?
            .into_model()?
            .results;
        assert_eq!(before.len(), 1);
        assert!(
            !before[0].allowed,
            "recovery spend should not be accepted before CSV delay"
        );
        tracing::info!(
            reject_reason = ?before[0].reject_reason,
            "Recovery spend rejected before CSV delay"
        );

        // Advance regtest median-time-past beyond the 60-day CSV delay. Mock
        // time alone is not enough; mining moves the chain MTP forward. The 2h
        // margin covers MTP lagging the mocked wall clock, since it is the
        // median of the last 11 block timestamps.
        let tip_hash = test_networks
            .bitcoin_node()
            .rpc_client()
            .best_block_hash()?;
        let tip_header = test_networks
            .bitcoin_node()
            .rpc_client()
            .get_block_header_verbose(&tip_hash)?;
        let future_time = tip_header.median_time
            + hashi_types::bitcoin::taproot::HASHI_MPC_RECOVERY_DELAY_SECONDS as i64
            + 2 * 60 * 60;
        test_networks
            .bitcoin_node()
            .rpc_client()
            .call::<serde_json::Value>("setmocktime", &[serde_json::json!(future_time)])?;
        test_networks.bitcoin_node().generate_blocks(20)?;

        // After the delay, the exact same recovery transaction should be valid
        // for the mempool.
        let after = test_networks
            .bitcoin_node()
            .rpc_client()
            .test_mempool_accept(&[recovery_tx.clone()])?
            .into_model()?
            .results;
        assert_eq!(after.len(), 1);
        assert!(
            after[0].allowed,
            "recovery spend should be accepted after CSV delay; reject_reason={:?}",
            after[0].reject_reason
        );

        // Broadcast, mine, and confirm the recovery spend, then verify it paid
        // the expected destination output.
        let recovery_txid = test_networks
            .bitcoin_node()
            .rpc_client()
            .send_raw_transaction(&recovery_tx)?
            .into_model()?
            .0;
        test_networks.bitcoin_node().generate_blocks(1)?;
        test_networks
            .bitcoin_node()
            .wait_for_transaction(&recovery_txid, std::time::Duration::from_secs(30))
            .await?;

        let confirmed_tx = test_networks
            .bitcoin_node()
            .rpc_client()
            .get_raw_transaction(recovery_txid)
            .and_then(|r| r.transaction().map_err(Into::into))?;
        let expected_recovery_amount = deposit_amount - miner_fee;
        assert!(confirmed_tx.output.iter().any(|output| {
            output.value == expected_recovery_amount
                && output.script_pubkey == destination.script_pubkey()
        }));
        let destination_balance_after = test_networks
            .bitcoin_node()
            .rpc_client()
            .get_received_by_address(&destination)?
            .into_model()?
            .0;
        assert_eq!(
            destination_balance_after - destination_balance_before,
            expected_recovery_amount,
            "destination address balance should increase by the recovered amount"
        );

        tracing::info!(%recovery_txid, "MPC recovery spend e2e test passed");
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
        .with_signer(user_key.clone().into());
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

        assert_nodes_agree_on_mpc_key(nodes).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_recovery_after_restart() -> Result<()> {
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
    async fn test_dkg_recovery_after_simultaneous_restart() -> Result<()> {
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

        let nodes = test_networks.hashi_network().nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }
        let dkg_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();
        let pk_before = get_mpc_key(test_networks.hashi_network().nodes());

        // Restart all nodes (still at the genesis DKG epoch).
        test_networks.hashi_network_mut().restart().await?;

        let nodes = test_networks.hashi_network().nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} DKG recovery after restart failed: {e}"));
        }
        let nodes = test_networks.hashi_network().nodes();
        let pk_after = get_mpc_key(nodes);
        assert_eq!(pk_after, pk_before, "key changed across the restart");
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let node_pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(
                node_pk, pk_before,
                "node {i} recovered a different key after the restart"
            );
        }
        assert_eq!(
            nodes[0].current_epoch().unwrap(),
            dkg_epoch,
            "epoch advanced during restart recovery; local DKG recovery should not need a rotation"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rotation_recovery_after_simultaneous_restart() -> Result<()> {
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

        let nodes = test_networks.hashi_network().nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }
        let dkg_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        let rotation_epoch =
            force_rotate_and_assert_key_agreement(&mut test_networks, dkg_epoch + 1).await;
        let pk_before = get_mpc_key(test_networks.hashi_network().nodes());

        // Coordinate-restart al nodes in the rotation epoch.
        test_networks.hashi_network_mut().restart().await?;

        let nodes = test_networks.hashi_network().nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} rotation recovery after restart failed: {e}"));
        }
        let nodes = test_networks.hashi_network().nodes();
        let pk_after = get_mpc_key(nodes);
        assert_eq!(
            pk_after, pk_before,
            "key changed across the coordinated restart in the rotation epoch"
        );
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let node_pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(
                node_pk, pk_before,
                "node {i} recovered a different key after the coordinated restart"
            );
        }
        assert_eq!(
            nodes[0].current_epoch().unwrap(),
            rotation_epoch,
            "epoch advanced during restart recovery; local rotation recovery should not need a rotation"
        );

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
            assert_nodes_agree_on_mpc_key(nodes).await;
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
            assert_nodes_agree_on_mpc_key(active_nodes).await;
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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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
            assert_nodes_agree_on_mpc_key(active_nodes).await;
        }

        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // 2. Force epoch change → key rotation with same 19 nodes.
        test_networks.sui_network.force_close_epoch().await?;
        let active_nodes = &test_networks.hashi_network().nodes()[..INITIAL_NODES];
        wait_for_rotation(active_nodes, initial_epoch + 1).await;
        assert_nodes_agree_on_mpc_key(active_nodes).await;

        // 3. Register and start the 20th node (new member)
        let client = test_networks.sui_network.client.clone();
        test_networks
            .hashi_network_mut()
            .register_and_start_pending_node(client)
            .await?;

        // 4. Force epoch change → key rotation 19→20.
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), initial_epoch + 2).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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
    async fn test_sync_if_stale_recovers_cleared_signing_manager() -> Result<()> {
        const TEST_NUM_NODES: usize = 4;
        const RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        crate::test_helpers::init_test_logging();

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

        let epoch = nodes[0].current_epoch().unwrap();
        wait_for_signing_manager(nodes, epoch, DKG_TIMEOUT).await?;

        nodes[0].hashi().clear_signing_manager_for_test();
        assert!(
            nodes[0].hashi().signing_manager_for(epoch).is_none(),
            "clear_signing_manager_for_test should have nulled the stored manager"
        );

        wait_for_signing_manager(&nodes[..1], epoch, RECOVERY_TIMEOUT).await?;

        let request_id = sui_sdk_types::Address::ZERO;
        let results = sign_on_all_nodes(
            nodes,
            b"msg-after-sync-if-stale-recovery",
            epoch,
            request_id,
            0,
            None,
        )
        .await;
        assert_all_signatures_match(results);

        Ok(())
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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

        // Phase 2: Rotation + nonce recovery with partial state
        let next_epoch = epoch + 1;
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), next_epoch).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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

        let signing_manager = nodes[0]
            .hashi()
            .signing_manager_for(epoch)
            .unwrap_or_else(|| panic!("SigningManager not initialized for epoch {epoch}"));
        let pool_size = signing_manager.initial_presig_count();
        let refill_trigger_at = pool_size - pool_size / hashi::constants::PRESIG_REFILL_DIVISOR;
        // Sign pool_size + 1 times: exhaust batch 0 and prove batch 1 swap works.
        let num_signings = pool_size + 1;
        // Wait for refill a few signs after the threshold, before exhaustion.
        let wait_at = refill_trigger_at + (pool_size - refill_trigger_at) / 2;

        for i in 0..num_signings {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let request_id = sui_sdk_types::Address::new(bytes);
            let results =
                sign_on_all_nodes(nodes, b"refill test", epoch, request_id, i as u64, None).await;
            assert_all_signatures_match(results);

            // After crossing the refill threshold, wait for the refill to
            // complete before we exhaust the pool.
            if i == wait_at {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                while !signing_manager.has_next_batch() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "Timed out waiting for presignature refill"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        assert_eq!(signing_manager.batch_index(), 1);
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
        assert_nodes_agree_on_mpc_key(nodes).await;

        // 2. Sign to verify nonce generation presigs (built via in-memory complaint recovery) work
        let epoch = nodes[0].hashi().onchain_state().epoch();
        let request_id = sui_sdk_types::Address::ZERO;
        let results = sign_on_all_nodes(nodes, b"complaint test", epoch, request_id, 0, None).await;
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
        let results = sign_on_all_nodes(nodes, b"post-restart", epoch, request_id, 0, None).await;
        assert_all_signatures_match(results);

        Ok(())
    }

    async fn build_avid_networks(builder: TestNetworksBuilder) -> Result<TestNetworks> {
        let mut test_networks = builder
            .with_onchain_config(
                "mpc_nonce_generation_protocol",
                hashi_types::move_types::ConfigValue::U64(1),
            )
            .build()
            .await?;
        let initial_epoch = {
            let nodes = test_networks.hashi_network().nodes();
            let mpc_key_futures: Vec<_> = nodes
                .iter()
                .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(mpc_key_futures).await;
            for (i, result) in results.into_iter().enumerate() {
                result.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
            assert_eq!(
                nodes[0]
                    .hashi()
                    .onchain_state()
                    .mpc_nonce_generation_protocol(),
                1,
                "the AVID protocol override must have landed"
            );
            nodes[0].current_epoch().unwrap()
        };
        force_rotate_and_assert_key_agreement(&mut test_networks, initial_epoch + 1).await;
        Ok(test_networks)
    }

    fn avid_fault_tolerant_builder() -> TestNetworksBuilder {
        TestNetworksBuilder::new()
            .with_nodes(4)
            .with_onchain_config(
                "mpc_threshold_in_basis_points",
                hashi_types::move_types::ConfigValue::U64(5000),
            )
            .with_onchain_config(
                "mpc_max_faulty_in_basis_points",
                hashi_types::move_types::ConfigValue::U64(2500),
            )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_avid_refill_presignature_pool() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let test_networks = build_avid_networks(TestNetworksBuilder::new().with_nodes(4)).await?;
        let nodes = test_networks.hashi_network().nodes();
        let epoch = nodes[0].hashi().onchain_state().epoch();

        wait_for_signing_manager(nodes, epoch, std::time::Duration::from_secs(120)).await?;
        let signing_manager = nodes[0]
            .hashi()
            .signing_manager_for(epoch)
            .expect("just waited for it");
        let pool_size = signing_manager.initial_presig_count();
        let refill_trigger_at = pool_size - pool_size / hashi::constants::PRESIG_REFILL_DIVISOR;
        let num_signings = pool_size + 1;
        let wait_at = refill_trigger_at + (pool_size - refill_trigger_at) / 2;

        for i in 0..num_signings {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let request_id = sui_sdk_types::Address::new(bytes);
            let results =
                sign_on_all_nodes(nodes, b"avid refill", epoch, request_id, i as u64, None).await;
            assert_all_signatures_match(results);

            if i == wait_at {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                while !signing_manager.has_next_batch() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "Timed out waiting for presignature refill"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        assert_eq!(signing_manager.batch_index(), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_avid_complaint_recovery() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let test_networks =
            build_avid_networks(avid_fault_tolerant_builder().with_corrupt_shares_target(0))
                .await?;
        let nodes = test_networks.hashi_network().nodes();
        let epoch = nodes[0].hashi().onchain_state().epoch();
        wait_for_signing_manager(nodes, epoch, std::time::Duration::from_secs(120)).await?;
        let request_id = sui_sdk_types::Address::ZERO;
        let results =
            sign_on_all_nodes(nodes, b"avid complaint test", epoch, request_id, 0, None).await;
        assert_all_signatures_match(results);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_avid_complaint_recovery_after_restart() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks =
            build_avid_networks(avid_fault_tolerant_builder().with_corrupt_shares_target(0))
                .await?;
        {
            let nodes = test_networks.hashi_network().nodes();
            let epoch = nodes[0].hashi().onchain_state().epoch();
            wait_for_signing_manager(nodes, epoch, std::time::Duration::from_secs(120)).await?;
            let results = sign_on_all_nodes(
                nodes,
                b"avid pre-restart",
                epoch,
                sui_sdk_types::Address::ZERO,
                0,
                None,
            )
            .await;
            assert_all_signatures_match(results);
        }

        test_networks.hashi_network_mut().restart().await?;
        let nodes = test_networks.hashi_network().nodes();
        let recovery_futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_mpc_key(DKG_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(recovery_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} MPC recovery after restart failed: {e}"));
        }
        let epoch = nodes[0].hashi().onchain_state().epoch();
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let results = sign_on_all_nodes(
            nodes,
            b"avid post-restart",
            epoch,
            sui_sdk_types::Address::new(bytes),
            1,
            None,
        )
        .await;
        assert_all_signatures_match(results);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_avid_straggler_catches_up() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks =
            build_avid_networks(avid_fault_tolerant_builder().with_batch_size_per_weight(1))
                .await?;
        let epoch = test_networks.hashi_network().nodes()[0]
            .hashi()
            .onchain_state()
            .epoch();
        let (pool_size, refill_trigger_at) = {
            let nodes = test_networks.hashi_network().nodes();
            wait_for_signing_manager(nodes, epoch, std::time::Duration::from_secs(120)).await?;
            let signing_manager = nodes[0]
                .hashi()
                .signing_manager_for(epoch)
                .expect("just waited for it");
            let pool_size = signing_manager.initial_presig_count();
            (
                pool_size,
                pool_size - pool_size / hashi::constants::PRESIG_REFILL_DIVISOR,
            )
        };

        test_networks.hashi_network_mut().nodes_mut()[3]
            .shutdown()
            .await;
        let wait_at = refill_trigger_at + (pool_size - refill_trigger_at) / 2;
        assert!(
            wait_at + 1 < pool_size,
            "batch too small: no batch-0 headroom after the drain (pool={pool_size}, wait_at={wait_at})"
        );

        {
            let nodes = &test_networks.hashi_network().nodes()[..3];
            let signing_manager = nodes[0]
                .hashi()
                .signing_manager_for(epoch)
                .expect("initialized before the straggler went dark");
            let inputs: Vec<_> = (0..=wait_at)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    (
                        sui_sdk_types::Address::new(bytes),
                        i as u64,
                        b"avid straggler".to_vec(),
                        None,
                    )
                })
                .collect();
            let results = sign_batch_on_all_nodes(nodes, epoch, &inputs).await;
            for node_results in &results {
                for result in node_results {
                    result.as_ref().expect("drain signing failed");
                }
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
            while !signing_manager.has_next_batch() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "Timed out waiting for the refill batch dealt without the straggler"
                );
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        test_networks.hashi_network_mut().nodes_mut()[3]
            .start()
            .await?;
        let nodes = test_networks.hashi_network().nodes();
        nodes[3].wait_for_mpc_key(DKG_TIMEOUT).await?;
        wait_for_signing_manager(&nodes[3..], epoch, std::time::Duration::from_secs(120)).await?;

        let inputs: Vec<_> = ((wait_at + 1)..pool_size)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
                (
                    sui_sdk_types::Address::new(bytes),
                    i as u64,
                    b"avid straggler".to_vec(),
                    None,
                )
            })
            .collect();
        let results = sign_batch_on_all_nodes(nodes, epoch, &inputs).await;
        for node_results in &results {
            for result in node_results {
                result
                    .as_ref()
                    .expect("post-restart batch-0 signing failed");
            }
        }

        for i in pool_size..(pool_size + 2) {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let request_id = sui_sdk_types::Address::new(bytes);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
            loop {
                let results =
                    sign_on_all_nodes(nodes, b"avid straggler", epoch, request_id, i as u64, None)
                        .await;
                if results.iter().all(|r| r.is_ok()) {
                    assert_all_signatures_match(results);
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "Timed out waiting for the straggler to sign refill-batch presigs: {:?}",
                    results
                        .iter()
                        .map(|r| r.as_ref().err().map(|e| e.to_string()))
                        .collect::<Vec<_>>()
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
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
        assert_nodes_agree_on_mpc_key(nodes).await;
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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

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
        assert_nodes_agree_on_mpc_key(nodes).await;
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
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes()).await;

        Ok(())
    }
}
