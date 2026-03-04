use anyhow::Result;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config as HashiConfig;
use hashi::config::HashiIds;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::EncryptionPublicKey;
use serde;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use sui_futures::service::Service;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use tracing::debug;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReconfigCompletionMessage {
    pub epoch: u64,
    pub mpc_public_key: Vec<u8>,
}

use crate::BitcoinNodeHandle;
use crate::SuiNetworkHandle;

const HTTPS_SCHEME: &str = "https://";
const HTTP_SCHEME: &str = "http://";
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const TEST_WEIGHT_DIVISOR: u16 = 100;

pub struct HashiNodeHandle {
    config: HashiConfig,
    /// The running service and Hashi instance. Both are dropped together on shutdown
    /// to ensure the database lock is released before a new instance can be created.
    service: Option<(Service, Arc<Hashi>)>,
}

impl HashiNodeHandle {
    pub fn new(config: HashiConfig) -> Result<Self> {
        Ok(Self {
            config,
            service: None,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.service.is_some() {
            anyhow::bail!("Hashi node already started");
        }
        let hashi = Self::create_hashi_retry(&self.config).await?;
        let service = hashi.clone().start().await?;
        self.service = Some((service, hashi));
        Ok(())
    }

    fn create_hashi(config: &HashiConfig) -> Result<Arc<Hashi>> {
        let server_version = ServerVersion::new("test-hashi", "0.1.0");
        let registry = prometheus::Registry::new();
        Hashi::new_with_registry(server_version, config.clone(), &registry)
    }

    /// Create a Hashi instance with retry logic for database lock contention.
    ///
    /// After shutdown, there may be a brief delay before the database lock is released.
    async fn create_hashi_retry(config: &HashiConfig) -> Result<Arc<Hashi>> {
        const MAX_ATTEMPTS: u32 = 3;

        for attempt in 1..=MAX_ATTEMPTS {
            match Self::create_hashi(config) {
                Ok(hashi) => return Ok(hashi),
                Err(e) if attempt == MAX_ATTEMPTS => return Err(e),
                Err(e) => {
                    tracing::debug!(
                        "Failed to create Hashi (attempt {attempt}/{MAX_ATTEMPTS}): {e}"
                    );
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
        unreachable!()
    }

    async fn shutdown(&mut self) {
        let Some((service, _hashi)) = self.service.take() else {
            tracing::warn!("Hashi node not running, cannot shutdown");
            return;
        };
        let result = service.shutdown().await;
        if let Err(e) = result {
            tracing::warn!("Hashi shutdown error: {e}");
        }
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.shutdown().await;
        self.start().await
    }

    pub fn hashi(&self) -> &Arc<Hashi> {
        &self.service.as_ref().expect("Hashi node not started").1
    }

    pub fn https_url(&self) -> String {
        format!("{}{}", HTTPS_SCHEME, self.https_address())
    }

    pub fn http_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.http_address())
    }

    pub fn metrics_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.metrics_address())
    }

    pub fn https_address(&self) -> SocketAddr {
        self.config.https_address()
    }

    pub fn http_address(&self) -> SocketAddr {
        self.config.http_address()
    }

    pub fn metrics_address(&self) -> SocketAddr {
        self.config.metrics_http_address()
    }

    pub async fn wait_for_mpc_key(&self, timeout: std::time::Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.wait_for_mpc_key_inner())
            .await
            .map_err(|_| anyhow::anyhow!("MPC key timed out after {:?}", timeout))?
    }

    async fn wait_for_mpc_key_inner(&self) -> Result<()> {
        loop {
            if let Some(mpc_handle) = self.hashi().mpc_handle()
                && mpc_handle.public_key().is_some()
            {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub fn current_epoch(&self) -> Option<u64> {
        self.hashi()
            .onchain_state_opt()
            .map(|s| s.state().hashi().committees.epoch())
    }

    pub async fn wait_for_epoch(
        &self,
        target_epoch: u64,
        timeout: std::time::Duration,
    ) -> Result<()> {
        tokio::time::timeout(timeout, self.wait_for_epoch_inner(target_epoch))
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for Hashi epoch {target_epoch}"))
    }

    async fn wait_for_epoch_inner(&self, target_epoch: u64) {
        loop {
            let onchain_state = match self.hashi().onchain_state_opt() {
                Some(state) => state,
                None => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            let epoch = onchain_state.state().hashi().committees.epoch();
            if epoch >= target_epoch {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

pub struct HashiNetwork {
    ids: HashiIds,
    nodes: Vec<HashiNodeHandle>,
    /// Keeps the mock screener gRPC server alive for the lifetime of the test network.
    _screener_service: Service,
}

impl HashiNetwork {
    pub fn nodes(&self) -> &[HashiNodeHandle] {
        &self.nodes
    }

    pub fn nodes_mut(&mut self) -> &mut [HashiNodeHandle] {
        &mut self.nodes
    }

    pub async fn restart(&mut self) -> Result<()> {
        futures::future::try_join_all(self.nodes.iter_mut().map(|node| node.restart())).await?;
        Ok(())
    }

    pub fn ids(&self) -> HashiIds {
        self.ids
    }

    pub async fn register_and_start_pending_node(&mut self, client: sui_rpc::Client) -> Result<()> {
        let node = self
            .nodes
            .iter_mut()
            .find(|n| n.service.is_none())
            .ok_or_else(|| anyhow::anyhow!("no pending nodes to start"))?;
        register_onchain(client, &node.config).await?;
        node.start().await?;
        Ok(())
    }
}

pub struct HashiNetworkBuilder {
    pub num_nodes: usize,
    /// `None` means all `num_nodes` are active (default).
    pub num_initially_active_nodes: Option<usize>,
    pub test_batch_size_per_weight: Option<u16>,
}

impl HashiNetworkBuilder {
    pub fn new() -> Self {
        Self {
            num_nodes: 1,
            num_initially_active_nodes: None,
            test_batch_size_per_weight: None,
        }
    }

    pub fn with_num_nodes(mut self, num_nodes: usize) -> Self {
        self.num_nodes = num_nodes;
        self
    }

    pub fn with_initially_active(mut self, initially_active: usize) -> Self {
        self.num_initially_active_nodes = Some(initially_active);
        self
    }

    pub fn with_batch_size_per_weight(mut self, batch_size_per_weight: u16) -> Self {
        self.test_batch_size_per_weight = Some(batch_size_per_weight);
        self
    }

    pub async fn build(
        self,
        dir: &Path,
        sui: &SuiNetworkHandle,
        bitcoin: &BitcoinNodeHandle,
        hashi_ids: HashiIds,
    ) -> Result<HashiNetwork> {
        // Start a mock screener server for integration tests
        let (screener_addr, screener_service) =
            hashi_screener::test_utils::start_mock_screener_server().await;
        let screener_endpoint = format!("http://{}", screener_addr);

        let bitcoin_rpc = bitcoin.rpc_url().to_owned();
        let sui_rpc = sui.rpc_url.clone();
        let service_info = sui
            .client
            .clone()
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();

        let mut configs = Vec::with_capacity(self.num_nodes);
        for (validator_address, private_key) in sui.validator_keys.iter().take(self.num_nodes) {
            let mut config = HashiConfig::new_for_testing();
            config.test_weight_divisor = Some(TEST_WEIGHT_DIVISOR);
            config.test_batch_size_per_weight = self.test_batch_size_per_weight;
            config.hashi_ids = Some(hashi_ids);
            config.validator_address = Some(*validator_address);
            config.operator_private_key = Some(private_key.to_pem()?);
            config.sui_rpc = Some(sui_rpc.clone());
            config.bitcoin_rpc = Some(bitcoin_rpc.clone());
            config.bitcoin_rpc_auth = Some(hashi::btc_monitor::config::BtcRpcAuth::UserPass(
                crate::bitcoin_node::RPC_USER.into(),
                crate::bitcoin_node::RPC_PASSWORD.into(),
            ));
            config.bitcoin_trusted_peers = Some(vec![bitcoin.p2p_address()]);
            // Bitcoin regtest chain id, from https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
            config.bitcoin_chain_id = Some(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206".to_string(),
            );
            config.sui_chain_id = service_info.chain_id.clone();
            config.screener_endpoint = Some(screener_endpoint.clone());
            config.db = Some(dir.join(validator_address.to_string()));
            configs.push(config);
        }

        let initially_active = self.num_initially_active_nodes.unwrap_or(configs.len());
        assert!(
            initially_active <= configs.len(),
            "initially_active ({initially_active}) must be <= num_nodes ({})",
            configs.len()
        );
        let active_bls_keys: Vec<_> = configs[..initially_active]
            .iter()
            .map(|c| {
                (
                    c.validator_address().unwrap(),
                    c.protocol_private_key().unwrap(),
                    c.encryption_public_key().unwrap(),
                )
            })
            .collect();
        for config in &configs[..initially_active] {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }
        // Initialize the initial committee with only active nodes
        start_reconfig(sui, hashi_ids).await?;
        // TODO: Remove this test-only logic once the node service handles committing the
        // MPC public key on-chain after DKG.
        let placeholder_mpc_public_key = vec![0u8; 33];
        end_reconfig(sui, hashi_ids, &active_bls_keys, placeholder_mpc_public_key).await?;
        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let node_handle = HashiNodeHandle::new(config)?;
            nodes.push(node_handle);
        }
        // Start only the active nodes
        for node in &mut nodes[..initially_active] {
            node.start().await?;
            debug!(
                "Created Hashi node {} at HTTPS: {}, HTTP: {}, Metrics: {}",
                node.config.validator_address()?,
                node.https_address(),
                node.http_address(),
                node.metrics_address()
            );
        }
        Ok(HashiNetwork {
            ids: hashi_ids,
            nodes,
            _screener_service: screener_service,
        })
    }
}

impl Default for HashiNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

async fn register_onchain(client: sui_rpc::Client, config: &HashiConfig) -> Result<()> {
    let signer = config.operator_private_key()?;
    let hashi_ids = config.hashi_ids();
    let mut executor = hashi::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);
    executor.execute_register_validator(config, None).await
}

pub async fn update_tls_public_key(client: sui_rpc::Client, config: &HashiConfig) -> Result<()> {
    let hashi_ids = config.hashi_ids();
    let private_key = config.operator_private_key()?;
    let validator_address = config.validator_address()?;
    let tls_key = config.tls_public_key()?;

    let mut executor = hashi::sui_tx_executor::SuiTxExecutor::new(client, private_key, hashi_ids);

    let mut builder = TransactionBuilder::new();

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let validator_address_arg = builder.pure(&validator_address);
    let tls_key_arg = builder.pure(&tls_key.as_bytes().to_vec());

    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("validator"),
            Identifier::from_static("update_tls_public_key"),
        ),
        vec![hashi_arg, validator_address_arg, tls_key_arg],
    );

    let response = executor.execute(builder).await?;
    assert!(
        response.transaction().effects().status().success(),
        "update_tls_public_key failed"
    );

    Ok(())
}

async fn start_reconfig(sui: &SuiNetworkHandle, hashi_ids: HashiIds) -> Result<()> {
    let private_key = sui.user_keys.first().unwrap().clone();
    let mut executor =
        hashi::sui_tx_executor::SuiTxExecutor::new(sui.client.clone(), private_key, hashi_ids);

    let mut builder = TransactionBuilder::new();

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let sui_system_arg = builder.object(
        ObjectInput::new(Address::from_static("0x5"))
            .as_shared()
            .with_mutable(false),
    );

    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("reconfig"),
            Identifier::from_static("start_reconfig"),
        ),
        vec![hashi_arg, sui_system_arg],
    );

    let response = executor.execute(builder).await?;

    if let Some(status) = response.transaction().effects().status().error_opt() {
        dbg!(status);
    }

    assert!(
        response.transaction().effects().status().success(),
        "start_reconfig failed"
    );

    Ok(())
}

async fn end_reconfig(
    sui: &SuiNetworkHandle,
    hashi_ids: HashiIds,
    bls_keys: &[(Address, Bls12381PrivateKey, EncryptionPublicKey)],
    mpc_public_key: Vec<u8>,
) -> Result<()> {
    let client = sui.client.clone();
    let private_key = sui.user_keys.first().unwrap().clone();

    let service_info = client
        .clone()
        .ledger_client()
        .get_service_info(GetServiceInfoRequest::default())
        .await?
        .into_inner();
    let epoch = service_info.epoch.unwrap_or(0);

    let committee_members: Vec<CommitteeMember> = bls_keys
        .iter()
        .map(|(addr, bls_key, enc_key)| {
            CommitteeMember::new(*addr, bls_key.public_key(), enc_key.clone(), 1)
        })
        .collect();
    let committee = Committee::new(committee_members, epoch);
    let message = ReconfigCompletionMessage {
        epoch,
        mpc_public_key: mpc_public_key.clone(),
    };
    let mut aggregator = BlsSignatureAggregator::new(&committee, message.clone());
    for (addr, bls_key, _) in bls_keys {
        let member_sig = bls_key.sign(epoch, *addr, &message);
        aggregator.add_signature(member_sig)?;
    }
    let signed_message = aggregator.finish()?;
    committee
        .verify_signature(&signed_message)
        .expect("Local signature verification failed");
    let signature_bytes = signed_message.signature_bytes();
    let signers_bitmap_bytes = signed_message.signers_bitmap_bytes();

    let mut executor = hashi::sui_tx_executor::SuiTxExecutor::new(client, private_key, hashi_ids);

    let mut builder = TransactionBuilder::new();

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let mpc_public_key_arg = builder.pure(&mpc_public_key);
    let signature_arg = builder.pure(&signature_bytes.to_vec());
    let signers_bitmap_arg = builder.pure(&signers_bitmap_bytes.to_vec());

    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("reconfig"),
            Identifier::from_static("end_reconfig"),
        ),
        vec![
            hashi_arg,
            mpc_public_key_arg,
            signature_arg,
            signers_bitmap_arg,
        ],
    );

    let response = executor.execute(builder).await?;
    assert!(
        response.transaction().effects().status().success(),
        "end_reconfig failed: {:?}",
        response.transaction().effects().status().error_opt()
    );
    Ok(())
}
