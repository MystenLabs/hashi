use anyhow::Result;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config as HashiConfig;
use hashi::config::HashiIds;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::BitcoinNodeHandle;
use crate::SuiNetworkHandle;

const HTTPS_SCHEME: &str = "https://";
const HTTP_SCHEME: &str = "http://";

pub struct HashiNodeHandle(pub Arc<Hashi>);

impl HashiNodeHandle {
    pub fn new(config: HashiConfig) -> Result<Self> {
        let server_version = ServerVersion::new("test-hashi", "0.1.0");
        let registry = prometheus::Registry::new();
        let hashi_instance = Hashi::new_with_registry(server_version, config, &registry);
        Ok(Self(hashi_instance))
    }

    pub fn start(&self) {
        self.0.clone().start();
    }

    pub fn https_url(&self) -> String {
        format!("{}{}", HTTPS_SCHEME, self.0.config.https_address())
    }

    pub fn http_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.0.config.http_address())
    }

    pub fn metrics_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.0.config.metrics_http_address())
    }

    pub fn https_address(&self) -> SocketAddr {
        self.0.config.https_address()
    }

    pub fn http_address(&self) -> SocketAddr {
        self.0.config.http_address()
    }

    pub fn metrics_address(&self) -> SocketAddr {
        self.0.config.metrics_http_address()
    }
}

pub struct HashiNetwork(pub Vec<HashiNodeHandle>);

impl HashiNetwork {
    pub fn nodes(&self) -> &[HashiNodeHandle] {
        &self.0
    }
}

pub struct HashiNetworkBuilder {
    pub num_nodes: usize,
}

impl HashiNetworkBuilder {
    pub fn new() -> Self {
        Self { num_nodes: 1 }
    }

    pub fn with_num_nodes(mut self, num_nodes: usize) -> Self {
        self.num_nodes = num_nodes;
        self
    }

    pub async fn build(
        self,
        sui: &SuiNetworkHandle,
        bitcoin: &BitcoinNodeHandle,
        hashi_ids: HashiIds,
    ) -> Result<HashiNetwork> {
        let bitcoin_rpc = bitcoin.rpc_url().to_owned();
        let sui_rpc = sui.rpc_url.clone();

        let mut configs = Vec::with_capacity(self.num_nodes);
        for (validator_address, private_key) in sui.validator_keys.iter().take(self.num_nodes) {
            let mut config = HashiConfig::new_for_testing();
            config.hashi_ids = Some(hashi_ids);
            config.validator_address = Some(*validator_address);
            config.operator_private_key = Some(private_key.to_pem()?);
            config.sui_rpc = Some(sui_rpc.clone());
            config.bitcoin_rpc = Some(bitcoin_rpc.clone());

            //TODO fill in chain ids
            config.sui_chain_id = None;
            config.bitcoin_chain_id = None;

            configs.push(config);
        }

        for config in &configs {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }

        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let validator_address = config.validator_address()?;
            let node_handle = HashiNodeHandle::new(config)?;
            node_handle.start();
            info!(
                "Created Hashi node {} at HTTPS: {}, HTTP: {}, Metrics: {}",
                validator_address,
                node_handle.https_address(),
                node_handle.http_address(),
                node_handle.metrics_address()
            );
            nodes.push(node_handle);
        }

        Ok(HashiNetwork(nodes))
    }
}

impl Default for HashiNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

async fn register_onchain(_client: sui_rpc::Client, _config: &HashiConfig) -> Result<()> {
    // TODO flesh out onchain register flow
    Ok(())
}
