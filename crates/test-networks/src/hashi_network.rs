use anyhow::Result;
use hashi::{Hashi, ServerVersion, config::Config as HashiConfig};
use std::{net::SocketAddr, sync::Arc};
use tracing::info;

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

    pub async fn build(self) -> Result<HashiNetwork> {
        let mut nodes = Vec::with_capacity(self.num_nodes);
        for i in 0..self.num_nodes {
            let config = HashiConfig::new_for_testing();
            let node_handle = HashiNodeHandle::new(config)?;
            node_handle.start();
            info!(
                "Created Hashi node {} at HTTPS: {}, HTTP: {}, Metrics: {}",
                i,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hashi_network_multiple_nodes() -> Result<()> {
        let hashi_network = HashiNetworkBuilder::new().with_num_nodes(3).build().await?;
        assert_eq!(hashi_network.nodes().len(), 3);
        for node in hashi_network.nodes().iter() {
            assert!(!node.https_url().is_empty());
            assert!(!node.http_url().is_empty());
            assert!(!node.metrics_url().is_empty());

            // Verify each node has unique ports
            let https_port = node.https_address().port();
            let http_port = node.http_address().port();
            let metrics_port = node.metrics_address().port();
            assert_ne!(https_port, http_port);
            assert_ne!(https_port, metrics_port);
            assert_ne!(http_port, metrics_port);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_default_configuration() -> Result<()> {
        let builder = HashiNetworkBuilder::new();
        assert_eq!(builder.num_nodes, 1);
        Ok(())
    }

    #[test]
    fn test_builder_fluent_api() {
        const NUM_NODES: usize = 3;

        let builder = HashiNetworkBuilder::new().with_num_nodes(NUM_NODES);

        assert_eq!(builder.num_nodes, NUM_NODES);
    }

    #[test]
    fn test_builder_default_trait() {
        let builder1 = HashiNetworkBuilder::new();
        let builder2 = HashiNetworkBuilder::default();

        assert_eq!(builder1.num_nodes, builder2.num_nodes);
    }

    #[tokio::test]
    async fn test_node_handle_url_formatting() -> Result<()> {
        let config = HashiConfig::new_for_testing();
        let https_port = config.https_address().port();
        let http_port = config.http_address().port();
        let metrics_port = config.metrics_http_address().port();
        let node_handle = HashiNodeHandle::new(config)?;

        const HTTPS_URL_PREFIX: &str = "https://127.0.0.1:";
        const HTTP_URL_PREFIX: &str = "http://127.0.0.1:";

        assert_eq!(
            node_handle.https_url(),
            format!("{}{}", HTTPS_URL_PREFIX, https_port)
        );
        assert_eq!(
            node_handle.http_url(),
            format!("{}{}", HTTP_URL_PREFIX, http_port)
        );
        assert_eq!(
            node_handle.metrics_url(),
            format!("{}{}", HTTP_URL_PREFIX, metrics_port)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_zero_nodes_build() -> Result<()> {
        let network = HashiNetworkBuilder::new().with_num_nodes(0).build().await?;

        assert_eq!(network.nodes().len(), 0);
        assert!(network.nodes().is_empty());

        Ok(())
    }
}
