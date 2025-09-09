use anyhow::Result;
use hashi::{Hashi, ServerVersion, config::Config as HashiConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub const LOCALHOST: [u8; 4] = [127, 0, 0, 1];

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
        format!("https://{}", self.0.config.https_address())
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.0.config.http_address())
    }

    pub fn metrics_url(&self) -> String {
        format!("http://{}", self.0.config.metrics_http_address())
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
            let https_port = self.get_available_port()?;
            let http_port = self.get_available_port()?;
            let metrics_port = self.get_available_port()?;
            let config = self.create_test_config(https_port, http_port, metrics_port)?;
            let node_handle = HashiNodeHandle::new(config)?;
            node_handle.start();
            nodes.push(node_handle);
            info!(
                "Created Hashi node {} at HTTPS: {}, HTTP: {}, Metrics: {}",
                i, https_port, http_port, metrics_port
            );
        }
        Ok(HashiNetwork(nodes))
    }

    fn create_test_config(
        &self,
        https_port: u16,
        http_port: u16,
        metrics_port: u16,
    ) -> Result<HashiConfig> {
        let mut config = HashiConfig::new_for_testing();
        config.https_address = Some(SocketAddr::from((LOCALHOST, https_port)));
        config.http_address = Some(SocketAddr::from((LOCALHOST, http_port)));
        config.metrics_http_address = Some(SocketAddr::from((LOCALHOST, metrics_port)));
        Ok(config)
    }

    fn get_available_port(&self) -> Result<u16> {
        Ok(hashi::config::get_available_port())
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
        const TEST_NUM_NODES: usize = 3;

        let builder = HashiNetworkBuilder::new().with_num_nodes(TEST_NUM_NODES);

        assert_eq!(builder.num_nodes, TEST_NUM_NODES);
    }

    #[test]
    fn test_builder_default_trait() {
        let builder1 = HashiNetworkBuilder::new();
        let builder2 = HashiNetworkBuilder::default();

        assert_eq!(builder1.num_nodes, builder2.num_nodes);
    }

    #[tokio::test]
    async fn test_create_test_config() -> Result<()> {
        const TEST_HTTPS_PORT: u16 = 50051;
        const TEST_HTTP_PORT: u16 = 8080;
        const TEST_METRICS_PORT: u16 = 9090;

        let builder = HashiNetworkBuilder::new();
        let config =
            builder.create_test_config(TEST_HTTPS_PORT, TEST_HTTP_PORT, TEST_METRICS_PORT)?;

        // Test addresses are set correctly
        assert_eq!(
            config.https_address(),
            SocketAddr::from((LOCALHOST, TEST_HTTPS_PORT))
        );
        assert_eq!(
            config.http_address(),
            SocketAddr::from((LOCALHOST, TEST_HTTP_PORT))
        );
        assert_eq!(
            config.metrics_http_address(),
            SocketAddr::from((LOCALHOST, TEST_METRICS_PORT))
        );

        // Test TLS key is generated and valid PEM format
        assert!(config.tls_private_key.is_some());
        let tls_key = config.tls_private_key.unwrap();
        assert!(tls_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(tls_key.ends_with("-----END PRIVATE KEY-----\n"));

        Ok(())
    }

    #[tokio::test]
    async fn test_node_handle_url_formatting() -> Result<()> {
        let builder = HashiNetworkBuilder::new();
        let config = builder.create_test_config(50051, 8080, 9090)?;
        let node_handle = HashiNodeHandle::new(config)?;

        assert_eq!(node_handle.https_url(), "https://127.0.0.1:50051");
        assert_eq!(node_handle.http_url(), "http://127.0.0.1:8080");
        assert_eq!(node_handle.metrics_url(), "http://127.0.0.1:9090");

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
