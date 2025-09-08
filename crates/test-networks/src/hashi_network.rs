use anyhow::Result;
use hashi::{Hashi, ServerVersion, config::Config as HashiConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub const DEFAULT_BASE_GRPC_PORT: u16 = 50051;
pub const DEFAULT_BASE_HTTP_PORT: u16 = 8080;
pub const LOCALHOST: [u8; 4] = [127, 0, 0, 1];

pub struct HashiNodeHandle {
    pub hashi_instance: Arc<Hashi>,
    pub https_address: SocketAddr,
    pub http_address: SocketAddr,
    pub metrics_address: SocketAddr,
}

impl HashiNodeHandle {
    pub fn new(config: HashiConfig) -> Result<Self> {
        let server_version = ServerVersion::new("test-hashi", "0.1.0");
        let https_address = config.https_address();
        let http_address = config.http_address();
        let metrics_address = config.metrics_http_address();
        let hashi_instance = Hashi::new(server_version, config);
        Ok(Self {
            hashi_instance,
            https_address,
            http_address,
            metrics_address,
        })
    }

    pub fn start(&self) {
        self.hashi_instance.clone().start();
    }

    pub fn https_url(&self) -> String {
        format!("https://{}", self.https_address)
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.http_address)
    }

    pub fn metrics_url(&self) -> String {
        format!("http://{}", self.metrics_address)
    }
}

pub struct HashiNetwork {
    pub nodes: Vec<HashiNodeHandle>,
}

impl HashiNetwork {
    pub fn nodes(&self) -> &[HashiNodeHandle] {
        &self.nodes
    }
}

pub struct HashiNetworkBuilder {
    pub num_nodes: usize,
    pub base_grpc_port: u16,
    pub base_http_port: u16,
}

impl HashiNetworkBuilder {
    pub fn new() -> Self {
        Self {
            num_nodes: 1,
            base_grpc_port: DEFAULT_BASE_GRPC_PORT,
            base_http_port: DEFAULT_BASE_HTTP_PORT,
        }
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
        Ok(HashiNetwork { nodes })
    }
}

impl Default for HashiNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HashiNetworkBuilder {
    fn create_test_config(
        &self,
        https_port: u16,
        http_port: u16,
        metrics_port: u16,
    ) -> Result<HashiConfig> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let mut config = HashiConfig::default();
        let tls_private_key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        config.tls_private_key = Some(
            String::from_utf8(
                tls_private_key
                    .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
            .expect("Invalid PEM encoding"),
        );
        config.https_address = Some(SocketAddr::from((LOCALHOST, https_port)));
        config.http_address = Some(SocketAddr::from((LOCALHOST, http_port)));
        config.metrics_http_address = Some(SocketAddr::from((LOCALHOST, metrics_port)));
        Ok(config)
    }

    fn get_available_port(&self) -> Result<u16> {
        const MAX_PORT_RETRIES: u32 = 1000;
        for _ in 0..MAX_PORT_RETRIES {
            if let Ok(port) = self.get_ephemeral_port() {
                return Ok(port);
            }
        }
        Err(anyhow::anyhow!(
            "Error: could not find an available port on localhost"
        ))
    }

    fn get_ephemeral_port(&self) -> std::io::Result<u16> {
        use std::net::{TcpListener, TcpStream};

        // Request a random available port from the OS
        let listener = TcpListener::bind(SocketAddr::from((LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        // Create and accept a connection (which we'll promptly drop) in order to force the port
        // into the TIME_WAIT state, ensuring that the port will be reserved from some limited
        // amount of time (roughly 60s on some Linux systems)
        let _sender = TcpStream::connect(addr)?;
        let _incoming = listener.accept()?;
        Ok(addr.port())
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
            let https_port = node.https_address.port();
            let http_port = node.http_address.port();
            let metrics_port = node.metrics_address.port();
            assert_ne!(https_port, http_port);
            assert_ne!(https_port, metrics_port);
            assert_ne!(http_port, metrics_port);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_default_ports() -> Result<()> {
        let builder = HashiNetworkBuilder::new();
        assert_eq!(builder.base_grpc_port, DEFAULT_BASE_GRPC_PORT);
        assert_eq!(builder.base_http_port, DEFAULT_BASE_HTTP_PORT);
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
        assert_eq!(builder1.base_grpc_port, builder2.base_grpc_port);
        assert_eq!(builder1.base_http_port, builder2.base_http_port);
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
    async fn test_get_available_port() -> Result<()> {
        let builder = HashiNetworkBuilder::new();
        let port1 = builder.get_available_port()?;
        let port2 = builder.get_available_port()?;

        // Ports should be in valid range and different
        assert!(port1 > 1024);
        assert!(port2 > 1024);
        assert_ne!(port1, port2);

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

    #[test]
    fn test_builder_edge_cases() {
        // Test extreme values
        let builder = HashiNetworkBuilder::new().with_num_nodes(1000);
        assert_eq!(builder.num_nodes, 1000);
    }
}
