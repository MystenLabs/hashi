use anyhow::Result;
use hashi::config::get_available_port;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;
use tokio::time::{Duration, sleep};

const DEFAULT_NUM_VALIDATORS: usize = 4;
const DEFAULT_EPOCH_DURATION_MS: u64 = 60_000;
const TEMP_DIR_PREFIX: &str = "sui-network-";
const LOCALHOST: &str = "127.0.0.1";
const HTTP_PREFIX: &str = "http://";
const NETWORK_STARTUP_TIMEOUT_SECS: u64 = 10;
const NETWORK_STARTUP_POLL_INTERVAL_SECS: u64 = 1;

fn make_url(port: u16) -> String {
    format!("{}{}:{}", HTTP_PREFIX, LOCALHOST, port)
}

fn ensure_sui_binary_exists(custom_path: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = custom_path {
        return Ok(path.clone());
    }
    if let Ok(path) = std::env::var("SUI_BINARY") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(output) = Command::new("which").arg("sui").output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let common_path = PathBuf::from(format!("{}/bin/sui", home));
    if common_path.exists() {
        return Ok(common_path);
    }
    anyhow::bail!("sui binary not found. Please install sui or set SUI_BINARY env var")
}

async fn wait_for_ready(port: u16) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", LOCALHOST, port).parse()?;
    for _ in 0..NETWORK_STARTUP_TIMEOUT_SECS {
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            drop(stream);
            return Ok(());
        }
        sleep(Duration::from_secs(NETWORK_STARTUP_POLL_INTERVAL_SECS)).await;
    }
    anyhow::bail!(
        "Network failed to start within {}s timeout on port {}",
        NETWORK_STARTUP_TIMEOUT_SECS,
        port
    )
}

/// Handle for a Sui network running via pre-compiled binary
pub struct SuiNetworkHandle {
    /// Child process running sui
    process: Child,

    /// Temporary directory for config (auto-cleanup on drop)
    _config_dir: TempDir,

    /// Network endpoints
    pub rpc_url: String,
    pub faucet_url: String,
    pub graphql_url: Option<String>,

    /// Network configuration
    pub num_validators: usize,
    pub epoch_duration_ms: u64,
}

impl Drop for SuiNetworkHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

pub struct SuiNetworkBuilder {
    pub num_validators: usize,
    pub epoch_duration_ms: u64,
    pub sui_binary_path: Option<PathBuf>, // Optional custom binary
}

impl Default for SuiNetworkBuilder {
    fn default() -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: DEFAULT_EPOCH_DURATION_MS,
            sui_binary_path: None,
        }
    }
}

impl SuiNetworkBuilder {
    pub fn with_num_validators(mut self, n: usize) -> Self {
        self.num_validators = n;
        self
    }

    pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
        self.epoch_duration_ms = ms;
        self
    }

    pub fn with_binary(mut self, path: PathBuf) -> Self {
        self.sui_binary_path = Some(path);
        self
    }

    pub async fn build(self) -> Result<SuiNetworkHandle> {
        let config_dir = tempfile::Builder::new().prefix(TEMP_DIR_PREFIX).tempdir()?;
        let sui_binary = ensure_sui_binary_exists(&self.sui_binary_path)?;
        self.generate_genesis(&sui_binary, &config_dir)?;
        let rpc_port = get_available_port();
        let faucet_port = get_available_port();
        let process = self.start_network(&sui_binary, &config_dir, rpc_port, faucet_port)?;
        let rpc_url = make_url(rpc_port);
        let faucet_url = make_url(faucet_port);
        wait_for_ready(rpc_port).await?;
        Ok(SuiNetworkHandle {
            process,
            _config_dir: config_dir,
            rpc_url,
            faucet_url,
            graphql_url: None,
            num_validators: self.num_validators,
            epoch_duration_ms: self.epoch_duration_ms,
        })
    }

    fn generate_genesis(&self, sui_binary: &PathBuf, config_dir: &TempDir) -> Result<()> {
        let mut cmd = Command::new(sui_binary);
        cmd.arg("genesis")
            .arg("--working-dir")
            .arg(config_dir.path())
            .arg("--epoch-duration-ms")
            .arg(self.epoch_duration_ms.to_string())
            .arg("--committee-size")
            .arg(self.num_validators.to_string())
            .arg("--with-faucet");
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to generate genesis"));
        }
        Ok(())
    }

    fn start_network(
        &self,
        sui_binary: &PathBuf,
        config_dir: &TempDir,
        rpc_port: u16,
        faucet_port: u16,
    ) -> Result<Child> {
        let mut cmd = Command::new(sui_binary);
        cmd.arg("start")
            .arg("--network.config")
            .arg(config_dir.path())
            .arg("--fullnode-rpc-port")
            .arg(rpc_port.to_string())
            .arg(format!("--with-faucet={}:{}", LOCALHOST, faucet_port))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(cmd.spawn()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_binary_sui_network() -> Result<()> {
        let sui_network = SuiNetworkBuilder::default().build().await?;

        assert_eq!(sui_network.num_validators, 4);
        assert!(!sui_network.rpc_url.is_empty());
        assert!(!sui_network.faucet_url.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_with_sui_epoch_duration_ms() -> Result<()> {
        const CUSTOM_EPOCH_MS: u64 = 120_000;

        let sui_network = SuiNetworkBuilder::default()
            .with_epoch_duration_ms(CUSTOM_EPOCH_MS)
            .build()
            .await?;

        assert_eq!(sui_network.epoch_duration_ms, CUSTOM_EPOCH_MS);

        Ok(())
    }

    #[tokio::test]
    async fn test_parallel_sui_networks() -> Result<()> {
        use futures::future::join_all;
        use std::collections::HashSet;

        const NUM_PARALLEL_NETWORKS: usize = 3;
        const NUM_VALIDATORS: usize = 5;

        // Spawn multiple networks in parallel
        let network_futures: Vec<_> = (0..NUM_PARALLEL_NETWORKS)
            .map(|i| async move {
                let network = SuiNetworkBuilder::default()
                    .with_num_validators(NUM_VALIDATORS)
                    .build()
                    .await;
                (i, network)
            })
            .collect();

        // Wait for all networks to start
        let results = join_all(network_futures).await;

        // Verify all networks started successfully with unique ports
        let mut networks = Vec::new();
        let mut rpc_ports = HashSet::new();
        let mut faucet_ports = HashSet::new();

        for (i, result) in results {
            match result {
                Ok(network) => {
                    let rpc_port: u16 = network
                        .rpc_url
                        .split(':')
                        .next_back()
                        .and_then(|p| p.parse().ok())
                        .expect("Failed to parse RPC port");
                    let faucet_port: u16 = network
                        .faucet_url
                        .split(':')
                        .next_back()
                        .and_then(|p| p.parse().ok())
                        .expect("Failed to parse faucet port");

                    // Verify ports are unique
                    assert!(
                        rpc_ports.insert(rpc_port),
                        "Network {} has duplicate RPC port {}",
                        i,
                        rpc_port
                    );
                    assert!(
                        faucet_ports.insert(faucet_port),
                        "Network {} has duplicate faucet port {}",
                        i,
                        faucet_port
                    );

                    // Verify network configuration
                    assert_eq!(network.num_validators, NUM_VALIDATORS);

                    networks.push(network);
                }
                Err(e) => {
                    panic!("Network {} failed to start: {}", i, e);
                }
            }
        }

        assert_eq!(networks.len(), NUM_PARALLEL_NETWORKS);

        Ok(())
    }
}
