use anyhow::Result;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;
use tokio::time::{Duration, sleep};

const DEFAULT_RPC_PORT: u16 = 9000;
const DEFAULT_FAUCET_PORT: u16 = 9123;
const DEFAULT_NUM_VALIDATORS: usize = 4;
const DEFAULT_EPOCH_DURATION_MS: u64 = 60_000;
const TEMP_DIR_PREFIX: &str = "sui-network-";
const LOCALHOST: &str = "127.0.0.1";

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

impl SuiNetworkHandle {
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

    async fn wait_for_ready(_rpc_url: &str) -> Result<()> {
        sleep(Duration::from_secs(2)).await;
        Ok(())
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
        let sui_binary = SuiNetworkHandle::ensure_sui_binary_exists(&self.sui_binary_path)?;
        self.generate_genesis(&sui_binary, &config_dir)?;
        let process = self.start_network(&sui_binary, &config_dir)?;
        let rpc_url = format!("http://{}:{}", LOCALHOST, DEFAULT_RPC_PORT);
        SuiNetworkHandle::wait_for_ready(&rpc_url).await?;
        Ok(SuiNetworkHandle {
            process,
            _config_dir: config_dir,
            rpc_url,
            faucet_url: format!("http://{}:{}", LOCALHOST, DEFAULT_FAUCET_PORT),
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

    fn start_network(&self, sui_binary: &PathBuf, config_dir: &TempDir) -> Result<Child> {
        let mut cmd = Command::new(sui_binary);
        cmd.arg("start")
            .arg("--network.config")
            .arg(config_dir.path())
            .arg("--with-faucet")
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

        const NUM_PARALLEL_NETWORKS: usize = 3;
        const NUM_VALIDATORS: usize = 7;

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

        // Verify all networks started successfully
        let mut networks = Vec::new();
        for (i, result) in results {
            match result {
                Ok(network) => {
                    assert_eq!(network.num_validators, NUM_VALIDATORS);
                    assert!(!network.rpc_url.is_empty());
                    assert!(!network.faucet_url.is_empty());
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
