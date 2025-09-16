#[cfg(not(feature = "binary-sui"))]
mod test_cluster_impl {
    pub use test_cluster::{TestCluster, TestClusterBuilder};

    pub type SuiNetwork = TestCluster;
    pub type SuiNetworkBuilder = TestClusterBuilder;
}

#[cfg(feature = "binary-sui")]
mod binary_impl {
    use anyhow::Result;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use tempfile::TempDir;
    use tokio::time::{Duration, sleep};

    const DEFAULT_RPC_PORT: u16 = 9000;
    const DEFAULT_FAUCET_PORT: u16 = 9123;
    const DEFAULT_NUM_VALIDATORS: usize = 4;
    const DEFAULT_EPOCH_DURATION_MS: u64 = 60_000;
    const NETWORK_STARTUP_TIMEOUT_SECS: u64 = 60;
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
        pub async fn new() -> Result<Self> {
            SuiNetworkBuilder::default().build().await
        }

        /// Ensure sui binary exists
        fn ensure_sui_binary(custom_path: &Option<PathBuf>) -> Result<PathBuf> {
            // 1. Check custom path if provided
            if let Some(path) = custom_path {
                return Ok(path.clone());
            }

            // 2. Check SUI_BINARY env var
            if let Ok(path) = std::env::var("SUI_BINARY") {
                return Ok(PathBuf::from(path));
            }

            // 3. Check if sui is in PATH
            if let Ok(output) = Command::new("which").arg("sui").output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }

            // 4. Check common locations
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let common_path = PathBuf::from(format!("{}/bin/sui", home));
            if common_path.exists() {
                return Ok(common_path);
            }

            anyhow::bail!("sui binary not found. Please install sui or set SUI_BINARY env var")
        }

        async fn wait_for_ready(_rpc_url: &str) -> Result<()> {
            for _ in 0..NETWORK_STARTUP_TIMEOUT_SECS {
                // Try to connect to RPC endpoint
                // For now, just check if port is open (proper RPC check can be added later)
                let addr = format!("{}:{}", LOCALHOST, DEFAULT_RPC_PORT);
                if std::net::TcpStream::connect(addr).is_ok() {
                    return Ok(());
                }
                sleep(Duration::from_secs(1)).await;
            }
            anyhow::bail!("Network failed to start within timeout")
        }
    }

    #[derive(Default)]
    pub struct SuiNetworkBuilder {
        pub num_validators: Option<usize>, // Currently ignored (always DEFAULT_NUM_VALIDATORS)
        pub epoch_duration_ms: Option<u64>,
        pub sui_binary_path: Option<PathBuf>, // Optional custom binary
    }

    impl SuiNetworkBuilder {
        pub fn with_validators(mut self, n: usize) -> Self {
            self.num_validators = Some(n);
            self
        }

        pub fn with_num_validators(self, n: usize) -> Self {
            self.with_validators(n)
        }

        pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
            self.epoch_duration_ms = Some(ms);
            self
        }

        pub fn with_binary(mut self, path: PathBuf) -> Self {
            self.sui_binary_path = Some(path);
            self
        }

        pub async fn build(self) -> Result<SuiNetworkHandle> {
            // Step 1: Create temporary directory for this network
            let config_dir = tempfile::Builder::new().prefix(TEMP_DIR_PREFIX).tempdir()?;

            // Step 2: Ensure sui binary exists
            let sui_binary = SuiNetworkHandle::ensure_sui_binary(&self.sui_binary_path)?;

            // Step 3: Generate genesis with configuration
            self.generate_genesis(&sui_binary, &config_dir)?;

            // Step 4: Start the network
            let process = self.start_network(&sui_binary, &config_dir)?;

            // Step 5: Wait for network to be ready
            let rpc_url = format!("http://{}:{}", LOCALHOST, DEFAULT_RPC_PORT);
            SuiNetworkHandle::wait_for_ready(&rpc_url).await?;

            Ok(SuiNetworkHandle {
                process,
                _config_dir: config_dir,
                rpc_url,
                faucet_url: format!("http://{}:{}", LOCALHOST, DEFAULT_FAUCET_PORT),
                graphql_url: None,
                num_validators: self.num_validators.unwrap_or(DEFAULT_NUM_VALIDATORS),
                epoch_duration_ms: self.epoch_duration_ms.unwrap_or(DEFAULT_EPOCH_DURATION_MS),
            })
        }

        fn generate_genesis(&self, sui_binary: &PathBuf, config_dir: &TempDir) -> Result<()> {
            let mut cmd = Command::new(sui_binary);
            cmd.arg("genesis")
                .arg("--working-dir")
                .arg(config_dir.path());
            if let Some(epoch_ms) = self.epoch_duration_ms {
                cmd.arg("--epoch-duration-ms").arg(epoch_ms.to_string());
            }
            if let Some(num_validators) = self.num_validators {
                // TODO: Uncomment when --num-validators flag is added to sui genesis
                // cmd.arg("--num-validators").arg(num_validators.to_string());
                // Currently sui genesis only supports DEFAULT_NUM_VALIDATORS validators
                let _ = num_validators; // Suppress unused warning
            }
            // Always enable faucet for testing
            cmd.arg("--with-faucet");
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
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // Always enable faucet for testing
            cmd.arg("--with-faucet");
            Ok(cmd.spawn()?)
        }
    }

    pub type SuiNetwork = SuiNetworkHandle;
}

#[cfg(not(feature = "binary-sui"))]
pub use test_cluster_impl::*;

#[cfg(feature = "binary-sui")]
pub use binary_impl::*;
