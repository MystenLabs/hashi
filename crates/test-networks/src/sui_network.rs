use anyhow::Result;
use anyhow::anyhow;
use hashi::config::get_available_port;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use tokio::time::{Duration, sleep};

const DEFAULT_NUM_VALIDATORS: usize = 4;
const DEFAULT_EPOCH_DURATION_MS: u64 = 60_000;
const NETWORK_STARTUP_TIMEOUT_SECS: u64 = 10;
const NETWORK_STARTUP_POLL_INTERVAL_SECS: u64 = 1;

pub fn sui_binary() -> &'static Path {
    static SUI_BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    SUI_BINARY
        .get_or_init(|| {
            if let Ok(path) = std::env::var("SUI_BINARY") {
                return PathBuf::from(path);
            }
            if let Ok(output) = Command::new("which").arg("sui").output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return PathBuf::from(path);
                }
            }
            panic!("sui binary not found. Please install sui or set SUI_BINARY env var")
        })
        .as_path()
}

async fn wait_for_ready(port: u16) -> Result<()> {
    let http_url = format!("http://127.0.0.1:{port}");
    let mut client = sui_rpc::Client::new(http_url)?;

    // Wait till the network has started up and at least one checkpoint has been produced
    for _ in 0..NETWORK_STARTUP_TIMEOUT_SECS {
        if let Ok(resp) = client
            .ledger_client()
            .get_service_info(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::default())
            .await
            && resp.into_inner().checkpoint_height() > 0
        {
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
    pub dir: PathBuf,

    /// Network endpoints
    pub rpc_url: String,
    pub faucet_url: String,

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
    pub dir: Option<PathBuf>,
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
            dir: None,
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

    pub fn dir(mut self, dir: &Path) -> Self {
        self.dir = Some(dir.to_owned());
        self
    }

    pub async fn build(self) -> Result<SuiNetworkHandle> {
        let dir = self
            .dir
            .clone()
            .ok_or_else(|| anyhow!("no directory configured"))?;
        self.generate_genesis(&dir)?;
        let rpc_port = get_available_port();
        let faucet_port = get_available_port();
        let process = self.start_network(&dir, rpc_port, faucet_port)?;
        let rpc_url = format!("http://127.0.0.1:{rpc_port}");
        let faucet_url = format!("http://127.0.0.1:{faucet_port}");
        wait_for_ready(rpc_port).await?;
        Ok(SuiNetworkHandle {
            process,
            dir,
            rpc_url,
            faucet_url,
            num_validators: self.num_validators,
            epoch_duration_ms: self.epoch_duration_ms,
        })
    }

    fn generate_genesis(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut cmd = Command::new(sui_binary());
        cmd.arg("genesis")
            .arg("--working-dir")
            .arg(dir)
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

    fn start_network(&self, dir: &Path, rpc_port: u16, _faucet_port: u16) -> Result<Child> {
        let stdout_name = dir.join("out.stdout");
        let stdout = std::fs::File::create(stdout_name)?;
        let stderr_name = dir.join("out.stderr");
        let stderr = std::fs::File::create(stderr_name)?;

        let mut cmd = Command::new(sui_binary());

        cmd.arg("start")
            .arg("--network.config")
            .arg(dir)
            .arg("--fullnode-rpc-port")
            .arg(rpc_port.to_string())
            //XXX uncomment once 1.62 release is cut
            // .arg(format!("--with-faucet=127.0.0.1:{faucet_port}"))
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| anyhow!("Failed to run `sui start`: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_parallel_sui_networks() -> Result<()> {
        use futures::future::join_all;
        use std::collections::HashSet;

        const NUM_PARALLEL_NETWORKS: usize = 3;
        const NUM_VALIDATORS: usize = 1;

        let tempdir = TempDir::new()?;

        // Spawn multiple networks in parallel
        let network_futures: Vec<_> = (0..NUM_PARALLEL_NETWORKS)
            .map(|i| {
                let dir = tempdir.path().join(format!("{i}"));

                async move {
                    let network = SuiNetworkBuilder::default()
                        .with_num_validators(NUM_VALIDATORS)
                        .dir(&dir)
                        .build()
                        .await;
                    (i, network)
                }
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
