use anyhow::{Result, anyhow};
use bitcoin::{Address, Amount, BlockHash, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use hashi::config::get_available_port;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tracing::{info, warn};

const DEFAULT_INITIAL_BLOCKS: u64 = 101;
const BITCOIN_CORE_STARTUP_TIMEOUT_SECS: u64 = 60;
const STARTUP_LOG_INTERVAL_SECS: u64 = 5;
const RPC_USER: &str = "test";
const RPC_PASSWORD: &str = "test";

pub struct BitcoinNodeHandle {
    rpc_client: Client,
    _data_dir: TempDir, // RAII: Keeps directory alive, auto-cleanup on drop
    process: Child,
    rpc_url: String,
    rpc_port: u16,
    p2p_port: u16,
}

impl BitcoinNodeHandle {
    pub fn new(rpc_port: u16, data_dir: TempDir, bitcoin_core_path: PathBuf) -> Result<Self> {
        let rpc_url = format!("http://127.0.0.1:{}", rpc_port);
        let p2p_port = get_available_port();
        info!(
            "Starting Bitcoin node with RPC at {} and P2P port {}",
            rpc_url, p2p_port
        );
        let mut process = Command::new(&bitcoin_core_path)
            .arg("-regtest")
            .arg("-server")
            .arg(format!("-datadir={}", data_dir.path().display()))
            .arg(format!("-rpcport={}", rpc_port))
            .arg(format!("-port={}", p2p_port))
            .arg(format!("-rpcuser={}", RPC_USER))
            .arg(format!("-rpcpassword={}", RPC_PASSWORD))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .arg("-fallbackfee=0.0001")
            .arg("-acceptnonstdtxn=1")
            .arg("-blockfilterindex=1") // Enable compact block filters (BIP-158)
            .arg("-peerblockfilters=1") // Serve filters to peers (BIP-157)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                anyhow!(
                    "Failed to start bitcoind: {}. Make sure bitcoind is installed and in PATH",
                    e
                )
            })?;

        // Give bitcoind a moment to start up and bind to the RPC port
        std::thread::sleep(Duration::from_millis(500));

        // Check if process exited already
        match process.try_wait() {
            Ok(Some(status)) => {
                return Err(anyhow!(
                    "bitcoind exited immediately with status: {:?}",
                    status
                ));
            }
            Ok(None) => {
                info!("Bitcoin process spawned with PID: {:?}", process.id());
            }
            Err(e) => {
                warn!("Error checking process status: {}", e);
            }
        }

        let rpc_client = Client::new(
            &rpc_url,
            Auth::UserPass(RPC_USER.to_string(), RPC_PASSWORD.to_string()),
        )?;
        Ok(Self {
            rpc_client,
            _data_dir: data_dir,
            process,
            rpc_url,
            rpc_port,
            p2p_port,
        })
    }

    pub async fn wait_until_ready(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(BITCOIN_CORE_STARTUP_TIMEOUT_SECS);
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Bitcoin Core failed to start within timeout"));
            }
            match self.rpc_client.get_blockchain_info() {
                Ok(_) => {
                    info!("Bitcoin node is ready");
                    match self
                        .rpc_client
                        .create_wallet("test", None, None, None, None)
                    {
                        Ok(_) => info!("Created test wallet"),
                        Err(e) => info!("Wallet creation: {}", e),
                    }
                    return Ok(());
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_secs();
                    if elapsed.is_multiple_of(STARTUP_LOG_INTERVAL_SECS) {
                        info!("Waiting for Bitcoin node to be ready ({}s): {}", elapsed, e);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub fn generate_blocks(&self, count: u64) -> Result<Vec<BlockHash>> {
        let blocks = self
            .rpc_client
            .generate_to_address(count, &self.get_new_address()?)?;
        info!("Generated {} blocks", count);
        Ok(blocks)
    }

    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid = self
            .rpc_client
            .send_to_address(address, amount, None, None, None, None, None, None)?;
        info!("Sent {} to {}: {}", amount, address, txid);
        Ok(txid)
    }

    pub fn get_balance(&self) -> Result<Amount> {
        let balance = self.rpc_client.get_balance(None, None)?;
        Ok(balance)
    }

    pub fn get_new_address(&self) -> Result<Address> {
        let address = self.rpc_client.get_new_address(None, None)?;
        Ok(address.assume_checked())
    }

    pub fn get_block_count(&self) -> Result<u64> {
        Ok(self.rpc_client.get_block_count()?)
    }

    pub async fn wait_for_transaction(&self, txid: &Txid, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Transaction {} not found within timeout", txid));
            }
            match self.rpc_client.get_transaction(txid, None) {
                Ok(_) => {
                    info!("Transaction {} confirmed", txid);
                    return Ok(());
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub fn stop(&self) -> Result<()> {
        self.rpc_client.stop()?;
        info!("Bitcoin node stopped");
        Ok(())
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    pub fn p2p_port(&self) -> u16 {
        self.p2p_port
    }

    pub fn p2p_address(&self) -> String {
        format!("127.0.0.1:{}", self.p2p_port)
    }

    pub fn rpc_client(&self) -> &Client {
        &self.rpc_client
    }
}

impl Drop for BitcoinNodeHandle {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            warn!("Failed to stop Bitcoin node gracefully: {}", e);
        }
        if let Err(e) = self.process.kill() {
            warn!("Failed to kill Bitcoin node process: {}", e);
        }
    }
}

pub struct BitcoinNodeBuilder {
    initial_blocks: u64,
    bitcoin_core_path: Option<PathBuf>,
}

impl BitcoinNodeBuilder {
    pub fn new() -> Self {
        Self {
            initial_blocks: DEFAULT_INITIAL_BLOCKS,
            bitcoin_core_path: None,
        }
    }

    pub fn with_initial_blocks(mut self, blocks: u64) -> Self {
        self.initial_blocks = blocks;
        self
    }

    pub fn with_bitcoin_core_path(mut self, path: PathBuf) -> Self {
        self.bitcoin_core_path = Some(path);
        self
    }

    pub async fn build(self) -> Result<BitcoinNodeHandle> {
        let bitcoin_core_path = self
            .bitcoin_core_path
            .unwrap_or_else(|| PathBuf::from("bitcoind"));
        let rpc_port = get_available_port();
        let data_dir = TempDir::new()?;
        let node_handle = BitcoinNodeHandle::new(rpc_port, data_dir, bitcoin_core_path)?;
        node_handle.wait_until_ready().await?;
        if self.initial_blocks > 0 {
            node_handle.generate_blocks(self.initial_blocks)?;
        }
        info!(
            "Created Bitcoin node at RPC port {} with {} initial blocks",
            rpc_port, self.initial_blocks
        );
        Ok(node_handle)
    }
}

impl Default for BitcoinNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default_trait() {
        let builder1 = BitcoinNodeBuilder::new();
        let builder2 = BitcoinNodeBuilder::default();

        assert_eq!(builder1.initial_blocks, builder2.initial_blocks);
    }

    #[test]
    fn test_builder_default_values() {
        let builder = BitcoinNodeBuilder::new();

        assert_eq!(builder.initial_blocks, DEFAULT_INITIAL_BLOCKS);
        assert!(builder.bitcoin_core_path.is_none());
    }

    #[test]
    fn test_builder_chain_methods() {
        const INITIAL_BLOCKS: u64 = 200;
        const BITCOIND_PATH: &str = "/usr/local/bin/bitcoind";

        let builder = BitcoinNodeBuilder::new()
            .with_initial_blocks(INITIAL_BLOCKS)
            .with_bitcoin_core_path(PathBuf::from(BITCOIND_PATH));

        assert_eq!(builder.initial_blocks, INITIAL_BLOCKS);
        assert_eq!(
            builder.bitcoin_core_path,
            Some(PathBuf::from(BITCOIND_PATH))
        );
    }
}
