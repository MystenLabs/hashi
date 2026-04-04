// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::Txid;
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client;
use hashi::config::get_available_port;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::time::Duration;
use tracing::info;
use tracing::warn;

const DEFAULT_INITIAL_BLOCKS: u64 = 101;
const BITCOIN_CORE_STARTUP_TIMEOUT_SECS: u64 = 60;
const STARTUP_LOG_INTERVAL_SECS: u64 = 5;
pub const RPC_USER: &str = "test";
pub const RPC_PASSWORD: &str = "test";

pub struct BitcoinNodeHandle {
    rpc_client: Client,
    #[allow(unused)]
    data_dir: PathBuf,
    process: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    rpc_url: String,
    rpc_port: u16,
    p2p_port: u16,
}

impl BitcoinNodeHandle {
    pub fn new(rpc_port: u16, data_dir: PathBuf, bitcoin_core_path: PathBuf) -> Result<Self> {
        let rpc_url = format!("http://127.0.0.1:{}", rpc_port);
        let p2p_port = get_available_port();
        info!(
            "Starting Bitcoin node with RPC at {} and P2P port {}",
            rpc_url, p2p_port
        );

        let stdout_name = data_dir.join("bitcoin.stdout");
        let stdout = std::fs::File::create(&stdout_name)?;
        let stderr_name = data_dir.join("bitcoin.stderr");
        let stderr = std::fs::File::create(&stderr_name)?;

        let mut process = Command::new(&bitcoin_core_path)
            .arg("-regtest")
            .arg("-server")
            .arg(format!("-datadir={}", data_dir.display()))
            .arg(format!("-rpcport={}", rpc_port))
            // Use -bind instead of -port to prevent Bitcoin Core from
            // also opening an onion listener on port+1.
            .arg(format!("-bind=127.0.0.1:{}", p2p_port))
            .arg("-listen=1")
            .arg(format!("-rpcuser={}", RPC_USER))
            .arg(format!("-rpcpassword={}", RPC_PASSWORD))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .arg("-fallbackfee=0.0001")
            .arg("-acceptnonstdtxn=1")
            .arg("-blockfilterindex=1") // Enable compact block filters (BIP-158)
            .arg("-peerblockfilters=1") // Serve filters to peers (BIP-157)
            .arg("-txindex=1") // Enable transaction index for RPC queries
            .arg("-listenonion=0")
            .stdout(stdout)
            .stderr(stderr)
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

        let rpc_client = Client::new_with_auth(
            &rpc_url,
            Auth::UserPass(RPC_USER.to_string(), RPC_PASSWORD.to_string()),
        )?;
        Ok(Self {
            rpc_client,
            data_dir,
            process,
            stdout_path: stdout_name,
            stderr_path: stderr_name,
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
                return Err(anyhow!(
                    "Bitcoin Core failed to start within timeout. {}",
                    self.startup_diagnostics()
                ));
            }
            match self.rpc_client.get_blockchain_info() {
                Ok(_) => {
                    info!("Bitcoin node is ready");
                    match self.rpc_client.create_wallet("test") {
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

    fn startup_diagnostics(&self) -> String {
        let mut diagnostics = Vec::new();

        for (label, path) in [
            ("stderr", &self.stderr_path),
            ("stdout", &self.stdout_path),
            ("debug.log", &self.data_dir.join("regtest/debug.log")),
        ] {
            let contents = std::fs::read_to_string(path)
                .ok()
                .and_then(|contents| {
                    let lines: Vec<_> = contents.lines().rev().take(20).collect();
                    if lines.is_empty() {
                        None
                    } else {
                        Some(lines.into_iter().rev().collect::<Vec<_>>().join(" | "))
                    }
                })
                .unwrap_or_else(|| format!("<empty or unavailable at {}>", path.display()));
            diagnostics.push(format!("{label}: {contents}"));
        }

        diagnostics.join("; ")
    }

    pub fn generate_blocks(&self, count: u64) -> Result<Vec<BlockHash>> {
        let blocks = self
            .rpc_client
            .generate_to_address(count as usize, &self.get_new_address()?)?
            .into_model()
            .map_err(|e| anyhow!("invalid block hash: {e}"))?
            .0;
        info!("Generated {} blocks", count);
        Ok(blocks)
    }

    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid = self
            .rpc_client
            .send_to_address(address, amount)?
            .into_model()
            .map_err(|e| anyhow!("invalid txid: {e}"))?
            .txid;
        info!("Sent {} to {}: {}", amount, address, txid);
        Ok(txid)
    }

    pub fn get_balance(&self) -> Result<Amount> {
        Ok(self
            .rpc_client
            .get_balance()?
            .into_model()
            .map_err(|e| anyhow!("invalid balance: {e}"))?
            .0)
    }

    pub fn get_new_address(&self) -> Result<Address> {
        let address = self.rpc_client.new_address()?;
        Ok(address)
    }

    pub fn get_block_count(&self) -> Result<u64> {
        Ok(self.rpc_client.get_block_count()?.0)
    }

    pub async fn wait_for_transaction(&self, txid: &Txid, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!("Transaction {} not found within timeout", txid));
            }
            match self.rpc_client.get_transaction(*txid) {
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
    dir: Option<PathBuf>,
    initial_blocks: u64,
    bitcoin_core_path: Option<PathBuf>,
    rpc_port: Option<u16>,
}

impl BitcoinNodeBuilder {
    pub fn new() -> Self {
        Self {
            initial_blocks: DEFAULT_INITIAL_BLOCKS,
            bitcoin_core_path: None,
            dir: None,
            rpc_port: None,
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

    pub fn dir(mut self, dir: &Path) -> Self {
        self.dir = Some(dir.to_owned());
        self
    }

    pub fn with_rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    pub async fn build(self) -> Result<BitcoinNodeHandle> {
        let bitcoin_core_path = self
            .bitcoin_core_path
            .unwrap_or_else(|| PathBuf::from("bitcoind"));
        let rpc_port = self.rpc_port.unwrap_or_else(get_available_port);

        let data_dir = self.dir.ok_or_else(|| anyhow!("no data_dir configured"))?;

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
