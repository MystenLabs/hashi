// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::Txid;
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client;
use hashi::config::get_available_port;
use hashi_types::bitcoin::BitcoinAddress;
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
        Self::new_with_args(rpc_port, data_dir, bitcoin_core_path, &[])
    }

    fn new_with_args(
        rpc_port: u16,
        data_dir: PathBuf,
        bitcoin_core_path: PathBuf,
        extra_args: &[String],
    ) -> Result<Self> {
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
            .args(extra_args)
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
        crate::tail_logs(&[
            ("stderr", &self.stderr_path),
            ("stdout", &self.stdout_path),
            ("debug.log", &self.data_dir.join("regtest/debug.log")),
        ])
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

    pub fn send_to_address(&self, address: &BitcoinAddress, amount: Amount) -> Result<Txid> {
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

    pub fn get_new_address(&self) -> Result<BitcoinAddress> {
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
    extra_args: Vec<String>,
}

impl BitcoinNodeBuilder {
    pub fn new() -> Self {
        Self {
            initial_blocks: DEFAULT_INITIAL_BLOCKS,
            bitcoin_core_path: None,
            dir: None,
            rpc_port: None,
            extra_args: Vec::new(),
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

    pub fn with_extra_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.extra_args.extend(args.into_iter().map(Into::into));
        self
    }

    pub async fn build(self) -> Result<BitcoinNodeHandle> {
        let bitcoin_core_path = self
            .bitcoin_core_path
            .unwrap_or_else(|| PathBuf::from("bitcoind"));
        let rpc_port = self.rpc_port.unwrap_or_else(get_available_port);

        let data_dir = self.dir.ok_or_else(|| anyhow!("no data_dir configured"))?;

        let node_handle = BitcoinNodeHandle::new_with_args(
            rpc_port,
            data_dir,
            bitcoin_core_path,
            &self.extra_args,
        )?;
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
pub(crate) use tests::fill_mempool_until_evicted;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::consensus::encode::serialize_hex;
    use hashi::btc_monitor::TrustedPeer;
    use hashi::btc_monitor::config::MonitorConfig;
    use hashi::btc_monitor::monitor::Monitor;
    use serde_json::Value;
    use serde_json::json;
    use std::sync::Arc;

    fn wallet_script(node: &BitcoinNodeHandle) -> Result<ScriptBuf> {
        let address: String = node
            .rpc_client()
            .call("getnewaddress", &[json!(""), json!("bech32")])?;
        Ok(address
            .parse::<bitcoin::Address<_>>()?
            .require_network(bitcoin::Network::Regtest)?
            .script_pubkey())
    }

    fn signed_spend(
        node: &BitcoinNodeHandle,
        input: OutPoint,
        output: Vec<TxOut>,
    ) -> Result<Transaction> {
        let unsigned = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output,
        };
        let signed: Value = node.rpc_client().call(
            "signrawtransactionwithwallet",
            &[json!(serialize_hex(&unsigned))],
        )?;
        anyhow::ensure!(
            signed["complete"] == true,
            "Incomplete wallet signature: {signed}"
        );
        Ok(deserialize_hex(signed["hex"].as_str().ok_or_else(
            || anyhow!("Missing signed transaction hex: {signed}"),
        )?)?)
    }

    fn confirmed_coins(node: &BitcoinNodeHandle) -> Result<Vec<(OutPoint, Amount)>> {
        let coins: Vec<Value> = node.rpc_client().call("listunspent", &[json!(1)])?;
        coins
            .into_iter()
            .map(|coin| {
                Ok((
                    OutPoint {
                        txid: serde_json::from_value(coin["txid"].clone())?,
                        vout: serde_json::from_value(coin["vout"].clone())?,
                    },
                    Amount::from_btc(
                        coin["amount"]
                            .as_f64()
                            .ok_or_else(|| anyhow!("Missing coin amount: {coin}"))?,
                    )?,
                ))
            })
            .collect()
    }

    fn mempool(node: &BitcoinNodeHandle) -> Result<Vec<Txid>> {
        Ok(node.rpc_client().call("getrawmempool", &[])?)
    }

    fn broadcast(node: &BitcoinNodeHandle, tx: &Transaction) -> Result<()> {
        let _: Txid = node
            .rpc_client()
            .call("sendrawtransaction", &[json!(serialize_hex(tx))])?;
        Ok(())
    }

    pub(crate) fn fill_mempool_until_evicted(
        node: &BitcoinNodeHandle,
        txids: &[Txid],
    ) -> Result<()> {
        // Independent confirmed inputs avoid ancestor limits and CPFP effects.
        // Each large transaction pays about 10 sat/vB.
        let script = wallet_script(node)?;
        let data = bitcoin::script::PushBytesBuf::try_from(vec![0; 80_000])?;
        let data_script = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(data)
            .into_script();
        for (input, amount) in confirmed_coins(node)? {
            let filler = signed_spend(
                node,
                input,
                vec![
                    TxOut {
                        value: amount - Amount::from_sat(810_000),
                        script_pubkey: script.clone(),
                    },
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: data_script.clone(),
                    },
                ],
            )?;
            // Equal-feerate fillers tie for eviction, so Core may trim the one
            // just submitted. That still raises the floor; check the pool below.
            if let Err(error) = broadcast(node, &filler)
                && !error.to_string().contains("mempool full")
            {
                return Err(error);
            }
            let pool = mempool(node)?;
            let info: Value = node.rpc_client().call("getmempoolinfo", &[])?;
            let floor = info["mempoolminfee"]
                .as_f64()
                .ok_or_else(|| anyhow!("Missing mempool floor: {info}"))?;
            let relay_floor = info["minrelaytxfee"]
                .as_f64()
                .ok_or_else(|| anyhow!("Missing relay floor: {info}"))?;
            if txids.iter().all(|txid| !pool.contains(txid)) && floor > relay_floor {
                return Ok(());
            }
        }
        anyhow::bail!(
            "Exhausted confirmed coins before eviction and dynamic mempool floor increase"
        )
    }

    fn monitor_config(node: &BitcoinNodeHandle) -> MonitorConfig {
        MonitorConfig::builder()
            .network(bitcoin::Network::Regtest)
            .trusted_peers(vec![TrustedPeer::from_hostname(
                "127.0.0.1",
                node.p2p_port(),
            )])
            .start_height(210)
            .bitcoind_rpc_config(
                node.rpc_url().to_owned(),
                Auth::UserPass(RPC_USER.to_owned(), RPC_PASSWORD.to_owned()),
            )
            .build()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_monitor_broadcast_package_recovers_evicted_parent() -> Result<()> {
        crate::test_helpers::init_test_logging();
        let dir = tempfile::tempdir()?;
        let node = BitcoinNodeBuilder::new()
            .dir(dir.path())
            .with_initial_blocks(210)
            .with_extra_args(["-maxmempool=5", "-datacarriersize=100000"])
            .build()
            .await?;
        let mut coins = confirmed_coins(&node)?.into_iter();
        let (input, amount) = coins.next().ok_or_else(|| anyhow!("No mature coinbase"))?;
        let script = wallet_script(&node)?;
        let parent = signed_spend(
            &node,
            input,
            vec![TxOut {
                value: amount - Amount::from_sat(200),
                script_pubkey: script.clone(),
            }],
        )?;
        broadcast(&node, &parent)?;
        let child = signed_spend(
            &node,
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            vec![TxOut {
                value: parent.output[0].value - Amount::from_sat(10_000),
                script_pubkey: script.clone(),
            }],
        )?;
        assert!(mempool(&node)?.contains(&parent.compute_txid()));

        fill_mempool_until_evicted(&node, &[parent.compute_txid()])?;
        assert!(
            !mempool(&node)?.contains(&parent.compute_txid()),
            "The low-fee parent must actually be evicted"
        );
        let info: Value = node.rpc_client().call("getmempoolinfo", &[])?;
        let floor_sat_vb = info["mempoolminfee"]
            .as_f64()
            .ok_or_else(|| anyhow!("Missing mempool floor: {info}"))?
            * 100_000.0;
        assert!(floor_sat_vb > 200.0 / parent.vsize() as f64);
        assert!(10_200.0 / (parent.vsize() + child.vsize()) as f64 > floor_sat_vb);

        let (monitor, _service) = Monitor::run(
            monitor_config(&node),
            Arc::new(hashi::metrics::Metrics::new_default()),
        )?;
        // submitpackage can return an RPC success envelope containing rejection.
        // The monitor must propagate that rejection, not report success.
        assert!(
            monitor
                .broadcast_package(vec![child.clone()])
                .await
                .is_err()
        );
        let pool = mempool(&node)?;
        assert!(!pool.contains(&child.compute_txid()));
        assert!(!pool.contains(&parent.compute_txid()));

        monitor
            .broadcast_package(vec![parent.clone(), child.clone()])
            .await?;
        let pool = mempool(&node)?;
        assert!(pool.contains(&parent.compute_txid()));
        assert!(pool.contains(&child.compute_txid()));

        // Already-in-mempool results are idempotent success.
        monitor
            .broadcast_package(vec![parent.clone(), child.clone()])
            .await?;
        let pool = mempool(&node)?;
        assert!(pool.contains(&parent.compute_txid()));
        assert!(pool.contains(&child.compute_txid()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_monitor_broadcast_package_with_confirmed_parent() -> Result<()> {
        crate::test_helpers::init_test_logging();
        let dir = tempfile::tempdir()?;
        let node = BitcoinNodeBuilder::new()
            .dir(dir.path())
            .with_initial_blocks(210)
            .build()
            .await?;
        let (input, amount) = confirmed_coins(&node)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No mature coinbase"))?;
        let script = wallet_script(&node)?;
        let parent = signed_spend(
            &node,
            input,
            vec![TxOut {
                value: amount - Amount::from_sat(200),
                script_pubkey: script.clone(),
            }],
        )?;
        broadcast(&node, &parent)?;
        node.generate_blocks(1)?;
        let parent_info: Value = node.rpc_client().call(
            "getrawtransaction",
            &[json!(parent.compute_txid()), json!(true)],
        )?;
        assert!(parent_info["confirmations"].as_u64().unwrap_or(0) > 0);
        assert!(!mempool(&node)?.contains(&parent.compute_txid()));
        let child = signed_spend(
            &node,
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            vec![TxOut {
                value: parent.output[0].value - Amount::from_sat(10_000),
                script_pubkey: script,
            }],
        )?;
        assert!(!mempool(&node)?.contains(&child.compute_txid()));
        let (monitor, _service) = Monitor::run(
            monitor_config(&node),
            Arc::new(hashi::metrics::Metrics::new_default()),
        )?;
        monitor.broadcast_package(vec![child.clone()]).await?;
        let pool = mempool(&node)?;
        assert!(pool.contains(&child.compute_txid()));
        assert!(!pool.contains(&parent.compute_txid()));
        Ok(())
    }
}
