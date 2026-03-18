use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bitcoincore_rpc::RpcApi;
use kyoto::FeeRate;
use kyoto::HeaderCheckpoint;
use kyoto::Warning;
use kyoto::builder::NodeDefault;
use sui_futures::service::Service;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::config::MonitorConfig;
use crate::metrics::Metrics;

/// 1 sat/vB expressed as sat/kwu.
const FALLBACK_FEE_RATE_SAT_PER_KWU: u64 = 250;

/// Number of consecutive connection failures before restarting Kyoto.
const KYOTO_MAX_CONSECUTIVE_FAILURES: u32 = 30;

/// Delay before restarting Kyoto after connectivity loss.
const KYOTO_RESTART_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Confirmed { confirmations: u32 },
    InMempool,
    NotFound,
}

enum KyotoEventLoopExit {
    ConnectivityLost,
    Shutdown,
}

/// Monitor loop that tracks the state of the Bitcoin chain.
///
/// Client provides functions for querying for specific transactions,
/// fee information, and transaction submission.
pub struct Monitor {
    config: MonitorConfig,
    metrics: Arc<Metrics>,
    bitcoind_rpc: Arc<bitcoincore_rpc::Client>,
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    requester: kyoto::Requester,
    tip: Option<HeaderCheckpoint>,
    pending_deposits: Vec<PendingDeposit>,
    pending_deposit_workers: JoinSet<()>,
}

impl Monitor {
    fn build_kyoto_node(config: &MonitorConfig) -> Result<(NodeDefault, kyoto::Client)> {
        let mut node_builder = kyoto::NodeBuilder::new(config.network)
            .add_peers(config.trusted_peers.iter().cloned())
            // Prevent Kyoto from storing additional peers via GetAddr.
            .peer_db_size(kyoto::PeerStoreSizeConfig::Limit(0))
            // TODO: should we set this higher than default?
            // .required_peers(num_peers)
            // Need a dummy script to prevent default match on every single block.
            // TODO: Remove once commit
            // https://github.com/rust-bitcoin/rust-bitcoin/commit/e7d992a5ff75807ec454655d112a671294a101dd
            // is available in a released version of the bitcoin crate.
            .add_scripts(vec![bitcoin::ScriptBuf::new()])
            .after_checkpoint(kyoto::HeaderCheckpoint::closest_checkpoint_below_height(
                config.start_height,
                config.network,
            ));
        if let Some(data_dir) = &config.data_dir {
            node_builder = node_builder.data_dir(data_dir.clone());
        }
        Ok(node_builder.build()?)
    }

    /// Run a BTC monitor with the given configuration.
    /// Returns the client for interacting with the monitor and a Service for lifecycle management.
    pub fn run(config: MonitorConfig, metrics: Arc<Metrics>) -> Result<(MonitorClient, Service)> {
        let bitcoind_rpc = bitcoincore_rpc::Client::new(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);

        let service = Service::new().spawn_aborting({
            let client_tx = client_tx.clone();
            async move {
                let bitcoind_rpc = Arc::new(bitcoind_rpc);

                // Build initial Kyoto node.
                let (kyoto_node, kyoto_client) = Self::build_kyoto_node(&config)?;

                let mut monitor = Monitor {
                    config,
                    metrics,
                    bitcoind_rpc,
                    requester: kyoto_client.requester.clone(),
                    client_tx,
                    tip: None,
                    pending_deposits: vec![],
                    pending_deposit_workers: JoinSet::new(),
                };

                monitor
                    .run_with_supervision(kyoto_node, kyoto_client, &mut client_rx)
                    .await
            }
        });

        Ok((MonitorClient { tx: client_tx }, service))
    }

    /// Run the monitor with automatic Kyoto restart on connectivity loss.
    async fn run_with_supervision(
        &mut self,
        kyoto_node: NodeDefault,
        kyoto_client: kyoto::Client,
        client_rx: &mut tokio::sync::mpsc::Receiver<MonitorMessage>,
    ) -> Result<()> {
        let mut current_node = kyoto_node;
        let mut current_client = kyoto_client;

        loop {
            info!(
                "Starting Bitcoin monitor for network: {:?}",
                self.config.network
            );

            // Spawn the Kyoto node as a background task. Node::run() takes
            // ownership, so we move it in and get a JoinHandle back.
            let kyoto_handle = tokio::spawn(async move { current_node.run().await });

            let result = self.run_event_loop(&mut current_client, client_rx).await;

            // Abort the Kyoto node task regardless of exit reason.
            kyoto_handle.abort();

            match result {
                KyotoEventLoopExit::ConnectivityLost => {
                    warn!(
                        "Lost connectivity to Bitcoin peers after {KYOTO_MAX_CONSECUTIVE_FAILURES} \
                         consecutive failures. Restarting Kyoto node..."
                    );

                    self.metrics.kyoto_restarts.inc();
                    self.metrics.kyoto_connected_peers.set(0);
                    self.metrics.kyoto_synced.set(0);
                    self.metrics.kyoto_consecutive_failures.set(0);

                    // Wait before restarting to avoid tight restart loops.
                    tokio::time::sleep(KYOTO_RESTART_DELAY).await;

                    // Build a fresh Kyoto node with the trusted peers re-added
                    // to the whitelist.
                    let (new_node, new_client) = Self::build_kyoto_node(&self.config)?;
                    current_node = new_node;
                    current_client = new_client;
                    self.requester = current_client.requester.clone();

                    info!("Kyoto node rebuilt, resuming monitor");
                }
                KyotoEventLoopExit::Shutdown => {
                    info!("Bitcoin monitor stopped");
                    return Ok(());
                }
            }
        }
    }

    /// Map a Kyoto `Warning` variant to a short label for metrics.
    fn warning_label(warning: &Warning) -> &'static str {
        match warning {
            Warning::NeedConnections { .. } => "need_connections",
            Warning::PeerTimedOut => "peer_timed_out",
            Warning::CouldNotConnect => "could_not_connect",
            Warning::NoCompactFilters => "no_compact_filters",
            Warning::PotentialStaleTip => "potential_stale_tip",
            Warning::UnsolicitedMessage => "unsolicited_message",
            Warning::InvalidStartHeight => "invalid_start_height",
            Warning::CorruptedHeaders => "corrupted_headers",
            Warning::TransactionRejected { .. } => "transaction_rejected",
            Warning::FailedPersistence { .. } => "failed_persistence",
            Warning::EvaluatingFork => "evaluating_fork",
            Warning::EmptyPeerDatabase => "empty_peer_database",
            Warning::UnexpectedSyncError { .. } => "unexpected_sync_error",
            Warning::ChannelDropped => "channel_dropped",
        }
    }

    /// Run the main event loop, returning the reason it exited.
    async fn run_event_loop(
        &mut self,
        kyoto_client: &mut kyoto::Client,
        client_rx: &mut tokio::sync::mpsc::Receiver<MonitorMessage>,
    ) -> KyotoEventLoopExit {
        let mut consecutive_failures: u32 = 0;
        let mut required_peers: usize = 0;

        loop {
            tokio::select! {
                Some(event) = kyoto_client.event_rx.recv() => {
                    self.process_kyoto_event(event);
                }
                Some(msg) = client_rx.recv() => {
                    self.process_client_message(msg);
                }
                Some(msg) = kyoto_client.log_rx.recv() => {
                    debug!("Kyoto log: {msg}");
                }
                Some(msg) = kyoto_client.info_rx.recv() => {
                    info!("Kyoto: {msg}");
                    // Reset failure counter on any info message (successful
                    // activity like syncing, handshakes, etc).
                    consecutive_failures = 0;
                    self.metrics.kyoto_consecutive_failures.set(0);

                    // Parse info messages for metrics where possible.
                    Self::update_info_metrics(&self.metrics, &msg, required_peers);
                }
                Some(warning) = kyoto_client.warn_rx.recv() => {
                    warn!("Kyoto: {warning}");
                    self.metrics.kyoto_warnings.with_label_values(&[Self::warning_label(&warning)]).inc();

                    // Track connected peer count from NeedConnections
                    if let Warning::NeedConnections { connected, required } = &warning {
                        self.metrics.kyoto_connected_peers.set(*connected as i64);
                        required_peers = *required;
                    }

                    let is_connectivity_failure = matches!(
                        warning,
                        Warning::CouldNotConnect
                        | Warning::PeerTimedOut
                        | Warning::NeedConnections { connected: 0, .. }
                    );
                    if is_connectivity_failure {
                        consecutive_failures += 1;
                        self.metrics.kyoto_consecutive_failures.set(consecutive_failures as i64);
                        if consecutive_failures >= KYOTO_MAX_CONSECUTIVE_FAILURES {
                            return KyotoEventLoopExit::ConnectivityLost;
                        }
                    }
                }
                Some(join_result) = self.pending_deposit_workers.join_next(), if !self.pending_deposit_workers.is_empty() => {
                    if let Err(e) = join_result {
                        error!("Pending deposit worker task failed: {e}");
                    }
                }
                else => {
                    return KyotoEventLoopExit::Shutdown;
                }
            }
        }
    }

    /// Extract metrics from Kyoto info messages.
    fn update_info_metrics(metrics: &Metrics, msg: &kyoto::Info, required_peers: usize) {
        match msg {
            kyoto::Info::ConnectionsMet => {
                metrics.kyoto_connected_peers.set(required_peers as i64);
            }
            kyoto::Info::Progress(progress) => {
                metrics
                    .kyoto_sync_percent
                    .set(progress.percentage_complete() as i64);
            }
            kyoto::Info::NewChainHeight(height) => {
                metrics.kyoto_best_height.set(*height as i64);
            }
            _ => {}
        }
    }

    fn process_kyoto_event(&mut self, event: kyoto::Event) {
        match event {
            kyoto::Event::Block(block) => self.process_block(block),
            kyoto::Event::Synced(sync_update) => self.process_synced(sync_update),
            kyoto::Event::BlocksDisconnected {
                accepted,
                disconnected,
            } => self.process_blocks_disconnected(accepted, disconnected),
        }
    }

    fn process_block(&mut self, block: kyoto::IndexedBlock) {
        info!(
            "Got block {} at height {} with {} transactions",
            block.block.block_hash(),
            block.height,
            block.block.txdata.len()
        );
        self.metrics.kyoto_blocks_received.inc();
        self.metrics.kyoto_best_height.set(block.height as i64);
    }

    fn process_synced(&mut self, sync_update: kyoto::messages::SyncUpdate) {
        let tip = sync_update.tip;
        info!(
            "Synchronized to height {} ({}) with {} recent headers",
            tip.height,
            tip.hash,
            sync_update.recent_history.len()
        );
        self.metrics.kyoto_synced.set(1);
        self.metrics.kyoto_best_height.set(tip.height as i64);
        self.metrics.kyoto_sync_percent.set(100);
        self.tip = Some(tip);
        self.process_pending_deposits();
    }

    fn process_blocks_disconnected(
        &mut self,
        accepted: Vec<kyoto::chain::IndexedHeader>,
        disconnected: Vec<kyoto::chain::IndexedHeader>,
    ) {
        info!(
            "Got reorg with {} accepted blocks and {} disconnected blocks",
            accepted.len(),
            disconnected.len()
        );
        self.metrics.kyoto_reorgs.inc();
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::ConfirmDeposit(pending_deposit) => {
                self.confirm_deposit(pending_deposit);
            }
            MonitorMessage::GetRecentFeeRate(conf_target, result_tx) => {
                self.get_recent_fee_rate(conf_target, result_tx);
            }
            MonitorMessage::BroadcastTransaction(tx, result_tx) => {
                self.broadcast_transaction(tx, result_tx);
            }
            MonitorMessage::GetTransactionStatus(txid, result_tx) => {
                self.get_transaction_status(txid, result_tx);
            }
        }
    }

    fn confirm_deposit(&mut self, pending_deposit: PendingDeposit) {
        debug!(
            "Processing deposit confirmation for {}",
            pending_deposit.outpoint.txid
        );

        let Some(tip) = &self.tip else {
            debug!(
                "Transaction {} confirmation on hold, pending chain tip update.",
                pending_deposit.outpoint.txid
            );
            self.pending_deposits.push(pending_deposit);
            return;
        };

        if pending_deposit.checked_at_height >= tip.height {
            debug!(
                "Transaction {} already checked at height {}. Waiting for more blocks.",
                pending_deposit.outpoint.txid, pending_deposit.checked_at_height
            );
            self.pending_deposits.push(pending_deposit);
            return;
        }

        self.pending_deposit_workers
            .spawn(Monitor::process_pending_deposit(
                tip.to_owned(),
                self.config.confirmation_threshold,
                self.bitcoind_rpc.clone(),
                self.requester.clone(),
                self.client_tx.clone(),
                pending_deposit,
            ));
    }

    fn get_recent_fee_rate(
        &mut self,
        conf_target: u16,
        result_tx: oneshot::Sender<Result<FeeRate>>,
    ) {
        let result = self
            .bitcoind_rpc
            .estimate_smart_fee(conf_target, None)
            .map_err(anyhow::Error::from)
            .map(|res| {
                let sat_per_kwu = match res.fee_rate {
                    Some(amount) => {
                        // Convert from BTC/kvB to sat/kwu (1 kvB = 4 kwu).
                        amount.to_sat() / 4
                    }
                    None => {
                        warn!(
                            conf_target,
                            fallback_sat_per_kwu = FALLBACK_FEE_RATE_SAT_PER_KWU,
                            "Node could not estimate fee rate; falling back to minimum relay fee"
                        );
                        FALLBACK_FEE_RATE_SAT_PER_KWU
                    }
                };
                self.metrics
                    .btc_fee_rate_sat_per_kvb
                    .set((sat_per_kwu * 4) as i64);
                FeeRate::from_sat_per_kwu(sat_per_kwu)
            });
        let _ = result_tx.send(result);
    }

    fn broadcast_transaction(
        &mut self,
        tx: bitcoin::Transaction,
        result_tx: oneshot::Sender<Result<()>>,
    ) {
        // Temp hack to get warning messages when a transaction would be rejected
        // TODO: https://linear.app/mysten-labs/issue/IOP-216/better-error-reporting-for-failed-btc-broadcasts
        let txid = tx.compute_txid();
        match self.bitcoind_rpc.test_mempool_accept(&[&tx]) {
            Ok(results) => match results.first() {
                Some(result) if !result.allowed => {
                    error!(
                        "Bitcoin Core mempool will reject tx {txid}: {}",
                        result.reject_reason.as_deref().unwrap_or("unknown reason")
                    );
                }
                Some(_) => {
                    debug!("Bitcoin Core mempool would accept tx {txid}");
                }
                None => {
                    warn!("Bitcoin Core testmempoolaccept returned no result for tx {txid}");
                }
            },
            Err(e) => {
                warn!("Failed to run testmempoolaccept for tx {txid}: {e}");
            }
        }

        let result = self.requester.broadcast_tx(kyoto::TxBroadcast {
            tx,
            broadcast_policy: kyoto::TxBroadcastPolicy::AllPeers,
        });
        let _ = result_tx.send(result.map_err(|e| anyhow::anyhow!(e)));
    }

    fn get_transaction_status(
        &self,
        txid: bitcoin::Txid,
        result_tx: oneshot::Sender<Result<TxStatus>>,
    ) {
        let result = match self.bitcoind_rpc.get_raw_transaction_info(&txid, None) {
            Ok(tx_info) => {
                if tx_info.blockhash.is_some() {
                    let confirmations = tx_info.confirmations.unwrap_or(0);
                    Ok(TxStatus::Confirmed { confirmations })
                } else {
                    Ok(TxStatus::InMempool)
                }
            }
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                ref e,
            ))) if e.code == -5 => {
                // RPC error -5: "No such mempool or blockchain transaction"
                Ok(TxStatus::NotFound)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to query transaction status: {e}")),
        };
        let _ = result_tx.send(result);
    }

    fn process_pending_deposits(&mut self) {
        let Some(tip) = &self.tip else {
            // Can't confirm deposits if we don't yet know the tip of the chain.
            return;
        };
        if self.pending_deposits.is_empty() {
            return;
        }

        info!(
            "Processing {} pending deposits",
            self.pending_deposits.len()
        );
        for pending_deposit in std::mem::take(&mut self.pending_deposits) {
            self.pending_deposit_workers
                .spawn(Monitor::process_pending_deposit(
                    tip.to_owned(),
                    self.config.confirmation_threshold,
                    self.bitcoind_rpc.clone(),
                    self.requester.clone(),
                    self.client_tx.clone(),
                    pending_deposit,
                ));
        }
    }

    async fn process_pending_deposit(
        tip: HeaderCheckpoint,
        confirmation_threshold: u32,
        bitcoind_rpc: Arc<bitcoincore_rpc::Client>,
        requester: kyoto::Requester,
        client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
        mut pending_deposit: PendingDeposit,
    ) {
        if pending_deposit.result_tx.is_closed() {
            // Cancel if the receiver is no longer listening.
            return;
        }

        pending_deposit.checked_at_height = tip.height;
        let mut pending_deposit = PendingDepositGuard::new(pending_deposit, client_tx);

        // Look up block from the txid.
        let block_info = match pending_deposit.block_info {
            Some(block_info) => block_info,
            None => {
                debug!(
                    "Looking up block for transaction {}",
                    pending_deposit.outpoint.txid
                );
                let tx_info = match bitcoind_rpc
                    .get_raw_transaction_info(&pending_deposit.outpoint.txid, None)
                {
                    Ok(tx_info) => tx_info,
                    Err(e) => {
                        error!(
                            "Failed to look up txid {}: {e}",
                            pending_deposit.outpoint.txid
                        );
                        return;
                    }
                };
                let Some(block_hash) = tx_info.blockhash else {
                    debug!(
                        "Transaction {} is not yet included in a block",
                        pending_deposit.outpoint.txid
                    );
                    return;
                };
                let block_header = match bitcoind_rpc.get_block_header_info(&block_hash) {
                    Ok(block_header) => block_header,
                    Err(e) => {
                        error!("Failed to look up block header {}: {e}", block_hash);
                        return;
                    }
                };
                // Double check header with Kyoto to verify the height reported by bitcoind.
                let kyoto_header = match requester.get_header(block_header.height as u32).await {
                    Ok(kyoto_header) => kyoto_header,
                    Err(e) => {
                        error!(
                            "Failed to look up header at height {}: {e}",
                            block_header.height
                        );
                        return;
                    }
                };
                if kyoto_header.block_hash() != block_hash {
                    warn!(
                        "Block hash mismatch at height {}! Possibly malicious behavior by the Bitcoin Core node. {} != {}",
                        block_header.height,
                        kyoto_header.block_hash(),
                        block_hash
                    );
                    return;
                }
                let block_info = kyoto::HeaderCheckpoint {
                    height: block_header.height as u32,
                    hash: block_header.hash,
                };
                pending_deposit.block_info = Some(block_info);
                block_info
            }
        };

        // Check if the deposit has enough confirmations yet.
        if block_info.height > tip.height - confirmation_threshold - 1 {
            debug!(
                "Transaction {} is not yet confirmed. Block height is {}, tip is {}. Waiting for more blocks.",
                pending_deposit.outpoint.txid, block_info.height, tip.height
            );
            return;
        }

        // If deposit is confirmed, look up the TxOut info.
        let block = match requester.get_block(block_info.hash).await {
            Ok(block) => block,
            Err(kyoto::error::FetchBlockError::UnknownHash) => {
                // Error: The block is no longer in the current chain.
                // TODO: Verify kyoto won't return blocks outside the chain of most work
                warn!(
                    "Pending deposit {:?}: Block is no longer in the current chain",
                    pending_deposit.as_ref(),
                );
                pending_deposit.block_info = None;
                return;
            }
            Err(e) => {
                error!("Failed to look up block {}: {}", block_info.hash, e);
                return;
            }
        };
        let Some(transaction) = block
            .block
            .txdata
            .iter()
            .find(|tx| tx.compute_txid() == pending_deposit.outpoint.txid)
        else {
            // Error: The transaction is not actually in the block.
            warn!(
                "Pending deposit {:?}: Transaction not present in the block reported by the Bitcoin Core node! Possibly malicious behavior by the Bitcoin Core node.",
                pending_deposit.as_ref(),
            );
            pending_deposit.block_info = None;
            return;
        };

        let result = transaction.tx_out(pending_deposit.outpoint.vout.try_into().unwrap());
        let pending_deposit = pending_deposit.take();
        let _ = pending_deposit
            .result_tx
            .send(result.cloned().map_err(|e| e.into()));
    }
}

#[derive(Debug)]
struct PendingDeposit {
    outpoint: bitcoin::OutPoint,
    block_info: Option<kyoto::HeaderCheckpoint>,
    result_tx: oneshot::Sender<Result<bitcoin::TxOut>>,
    checked_at_height: u32,
}

/// RAII guard that re-enqueues a pending deposit on drop unless marked as complete.
struct PendingDepositGuard {
    deposit: Option<PendingDeposit>,
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl PendingDepositGuard {
    fn new(deposit: PendingDeposit, client_tx: tokio::sync::mpsc::Sender<MonitorMessage>) -> Self {
        Self {
            deposit: Some(deposit),
            client_tx,
        }
    }

    fn take(mut self) -> PendingDeposit {
        self.deposit.take().unwrap()
    }
}

impl std::ops::Deref for PendingDepositGuard {
    type Target = PendingDeposit;

    fn deref(&self) -> &Self::Target {
        self.deposit.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PendingDepositGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.deposit.as_mut().unwrap()
    }
}

impl AsRef<PendingDeposit> for PendingDepositGuard {
    fn as_ref(&self) -> &PendingDeposit {
        self.deposit.as_ref().unwrap()
    }
}

impl Drop for PendingDepositGuard {
    fn drop(&mut self) {
        if let Some(deposit) = self.deposit.take()
            && let Err(e) = self
                .client_tx
                .try_send(MonitorMessage::ConfirmDeposit(deposit))
        {
            warn!("Failed to re-enqueue PendingDeposit on drop: {e}");
        }
    }
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl MonitorClient {
    pub async fn confirm_deposit(&self, outpoint: bitcoin::OutPoint) -> Result<bitcoin::TxOut> {
        let (tx, rx) = oneshot::channel();
        let pending_deposit = PendingDeposit {
            outpoint,
            block_info: None,
            result_tx: tx,
            checked_at_height: 0,
        };
        self.tx
            .send(MonitorMessage::ConfirmDeposit(pending_deposit))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| {
                anyhow::anyhow!("confirm_deposit timed out waiting for Bitcoin confirmation")
            })?
            .map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn get_recent_fee_rate(&self, conf_target: u16) -> Result<FeeRate> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::GetRecentFeeRate(conf_target, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn broadcast_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::BroadcastTransaction(transaction, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn get_transaction_status(&self, txid: bitcoin::Txid) -> Result<TxStatus> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::GetTransactionStatus(txid, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }
}

enum MonitorMessage {
    // Locates the given OutPoint in a block, waits for it to have enough
    // confirmations, and returns output information. Will keep trying to
    // confirm indefinitely, unless the proivded channel is closed.
    ConfirmDeposit(PendingDeposit),

    // Returns an estimated fee rate targeting confirmation within `conf_target` blocks.
    GetRecentFeeRate(u16, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),

    // Query the status of a transaction (confirmed, in mempool, or not found).
    GetTransactionStatus(bitcoin::Txid, oneshot::Sender<Result<TxStatus>>),
}
