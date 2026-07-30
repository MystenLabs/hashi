// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use kyoto::FeeRate;
use kyoto::HashCheckpoint;
use kyoto::Warning;
use lru::LruCache;
use rand::Rng;
use sui_futures::service::Service;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::config::MonitorConfig;
use crate::deposit_tracker::DepositDiscovery;
use crate::deposit_tracker::DepositStatus;
use crate::deposit_tracker::DepositTracker;
use crate::deposit_tracker::DiscoveryFinish;
use crate::metrics::Metrics;

/// 1 sat/vB expressed as sat/kwu.
const FALLBACK_FEE_RATE_SAT_PER_KWU: u64 = 250;

/// Number of consecutive connection failures before restarting Kyoto.
const KYOTO_MAX_CONSECUTIVE_FAILURES: u32 = 15;

/// Base delay before restarting Kyoto after connectivity loss.
const KYOTO_RESTART_DELAY_BASE: Duration = Duration::from_secs(5);

/// Random additional delay to spread reconnects across pods.
const KYOTO_MAX_RESTART_DELAY_JITTER: Duration = Duration::from_secs(30);

/// Kyoto's block request has no internal deadline.
const BLOCK_SCAN_TIMEOUT: Duration = Duration::from_secs(30);

fn next_restart_delay() -> Duration {
    let jitter = Duration::from_millis(
        rand::thread_rng().gen_range(0..=KYOTO_MAX_RESTART_DELAY_JITTER.as_millis() as u64),
    );
    KYOTO_RESTART_DELAY_BASE + jitter
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Confirmed { confirmations: u32 },
    InMempool,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositConfirmation {
    Confirmed(bitcoin::TxOut),
    NotFound,
    InMempool,
    InsufficientConfirmations { confirmations: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum DepositConfirmError {
    #[error("UTXO {txid}:{vout} has already been spent on Bitcoin")]
    UtxoSpent { txid: bitcoin::Txid, vout: u32 },
    #[error("transaction {txid} has no output at vout {vout}")]
    InvalidVout { txid: bitcoin::Txid, vout: u32 },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
struct DepositCheckRequest {
    outpoint: bitcoin::OutPoint,
    confirmation_threshold: u32,
    result_tx: oneshot::Sender<Result<DepositConfirmation, DepositConfirmError>>,
}

struct DepositLookupCache {
    tx_blocks: LruCache<bitcoin::Txid, HashCheckpoint>,
    block_heights: LruCache<bitcoin::BlockHash, u32>,
    transactions: LruCache<bitcoin::Txid, Arc<bitcoin::Transaction>>,
}

impl DepositLookupCache {
    /// Sizes for the shared deposit lookup caches. These caches collapse repeated
    /// per-output lookups for large deposit transactions while keeping memory bounded.
    const TX_BLOCK_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
    const BLOCK_HEIGHT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();
    const TRANSACTION_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

    fn new() -> Self {
        Self {
            tx_blocks: LruCache::new(Self::TX_BLOCK_CACHE_SIZE),
            block_heights: LruCache::new(Self::BLOCK_HEIGHT_CACHE_SIZE),
            transactions: LruCache::new(Self::TRANSACTION_CACHE_SIZE),
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.tx_blocks.clear();
        self.block_heights.clear();
        self.transactions.clear();
    }

    fn invalidate_tx(&mut self, txid: &bitcoin::Txid) {
        self.tx_blocks.pop(txid);
        self.transactions.pop(txid);
    }
}

#[derive(Clone)]
struct SharedDepositLookupCache {
    inner: Arc<Mutex<DepositLookupCache>>,
    metrics: Arc<Metrics>,
}

impl SharedDepositLookupCache {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DepositLookupCache::new())),
            metrics,
        }
    }

    fn fresh(&self) -> Self {
        Self::new(self.metrics.clone())
    }

    #[cfg(test)]
    fn clear(&self) {
        self.lock().clear();
    }

    fn get_tx_block(&self, txid: &bitcoin::Txid) -> Option<HashCheckpoint> {
        let result = self.lock().tx_blocks.get(txid).copied();
        self.record_request("tx_block", result.is_some());
        result
    }

    fn put_tx_block(&self, txid: bitcoin::Txid, block_info: HashCheckpoint) {
        self.lock().tx_blocks.put(txid, block_info);
    }

    fn get_block_height(&self, block_hash: &bitcoin::BlockHash) -> Option<u32> {
        let result = self.lock().block_heights.get(block_hash).copied();
        self.record_request("block_height", result.is_some());
        result
    }

    fn put_block_height(&self, block_hash: bitcoin::BlockHash, height: u32) {
        self.lock().block_heights.put(block_hash, height);
    }

    fn get_transaction(&self, txid: &bitcoin::Txid) -> Option<Arc<bitcoin::Transaction>> {
        let result = self.lock().transactions.get(txid).cloned();
        self.record_request("transaction", result.is_some());
        result
    }

    fn put_transaction(&self, txid: bitcoin::Txid, transaction: Arc<bitcoin::Transaction>) {
        self.lock().transactions.put(txid, transaction);
    }

    fn invalidate_tx(&self, txid: &bitcoin::Txid) {
        self.lock().invalidate_tx(txid);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DepositLookupCache> {
        self.inner
            .lock()
            .expect("deposit lookup cache lock poisoned")
    }

    fn record_request(&self, cache: &'static str, hit: bool) {
        let result = if hit { "hit" } else { "miss" };
        self.metrics
            .deposit_lookup_cache_requests_total
            .with_label_values(&[cache, result])
            .inc();
    }
}

struct BlockScanResult {
    checkpoint: HashCheckpoint,
    generation: u64,
    result: Result<bitcoin::Block>,
}

struct DepositCheckWorkerResult {
    generation: u64,
    result_tx: oneshot::Sender<Result<DepositConfirmation, DepositConfirmError>>,
    result: Result<DepositConfirmation, DepositConfirmError>,
}

struct DepositCheckContext {
    tip: HashCheckpoint,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    deposit_tracker: Arc<DepositTracker>,
    generation: u64,
}

enum KyotoEventLoopExit {
    BlockScanFailed,
    ConnectivityLost,
    KyotoNodeExited,
    Shutdown,
}

/// Monitor loop that tracks the state of the Bitcoin chain.
///
/// Client provides functions for querying for specific transactions,
/// fee information, and transaction submission.
pub struct Monitor {
    config: MonitorConfig,
    metrics: Arc<Metrics>,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    tip: Option<HashCheckpoint>,
    start_checkpoint: HashCheckpoint,
    /// Set once Kyoto's initial filter sync completes; gates per-block side
    /// effects so the catch-up replay doesn't run them per header.
    synced: bool,
    block_height_tx: tokio::sync::watch::Sender<u32>,
    requester: kyoto::Requester,
    deposit_check_workers: JoinSet<DepositCheckWorkerResult>,
    block_scan_workers: JoinSet<BlockScanResult>,
    block_scan_queue: VecDeque<HashCheckpoint>,
    deposit_lookup_cache: SharedDepositLookupCache,
    deposit_tracker: Arc<DepositTracker>,
    rpc_workers: JoinSet<()>,
}

/// Offload a blocking Bitcoin Core RPC call to the tokio blocking thread pool.
async fn btc_rpc_call<F, T>(client: &Arc<corepc_client::client_sync::v29::Client>, f: F) -> T
where
    F: FnOnce(&corepc_client::client_sync::v29::Client) -> T + Send + 'static,
    T: Send + 'static,
{
    let client = Arc::clone(client);
    tokio::task::spawn_blocking(move || f(&client))
        .await
        .expect("btc_rpc_call: spawn_blocking task panicked")
}

impl Monitor {
    fn confirm_deposit(&mut self, request: DepositCheckRequest) {
        debug!("Checking deposit for {}", request.outpoint.txid);

        let Some(tip) = self.tip else {
            let _ =
                request.result_tx.send(Err(
                    anyhow::anyhow!("Bitcoin chain tip is not available").into()
                ));
            return;
        };

        let discovery = self.deposit_tracker.discovery(&request.outpoint);
        self.deposit_check_workers.spawn(process_deposit_check(
            DepositCheckContext {
                tip,
                bitcoind_rpc: self.bitcoind_rpc.clone(),
                requester: self.requester.clone(),
                deposit_lookup_cache: self.deposit_lookup_cache.clone(),
                deposit_tracker: self.deposit_tracker.clone(),
                generation: self.deposit_tracker.bitcoin_generation(),
            },
            request,
            discovery,
        ));
    }

    fn queue_block_scan(&mut self, checkpoint: HashCheckpoint) {
        if !self.deposit_tracker.has_scan_candidates() {
            return;
        }

        self.block_scan_queue.push_back(checkpoint);
        self.start_next_block_scan();
    }

    fn cancel_deposit_workers(&mut self) {
        self.deposit_check_workers.abort_all();
        self.block_scan_workers.abort_all();
        self.block_scan_queue.clear();
    }

    fn finish_deposit_check(
        &mut self,
        join_result: std::result::Result<DepositCheckWorkerResult, tokio::task::JoinError>,
    ) {
        match join_result {
            Ok(result) if result.generation == self.deposit_tracker.bitcoin_generation() => {
                let _ = result.result_tx.send(result.result);
            }
            Ok(result) => {
                let _ = result.result_tx.send(Err(anyhow::anyhow!(
                    "Bitcoin deposit check was invalidated by a chain update"
                )
                .into()));
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => {
                error!("Deposit check worker task failed: {e}");
            }
        }
    }

    fn start_next_block_scan(&mut self) {
        if !self.block_scan_workers.is_empty() {
            return;
        }

        while let Some(checkpoint) = self.block_scan_queue.pop_front() {
            if !self.deposit_tracker.has_scan_candidates() {
                continue;
            }

            let requester = self.requester.clone();
            let generation = self.deposit_tracker.bitcoin_generation();
            self.block_scan_workers.spawn(async move {
                let result = async {
                    let indexed_block = tokio::time::timeout(
                        BLOCK_SCAN_TIMEOUT,
                        requester.get_block(checkpoint.hash),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "Timed out fetching block {} at height {}",
                            checkpoint.hash,
                            checkpoint.height,
                        )
                    })??;
                    let fetched_hash = indexed_block.block.block_hash();
                    if indexed_block.height != checkpoint.height || fetched_hash != checkpoint.hash {
                        anyhow::bail!(
                            "Kyoto returned block {fetched_hash} at height {} for requested {} at height {}",
                            indexed_block.height,
                            checkpoint.hash,
                            checkpoint.height,
                        );
                    }
                    Ok(indexed_block.block)
                }
                .await;
                BlockScanResult {
                    checkpoint,
                    generation,
                    result,
                }
            });
            break;
        }
    }

    fn finish_block_scan(
        &mut self,
        join_result: std::result::Result<BlockScanResult, tokio::task::JoinError>,
    ) -> bool {
        match join_result {
            Ok(result) if result.generation != self.deposit_tracker.bitcoin_generation() => false,
            Ok(BlockScanResult {
                checkpoint,
                generation,
                result: Ok(block),
            }) => {
                self.deposit_tracker
                    .apply_block_if_current(generation, checkpoint, &block);
                false
            }
            Ok(BlockScanResult {
                checkpoint,
                result: Err(e),
                ..
            }) => {
                error!(
                    "Failed to scan Bitcoin block {} at height {}: {e}",
                    checkpoint.hash, checkpoint.height,
                );
                true
            }
            Err(e) if e.is_cancelled() => false,
            Err(e) => {
                error!("Block scan worker task failed: {e}");
                true
            }
        }
    }

    fn build_kyoto_node(
        config: &MonitorConfig,
        checkpoint: HashCheckpoint,
    ) -> (kyoto::Node, kyoto::Client) {
        let mut builder = kyoto::Builder::new(config.network)
            .add_peers(config.trusted_peers.iter().cloned())
            // Only connect to the configured trusted peers. Prevents Kyoto from
            // discovering additional peers via DNS seeding or addr gossip.
            // If all peers disconnect, the node exits with NoReachablePeers
            // and the supervision loop rebuilds it.
            .whitelist_only()
            .maximum_connection_time(Duration::MAX)
            .chain_state(kyoto::ChainState::Checkpoint(checkpoint));

        if let Some(data_dir) = &config.data_dir {
            builder = builder.data_dir(data_dir.clone());
        }

        builder.build()
    }

    /// Kyoto re-syncs from its checkpoint on every build, so anchoring at genesis
    /// replays the whole chain. Anchor non-mainnet at `start_height`; mainnet
    /// keeps the soft-fork activation anchors.
    async fn resolve_start_checkpoint(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
        config: &MonitorConfig,
    ) -> HashCheckpoint {
        match config.network {
            bitcoin::Network::Bitcoin if config.start_height > 709_631 => {
                HashCheckpoint::taproot_activation()
            }
            bitcoin::Network::Bitcoin if config.start_height > 481_823 => {
                HashCheckpoint::segwit_activation()
            }
            network => Self::checkpoint_at_height(bitcoind_rpc, config.start_height, network).await,
        }
    }

    async fn checkpoint_at_height(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
        height: u32,
        network: bitcoin::Network,
    ) -> HashCheckpoint {
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: Duration = Duration::from_secs(2);

        for attempt in 1..=MAX_ATTEMPTS {
            match btc_rpc_call(bitcoind_rpc, move |rpc| rpc.get_block_hash(height as u64)).await {
                Ok(raw) => match raw.into_model() {
                    Ok(model) => {
                        info!("Anchoring Kyoto at start height {height} ({})", model.0);
                        return HashCheckpoint::new(height, model.0);
                    }
                    Err(e) => error!("Failed to parse getblockhash({height}) response: {e}"),
                },
                // RPC error -8 "block height out of range": start_height is beyond
                // the node's tip — permanent, so anchor at genesis instead of retrying.
                Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(
                    ref e,
                ))) if e.code == -8 => {
                    warn!(
                        "Start height {height} is beyond bitcoind's tip; anchoring Kyoto at genesis"
                    );
                    return HashCheckpoint::from_genesis(network);
                }
                Err(e) => warn!(
                    "Failed to fetch block hash at start height {height} \
                     (attempt {attempt}/{MAX_ATTEMPTS}): {e}"
                ),
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }

        warn!(
            "Could not resolve a checkpoint at start height {height}; falling back to genesis. \
             Kyoto will sync the entire chain from genesis."
        );
        HashCheckpoint::from_genesis(network)
    }

    /// Run a BTC monitor with the given configuration.
    /// Returns the client for interacting with the monitor and a Service for lifecycle management.
    pub fn run(config: MonitorConfig, metrics: Arc<Metrics>) -> Result<(MonitorClient, Service)> {
        let deposit_tracker = Arc::new(DepositTracker::new(metrics.clone()));
        Self::run_with_tracker(config, metrics, deposit_tracker)
    }

    pub(crate) fn run_with_tracker(
        config: MonitorConfig,
        metrics: Arc<Metrics>,
        deposit_tracker: Arc<DepositTracker>,
    ) -> Result<(MonitorClient, Service)> {
        let bitcoind_rpc = crate::btc_monitor::config::new_rpc_client(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);
        let (block_height_tx, block_height_rx) = tokio::sync::watch::channel(0u32);

        let service = Service::new().spawn_aborting({
            async move {
                let bitcoind_rpc = Arc::new(bitcoind_rpc);

                let start_checkpoint = Self::resolve_start_checkpoint(&bitcoind_rpc, &config).await;
                let (kyoto_node, kyoto_client) = Self::build_kyoto_node(&config, start_checkpoint);
                let mut monitor = Monitor {
                    config,
                    metrics: metrics.clone(),
                    bitcoind_rpc,
                    tip: None,
                    start_checkpoint,
                    synced: false,
                    block_height_tx,
                    requester: kyoto_client.requester.clone(),
                    deposit_check_workers: JoinSet::new(),
                    block_scan_workers: JoinSet::new(),
                    block_scan_queue: VecDeque::new(),
                    deposit_lookup_cache: SharedDepositLookupCache::new(metrics),
                    deposit_tracker,
                    rpc_workers: JoinSet::new(),
                };

                monitor
                    .run_with_supervision(kyoto_node, kyoto_client, &mut client_rx)
                    .await
            }
        });

        Ok((
            MonitorClient {
                tx: client_tx,
                block_height_rx,
            },
            service,
        ))
    }

    /// Run the monitor with automatic Kyoto restart on connectivity loss.
    async fn run_with_supervision(
        &mut self,
        kyoto_node: kyoto::Node,
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

            let mut kyoto_handle = tokio::spawn(async move { current_node.run().await });

            // Race the event loop against the node task. In bip157 ≥ 0.5.0
            // hostname peers are popped on use, so a single peer drop ends
            // `Node::run()`; without this, the event loop would wait on
            // silent channels forever.
            let result = tokio::select! {
                event_loop_exit = self.run_event_loop(&mut current_client, client_rx) => event_loop_exit,
                join_result = &mut kyoto_handle => {
                    match join_result {
                        Ok(Ok(())) => warn!("Kyoto node exited cleanly; restarting"),
                        Ok(Err(e)) => warn!("Kyoto node exited with error: {e}; restarting"),
                        Err(e) if e.is_cancelled() => {
                            info!("Bitcoin monitor stopped");
                            return Ok(());
                        }
                        Err(e) => error!("Kyoto node task panicked: {e}; restarting"),
                    }
                    KyotoEventLoopExit::KyotoNodeExited
                }
            };

            kyoto_handle.abort();

            match result {
                KyotoEventLoopExit::ConnectivityLost => {
                    warn!(
                        "Lost connectivity to Bitcoin peers after {KYOTO_MAX_CONSECUTIVE_FAILURES} \
                         consecutive failures. Restarting Kyoto node..."
                    );
                }
                KyotoEventLoopExit::BlockScanFailed => {
                    warn!("Restarting Kyoto after a Bitcoin block scan failed");
                }
                KyotoEventLoopExit::KyotoNodeExited => {}
                KyotoEventLoopExit::Shutdown => {
                    info!("Bitcoin monitor stopped");
                    return Ok(());
                }
            }

            self.synced = false;
            self.tip = None;
            self.cancel_deposit_workers();
            self.deposit_lookup_cache = self.deposit_lookup_cache.fresh();
            self.deposit_tracker.reset_bitcoin_state();
            self.metrics.kyoto_restarts.inc();
            self.metrics.kyoto_connected_peers.set(0);
            self.metrics.kyoto_synced.set(0);
            self.metrics.kyoto_consecutive_failures.set(0);

            tokio::time::sleep(next_restart_delay()).await;

            let (new_node, new_client) =
                Self::build_kyoto_node(&self.config, self.start_checkpoint);
            current_node = new_node;
            current_client = new_client;
            self.requester = current_client.requester.clone();
            info!("Kyoto node rebuilt, resuming monitor");
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
            Warning::TransactionRejected { .. } => "transaction_rejected",
            Warning::EvaluatingFork => "evaluating_fork",
            Warning::UnexpectedSyncError { .. } => "unexpected_sync_error",
            Warning::ChannelDropped => "channel_dropped",
        }
    }

    /// Run the main event loop, returning the reason it exited.
    #[tracing::instrument(name = "btc_monitor", skip_all)]
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
                Some(join_result) = self.deposit_check_workers.join_next() => {
                    self.finish_deposit_check(join_result);
                }
                Some(join_result) = self.block_scan_workers.join_next() => {
                    if self.finish_block_scan(join_result) {
                        return KyotoEventLoopExit::BlockScanFailed;
                    }
                    self.start_next_block_scan();
                }
                Some(join_result) = self.rpc_workers.join_next() => {
                    if let Err(e) = join_result {
                        error!("RPC worker task failed: {e}");
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
            _ => {}
        }
    }

    fn process_kyoto_event(&mut self, event: kyoto::Event) {
        match event {
            kyoto::Event::ChainUpdate(changes) => self.process_chain_update(changes),
            kyoto::Event::FiltersSynced(sync_update) => self.process_synced(sync_update),
            kyoto::Event::IndexedFilter(filter) => {
                debug!(
                    "Received compact block filter at height {} (block {})",
                    filter.height(),
                    filter.block_hash()
                );
            }
        }
    }

    fn process_chain_update(&mut self, changes: kyoto::chain::BlockHeaderChanges) {
        match changes {
            kyoto::chain::BlockHeaderChanges::Connected(indexed_header) => {
                self.metrics.kyoto_blocks_received.inc();
                self.metrics
                    .kyoto_best_height
                    .set(indexed_header.height as i64);
                self.tip = Some(kyoto::HashCheckpoint::new(
                    indexed_header.height,
                    indexed_header.block_hash(),
                ));
                // Kyoto replays a Connected event per header during catch-up;
                // gate side effects until synced to avoid a per-block storm.
                if self.synced {
                    info!(
                        "New block header at height {} ({})",
                        indexed_header.height,
                        indexed_header.block_hash()
                    );
                    let checkpoint =
                        HashCheckpoint::new(indexed_header.height, indexed_header.block_hash());
                    self.deposit_tracker.set_tip(checkpoint);
                    let _ = self.block_height_tx.send(checkpoint.height);
                    self.queue_block_scan(checkpoint);
                } else {
                    debug!(
                        "Catching up: connected header at height {} ({})",
                        indexed_header.height,
                        indexed_header.block_hash()
                    );
                }
            }
            kyoto::chain::BlockHeaderChanges::Reorganized {
                accepted,
                reorganized,
            } => {
                info!(
                    "Reorg detected: {} accepted, {} disconnected",
                    accepted.len(),
                    reorganized.len()
                );
                self.metrics.kyoto_reorgs.inc();
                // Checks are tied to the tip they started against. Cancel them before
                // clearing caches so stale workers cannot repopulate disconnected data.
                let disconnected: Vec<_> = reorganized
                    .iter()
                    .map(|header| HashCheckpoint::new(header.height, header.block_hash()))
                    .collect();
                self.cancel_deposit_workers();
                self.tip = None;
                self.deposit_lookup_cache = self.deposit_lookup_cache.fresh();
                self.deposit_tracker.apply_reorg(&disconnected);

                let new_tip = accepted
                    .last()
                    .map(|header| HashCheckpoint::new(header.height, header.block_hash()))
                    .or_else(|| {
                        reorganized.first().and_then(|header| {
                            header
                                .height
                                .checked_sub(1)
                                .map(|height| HashCheckpoint::new(height, header.prev_blockhash()))
                        })
                    });
                if let Some(new_tip) = new_tip {
                    self.tip = Some(new_tip);
                    self.deposit_tracker.set_tip(new_tip);
                    self.metrics.kyoto_best_height.set(new_tip.height as i64);
                    if self.synced {
                        let _ = self.block_height_tx.send(new_tip.height);
                        for header in accepted {
                            self.queue_block_scan(HashCheckpoint::new(
                                header.height,
                                header.block_hash(),
                            ));
                        }
                    }
                }
            }
            kyoto::chain::BlockHeaderChanges::ForkAdded(indexed_header) => {
                debug!(
                    "Fork header received at height {} ({})",
                    indexed_header.height,
                    indexed_header.block_hash()
                );
            }
        }
    }

    fn process_synced(&mut self, sync_update: kyoto::SyncUpdate) {
        let tip = sync_update.tip;
        info!(
            "Synchronized to height {} ({}) with {} recent headers",
            tip.height,
            tip.hash,
            sync_update.recent_history.len()
        );
        self.synced = true;
        self.metrics.kyoto_synced.set(1);
        self.metrics.kyoto_best_height.set(tip.height as i64);
        self.metrics.kyoto_sync_percent.set(100);
        self.tip = Some(tip);
        self.deposit_tracker.set_tip(tip);
        // Publish the synchronized tip. Subsequent updates are published as soon
        // as their headers connect; deposit scans notify the tracker separately.
        let _ = self.block_height_tx.send(tip.height);
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::CheckDeposit(request) => {
                self.confirm_deposit(request);
            }
            MonitorMessage::GetRecentFeeRate(conf_target, result_tx) => {
                self.rpc_workers.spawn(Self::get_recent_fee_rate(
                    self.bitcoind_rpc.clone(),
                    self.metrics.clone(),
                    conf_target,
                    result_tx,
                ));
            }
            MonitorMessage::BroadcastTransaction(tx, result_tx) => {
                self.rpc_workers.spawn(Self::broadcast_transaction(
                    self.bitcoind_rpc.clone(),
                    tx,
                    result_tx,
                ));
            }
            MonitorMessage::GetTransactionStatus(txid, result_tx) => {
                self.rpc_workers.spawn(Self::get_transaction_status(
                    self.bitcoind_rpc.clone(),
                    txid,
                    result_tx,
                ));
            }
        }
    }

    async fn get_recent_fee_rate(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        metrics: Arc<Metrics>,
        conf_target: u16,
        result_tx: oneshot::Sender<Result<FeeRate>>,
    ) {
        // ECONOMICAL tracks spot fees more closely than the default
        // CONSERVATIVE, which blends in a long-horizon max.
        let result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.call::<corepc_client::types::v29::EstimateSmartFee>(
                "estimatesmartfee",
                &[
                    serde_json::json!(conf_target as u32),
                    serde_json::json!("ECONOMICAL"),
                ],
            )
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|res| Ok(res.into_model()?))
        .map(|res| {
            let sat_per_kwu = match res.fee_rate {
                Some(fee_rate) => fee_rate.to_sat_per_kwu(),
                None => {
                    warn!(
                        conf_target,
                        fallback_sat_per_kwu = FALLBACK_FEE_RATE_SAT_PER_KWU,
                        "Node could not estimate fee rate; falling back to minimum relay fee"
                    );
                    FALLBACK_FEE_RATE_SAT_PER_KWU
                }
            };
            metrics
                .btc_fee_rate_sat_per_kvb
                .set((sat_per_kwu * 4) as i64);
            FeeRate::from_sat_per_kwu(sat_per_kwu)
        });
        let _ = result_tx.send(result);
    }

    async fn broadcast_transaction(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        tx: bitcoin::Transaction,
        result_tx: oneshot::Sender<Result<()>>,
    ) {
        // Broadcast via the bitcoind RPC, not kyoto's P2P submit_package, which
        // dropped its response or hung under load.
        let txid = tx.compute_txid();
        let result = btc_rpc_call(&bitcoind_rpc, move |rpc| rpc.send_raw_transaction(&tx)).await;
        match result {
            Ok(_) => {
                info!("Transaction {txid} broadcast via Bitcoin Core RPC");
                let _ = result_tx.send(Ok(()));
            }
            Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(ref e)))
                if e.code == -27 =>
            {
                // RPC error -27: tx already confirmed on-chain ("outputs already in utxo
                // set"), so the broadcast succeeded. (A mempool duplicate returns Ok.)
                debug!("Transaction {txid} already confirmed on-chain");
                let _ = result_tx.send(Ok(()));
            }
            Err(e) => {
                error!("Failed to broadcast transaction {txid}: {e}");
                let _ = result_tx.send(Err(anyhow::anyhow!(e)));
            }
        }
    }

    async fn get_transaction_status(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        txid: bitcoin::Txid,
        result_tx: oneshot::Sender<Result<TxStatus>>,
    ) {
        let rpc_result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.get_raw_transaction_verbose(txid)
        })
        .await;
        let result = match rpc_result {
            Ok(tx_info) => match tx_info.into_model() {
                Ok(tx_info) => {
                    if tx_info.block_hash.is_some() {
                        let confirmations = tx_info.confirmations.unwrap_or(0) as u32;
                        Ok(TxStatus::Confirmed { confirmations })
                    } else {
                        Ok(TxStatus::InMempool)
                    }
                }
                Err(e) => Err(anyhow::anyhow!("Failed to parse transaction info: {e}")),
            },
            Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(ref e)))
                if e.code == -5 =>
            {
                // RPC error -5: "No such mempool or blockchain transaction"
                Ok(TxStatus::NotFound)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to query transaction status: {e}")),
        };
        let _ = result_tx.send(result);
    }
}

async fn process_deposit_check(
    context: DepositCheckContext,
    request: DepositCheckRequest,
    discovery: DepositDiscovery,
) -> DepositCheckWorkerResult {
    let generation = context.generation;
    let DepositCheckRequest {
        outpoint,
        confirmation_threshold,
        result_tx,
    } = request;
    let result = observe_deposit(context, confirmation_threshold, outpoint, discovery).await;
    DepositCheckWorkerResult {
        generation,
        result_tx,
        result,
    }
}

async fn observe_deposit(
    context: DepositCheckContext,
    confirmation_threshold: u32,
    outpoint: bitcoin::OutPoint,
    discovery: DepositDiscovery,
) -> Result<DepositConfirmation, DepositConfirmError> {
    let DepositCheckContext {
        tip,
        bitcoind_rpc,
        requester,
        deposit_lookup_cache,
        deposit_tracker,
        ..
    } = context;
    let status = match discovery {
        DepositDiscovery::Discover(token) => {
            let discovered = discover_deposit(
                bitcoind_rpc.clone(),
                requester,
                deposit_lookup_cache,
                outpoint,
                tip,
            )
            .await?;
            match deposit_tracker.finish_discovery(token, discovered.clone()) {
                DiscoveryFinish::Recorded => discovered,
                DiscoveryFinish::Superseded(DepositStatus::Unchecked) => {
                    return Err(anyhow::anyhow!(
                        "Bitcoin deposit observation changed while the check was in flight"
                    )
                    .into());
                }
                DiscoveryFinish::Superseded(status) => status,
                DiscoveryFinish::Untracked => {
                    return Err(anyhow::anyhow!(
                        "Bitcoin deposit request left the tracker during discovery"
                    )
                    .into());
                }
            }
        }
        DepositDiscovery::Untracked => {
            discover_deposit(
                bitcoind_rpc.clone(),
                requester,
                deposit_lookup_cache,
                outpoint,
                tip,
            )
            .await?
        }
        DepositDiscovery::Known(status) => status,
    };

    check_result_from_status(status, tip, confirmation_threshold, bitcoind_rpc, outpoint).await
}

async fn check_result_from_status(
    status: DepositStatus,
    tip: HashCheckpoint,
    confirmation_threshold: u32,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    outpoint: bitcoin::OutPoint,
) -> Result<DepositConfirmation, DepositConfirmError> {
    match status {
        DepositStatus::Unchecked => unreachable!("discovery returned Unchecked"),
        DepositStatus::NotFound => Ok(DepositConfirmation::NotFound),
        DepositStatus::InMempool => Ok(DepositConfirmation::InMempool),
        DepositStatus::InvalidVout { .. } => Err(DepositConfirmError::InvalidVout {
            txid: outpoint.txid,
            vout: outpoint.vout,
        }),
        DepositStatus::InBlock { checkpoint, txout } => {
            let confirmations = tip
                .height
                .saturating_add(1)
                .saturating_sub(checkpoint.height);
            if confirmations < confirmation_threshold {
                return Ok(DepositConfirmation::InsufficientConfirmations { confirmations });
            }
            check_unspent_at_tip(
                bitcoind_rpc,
                tip,
                outpoint,
                txout,
                confirmations,
                confirmation_threshold,
            )
            .await
        }
    }
}

async fn discover_deposit(
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    outpoint: bitcoin::OutPoint,
    tip: HashCheckpoint,
) -> Result<DepositStatus, DepositConfirmError> {
    let txid = outpoint.txid;
    let block_info = if let Some(block_info) = deposit_lookup_cache.get_tx_block(&txid) {
        block_info
    } else {
        debug!("Looking up block for transaction {txid}");
        require_core_tip(&bitcoind_rpc, tip, "before transaction lookup").await?;
        let tx_info = match btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.get_raw_transaction_verbose(txid)
        })
        .await
        {
            Ok(tx_info) => tx_info,
            Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(ref e)))
                if e.code == -5 =>
            {
                require_core_tip(&bitcoind_rpc, tip, "after transaction lookup").await?;
                return Ok(DepositStatus::NotFound);
            }
            Err(e) => return Err(anyhow::anyhow!("Failed to look up txid {txid}: {e}").into()),
        };
        let tx_info = tx_info
            .into_model()
            .map_err(|e| anyhow::anyhow!("Failed to parse transaction info for {txid}: {e}"))?;
        let Some(block_hash) = tx_info.block_hash else {
            require_core_tip(&bitcoind_rpc, tip, "after transaction lookup").await?;
            return Ok(DepositStatus::InMempool);
        };
        let height = if let Some(height) = deposit_lookup_cache.get_block_height(&block_hash) {
            height
        } else {
            let height = requester
                .height_of_hash(block_hash)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to look up block hash {block_hash} in Kyoto: {e}")
                })?
                .ok_or_else(|| {
                    anyhow::anyhow!("Block hash {block_hash} from bitcoind is not on Kyoto's chain")
                })?;
            deposit_lookup_cache.put_block_height(block_hash, height);
            height
        };
        let block_info = HashCheckpoint::new(height, block_hash);
        deposit_lookup_cache.put_tx_block(txid, block_info);
        block_info
    };

    let transaction = if let Some(transaction) = deposit_lookup_cache.get_transaction(&txid) {
        transaction
    } else {
        let indexed_block = requester
            .get_block(block_info.hash)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to look up block {}: {e}", block_info.hash))?;
        let fetched_hash = indexed_block.block.block_hash();
        if indexed_block.height != block_info.height || fetched_hash != block_info.hash {
            deposit_lookup_cache.invalidate_tx(&txid);
            return Err(anyhow::anyhow!(
                "Kyoto returned block {fetched_hash} at height {} for requested {} at height {}",
                indexed_block.height,
                block_info.hash,
                block_info.height,
            )
            .into());
        }
        let Some(transaction) = indexed_block
            .block
            .txdata
            .iter()
            .find(|transaction| transaction.compute_txid() == txid)
        else {
            deposit_lookup_cache.invalidate_tx(&txid);
            return Err(anyhow::anyhow!(
                "Transaction {txid} is not present in block {} reported by Bitcoin Core",
                block_info.hash,
            )
            .into());
        };
        let transaction = Arc::new(transaction.clone());
        deposit_lookup_cache.put_transaction(txid, transaction.clone());
        transaction
    };

    let Some(txout) = transaction.output.get(outpoint.vout as usize) else {
        return Ok(DepositStatus::InvalidVout {
            checkpoint: block_info,
        });
    };
    Ok(DepositStatus::InBlock {
        checkpoint: block_info,
        txout: txout.clone(),
    })
}

async fn get_best_block(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
) -> Result<bitcoin::BlockHash> {
    btc_rpc_call(bitcoind_rpc, move |rpc| {
        rpc.call::<bitcoin::BlockHash>("getbestblockhash", &[])
    })
    .await
    .map_err(anyhow::Error::from)
}

async fn require_core_tip(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    tip: HashCheckpoint,
    context: &str,
) -> Result<(), DepositConfirmError> {
    let bitcoind_tip = get_best_block(bitcoind_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Bitcoin Core tip {context}: {e}"))?;
    if bitcoind_tip != tip.hash {
        return Err(anyhow::anyhow!(
            "Bitcoin Core is at {bitcoind_tip}, but captured Kyoto tip is {} {context}",
            tip.hash,
        )
        .into());
    }
    Ok(())
}

async fn get_tx_out(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    outpoint: bitcoin::OutPoint,
) -> Result<Option<serde_json::Value>, corepc_client::client_sync::Error> {
    btc_rpc_call(bitcoind_rpc, move |rpc| {
        rpc.call::<Option<serde_json::Value>>(
            "gettxout",
            &[
                serde_json::json!(outpoint.txid),
                serde_json::json!(outpoint.vout),
                serde_json::json!(true),
            ],
        )
    })
    .await
}

fn get_tx_out_best_block(response: &serde_json::Value) -> Result<bitcoin::BlockHash> {
    response
        .get("bestblock")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("gettxout response is missing bestblock"))?
        .parse::<bitcoin::BlockHash>()
        .map_err(|e| anyhow::anyhow!("invalid gettxout bestblock: {e}"))
}

async fn check_unspent_at_tip(
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    tip: HashCheckpoint,
    outpoint: bitcoin::OutPoint,
    txout: bitcoin::TxOut,
    confirmations: u32,
    confirmation_threshold: u32,
) -> Result<DepositConfirmation, DepositConfirmError> {
    // Always make this check fresh; neither successful nor spent results clear
    // the tracker's independently established InBlock observation.
    let expected_tip = tip.hash;
    let bitcoind_tip = get_best_block(&bitcoind_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Bitcoin Core tip: {e}"))?;
    if bitcoind_tip != expected_tip {
        return Err(anyhow::anyhow!(
            "Bitcoin Core is at {bitcoind_tip}, but Kyoto is at {expected_tip}"
        )
        .into());
    }

    let gettxout_result = get_tx_out(&bitcoind_rpc, outpoint).await;
    let bitcoind_tip = get_best_block(&bitcoind_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to re-read Bitcoin Core tip: {e}"))?;
    if bitcoind_tip != expected_tip {
        return Err(anyhow::anyhow!(
            "Bitcoin Core tip changed from {expected_tip} to {bitcoind_tip} during gettxout"
        )
        .into());
    }
    match gettxout_result {
        Ok(Some(response)) => {
            let best_block = get_tx_out_best_block(&response)?;
            if best_block != tip.hash {
                return Err(anyhow::anyhow!(
                    "Bitcoin Core UTXO view is at {best_block}, but Kyoto is at {}",
                    tip.hash
                )
                .into());
            }
            info!(
                "Deposit {}:{} confirmed with {confirmations}/{confirmation_threshold} confirmations",
                outpoint.txid, outpoint.vout,
            );
            Ok(DepositConfirmation::Confirmed(txout))
        }
        Ok(None) => {
            warn!(
                "Deposit UTXO {}:{} has already been spent on Bitcoin. Rejecting deposit.",
                outpoint.txid, outpoint.vout,
            );
            Err(DepositConfirmError::UtxoSpent {
                txid: outpoint.txid,
                vout: outpoint.vout,
            })
        }
        Err(e) => {
            Err(anyhow::anyhow!("Failed to check UTXO spent status via gettxout: {e}").into())
        }
    }
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    block_height_rx: tokio::sync::watch::Receiver<u32>,
}

impl MonitorClient {
    /// Subscribe to sync-complete and connected Bitcoin tip updates.
    pub fn subscribe_block_height(&self) -> tokio::sync::watch::Receiver<u32> {
        self.block_height_rx.clone()
    }

    pub async fn confirm_deposit(
        &self,
        outpoint: bitcoin::OutPoint,
        confirmation_threshold: u32,
    ) -> Result<DepositConfirmation, DepositConfirmError> {
        let (tx, rx) = oneshot::channel();
        let request = DepositCheckRequest {
            outpoint,
            confirmation_threshold,
            result_tx: tx,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            self.tx
                .send(MonitorMessage::CheckDeposit(request))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))?
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("confirm_deposit timed out waiting for Bitcoin deposit check")
        })?
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
    // Checks the given OutPoint against the monitor's current Bitcoin tip.
    CheckDeposit(DepositCheckRequest),

    // Returns an estimated fee rate targeting confirmation within `conf_target` blocks.
    GetRecentFeeRate(u16, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),

    // Query the status of a transaction (confirmed, in mempool, or not found).
    GetTransactionStatus(bitcoin::Txid, oneshot::Sender<Result<TxStatus>>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn make_outpoint(seed: u8) -> bitcoin::OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(bytes),
            vout: 0,
        }
    }

    fn fresh_metrics() -> Metrics {
        Metrics::new(&prometheus::Registry::new())
    }

    fn cache_requests(metrics: &Metrics, cache: &str, result: &str) -> u64 {
        metrics
            .deposit_lookup_cache_requests_total
            .with_label_values(&[cache, result])
            .get()
    }

    fn block_hash(seed: u8) -> bitcoin::BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bitcoin::BlockHash::from_byte_array(bytes)
    }

    fn deposit_check_request_for(
        outpoint: bitcoin::OutPoint,
    ) -> (
        DepositCheckRequest,
        oneshot::Receiver<Result<DepositConfirmation, DepositConfirmError>>,
    ) {
        let (result_tx, result_rx) = oneshot::channel();
        (
            DepositCheckRequest {
                outpoint,
                confirmation_threshold: 100,
                result_tx,
            },
            result_rx,
        )
    }

    fn record_status(
        tracker: &DepositTracker,
        outpoint: &bitcoin::OutPoint,
        status: DepositStatus,
    ) {
        let DepositDiscovery::Discover(token) = tracker.discovery(outpoint) else {
            panic!("expected discovery token");
        };
        assert_eq!(
            tracker.finish_discovery(token, status),
            DiscoveryFinish::Recorded
        );
    }

    fn test_monitor(metrics: Arc<Metrics>, tracker: Arc<DepositTracker>) -> Monitor {
        let (_, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();
        let start_checkpoint = HashCheckpoint::from_genesis(bitcoin::Network::Bitcoin);
        Monitor {
            config: MonitorConfig::default(),
            metrics: metrics.clone(),
            bitcoind_rpc: Arc::new(corepc_client::client_sync::v29::Client::new(
                "http://127.0.0.1:1",
            )),
            tip: None,
            start_checkpoint,
            synced: false,
            block_height_tx: tokio::sync::watch::channel(0).0,
            requester: kyoto_client.requester,
            deposit_check_workers: JoinSet::new(),
            block_scan_workers: JoinSet::new(),
            block_scan_queue: VecDeque::new(),
            deposit_lookup_cache: SharedDepositLookupCache::new(metrics),
            deposit_tracker: tracker,
            rpc_workers: JoinSet::new(),
        }
    }

    #[test]
    fn deposit_lookup_cache_records_and_clears_entries() {
        let txid = make_outpoint(1).txid;
        let block_hash = block_hash(2);
        let block_info = HashCheckpoint::new(42, block_hash);
        let metrics = Arc::new(fresh_metrics());
        let cache = SharedDepositLookupCache::new(metrics.clone());

        cache.put_tx_block(txid, block_info);
        cache.put_block_height(block_hash, 42);

        assert_eq!(cache.get_tx_block(&txid), Some(block_info));
        assert_eq!(cache.get_block_height(&block_hash), Some(42));
        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 1);
        assert_eq!(cache_requests(&metrics, "block_height", "hit"), 1);

        cache.clear();

        assert!(cache.get_tx_block(&txid).is_none());
        assert!(cache.get_block_height(&block_hash).is_none());
        assert_eq!(cache_requests(&metrics, "tx_block", "miss"), 1);
        assert_eq!(cache_requests(&metrics, "block_height", "miss"), 1);
    }

    #[test]
    fn deposit_lookup_cache_invalidates_tx_entries_only() {
        let txid = make_outpoint(1).txid;
        let block_hash = block_hash(2);
        let block_info = HashCheckpoint::new(42, block_hash);
        let cache = SharedDepositLookupCache::new(Arc::new(fresh_metrics()));

        cache.put_tx_block(txid, block_info);
        cache.put_block_height(block_hash, 42);
        cache.invalidate_tx(&txid);

        assert!(cache.get_tx_block(&txid).is_none());
        assert_eq!(cache.get_block_height(&block_hash), Some(42));
    }

    #[tokio::test]
    async fn stale_worker_result_is_not_delivered_after_reset() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = Arc::new(DepositTracker::new(metrics.clone()));
        let mut monitor = test_monitor(metrics, tracker.clone());
        let outpoint = make_outpoint(1);
        let (request, result_rx) = deposit_check_request_for(outpoint);
        let generation = tracker.bitcoin_generation();

        tracker.reset_bitcoin_state();
        monitor.finish_deposit_check(Ok(DepositCheckWorkerResult {
            generation,
            result_tx: request.result_tx,
            result: Ok(DepositConfirmation::NotFound),
        }));

        assert!(matches!(
            result_rx.await.unwrap(),
            Err(DepositConfirmError::Other(_))
        ));
    }

    #[test]
    fn scan_without_candidates_does_not_start_a_worker() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = Arc::new(DepositTracker::new(metrics.clone()));
        let mut monitor = test_monitor(metrics, tracker);

        monitor.queue_block_scan(HashCheckpoint::new(42, block_hash(2)));

        assert!(monitor.block_scan_queue.is_empty());
        assert!(monitor.block_scan_workers.is_empty());
    }

    #[tokio::test]
    async fn process_deposit_check_uses_tracker_state_without_rpc() {
        let metrics = Arc::new(fresh_metrics());
        let cache = SharedDepositLookupCache::new(metrics.clone());
        let outpoint = make_outpoint(1);
        let txid = outpoint.txid;
        let block_info = HashCheckpoint::new(42, block_hash(2));
        let tracker = Arc::new(DepositTracker::new(metrics.clone()));
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), outpoint);
        record_status(
            &tracker,
            &outpoint,
            DepositStatus::InBlock {
                checkpoint: block_info,
                txout: bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            },
        );
        let mut result_rxs = Vec::new();
        let (_, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();

        for vout in [0, 1] {
            let current = bitcoin::OutPoint { txid, vout };
            if vout == 1 {
                tracker.upsert_request(sui_sdk_types::Address::new([2; 32]), current);
                record_status(&tracker, &current, DepositStatus::NotFound);
            }
            let discovery = tracker.discovery(&current);
            let (request, result_rx) = deposit_check_request_for(current);
            result_rxs.push(result_rx);
            let result = process_deposit_check(
                DepositCheckContext {
                    tip: HashCheckpoint::new(50, block_hash(3)),
                    bitcoind_rpc: Arc::new(corepc_client::client_sync::v29::Client::new(
                        "http://127.0.0.1:1",
                    )),
                    requester: kyoto_client.requester.clone(),
                    deposit_lookup_cache: cache.clone(),
                    deposit_tracker: tracker.clone(),
                    generation: tracker.bitcoin_generation(),
                },
                request,
                discovery,
            )
            .await;
            let _ = result.result_tx.send(result.result);
        }

        assert_eq!(
            result_rxs.remove(0).await.unwrap().unwrap(),
            DepositConfirmation::InsufficientConfirmations { confirmations: 9 }
        );
        assert_eq!(
            result_rxs.remove(0).await.unwrap().unwrap(),
            DepositConfirmation::NotFound
        );
        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 0);
    }

    #[tokio::test]
    async fn resolve_start_checkpoint_uses_mainnet_activation_anchors() {
        // Mainnet uses hard-coded anchors, so the RPC is never called here.
        let rpc = Arc::new(corepc_client::client_sync::v29::Client::new(
            "http://127.0.0.1:1",
        ));

        let above_taproot = MonitorConfig {
            network: bitcoin::Network::Bitcoin,
            start_height: 800_000,
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::resolve_start_checkpoint(&rpc, &above_taproot).await,
            HashCheckpoint::taproot_activation(),
        );

        let between_segwit_and_taproot = MonitorConfig {
            network: bitcoin::Network::Bitcoin,
            start_height: 500_000,
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::resolve_start_checkpoint(&rpc, &between_segwit_and_taproot).await,
            HashCheckpoint::segwit_activation(),
        );
    }

    #[test]
    fn next_restart_delay_stays_in_range() {
        let max = KYOTO_RESTART_DELAY_BASE + KYOTO_MAX_RESTART_DELAY_JITTER;
        for _ in 0..1000 {
            let d = next_restart_delay();
            assert!(d >= KYOTO_RESTART_DELAY_BASE, "{d:?} < base");
            assert!(d <= max, "{d:?} > base + jitter");
        }
    }
}
