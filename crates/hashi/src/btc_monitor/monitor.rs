// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

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
use crate::metrics::Metrics;

/// 1 sat/vB expressed as sat/kwu.
const FALLBACK_FEE_RATE_SAT_PER_KWU: u64 = 250;

/// Number of consecutive connection failures before restarting Kyoto.
const KYOTO_MAX_CONSECUTIVE_FAILURES: u32 = 15;

/// Base delay before restarting Kyoto after connectivity loss.
const KYOTO_RESTART_DELAY_BASE: Duration = Duration::from_secs(5);

/// Random additional delay to spread reconnects across pods.
const KYOTO_MAX_RESTART_DELAY_JITTER: Duration = Duration::from_secs(30);

/// How many Bitcoin blocks a deposit observation can go without being
/// refreshed before it's dropped from the confirmation-metrics cache.
const STALE_OBSERVATION_BLOCKS: u32 = 10;

/// Ceiling on a single round-trip through the monitor loop.
const MONITOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedDepositObservation {
    NotFound,
    InMempool,
    InBlock { height: u32 },
}

#[derive(Debug, Clone, Copy)]
struct CachedDepositEntry {
    observation: CachedDepositObservation,
    last_updated_tip: u32,
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

#[derive(Debug, thiserror::Error)]
pub enum DepositConfirmError {
    #[error("UTXO {txid}:{vout} has already been spent on Bitcoin")]
    UtxoSpent { txid: bitcoin::Txid, vout: u32 },
    #[error("transaction {txid} has no output at vout {vout}")]
    InvalidVout { txid: bitcoin::Txid, vout: u32 },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

enum KyotoEventLoopExit {
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
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    requester: kyoto::Requester,
    tip: Option<HashCheckpoint>,
    start_checkpoint: HashCheckpoint,
    /// Set once Kyoto's initial filter sync completes; gates per-block side
    /// effects so the catch-up replay doesn't run them per header.
    synced: bool,
    block_height_tx: tokio::sync::watch::Sender<u32>,
    deposit_check_workers: JoinSet<()>,
    rpc_workers: JoinSet<()>,
    deposit_lookup_cache: SharedDepositLookupCache,
    deposit_observation_cache: HashMap<bitcoin::OutPoint, CachedDepositEntry>,
    /// Endless rotation of `config.trusted_peers`; yields `None` when it's empty.
    trusted_peer_rotation: std::iter::Cycle<std::vec::IntoIter<kyoto::TrustedPeer>>,
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
    fn build_kyoto_node(
        config: &MonitorConfig,
        checkpoint: HashCheckpoint,
    ) -> (kyoto::Node, kyoto::Client) {
        kyoto::Builder::new(config.network)
            .add_peers(config.trusted_peers.iter().cloned())
            // Only connect to the configured trusted peers. Prevents Kyoto from
            // discovering additional peers via DNS seeding or addr gossip.
            // `replenish_trusted_peers` keeps the whitelist stocked; if it still
            // drains, the node exits and the supervision loop rebuilds it.
            .whitelist_only()
            .maximum_connection_time(Duration::MAX)
            .chain_state(kyoto::ChainState::Checkpoint(checkpoint))
            .build()
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
            _ => Self::checkpoint_at_height(bitcoind_rpc, config.start_height).await,
        }
    }

    /// Wait for bitcoind to have the block at `height`. A node still in initial
    /// block download reports the same "out of range" error as a height past the
    /// tip, so giving up would anchor Kyoto far below `height` permanently.
    async fn checkpoint_at_height(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
        height: u32,
    ) -> HashCheckpoint {
        const RETRY_DELAY: Duration = Duration::from_secs(2);
        const LOG_INTERVAL: Duration = Duration::from_secs(30);

        let mut next_log = Instant::now();
        loop {
            match btc_rpc_call(bitcoind_rpc, move |rpc| rpc.get_block_hash(height as u64)).await {
                Ok(raw) => match raw.into_model() {
                    Ok(model) => {
                        info!("Anchoring Kyoto at start height {height} ({})", model.0);
                        return HashCheckpoint::new(height, model.0);
                    }
                    Err(e) => error!("Failed to parse getblockhash({height}) response: {e}"),
                },
                Err(e) => {
                    if Instant::now() >= next_log {
                        next_log = Instant::now() + LOG_INTERVAL;
                        match Self::bitcoind_height(bitcoind_rpc).await {
                            Some(blocks) => warn!(
                                "Waiting for bitcoind to reach start height {height}; it is at {blocks}"
                            ),
                            None => warn!("Waiting for a block at start height {height}: {e}"),
                        }
                    }
                }
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    async fn bitcoind_height(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    ) -> Option<u32> {
        btc_rpc_call(bitcoind_rpc, |rpc| rpc.get_blockchain_info())
            .await
            .ok()
            .and_then(|info| info.into_model().ok())
            .map(|info| info.blocks)
    }

    /// Run a BTC monitor with the given configuration.
    /// Returns the client for interacting with the monitor and a Service for lifecycle management.
    pub fn run(config: MonitorConfig, metrics: Arc<Metrics>) -> Result<(MonitorClient, Service)> {
        let bitcoind_rpc = crate::btc_monitor::config::new_rpc_client(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);
        let (block_height_tx, block_height_rx) = tokio::sync::watch::channel(0u32);

        let service = Service::new().spawn_aborting({
            let client_tx = client_tx.clone();
            async move {
                let bitcoind_rpc = Arc::new(bitcoind_rpc);

                let start_checkpoint = Self::resolve_start_checkpoint(&bitcoind_rpc, &config).await;
                let (kyoto_node, kyoto_client) = Self::build_kyoto_node(&config, start_checkpoint);
                let trusted_peer_rotation = config.trusted_peers.clone().into_iter().cycle();

                let mut monitor = Monitor {
                    config,
                    metrics: metrics.clone(),
                    bitcoind_rpc,
                    requester: kyoto_client.requester.clone(),
                    client_tx,
                    tip: None,
                    start_checkpoint,
                    synced: false,
                    block_height_tx,
                    deposit_check_workers: JoinSet::new(),
                    rpc_workers: JoinSet::new(),
                    deposit_lookup_cache: SharedDepositLookupCache::new(metrics),
                    deposit_observation_cache: HashMap::new(),
                    trusted_peer_rotation,
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
                KyotoEventLoopExit::KyotoNodeExited => {}
                KyotoEventLoopExit::Shutdown => {
                    info!("Bitcoin monitor stopped");
                    return Ok(());
                }
            }

            self.synced = false;
            self.tip = None;
            self.deposit_check_workers.abort_all();
            self.deposit_lookup_cache.clear();
            self.deposit_observation_cache.clear();
            self.rebuild_confirmation_metrics();
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

    /// Kyoto pops a whitelist entry per dial and never refills it, so a
    /// `whitelist_only` node eventually exits with `NoReachablePeers`. It warns
    /// once per dial, so one peer per warning refills it at the rate it drains.
    fn replenish_trusted_peers(&mut self) {
        let Some(peer) = self.trusted_peer_rotation.next() else {
            return;
        };
        if let Err(e) = self.requester.add_peer(peer) {
            debug!("Could not return a trusted peer to Kyoto's whitelist: {e}");
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
                        self.replenish_trusted_peers();
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
                    if let Err(e) = join_result && !e.is_cancelled() {
                        error!("Deposit check worker task failed: {e}");
                    }
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
                    let _ = self.block_height_tx.send(indexed_header.height);
                    self.rebuild_confirmation_metrics();
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
                // Checks are tied to the tip they started against. Request cancellation
                // before clearing caches, though workers may run until their next await.
                self.deposit_check_workers.abort_all();
                self.deposit_lookup_cache.clear();
                self.deposit_observation_cache.clear();
                if let Some(new_tip) = accepted.last() {
                    self.tip = Some(kyoto::HashCheckpoint::new(
                        new_tip.height,
                        new_tip.block_hash(),
                    ));
                    self.metrics.kyoto_best_height.set(new_tip.height as i64);
                    let _ = self.block_height_tx.send(new_tip.height);
                }
                self.rebuild_confirmation_metrics();
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
        let _ = self.block_height_tx.send(tip.height);
        self.rebuild_confirmation_metrics();
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::ConfirmDeposit(request) => {
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
            MonitorMessage::RecordDepositObservation {
                outpoint,
                observation,
            } => {
                self.record_deposit_observation(outpoint, observation);
            }
            MonitorMessage::ForgetDeposit(outpoint) => {
                self.forget_deposit_observation(outpoint);
            }
        }
    }

    fn record_deposit_observation(
        &mut self,
        outpoint: bitcoin::OutPoint,
        observation: CachedDepositObservation,
    ) {
        let last_updated_tip = self.tip.as_ref().map(|t| t.height).unwrap_or(0);
        let previous = self.deposit_observation_cache.insert(
            outpoint,
            CachedDepositEntry {
                observation,
                last_updated_tip,
            },
        );
        update_confirmation_metrics_for_change(
            &self.metrics,
            last_updated_tip,
            previous.map(|entry| entry.observation),
            Some(observation),
        );
    }

    fn forget_deposit_observation(&mut self, outpoint: bitcoin::OutPoint) {
        let Some(previous) = self.deposit_observation_cache.remove(&outpoint) else {
            return;
        };
        let tip_height = self.tip.as_ref().map(|t| t.height).unwrap_or(0);
        update_confirmation_metrics_for_change(
            &self.metrics,
            tip_height,
            Some(previous.observation),
            None,
        );
    }

    /// Drop cache entries that haven't been refreshed in the last
    /// `STALE_OBSERVATION_BLOCKS` Bitcoin blocks, then write the current
    /// bucket counts to `deposit_request_confirmations`.
    fn rebuild_confirmation_metrics(&mut self) {
        let tip_height = self.tip.as_ref().map(|t| t.height).unwrap_or(0);
        rebuild_confirmation_metrics_inner(
            &mut self.deposit_observation_cache,
            tip_height,
            &self.metrics,
        );
    }

    fn confirm_deposit(&mut self, request: DepositCheckRequest) {
        debug!(
            "Checking deposit confirmation for {}",
            request.outpoint.txid
        );

        let Some(tip) = &self.tip else {
            let _ =
                request.result_tx.send(Err(
                    anyhow::anyhow!("Bitcoin chain tip is not available").into()
                ));
            return;
        };

        self.deposit_check_workers
            .spawn(Monitor::process_deposit_check(
                tip.to_owned(),
                self.bitcoind_rpc.clone(),
                self.requester.clone(),
                self.client_tx.clone(),
                self.deposit_lookup_cache.clone(),
                request,
            ));
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

    async fn process_deposit_check(
        tip: HashCheckpoint,
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        requester: kyoto::Requester,
        client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
        deposit_lookup_cache: SharedDepositLookupCache,
        request: DepositCheckRequest,
    ) {
        if request.result_tx.is_closed() {
            // Cancel if the receiver is no longer listening.
            return;
        }

        let DepositCheckRequest {
            outpoint,
            confirmation_threshold,
            result_tx,
        } = request;
        let result = Self::observe_deposit(
            tip,
            confirmation_threshold,
            bitcoind_rpc,
            requester,
            client_tx,
            deposit_lookup_cache,
            outpoint,
        )
        .await;
        let _ = result_tx.send(result);
    }

    async fn observe_deposit(
        tip: HashCheckpoint,
        confirmation_threshold: u32,
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        requester: kyoto::Requester,
        client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
        deposit_lookup_cache: SharedDepositLookupCache,
        outpoint: bitcoin::OutPoint,
    ) -> Result<DepositConfirmation, DepositConfirmError> {
        let txid = outpoint.txid;

        // Look up block from the txid.
        let block_info = if let Some(block_info) = deposit_lookup_cache.get_tx_block(&txid) {
            block_info
        } else {
            debug!("Looking up block for transaction {txid}");
            let tx_info = match btc_rpc_call(&bitcoind_rpc, move |rpc| {
                rpc.get_raw_transaction_verbose(txid)
            })
            .await
            {
                Ok(tx_info) => tx_info,
                Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(
                    ref e,
                ))) if e.code == -5 => {
                    // RPC error -5: "No such mempool or blockchain transaction"
                    debug!("Transaction {txid} not found in mempool or blockchain");
                    send_observation(&client_tx, outpoint, CachedDepositObservation::NotFound);
                    return Ok(DepositConfirmation::NotFound);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to look up txid {txid}: {e}").into());
                }
            };
            let tx_info = tx_info
                .into_model()
                .map_err(|e| anyhow::anyhow!("Failed to parse transaction info for {txid}: {e}"))?;
            let Some(block_hash) = tx_info.block_hash else {
                debug!("Transaction {txid} is not yet included in a block");
                send_observation(&client_tx, outpoint, CachedDepositObservation::InMempool);
                return Ok(DepositConfirmation::InMempool);
            };
            // Verify the block hash is in kyoto's independently-validated
            // chain of most work. This catches a malicious bitcoind reporting
            // a fake or forked block hash.
            let cached_height = deposit_lookup_cache.get_block_height(&block_hash);
            let height = match cached_height {
                Some(height) => height,
                None => {
                    let height = match requester.height_of_hash(block_hash).await {
                        Ok(Some(height)) => height,
                        Ok(None) => {
                            return Err(anyhow::anyhow!(
                                "Block hash {block_hash} from bitcoind is not on Kyoto's chain"
                            )
                            .into());
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Failed to look up block hash {block_hash} in Kyoto: {e}"
                            )
                            .into());
                        }
                    };
                    deposit_lookup_cache.put_block_height(block_hash, height);
                    height
                }
            };
            let block_info = kyoto::HashCheckpoint {
                height,
                hash: block_hash,
            };
            deposit_lookup_cache.put_tx_block(txid, block_info);
            block_info
        };

        send_observation(
            &client_tx,
            outpoint,
            CachedDepositObservation::InBlock {
                height: block_info.height,
            },
        );

        // Check if the deposit has enough confirmations yet.
        let confirmations = (tip.height + 1).saturating_sub(block_info.height);
        if confirmations < confirmation_threshold {
            debug!(
                "Transaction {} has {confirmations}/{confirmation_threshold} confirmations. Waiting for more blocks.",
                outpoint.txid,
            );
            return Ok(DepositConfirmation::InsufficientConfirmations { confirmations });
        }

        // If deposit is confirmed, look up the TxOut info.
        let cached_transaction = deposit_lookup_cache.get_transaction(&txid);
        let transaction = match cached_transaction {
            Some(transaction) => transaction,
            None => {
                let block = match requester.get_block(block_info.hash).await {
                    Ok(block) => block,
                    Err(kyoto::error::FetchBlockError::UnknownHash) => {
                        deposit_lookup_cache.invalidate_tx(&txid);
                        return Err(anyhow::anyhow!(
                            "Block {} is no longer in the current chain",
                            block_info.hash
                        )
                        .into());
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to look up block {}: {e}",
                            block_info.hash
                        )
                        .into());
                    }
                };
                let Some(transaction) = block
                    .block
                    .txdata
                    .iter()
                    .find(|tx| tx.compute_txid() == txid)
                else {
                    deposit_lookup_cache.invalidate_tx(&txid);
                    return Err(anyhow::anyhow!(
                        "Transaction {txid} is not present in block {} reported by Bitcoin Core",
                        block_info.hash
                    )
                    .into());
                };
                let transaction = Arc::new(transaction.clone());
                deposit_lookup_cache.put_transaction(txid, transaction.clone());
                transaction
            }
        };

        let txout = match transaction.tx_out(outpoint.vout.try_into().unwrap()) {
            Ok(txout) => txout.clone(),
            Err(_) => {
                send_forget(&client_tx, outpoint);
                return Err(DepositConfirmError::InvalidVout {
                    txid,
                    vout: outpoint.vout,
                });
            }
        };

        // Verify the UTXO is still unspent in Bitcoin's UTXO set (including mempool).
        // Use raw `call()` because gettxout returns null when the UTXO is spent,
        // and the typed `get_tx_out` method doesn't return Option.
        let outpoint_txid = outpoint.txid;
        let outpoint_vout = outpoint.vout;
        let gettxout_result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.call::<Option<serde_json::Value>>(
                "gettxout",
                &[
                    serde_json::json!(outpoint_txid),
                    serde_json::json!(outpoint_vout),
                    serde_json::json!(true), // include_mempool
                ],
            )
        })
        .await;
        match gettxout_result {
            Ok(Some(_)) => {
                info!(
                    "Deposit {}:{} confirmed with {confirmations}/{confirmation_threshold} confirmations",
                    outpoint.txid, outpoint.vout,
                );
                send_forget(&client_tx, outpoint);
                Ok(DepositConfirmation::Confirmed(txout))
            }
            Ok(None) => {
                warn!(
                    "Deposit UTXO {}:{} has already been spent on Bitcoin. Rejecting deposit.",
                    outpoint.txid, outpoint.vout,
                );
                send_forget(&client_tx, outpoint);
                Err(DepositConfirmError::UtxoSpent {
                    txid,
                    vout: outpoint.vout,
                })
            }
            Err(e) => {
                Err(anyhow::anyhow!("Failed to check UTXO spent status via gettxout: {e}").into())
            }
        }
    }
}

/// GC stale entries from the cache, then write bucket counts into the
/// `deposit_request_confirmations` gauge.
fn rebuild_confirmation_metrics_inner(
    cache: &mut HashMap<bitcoin::OutPoint, CachedDepositEntry>,
    tip_height: u32,
    metrics: &Metrics,
) {
    let min_fresh = tip_height.saturating_sub(STALE_OBSERVATION_BLOCKS);
    cache.retain(|_, entry| entry.last_updated_tip >= min_fresh);

    let mut counts = [0i64; crate::metrics::CONFIRMATION_STATUS_LABELS.len()];
    for entry in cache.values() {
        let idx = confirmation_bucket(entry.observation, tip_height);
        counts[idx] += 1;
    }

    for (i, label) in crate::metrics::CONFIRMATION_STATUS_LABELS
        .iter()
        .enumerate()
    {
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .set(counts[i]);
    }
}

fn update_confirmation_metrics_for_change(
    metrics: &Metrics,
    tip_height: u32,
    previous: Option<CachedDepositObservation>,
    current: Option<CachedDepositObservation>,
) {
    if let Some(previous) = previous {
        let label =
            crate::metrics::CONFIRMATION_STATUS_LABELS[confirmation_bucket(previous, tip_height)];
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .dec();
    }
    if let Some(current) = current {
        let label =
            crate::metrics::CONFIRMATION_STATUS_LABELS[confirmation_bucket(current, tip_height)];
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .inc();
    }
}

fn confirmation_bucket(observation: CachedDepositObservation, tip_height: u32) -> usize {
    match observation {
        CachedDepositObservation::NotFound => 0,
        CachedDepositObservation::InMempool => 1,
        CachedDepositObservation::InBlock { height } => {
            let confirmations = (tip_height + 1).saturating_sub(height);
            // +2 skips the not_found/mempool slots; 0..=6 confirmations land in indices 2..=8.
            (2 + confirmations.min(6) as usize).min(8)
        }
    }
}

fn send_observation(
    client_tx: &tokio::sync::mpsc::Sender<MonitorMessage>,
    outpoint: bitcoin::OutPoint,
    observation: CachedDepositObservation,
) {
    let result = client_tx.try_send(MonitorMessage::RecordDepositObservation {
        outpoint,
        observation,
    });
    match result {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!("Dropping deposit observation because the monitor channel is full");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            debug!("Dropping deposit observation because the monitor channel is closed");
        }
    }
}

fn send_forget(client_tx: &tokio::sync::mpsc::Sender<MonitorMessage>, outpoint: bitcoin::OutPoint) {
    match client_tx.try_send(MonitorMessage::ForgetDeposit(outpoint)) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!("Dropping deposit observation removal because the monitor channel is full");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            debug!("Dropping deposit observation removal because the monitor channel is closed");
        }
    }
}

#[derive(Debug)]
struct DepositCheckRequest {
    outpoint: bitcoin::OutPoint,
    confirmation_threshold: u32,
    result_tx: oneshot::Sender<Result<DepositConfirmation, DepositConfirmError>>,
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    block_height_rx: tokio::sync::watch::Receiver<u32>,
}

impl MonitorClient {
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
                .send(MonitorMessage::ConfirmDeposit(request))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))?
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("confirm_deposit timed out waiting for Bitcoin deposit check")
        })?
    }

    /// Round-trip a request through the monitor loop, bounded so callers fail
    /// rather than block while the loop is still resolving its start checkpoint.
    async fn request<T>(
        &self,
        message: impl FnOnce(oneshot::Sender<Result<T>>) -> MonitorMessage,
        what: &str,
    ) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        tokio::time::timeout(MONITOR_REQUEST_TIMEOUT, async {
            self.tx
                .send(message(tx))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))?
        })
        .await
        .map_err(|_| anyhow::anyhow!("{what} timed out waiting for the Bitcoin monitor"))?
    }

    pub async fn get_recent_fee_rate(&self, conf_target: u16) -> Result<FeeRate> {
        self.request(
            |tx| MonitorMessage::GetRecentFeeRate(conf_target, tx),
            "get_recent_fee_rate",
        )
        .await
    }

    pub async fn broadcast_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        self.request(
            |tx| MonitorMessage::BroadcastTransaction(transaction, tx),
            "broadcast_transaction",
        )
        .await
    }

    pub async fn get_transaction_status(&self, txid: bitcoin::Txid) -> Result<TxStatus> {
        self.request(
            |tx| MonitorMessage::GetTransactionStatus(txid, tx),
            "get_transaction_status",
        )
        .await
    }
}

enum MonitorMessage {
    // Checks the given OutPoint against the monitor's current Bitcoin tip.
    ConfirmDeposit(DepositCheckRequest),

    // Returns an estimated fee rate targeting confirmation within `conf_target` blocks.
    GetRecentFeeRate(u16, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),

    // Query the status of a transaction (confirmed, in mempool, or not found).
    GetTransactionStatus(bitcoin::Txid, oneshot::Sender<Result<TxStatus>>),

    // Updates `deposit_observation_cache`
    RecordDepositObservation {
        outpoint: bitcoin::OutPoint,
        observation: CachedDepositObservation,
    },

    // Drop a deposit from `deposit_observation_cache`
    ForgetDeposit(bitcoin::OutPoint),
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

    fn bucket(metrics: &Metrics, label: &str) -> i64 {
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .get()
    }

    fn cache_requests(metrics: &Metrics, cache: &str, result: &str) -> u64 {
        metrics
            .deposit_lookup_cache_requests_total
            .with_label_values(&[cache, result])
            .get()
    }

    fn entry(observation: CachedDepositObservation, last_updated_tip: u32) -> CachedDepositEntry {
        CachedDepositEntry {
            observation,
            last_updated_tip,
        }
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
    async fn process_deposit_check_reuses_cached_tx_block_for_shared_txid() {
        let metrics = Arc::new(fresh_metrics());
        let cache = SharedDepositLookupCache::new(metrics.clone());
        let txid = make_outpoint(1).txid;
        let block_info = HashCheckpoint::new(42, block_hash(2));
        cache.put_tx_block(txid, block_info);
        let (client_tx, _client_rx) = tokio::sync::mpsc::channel(10);
        let mut result_rxs = Vec::new();
        let (_, kyoto_client) = Monitor::build_kyoto_node(
            &MonitorConfig::default(),
            HashCheckpoint::from_genesis(bitcoin::Network::Bitcoin),
        );

        for vout in [0, 1] {
            let (request, result_rx) = deposit_check_request_for(bitcoin::OutPoint { txid, vout });
            result_rxs.push(result_rx);
            Monitor::process_deposit_check(
                HashCheckpoint::new(50, block_hash(3)),
                Arc::new(corepc_client::client_sync::v29::Client::new(
                    "http://127.0.0.1:1",
                )),
                kyoto_client.requester.clone(),
                client_tx.clone(),
                cache.clone(),
                request,
            )
            .await;
        }

        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 2);
        for result_rx in result_rxs {
            assert_eq!(
                result_rx.await.unwrap().unwrap(),
                DepositConfirmation::InsufficientConfirmations { confirmations: 9 }
            );
        }
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

    #[tokio::test]
    async fn checkpoint_at_height_waits_out_a_lagging_bitcoind() {
        use std::sync::atomic::AtomicU32;
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        const HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        // `getblockhash` replies "out of range" this many times before the block lands.
        const LAGGING_REPLIES: u32 = 2;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let block_hash_calls = Arc::new(AtomicU32::new(0));

        tokio::spawn({
            let block_hash_calls = block_hash_calls.clone();
            async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let block_hash_calls = block_hash_calls.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        while let Ok(n) = sock.read(&mut buf).await {
                            if n == 0 {
                                return;
                            }
                            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let id = req
                                .rsplit_once("\"id\":")
                                .and_then(|(_, rest)| rest.split([',', '}']).next())
                                .unwrap_or("0")
                                .to_string();
                            let out_of_range = |id: &str| {
                                format!(
                                    r#"{{"result":null,"error":{{"code":-8,"message":"Block height out of range"}},"id":{id}}}"#
                                )
                            };
                            let body = if req.contains("\"getblockhash\"") {
                                if block_hash_calls.fetch_add(1, Ordering::SeqCst) < LAGGING_REPLIES
                                {
                                    out_of_range(&id)
                                } else {
                                    format!(r#"{{"result":"{HASH}","error":null,"id":{id}}}"#)
                                }
                            } else {
                                // The progress-logging `getblockchaininfo`; failing it
                                // exercises the branch that logs without a height.
                                out_of_range(&id)
                            };
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            }
        });

        let rpc = Arc::new(corepc_client::client_sync::v29::Client::new(&format!(
            "http://{addr}"
        )));

        // The old "-8 is permanent" path returned a genesis checkpoint on the first reply.
        let checkpoint = tokio::time::timeout(
            Duration::from_secs(60),
            Monitor::checkpoint_at_height(&rpc, 300_000),
        )
        .await
        .expect("checkpoint_at_height gave up instead of waiting for bitcoind");

        assert_eq!(checkpoint.height, 300_000);
        assert_eq!(checkpoint.hash.to_string(), HASH);
        assert!(block_hash_calls.load(Ordering::SeqCst) > LAGGING_REPLIES);
    }

    #[test]
    fn empty_cache_writes_all_labels_as_zero() {
        let metrics = fresh_metrics();
        let mut cache: HashMap<bitcoin::OutPoint, CachedDepositEntry> = HashMap::new();

        rebuild_confirmation_metrics_inner(&mut cache, 100, &metrics);

        for label in crate::metrics::CONFIRMATION_STATUS_LABELS {
            assert_eq!(bucket(&metrics, label), 0, "label {label} should be zero");
        }
    }

    #[test]
    fn observation_to_bucket_mapping() {
        // (observation, tip, expected bucket). Covers NotFound, InMempool,
        // and InBlock at 0 (height > tip via saturating_sub), 1, 5, 6 (boundary),
        // and a far-clamp case.
        let cases: &[(CachedDepositObservation, u32, &str)] = &[
            (CachedDepositObservation::NotFound, 100, "not_found"),
            (CachedDepositObservation::InMempool, 100, "mempool"),
            (CachedDepositObservation::InBlock { height: 101 }, 100, "0"),
            (CachedDepositObservation::InBlock { height: 100 }, 100, "1"),
            (CachedDepositObservation::InBlock { height: 96 }, 100, "5"),
            (
                CachedDepositObservation::InBlock { height: 95 },
                100,
                "6_plus",
            ),
            (
                CachedDepositObservation::InBlock { height: 0 },
                100,
                "6_plus",
            ),
        ];

        for &(observation, tip, want_label) in cases {
            let metrics = fresh_metrics();
            let mut cache = HashMap::from([(make_outpoint(1), entry(observation, tip))]);
            rebuild_confirmation_metrics_inner(&mut cache, tip, &metrics);
            assert_eq!(
                bucket(&metrics, want_label),
                1,
                "{observation:?} with tip {tip} should land in {want_label}"
            );
        }
    }

    #[test]
    fn incremental_observation_changes_update_affected_buckets() {
        let metrics = fresh_metrics();
        let tip = 100;

        update_confirmation_metrics_for_change(
            &metrics,
            tip,
            None,
            Some(CachedDepositObservation::InMempool),
        );
        assert_eq!(bucket(&metrics, "mempool"), 1);

        update_confirmation_metrics_for_change(
            &metrics,
            tip,
            Some(CachedDepositObservation::InMempool),
            Some(CachedDepositObservation::InBlock { height: 100 }),
        );
        assert_eq!(bucket(&metrics, "mempool"), 0);
        assert_eq!(bucket(&metrics, "1"), 1);

        update_confirmation_metrics_for_change(
            &metrics,
            tip,
            Some(CachedDepositObservation::InBlock { height: 100 }),
            Some(CachedDepositObservation::InBlock { height: 100 }),
        );
        assert_eq!(bucket(&metrics, "1"), 1);

        update_confirmation_metrics_for_change(
            &metrics,
            tip,
            Some(CachedDepositObservation::InBlock { height: 100 }),
            None,
        );
        assert_eq!(bucket(&metrics, "1"), 0);
    }

    #[test]
    fn tip_advance_shifts_buckets_without_fresh_observations() {
        let metrics = fresh_metrics();
        let mut cache = HashMap::from([(
            make_outpoint(1),
            entry(CachedDepositObservation::InBlock { height: 100 }, 100),
        )]);

        // Tip 100: confirmations = (100+1) - 100 = 1 → bucket "1".
        rebuild_confirmation_metrics_inner(&mut cache, 100, &metrics);
        assert_eq!(bucket(&metrics, "1"), 1);

        // Tip 101 (no re-observation): confirmations = 2 → bucket "2".
        rebuild_confirmation_metrics_inner(&mut cache, 101, &metrics);
        assert_eq!(bucket(&metrics, "1"), 0);
        assert_eq!(bucket(&metrics, "2"), 1);
    }

    #[test]
    fn stale_entries_gced_at_inclusive_boundary() {
        let metrics = fresh_metrics();
        let tip = 100;
        let mut cache = HashMap::from([
            // On the boundary: kept (inclusive).
            (
                make_outpoint(1),
                entry(
                    CachedDepositObservation::InMempool,
                    tip - STALE_OBSERVATION_BLOCKS,
                ),
            ),
            // Just past the boundary: dropped.
            (
                make_outpoint(2),
                entry(
                    CachedDepositObservation::InMempool,
                    tip - STALE_OBSERVATION_BLOCKS - 1,
                ),
            ),
        ]);

        rebuild_confirmation_metrics_inner(&mut cache, tip, &metrics);

        assert_eq!(cache.len(), 1, "entry past boundary should be GC'd");
        assert!(cache.contains_key(&make_outpoint(1)));
        assert_eq!(bucket(&metrics, "mempool"), 1);
    }

    #[test]
    fn tip_zero_bootstrap_keeps_entries() {
        // Before the first block, tip is 0. Entries with `last_updated_tip = 0`
        // must not be GC'd immediately, otherwise fresh observations would
        // vanish before the first block arrives.
        let metrics = fresh_metrics();
        let mut cache = HashMap::from([(
            make_outpoint(1),
            entry(CachedDepositObservation::InMempool, 0),
        )]);

        rebuild_confirmation_metrics_inner(&mut cache, 0, &metrics);

        assert_eq!(cache.len(), 1);
        assert_eq!(bucket(&metrics, "mempool"), 1);
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
