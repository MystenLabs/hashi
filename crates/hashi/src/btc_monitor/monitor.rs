// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use futures::FutureExt;
use futures::StreamExt;
use futures::TryStreamExt;
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
use crate::deposit_tracker::DiscoveryResolution;
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
const BLOCK_SCAN_RETRY_BASE_DELAY: Duration = Duration::from_secs(1);
const DEPOSIT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
// Also bounds the check worker itself: the underlying bitcoind HTTP client
// times out per call (60s), so an unbounded worker could hold RPC slots for
// minutes after every caller's own `DEPOSIT_CHECK_TIMEOUT` budget expired.
const DEPOSIT_CHECK_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_PENDING_DEPOSIT_CHECKS_PER_OUTPOINT: usize = 100;
// At most 16 concurrent txid lookups: bitcoind's default rpcworkqueue is 16,
// and overflowing it fails calls outright ("Work queue depth exceeded").
const UTXO_HEIGHT_LOOKUP_CONCURRENCY: usize = 16;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UtxoHeightSnapshot {
    pub(crate) tip: HashCheckpoint,
    pub(crate) confirmation_height_by_txid: BTreeMap<bitcoin::Txid, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxBlockLookup {
    Confirmed(HashCheckpoint),
    InMempool,
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum DepositConfirmError {
    #[error("UTXO {txid}:{vout} has already been spent on Bitcoin")]
    UtxoSpent { txid: bitcoin::Txid, vout: u32 },
    #[error("transaction {txid} has no output at vout {vout}")]
    InvalidVout { txid: bitcoin::Txid, vout: u32 },
    #[error("Bitcoin deposit check timed out")]
    TimedOut,
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
    retry_round: u32,
    result: Result<bitcoin::Block>,
}

struct DepositCheckWorkerResult {
    generation: u64,
    result_tx: oneshot::Sender<Result<DepositConfirmation, DepositConfirmError>>,
    result: Result<DepositConfirmation, DepositConfirmError>,
}

struct DepositDiscoveryWorkerResult {
    token: Option<crate::deposit_tracker::ObservationToken>,
    generation: u64,
    outpoint: bitcoin::OutPoint,
    result: Result<DepositStatus, DepositConfirmError>,
}

struct DepositDiscoveryContext {
    tip: HashCheckpoint,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    generation: u64,
}

struct UtxoHeightResolutionContext {
    tip: HashCheckpoint,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    block_sequence: Arc<AtomicU64>,
    captured_sequence: u64,
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
    tip: Option<HashCheckpoint>,
    start_checkpoint: HashCheckpoint,
    /// Set once Kyoto's initial filter sync completes; gates per-block side
    /// effects so the catch-up replay doesn't run them per header.
    synced: bool,
    block_height_tx: tokio::sync::watch::Sender<u32>,
    block_sequence: Arc<AtomicU64>,
    requester: kyoto::Requester,
    deposit_check_workers: JoinSet<DepositCheckWorkerResult>,
    deposit_discovery_workers: JoinSet<DepositDiscoveryWorkerResult>,
    pending_deposit_checks: HashMap<bitcoin::OutPoint, Vec<DepositCheckRequest>>,
    block_scan_workers: JoinSet<BlockScanResult>,
    /// Pending block scans. The front entry is the one running in
    /// `block_scan_workers` (if any); it is only popped when its result
    /// arrives, so cancelled scans are respawned rather than lost.
    block_scan_queue: VecDeque<(HashCheckpoint, u32)>,
    deposit_lookup_cache: SharedDepositLookupCache,
    deposit_tracker: DepositTracker,
    rpc_workers: JoinSet<()>,
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
    fn confirm_deposit(&mut self, request: DepositCheckRequest) {
        debug!("Checking deposit for {}", request.outpoint.txid);

        if request.result_tx.is_closed() {
            return;
        }

        // Refuse checks until Kyoto is synced: catch-up `Connected` events set
        // `self.tip` but are never block-scanned, so a `NotFound`/`InMempool`
        // status discovered against a catch-up tip would go permanently stale
        // if the transaction confirms in a block connected before sync
        // completes. Callers retry when sync completion bumps the block
        // sequence.
        let Some(tip) = self.tip.filter(|_| self.synced) else {
            let _ = request.result_tx.send(Err(anyhow::anyhow!(
                "Bitcoin monitor is not synced to a chain tip"
            )
            .into()));
            return;
        };

        let discovery = self.deposit_tracker.discovery(&request.outpoint);
        match discovery {
            DepositDiscovery::Discover(token) => {
                let outpoint = request.outpoint;
                if self.queue_deposit_check(request) {
                    let context = self.deposit_discovery_context(tip);
                    self.deposit_discovery_workers
                        .spawn(process_deposit_discovery(context, outpoint, Some(token)));
                } else {
                    let _ = self
                        .deposit_tracker
                        .resolve_discovery(token, Err::<DepositStatus, ()>(()));
                }
            }
            DepositDiscovery::Pending => {
                self.queue_deposit_check(request);
            }
            DepositDiscovery::Untracked => {
                let outpoint = request.outpoint;
                let already_pending = self.pending_deposit_checks.contains_key(&outpoint);
                if self.queue_deposit_check(request) && !already_pending {
                    let context = self.deposit_discovery_context(tip);
                    self.deposit_discovery_workers
                        .spawn(process_deposit_discovery(context, outpoint, None));
                }
            }
            DepositDiscovery::Known(status) => self.start_deposit_check(tip, request, status),
        }
    }

    fn queue_deposit_check(&mut self, request: DepositCheckRequest) -> bool {
        let requests = self
            .pending_deposit_checks
            .entry(request.outpoint)
            .or_default();
        requests.retain(|request| !request.result_tx.is_closed());
        if requests.len() >= MAX_PENDING_DEPOSIT_CHECKS_PER_OUTPOINT {
            let _ = request.result_tx.send(Err(anyhow::anyhow!(
                "Too many pending checks for Bitcoin deposit {}",
                request.outpoint
            )
            .into()));
            false
        } else {
            requests.push(request);
            true
        }
    }

    fn deposit_discovery_context(&self, tip: HashCheckpoint) -> DepositDiscoveryContext {
        DepositDiscoveryContext {
            tip,
            bitcoind_rpc: self.bitcoind_rpc.clone(),
            requester: self.requester.clone(),
            deposit_lookup_cache: self.deposit_lookup_cache.clone(),
            generation: self.deposit_tracker.bitcoin_generation(),
        }
    }

    fn start_deposit_check(
        &mut self,
        tip: HashCheckpoint,
        request: DepositCheckRequest,
        status: DepositStatus,
    ) {
        self.deposit_check_workers.spawn(process_deposit_check(
            self.deposit_tracker.bitcoin_generation(),
            tip,
            self.bitcoind_rpc.clone(),
            request,
            status,
        ));
    }

    fn queue_block_scan(&mut self, checkpoint: HashCheckpoint) {
        if !self.deposit_tracker.has_scan_candidates() {
            return;
        }

        self.block_scan_queue.push_back((checkpoint, 0));
        self.start_next_block_scan();
    }

    fn cancel_deposit_workers(&mut self) {
        self.deposit_check_workers.abort_all();
        self.deposit_discovery_workers.abort_all();
        for request in self
            .pending_deposit_checks
            .drain()
            .flat_map(|(_, requests)| requests)
        {
            let _ = request.result_tx.send(Err(anyhow::anyhow!(
                "Bitcoin deposit check was invalidated by a chain update"
            )
            .into()));
        }
        self.block_scan_workers.abort_all();
    }

    /// Drop only the scans for disconnected blocks. Scans for blocks that
    /// survived the reorg must still run: nothing re-discovers a
    /// `NotFound`/`InMempool` entry, so a dropped scan would leave a deposit
    /// confirmed in one of those blocks stuck forever.
    fn drop_disconnected_block_scans(&mut self, disconnected: &[HashCheckpoint]) {
        self.block_scan_queue
            .retain(|(checkpoint, _)| !disconnected.contains(checkpoint));
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

    fn finish_deposit_discovery(
        &mut self,
        join_result: std::result::Result<DepositDiscoveryWorkerResult, tokio::task::JoinError>,
    ) {
        let result = match join_result {
            Ok(result) => result,
            Err(e) if e.is_cancelled() => return,
            Err(e) => {
                error!("Deposit discovery worker task failed: {e}");
                return;
            }
        };
        if result.generation != self.deposit_tracker.bitcoin_generation() {
            return;
        }

        let status = match result.token {
            Some(token) => match self.deposit_tracker.resolve_discovery(token, result.result) {
                DiscoveryResolution::Complete(result) => result,
                DiscoveryResolution::Pending => return,
                DiscoveryResolution::Untracked => Err(anyhow::anyhow!(
                    "Bitcoin deposit request left the tracker during discovery"
                )
                .into()),
            },
            None => result.result,
        };
        let requests = self
            .pending_deposit_checks
            .remove(&result.outpoint)
            .unwrap_or_default();
        let Some(tip) = self.tip else {
            for request in requests {
                let _ = request.result_tx.send(Err(anyhow::anyhow!(
                    "Bitcoin deposit check was invalidated by a chain update"
                )
                .into()));
            }
            return;
        };
        for request in requests {
            if request.result_tx.is_closed() {
                continue;
            }
            match &status {
                Ok(status) => self.start_deposit_check(tip, request, status.clone()),
                Err(e) => {
                    let _ = request
                        .result_tx
                        .send(Err(anyhow::anyhow!(e.to_string()).into()));
                }
            }
        }
    }

    fn start_next_block_scan(&mut self) {
        if !self.block_scan_workers.is_empty() {
            return;
        }

        if !self.deposit_tracker.has_scan_candidates() {
            self.block_scan_queue.clear();
            return;
        }

        // Scan order does not affect correctness, so run the scan with the
        // fewest failed attempts first: its backoff sleep happens inside
        // the single-flight worker, and a persistently failing block must
        // not delay scans of fresh blocks. Move the pick to the front,
        // where `finish_block_scan` expects the in-flight scan.
        let Some(next) = self
            .block_scan_queue
            .iter()
            .enumerate()
            .min_by_key(|(index, (_, retry_round))| (*retry_round, *index))
            .map(|(index, _)| index)
        else {
            return;
        };
        let (checkpoint, retry_round) = self.block_scan_queue.remove(next).unwrap();
        self.block_scan_queue.push_front((checkpoint, retry_round));

        let requester = self.requester.clone();
        let generation = self.deposit_tracker.bitcoin_generation();
        self.block_scan_workers.spawn(async move {
            let scan = AssertUnwindSafe(async {
                if retry_round > 0 {
                    tokio::time::sleep(BLOCK_SCAN_RETRY_BASE_DELAY * 2u32.pow(retry_round.min(5)))
                        .await;
                }
                fetch_block_for_scan(&requester, checkpoint).await
            })
            .catch_unwind()
            .await;
            BlockScanResult {
                checkpoint,
                generation,
                retry_round,
                result: scan.unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "Bitcoin block scan task panicked for {} at height {}",
                        checkpoint.hash,
                        checkpoint.height,
                    ))
                }),
            }
        });
    }

    fn finish_block_scan(
        &mut self,
        join_result: std::result::Result<BlockScanResult, tokio::task::JoinError>,
    ) {
        match join_result {
            // The reset or reorg that bumped the generation already cleared
            // this scan from the queue or decided it should be rescanned;
            // either way the front of the queue is no longer this scan.
            Ok(result) if result.generation != self.deposit_tracker.bitcoin_generation() => {}
            Ok(BlockScanResult {
                checkpoint,
                generation,
                result: Ok(block),
                ..
            }) => {
                self.block_scan_queue.pop_front();
                self.deposit_tracker
                    .apply_block_if_current(generation, checkpoint, &block);
            }
            Ok(BlockScanResult {
                checkpoint,
                retry_round,
                result: Err(e),
                ..
            }) => {
                error!(
                    "Failed to scan Bitcoin block {} at height {}: {e}",
                    checkpoint.hash, checkpoint.height,
                );
                self.block_scan_queue.pop_front();
                self.block_scan_queue
                    .push_back((checkpoint, retry_round.saturating_add(1)));
            }
            Err(e) if e.is_cancelled() => {}
            // Scans catch panics internally, so this should be unreachable.
            // The scan stays at the front of the queue and is respawned.
            Err(e) => error!("Block scan worker task failed: {e}"),
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
            // `replenish_trusted_peers` keeps the whitelist stocked; if it still
            // drains, the node exits and the supervision loop rebuilds it.
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
        let deposit_tracker = DepositTracker::new(metrics.clone());
        Self::run_with_tracker(config, metrics, deposit_tracker)
    }

    pub(crate) fn run_with_tracker(
        config: MonitorConfig,
        metrics: Arc<Metrics>,
        deposit_tracker: DepositTracker,
    ) -> Result<(MonitorClient, Service)> {
        let bitcoind_rpc = crate::btc_monitor::config::new_rpc_client(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);
        let (block_height_tx, block_height_rx) = tokio::sync::watch::channel(0u32);
        let block_sequence = Arc::new(AtomicU64::new(0));

        let service_block_sequence = block_sequence.clone();
        let service = Service::new().spawn_aborting({
            async move {
                let bitcoind_rpc = Arc::new(bitcoind_rpc);

                let start_checkpoint = Self::resolve_start_checkpoint(&bitcoind_rpc, &config).await;
                let (kyoto_node, kyoto_client) = Self::build_kyoto_node(&config, start_checkpoint);
                let trusted_peer_rotation = config.trusted_peers.clone().into_iter().cycle();

                let mut monitor = Monitor {
                    config,
                    metrics: metrics.clone(),
                    bitcoind_rpc,
                    tip: None,
                    start_checkpoint,
                    synced: false,
                    block_height_tx,
                    block_sequence: service_block_sequence,
                    requester: kyoto_client.requester.clone(),
                    deposit_check_workers: JoinSet::new(),
                    deposit_discovery_workers: JoinSet::new(),
                    pending_deposit_checks: HashMap::new(),
                    block_scan_workers: JoinSet::new(),
                    block_scan_queue: VecDeque::new(),
                    deposit_lookup_cache: SharedDepositLookupCache::new(metrics),
                    deposit_tracker,
                    rpc_workers: JoinSet::new(),
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
                block_sequence,
            },
            service,
        ))
    }

    /// Invalidate Bitcoin-tip-dependent work before resetting Kyoto state.
    fn reset_bitcoin_state_for_restart(&mut self) {
        self.block_sequence.fetch_add(1, Ordering::SeqCst);
        self.synced = false;
        self.tip = None;
        self.cancel_deposit_workers();
        self.block_scan_queue.clear();
        self.deposit_lookup_cache = self.deposit_lookup_cache.fresh();
        self.deposit_tracker.reset_bitcoin_state();
        self.metrics.kyoto_restarts.inc();
        self.metrics.kyoto_connected_peers.set(0);
        self.metrics.kyoto_synced.set(0);
        self.metrics.kyoto_consecutive_failures.set(0);
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

            self.reset_bitcoin_state_for_restart();

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
                    self.finish_deposit_check(join_result);
                }
                Some(join_result) = self.deposit_discovery_workers.join_next() => {
                    self.finish_deposit_discovery(join_result);
                }
                Some(join_result) = self.block_scan_workers.join_next() => {
                    self.finish_block_scan(join_result);
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
                    self.publish_block_height(checkpoint.height);
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
                self.drop_disconnected_block_scans(&disconnected);
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
                        self.publish_block_height(new_tip.height);
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
        self.publish_block_height(tip.height);
    }

    fn publish_block_height(&self, height: u32) {
        self.block_sequence.fetch_add(1, Ordering::SeqCst);
        let _ = self.block_height_tx.send(height);
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::CheckDeposit(request) => {
                self.confirm_deposit(request);
            }
            MonitorMessage::ResolveUtxoConfirmationHeights(txids, result_tx) => {
                let Some(tip) = self.tip.filter(|_| self.synced) else {
                    let _ = result_tx.send(Err(anyhow::anyhow!(
                        "Bitcoin monitor is not synced to a chain tip"
                    )));
                    return;
                };
                let context = UtxoHeightResolutionContext {
                    tip,
                    bitcoind_rpc: self.bitcoind_rpc.clone(),
                    requester: self.requester.clone(),
                    deposit_lookup_cache: self.deposit_lookup_cache.clone(),
                    block_sequence: self.block_sequence.clone(),
                    captured_sequence: self.block_sequence.load(Ordering::SeqCst),
                };
                self.rpc_workers
                    .spawn(Self::resolve_utxo_confirmation_heights(
                        context, txids, result_tx,
                    ));
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

    async fn resolve_utxo_confirmation_heights(
        context: UtxoHeightResolutionContext,
        txids: BTreeSet<bitcoin::Txid>,
        result_tx: oneshot::Sender<Result<UtxoHeightSnapshot>>,
    ) {
        let UtxoHeightResolutionContext {
            tip,
            bitcoind_rpc,
            requester,
            deposit_lookup_cache,
            block_sequence,
            captured_sequence,
        } = context;
        let result = assemble_utxo_height_snapshot(
            tip,
            block_sequence,
            captured_sequence,
            txids,
            move |txid| {
                lookup_tx_block(
                    bitcoind_rpc.clone(),
                    requester.clone(),
                    deposit_lookup_cache.clone(),
                    txid,
                    tip,
                )
            },
        )
        .await;
        let _ = result_tx.send(result);
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

async fn fetch_block_for_scan(
    requester: &kyoto::Requester,
    checkpoint: HashCheckpoint,
) -> Result<bitcoin::Block> {
    let indexed_block =
        tokio::time::timeout(BLOCK_SCAN_TIMEOUT, requester.get_block(checkpoint.hash))
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

async fn process_deposit_discovery(
    context: DepositDiscoveryContext,
    outpoint: bitcoin::OutPoint,
    token: Option<crate::deposit_tracker::ObservationToken>,
) -> DepositDiscoveryWorkerResult {
    let generation = context.generation;
    let discovery = AssertUnwindSafe(discover_deposit(
        context.bitcoind_rpc,
        context.requester,
        context.deposit_lookup_cache,
        outpoint,
        context.tip,
    ));
    let result = match tokio::time::timeout(DEPOSIT_DISCOVERY_TIMEOUT, discovery.catch_unwind())
        .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            Err(anyhow::anyhow!("Bitcoin deposit discovery task panicked for {outpoint}").into())
        }
        Err(_) => Err(anyhow::anyhow!("Timed out discovering Bitcoin deposit {outpoint}").into()),
    };
    DepositDiscoveryWorkerResult {
        token,
        generation,
        outpoint,
        result,
    }
}

async fn process_deposit_check(
    generation: u64,
    tip: HashCheckpoint,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    request: DepositCheckRequest,
    status: DepositStatus,
) -> DepositCheckWorkerResult {
    let DepositCheckRequest {
        outpoint,
        confirmation_threshold,
        result_tx,
    } = request;
    let result = tokio::time::timeout(
        DEPOSIT_CHECK_TIMEOUT,
        check_result_from_status(status, tip, confirmation_threshold, bitcoind_rpc, outpoint),
    )
    .await
    .unwrap_or(Err(DepositConfirmError::TimedOut));
    DepositCheckWorkerResult {
        generation,
        result_tx,
        result,
    }
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

async fn lookup_tx_block(
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    txid: bitcoin::Txid,
    tip: HashCheckpoint,
) -> Result<TxBlockLookup, DepositConfirmError> {
    if let Some(block_info) = deposit_lookup_cache.get_tx_block(&txid) {
        return Ok(TxBlockLookup::Confirmed(block_info));
    }

    debug!("Looking up block for transaction {txid}");
    require_core_checkpoint(&bitcoind_rpc, tip, "before transaction lookup").await?;
    let tx_info = match btc_rpc_call(&bitcoind_rpc, move |rpc| {
        rpc.get_raw_transaction_verbose(txid)
    })
    .await
    {
        Ok(tx_info) => tx_info,
        // -5 also covers "-txindex off" and "txindex still indexing";
        // only the ready-index message is a durable not-found.
        Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(e)))
            if e.code == -5
                && e.message
                    .starts_with("No such mempool or blockchain transaction") =>
        {
            require_core_checkpoint(&bitcoind_rpc, tip, "after transaction lookup").await?;
            return Ok(TxBlockLookup::NotFound);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to look up txid {txid}: {e}").into());
        }
    };
    let tx_info = tx_info
        .into_model()
        .map_err(|e| anyhow::anyhow!("Failed to parse transaction info for {txid}: {e}"))?;
    let Some(block_hash) = tx_info.block_hash else {
        require_core_checkpoint(&bitcoind_rpc, tip, "after transaction lookup").await?;
        return Ok(TxBlockLookup::InMempool);
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
    Ok(TxBlockLookup::Confirmed(block_info))
}

async fn assemble_utxo_height_snapshot<F, Fut>(
    tip: HashCheckpoint,
    block_sequence: Arc<AtomicU64>,
    captured_sequence: u64,
    txids: BTreeSet<bitcoin::Txid>,
    mut lookup: F,
) -> Result<UtxoHeightSnapshot>
where
    F: FnMut(bitcoin::Txid) -> Fut,
    Fut: Future<Output = Result<TxBlockLookup, DepositConfirmError>>,
{
    let confirmation_height_by_txid = futures::stream::iter(txids)
        .map(move |txid| {
            let lookup = lookup(txid);
            async move {
                match lookup.await? {
                    TxBlockLookup::Confirmed(checkpoint) => Ok((txid, checkpoint.height)),
                    TxBlockLookup::InMempool => {
                        Err(anyhow::anyhow!("transaction {txid} is in the mempool"))
                    }
                    TxBlockLookup::NotFound => {
                        Err(anyhow::anyhow!("transaction {txid} was not found"))
                    }
                }
            }
        })
        .buffer_unordered(UTXO_HEIGHT_LOOKUP_CONCURRENCY)
        .try_collect::<BTreeMap<_, _>>()
        .await?;

    let completed_sequence = block_sequence.load(Ordering::SeqCst);
    if completed_sequence != captured_sequence {
        anyhow::bail!(
            "Bitcoin chain tip changed while resolving UTXO confirmation heights \
             (sequence {captured_sequence} to {completed_sequence})"
        );
    }

    Ok(UtxoHeightSnapshot {
        tip,
        confirmation_height_by_txid,
    })
}

async fn discover_deposit(
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    outpoint: bitcoin::OutPoint,
    tip: HashCheckpoint,
) -> Result<DepositStatus, DepositConfirmError> {
    let txid = outpoint.txid;
    let block_info = match lookup_tx_block(
        bitcoind_rpc,
        requester.clone(),
        deposit_lookup_cache.clone(),
        txid,
        tip,
    )
    .await?
    {
        TxBlockLookup::Confirmed(block_info) => block_info,
        TxBlockLookup::InMempool => return Ok(DepositStatus::InMempool),
        TxBlockLookup::NotFound => return Ok(DepositStatus::NotFound),
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

async fn get_block_hash(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    height: u32,
) -> Result<bitcoin::BlockHash> {
    btc_rpc_call(bitcoind_rpc, move |rpc| {
        rpc.call::<bitcoin::BlockHash>("getblockhash", &[serde_json::json!(height)])
    })
    .await
    .map_err(anyhow::Error::from)
}

async fn require_core_checkpoint(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    tip: HashCheckpoint,
    context: &str,
) -> Result<(), DepositConfirmError> {
    let bitcoind_hash = get_block_hash(bitcoind_rpc, tip.height)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to read Bitcoin Core block at Kyoto height {} {context}: {e}",
                tip.height
            )
        })?;
    if bitcoind_hash != tip.hash {
        return Err(anyhow::anyhow!(
            "Bitcoin Core has {bitcoind_hash} at height {}, but captured Kyoto checkpoint is {} {context}",
            tip.height,
            tip.hash,
        )
        .into());
    }
    Ok(())
}

async fn get_tx_out(
    bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    outpoint: bitcoin::OutPoint,
    include_mempool: bool,
) -> Result<Option<serde_json::Value>, corepc_client::client_sync::Error> {
    btc_rpc_call(bitcoind_rpc, move |rpc| {
        rpc.call::<Option<serde_json::Value>>(
            "gettxout",
            &[
                serde_json::json!(outpoint.txid),
                serde_json::json!(outpoint.vout),
                serde_json::json!(include_mempool),
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
    let bitcoind_tip = get_best_block(&bitcoind_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Bitcoin Core tip: {e}"))?;
    // Bitcoin Core only needs to be on Kyoto's chain at or past `tip`: unspent
    // at a descendant implies unspent at `tip`, and a spend at a descendant is
    // real.
    require_core_checkpoint(&bitcoind_rpc, tip, "before gettxout").await?;

    let unspent = get_tx_out(&bitcoind_rpc, outpoint, true)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check UTXO spent status via gettxout: {e}"))?;
    // With include_mempool, a missing UTXO can mean an *unconfirmed* spend,
    // which can vanish again without a reorg (eviction, replacement). Only a
    // spend missing from the confirmed UTXO set too is reported as
    // `UtxoSpent`; the leader suppresses those until a reorg.
    let spent_in_mempool_only = unspent.is_none()
        && get_tx_out(&bitcoind_rpc, outpoint, false)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to check confirmed UTXO spent status via gettxout: {e}")
            })?
            .is_some();
    let updated_bitcoind_tip = get_best_block(&bitcoind_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to re-read Bitcoin Core tip: {e}"))?;
    if updated_bitcoind_tip != bitcoind_tip {
        return Err(anyhow::anyhow!(
            "Bitcoin Core tip changed from {bitcoind_tip} to {updated_bitcoind_tip} during gettxout"
        )
        .into());
    }
    match unspent {
        Some(response) => {
            let best_block = get_tx_out_best_block(&response)?;
            if best_block != bitcoind_tip {
                return Err(anyhow::anyhow!(
                    "Bitcoin Core UTXO view is at {best_block}, but its captured tip is {bitcoind_tip}",
                )
                .into());
            }
            info!(
                "Deposit {}:{} confirmed with {confirmations}/{confirmation_threshold} confirmations",
                outpoint.txid, outpoint.vout,
            );
            Ok(DepositConfirmation::Confirmed(txout))
        }
        None if spent_in_mempool_only => {
            warn!(
                "Deposit UTXO {}:{} is spent by an unconfirmed transaction. Deferring deposit.",
                outpoint.txid, outpoint.vout,
            );
            Err(anyhow::anyhow!(
                "Deposit UTXO {}:{} is spent by an unconfirmed transaction",
                outpoint.txid,
                outpoint.vout,
            )
            .into())
        }
        None => {
            warn!(
                "Deposit UTXO {}:{} has already been spent on Bitcoin. Rejecting deposit.",
                outpoint.txid, outpoint.vout,
            );
            Err(DepositConfirmError::UtxoSpent {
                txid: outpoint.txid,
                vout: outpoint.vout,
            })
        }
    }
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    block_height_rx: tokio::sync::watch::Receiver<u32>,
    block_sequence: Arc<AtomicU64>,
}

impl MonitorClient {
    /// Subscribe to sync-complete and connected Bitcoin tip updates.
    pub fn subscribe_block_height(&self) -> tokio::sync::watch::Receiver<u32> {
        self.block_height_rx.clone()
    }

    pub(crate) fn block_sequence(&self) -> u64 {
        self.block_sequence.load(Ordering::SeqCst)
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
        tokio::time::timeout(DEPOSIT_CHECK_TIMEOUT, async {
            self.tx
                .send(MonitorMessage::CheckDeposit(request))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))?
        })
        .await
        .map_err(|_| DepositConfirmError::TimedOut)?
    }

    pub(crate) async fn resolve_utxo_confirmation_heights(
        &self,
        txids: BTreeSet<bitcoin::Txid>,
    ) -> Result<UtxoHeightSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::ResolveUtxoConfirmationHeights(txids, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
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

    // Resolves confirmation heights against one stable, synced Bitcoin tip.
    ResolveUtxoConfirmationHeights(
        BTreeSet<bitcoin::Txid>,
        oneshot::Sender<Result<UtxoHeightSnapshot>>,
    ),

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
            tracker.resolve_discovery(token, Ok::<_, ()>(status.clone())),
            DiscoveryResolution::Complete(Ok(status))
        );
    }

    fn test_monitor(metrics: Arc<Metrics>, tracker: DepositTracker) -> Monitor {
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
            block_sequence: Arc::new(AtomicU64::new(0)),
            requester: kyoto_client.requester,
            deposit_check_workers: JoinSet::new(),
            deposit_discovery_workers: JoinSet::new(),
            pending_deposit_checks: HashMap::new(),
            block_scan_workers: JoinSet::new(),
            block_scan_queue: VecDeque::new(),
            deposit_lookup_cache: SharedDepositLookupCache::new(metrics),
            deposit_tracker: tracker,
            rpc_workers: JoinSet::new(),
            trusted_peer_rotation: Vec::new().into_iter().cycle(),
        }
    }

    #[tokio::test]
    async fn lookup_tx_block_returns_cached_confirmation_without_rpc() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let monitor = test_monitor(metrics.clone(), tracker);
        let txid = make_outpoint(1).txid;
        let cached = HashCheckpoint::new(42, block_hash(2));
        monitor.deposit_lookup_cache.put_tx_block(txid, cached);

        let result = lookup_tx_block(
            monitor.bitcoind_rpc.clone(),
            monitor.requester.clone(),
            monitor.deposit_lookup_cache.clone(),
            txid,
            HashCheckpoint::new(100, block_hash(3)),
        )
        .await
        .unwrap();

        assert_eq!(result, TxBlockLookup::Confirmed(cached));
        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 1);
    }

    #[tokio::test]
    async fn cached_utxo_height_batch_returns_captured_tip_and_all_heights() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker);
        let tip = HashCheckpoint::new(100, block_hash(3));
        let first_txid = make_outpoint(1).txid;
        let second_txid = make_outpoint(2).txid;
        monitor.synced = true;
        monitor.tip = Some(tip);
        monitor
            .deposit_lookup_cache
            .put_tx_block(first_txid, HashCheckpoint::new(40, block_hash(4)));
        monitor
            .deposit_lookup_cache
            .put_tx_block(second_txid, HashCheckpoint::new(75, block_hash(5)));
        let (result_tx, result_rx) = oneshot::channel();

        monitor.process_client_message(MonitorMessage::ResolveUtxoConfirmationHeights(
            BTreeSet::from([first_txid, second_txid]),
            result_tx,
        ));
        assert_eq!(monitor.rpc_workers.len(), 1);
        monitor.rpc_workers.join_next().await.unwrap().unwrap();
        let snapshot = result_rx.await.unwrap().unwrap();

        assert_eq!(snapshot.tip, tip);
        assert_eq!(
            snapshot.confirmation_height_by_txid,
            BTreeMap::from([(first_txid, 40), (second_txid, 75)])
        );
        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 2);
    }

    #[tokio::test]
    async fn unsynced_monitor_rejects_utxo_height_batch_without_worker() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker);
        let (result_tx, result_rx) = oneshot::channel();

        monitor.process_client_message(MonitorMessage::ResolveUtxoConfirmationHeights(
            BTreeSet::from([make_outpoint(1).txid]),
            result_tx,
        ));

        assert!(monitor.rpc_workers.is_empty());
        assert!(
            result_rx
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("not synced")
        );
    }

    #[tokio::test]
    async fn utxo_height_batch_rejects_mempool_and_not_found_transactions() {
        let tip = HashCheckpoint::new(100, block_hash(3));
        let txid = make_outpoint(1).txid;

        for (lookup, expected) in [
            (TxBlockLookup::InMempool, "mempool"),
            (TxBlockLookup::NotFound, "not found"),
        ] {
            let result = assemble_utxo_height_snapshot(
                tip,
                Arc::new(AtomicU64::new(0)),
                0,
                BTreeSet::from([txid]),
                move |_| async move { Ok::<_, DepositConfirmError>(lookup) },
            )
            .await;

            assert!(result.unwrap_err().to_string().contains(expected));
        }
    }

    #[tokio::test]
    async fn utxo_height_batch_rejects_monitor_restart_during_lookup() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker);
        let tip = HashCheckpoint::new(100, block_hash(3));
        let txid = make_outpoint(1).txid;
        let captured_sequence = monitor.block_sequence.load(Ordering::SeqCst);
        let lookup_started = Arc::new(tokio::sync::Notify::new());
        let release_lookup = Arc::new(tokio::sync::Notify::new());
        // Hold one uncached-style lookup in flight so the restart is deterministic.
        let worker = tokio::spawn(assemble_utxo_height_snapshot(
            tip,
            monitor.block_sequence.clone(),
            captured_sequence,
            BTreeSet::from([txid]),
            {
                let lookup_started = lookup_started.clone();
                let release_lookup = release_lookup.clone();
                move |_| {
                    let lookup_started = lookup_started.clone();
                    let release_lookup = release_lookup.clone();
                    async move {
                        lookup_started.notify_one();
                        release_lookup.notified().await;
                        Ok::<_, DepositConfirmError>(TxBlockLookup::Confirmed(HashCheckpoint::new(
                            42,
                            block_hash(2),
                        )))
                    }
                }
            },
        ));

        lookup_started.notified().await;
        monitor.reset_bitcoin_state_for_restart();
        release_lookup.notify_one();
        let error = worker.await.unwrap().unwrap_err();

        assert!(error.to_string().contains("chain tip changed"));
    }

    #[test]
    fn deposit_lookup_cache_records_and_replaces_entries() {
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

        let cache = cache.fresh();

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
        let tracker = DepositTracker::new(metrics.clone());
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
    fn stale_discovery_result_does_not_drain_new_generation_waiters() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        let outpoint = make_outpoint(1);
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), outpoint);
        let DepositDiscovery::Discover(stale_token) = tracker.discovery(&outpoint) else {
            panic!("expected initial discovery token");
        };
        let stale_generation = tracker.bitcoin_generation();
        tracker.reset_bitcoin_state();
        let DepositDiscovery::Discover(_current_token) = tracker.discovery(&outpoint) else {
            panic!("expected current discovery token");
        };
        let (request, _result_rx) = deposit_check_request_for(outpoint);
        monitor
            .pending_deposit_checks
            .insert(outpoint, vec![request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(stale_token),
            generation: stale_generation,
            outpoint,
            result: Ok(DepositStatus::NotFound),
        }));

        assert_eq!(monitor.pending_deposit_checks[&outpoint].len(), 1);
        assert_eq!(tracker.discovery(&outpoint), DepositDiscovery::Pending);
    }

    #[test]
    fn replaced_tracker_lease_keeps_waiters_for_the_new_discovery() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        let outpoint = make_outpoint(1);
        let old_request_id = sui_sdk_types::Address::new([1; 32]);
        tracker.upsert_request(old_request_id, outpoint);
        let DepositDiscovery::Discover(old_token) = tracker.discovery(&outpoint) else {
            panic!("expected old discovery token");
        };
        tracker.remove_request(&old_request_id);
        tracker.upsert_request(sui_sdk_types::Address::new([2; 32]), outpoint);
        let DepositDiscovery::Discover(_new_token) = tracker.discovery(&outpoint) else {
            panic!("expected new discovery token");
        };
        let (old_request, _old_result_rx) = deposit_check_request_for(outpoint);
        let (new_request, _new_result_rx) = deposit_check_request_for(outpoint);
        monitor
            .pending_deposit_checks
            .insert(outpoint, vec![old_request, new_request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(old_token),
            generation: tracker.bitcoin_generation(),
            outpoint,
            result: Ok(DepositStatus::NotFound),
        }));

        assert_eq!(monitor.pending_deposit_checks[&outpoint].len(), 2);
        assert_eq!(tracker.discovery(&outpoint), DepositDiscovery::Pending);
    }

    #[tokio::test]
    async fn failed_discovery_uses_a_superseding_block_scan_result() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), outpoint);
        let DepositDiscovery::Discover(token) = tracker.discovery(&outpoint) else {
            panic!("expected discovery token");
        };
        let generation = tracker.bitcoin_generation();
        let checkpoint = HashCheckpoint::new(0, block.block_hash());
        tracker.apply_block_if_current(generation, checkpoint, &block);
        monitor.tip = Some(checkpoint);
        let (request, _result_rx) = deposit_check_request_for(outpoint);
        monitor
            .pending_deposit_checks
            .insert(outpoint, vec![request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(token),
            generation,
            outpoint,
            result: Err(anyhow::anyhow!("stale discovery failure").into()),
        }));

        assert!(!monitor.pending_deposit_checks.contains_key(&outpoint));
        assert_eq!(monitor.deposit_check_workers.len(), 1);
    }

    #[test]
    fn failed_block_scan_is_requeued_without_restarting_kyoto() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), make_outpoint(1));
        let generation = tracker.bitcoin_generation();
        let mut monitor = test_monitor(metrics, tracker);
        let checkpoint = HashCheckpoint::new(42, block_hash(2));
        monitor.block_scan_queue = VecDeque::from([(checkpoint, 2)]);

        monitor.finish_block_scan(Ok(BlockScanResult {
            checkpoint,
            generation,
            retry_round: 2,
            result: Err(anyhow::anyhow!("fetch failed")),
        }));

        assert_eq!(monitor.block_scan_queue, VecDeque::from([(checkpoint, 3)]));
    }

    #[test]
    fn reorg_drops_only_disconnected_block_scans() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker);
        let inflight = HashCheckpoint::new(39, block_hash(3));
        let survived = HashCheckpoint::new(40, block_hash(1));
        let disconnected = HashCheckpoint::new(41, block_hash(2));
        monitor.block_scan_queue =
            VecDeque::from([(inflight, 2), (survived, 0), (disconnected, 1)]);

        monitor.drop_disconnected_block_scans(&[disconnected]);

        assert_eq!(
            monitor.block_scan_queue,
            VecDeque::from([(inflight, 2), (survived, 0)])
        );
    }

    #[test]
    fn stale_block_scan_result_does_not_pop_the_queue() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let stale_generation = tracker.bitcoin_generation();
        tracker.reset_bitcoin_state();
        let mut monitor = test_monitor(metrics, tracker);
        let checkpoint = HashCheckpoint::new(42, block_hash(2));
        monitor.block_scan_queue = VecDeque::from([(checkpoint, 0)]);

        monitor.finish_block_scan(Ok(BlockScanResult {
            checkpoint,
            generation: stale_generation,
            retry_round: 0,
            result: Err(anyhow::anyhow!("fetch failed")),
        }));

        assert_eq!(monitor.block_scan_queue, VecDeque::from([(checkpoint, 0)]));
    }

    #[tokio::test]
    async fn untracked_discovery_is_single_flight() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker);
        monitor.synced = true;
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let outpoint = make_outpoint(1);
        let (first, _first_rx) = deposit_check_request_for(outpoint);
        let (second, _second_rx) = deposit_check_request_for(outpoint);

        monitor.confirm_deposit(first);
        monitor.confirm_deposit(second);

        assert_eq!(monitor.deposit_discovery_workers.len(), 1);
        assert_eq!(monitor.pending_deposit_checks[&outpoint].len(), 2);
    }

    #[tokio::test]
    async fn deposit_check_during_kyoto_catch_up_is_refused() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        // Catch-up `Connected` events set the tip before the node is synced;
        // a check accepted here would cache a status that block scans can
        // never correct.
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let outpoint = make_outpoint(1);
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), outpoint);
        let (request, result_rx) = deposit_check_request_for(outpoint);

        monitor.confirm_deposit(request);

        assert!(matches!(
            result_rx.await.unwrap(),
            Err(DepositConfirmError::Other(_))
        ));
        assert!(monitor.deposit_discovery_workers.is_empty());
        assert!(monitor.pending_deposit_checks.is_empty());
        assert!(matches!(
            tracker.discovery(&outpoint),
            DepositDiscovery::Discover(_)
        ));
    }

    #[tokio::test]
    async fn failing_block_scan_does_not_delay_fresh_blocks() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        tracker.upsert_request(sui_sdk_types::Address::new([1; 32]), make_outpoint(1));
        let mut monitor = test_monitor(metrics, tracker);
        let failing = HashCheckpoint::new(41, block_hash(1));
        let fresh = HashCheckpoint::new(42, block_hash(2));
        monitor.block_scan_queue = VecDeque::from([(failing, 3), (fresh, 0)]);

        monitor.start_next_block_scan();

        assert_eq!(
            monitor.block_scan_queue,
            VecDeque::from([(fresh, 0), (failing, 3)])
        );
        assert_eq!(monitor.block_scan_workers.len(), 1);
    }

    #[test]
    fn scan_without_candidates_does_not_start_a_worker() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker);

        monitor.queue_block_scan(HashCheckpoint::new(42, block_hash(2)));

        assert!(monitor.block_scan_queue.is_empty());
        assert!(monitor.block_scan_workers.is_empty());
    }

    #[tokio::test]
    async fn process_deposit_check_uses_tracker_state_without_rpc() {
        let metrics = Arc::new(fresh_metrics());
        let outpoint = make_outpoint(1);
        let txid = outpoint.txid;
        let block_info = HashCheckpoint::new(42, block_hash(2));
        let tracker = DepositTracker::new(metrics.clone());
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
        for vout in [0, 1] {
            let current = bitcoin::OutPoint { txid, vout };
            if vout == 1 {
                tracker.upsert_request(sui_sdk_types::Address::new([2; 32]), current);
                record_status(&tracker, &current, DepositStatus::NotFound);
            }
            let DepositDiscovery::Known(status) = tracker.discovery(&current) else {
                panic!("expected known tracker status");
            };
            let (request, result_rx) = deposit_check_request_for(current);
            result_rxs.push(result_rx);
            let result = process_deposit_check(
                tracker.bitcoin_generation(),
                HashCheckpoint::new(50, block_hash(3)),
                Arc::new(corepc_client::client_sync::v29::Client::new(
                    "http://127.0.0.1:1",
                )),
                request,
                status,
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
        assert_eq!(cache_requests(&metrics, "tx_block", "miss"), 0);
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
