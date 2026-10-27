// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::future::Future;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use corepc_client::types::model::MempoolAcceptance;
use futures::FutureExt;
use futures::StreamExt;
use futures::TryStreamExt;
use kyoto::FeeRate;
use kyoto::HashCheckpoint;
use kyoto::Warning;
use lru::LruCache;
use prometheus::Histogram;
use rand::Rng;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::config::MonitorConfig;
use super::limits::BitcoindCharge;
use super::limits::Held;
use crate::deposit_tracker::DepositDiscovery;
use crate::deposit_tracker::DepositStatus;
use crate::deposit_tracker::DepositTracker;
use crate::deposit_tracker::DiscoveryResolution;
use crate::deposit_tracker::effective_deposit_confirmation_threshold;
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
const MAX_PENDING_DEPOSIT_CHECKS_PER_OUTPOINT_AND_CALLER: usize = 100;
// bitcoind's default rpcthreads (v29+); a full work queue fails calls.
const UTXO_HEIGHT_LOOKUP_CONCURRENCY: usize = 16;

/// Budget for one bitcoind RPC: corepc's fixed 60s transport timeout, which
/// minreq enforces around the whole request, plus a scheduling margin.
const BITCOIND_RPC_BUDGET: Duration = Duration::from_secs(65);

/// How long a `MonitorClient` call waits for the loop. A worker starts an RPC
/// only if its budget fits before this deadline, so a call that times out on
/// it never has one in flight.
const MONITOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const _: () = assert!(MONITOR_REQUEST_TIMEOUT.as_secs() > BITCOIND_RPC_BUDGET.as_secs());

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
    InsufficientConfirmations {
        confirmations: u32,
        required_confirmations: u32,
    },
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

#[derive(serde::Deserialize)]
struct RawTransactionLocation {
    #[serde(rename = "blockhash")]
    block_hash: Option<bitcoin::BlockHash>,
}

#[derive(Debug, thiserror::Error)]
pub enum DepositConfirmError {
    #[error("UTXO {txid}:{vout} has already been spent on Bitcoin")]
    UtxoSpent { txid: bitcoin::Txid, vout: u32 },
    #[error("transaction {txid} has no output at vout {vout}")]
    InvalidVout { txid: bitcoin::Txid, vout: u32 },
    #[error(
        "output {txid}:{vout} pays {}, not the expected {}",
        txout_summary(.actual),
        txout_summary(.expected)
    )]
    OutputMismatch {
        txid: bitcoin::Txid,
        vout: u32,
        expected: bitcoin::TxOut,
        actual: bitcoin::TxOut,
    },
    #[error("per-caller deposit discovery limit reached")]
    DiscoveriesFull,
    #[error("Bitcoin deposit check timed out")]
    TimedOut,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

fn txout_summary(txout: &bitcoin::TxOut) -> String {
    const SHOWN: usize = 34;
    let script = txout.script_pubkey.as_bytes();
    format!(
        "{} sat to script 0x{}{} ({} bytes)",
        txout.value.to_sat(),
        hex::encode(&script[..script.len().min(SHOWN)]),
        if script.len() > SHOWN { "..." } else { "" },
        script.len()
    )
}

#[derive(Debug)]
struct DepositCheckRequest {
    outpoint: bitcoin::OutPoint,
    expected_txout: bitcoin::TxOut,
    confirmation_threshold: u32,
    charge: BitcoindCharge,
    result_tx: oneshot::Sender<Result<DepositConfirmation, DepositConfirmError>>,
}

impl DepositCheckRequest {
    fn owner(&self) -> Option<Address> {
        self.charge.as_ref().map(|charge| charge.caller())
    }
}

type DiscoveryGroup = (bitcoin::OutPoint, Option<Address>);

struct CachedOutputs {
    is_coinbase: bool,
    outputs: Vec<bitcoin::TxOut>,
    bytes: usize,
}

impl CachedOutputs {
    fn new(transaction: &bitcoin::Transaction) -> Self {
        let outputs = transaction.output.clone();
        let bytes = outputs.capacity() * size_of::<bitcoin::TxOut>()
            + outputs
                .iter()
                .map(|output| output.script_pubkey.len())
                .sum::<usize>();
        Self {
            is_coinbase: transaction.is_coinbase(),
            outputs,
            bytes,
        }
    }
}

type BlockAnswer = Result<kyoto::IndexedBlock, kyoto::error::FetchBlockError>;
type FetchedOutputs = Result<Arc<CachedOutputs>, String>;
type RequestedFetch = (u64, oneshot::Receiver<BlockAnswer>);
type FetchAnswers = Vec<(oneshot::Sender<FetchedOutputs>, FetchedOutputs)>;

struct BlockFetch {
    id: u64,
    txids: HashSet<bitcoin::Txid>,
    registrants: Vec<(bitcoin::Txid, oneshot::Sender<FetchedOutputs>)>,
}

impl BlockFetch {
    fn register(&mut self, txid: bitcoin::Txid) -> oneshot::Receiver<FetchedOutputs> {
        self.registrants
            .retain(|(_, registrant)| !registrant.is_closed());
        self.txids.insert(txid);
        let (registrant, outputs) = oneshot::channel();
        self.registrants.push((txid, registrant));
        outputs
    }
}

enum OutputsLookup {
    Cached(Arc<CachedOutputs>),
    Fetching(oneshot::Receiver<FetchedOutputs>),
}

struct DepositLookupCache {
    tx_blocks: LruCache<bitcoin::Txid, HashCheckpoint>,
    block_heights: LruCache<bitcoin::BlockHash, u32>,
    outputs: LruCache<bitcoin::Txid, Arc<CachedOutputs>>,
    output_bytes: usize,
    fetches: HashMap<bitcoin::BlockHash, BlockFetch>,
    next_fetch_id: u64,
}

impl DepositLookupCache {
    /// Sizes for the shared deposit lookup caches. These caches collapse repeated
    /// per-output lookups for large deposit transactions while keeping memory bounded.
    const TX_BLOCK_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
    const BLOCK_HEIGHT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(128).unwrap();
    const OUTPUT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
    const OUTPUT_CACHE_BYTES: usize = 32 << 20;

    fn new() -> Self {
        Self {
            tx_blocks: LruCache::new(Self::TX_BLOCK_CACHE_SIZE),
            block_heights: LruCache::new(Self::BLOCK_HEIGHT_CACHE_SIZE),
            outputs: LruCache::new(Self::OUTPUT_CACHE_SIZE),
            output_bytes: 0,
            fetches: HashMap::new(),
            next_fetch_id: 0,
        }
    }

    fn lock(cache: &Mutex<Self>) -> std::sync::MutexGuard<'_, Self> {
        cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn put_outputs(
        &mut self,
        txid: bitcoin::Txid,
        outputs: Arc<CachedOutputs>,
    ) -> Vec<Arc<CachedOutputs>> {
        let mut evicted = Vec::new();
        if outputs.bytes > Self::OUTPUT_CACHE_BYTES {
            return evicted;
        }
        self.output_bytes += outputs.bytes;
        if let Some((_, displaced)) = self.outputs.push(txid, outputs) {
            self.output_bytes -= displaced.bytes;
            evicted.push(displaced);
        }
        while self.output_bytes > Self::OUTPUT_CACHE_BYTES
            && let Some((_, lru)) = self.outputs.pop_lru()
        {
            self.output_bytes -= lru.bytes;
            evicted.push(lru);
        }
        evicted
    }

    fn invalidate_tx(&mut self, txid: &bitcoin::Txid) {
        self.tx_blocks.pop(txid);
        if let Some(outputs) = self.outputs.pop(txid) {
            self.output_bytes -= outputs.bytes;
        }
    }

    fn find_outputs(
        &mut self,
        txid: bitcoin::Txid,
        block_hash: bitcoin::BlockHash,
    ) -> Option<OutputsLookup> {
        if let Some(outputs) = self.outputs.get(&txid) {
            return Some(OutputsLookup::Cached(outputs.clone()));
        }
        self.fetches
            .get_mut(&block_hash)
            .map(|fetch| OutputsLookup::Fetching(fetch.register(txid)))
    }

    fn insert_fetch(
        &mut self,
        block_hash: bitcoin::BlockHash,
        txid: bitcoin::Txid,
    ) -> (u64, oneshot::Receiver<FetchedOutputs>) {
        let id = self.next_fetch_id;
        self.next_fetch_id += 1;
        let mut fetch = BlockFetch {
            id,
            txids: HashSet::new(),
            registrants: Vec::new(),
        };
        let outputs = fetch.register(txid);
        self.fetches.insert(block_hash, fetch);
        (id, outputs)
    }

    fn take_fetch(&mut self, block_hash: bitcoin::BlockHash, id: u64) -> Option<BlockFetch> {
        if self.fetches.get(&block_hash)?.id != id {
            return None;
        }
        self.fetches.remove(&block_hash)
    }

    fn finish_fetch(
        &mut self,
        block_hash: bitcoin::BlockHash,
        id: u64,
        index: &Result<HashMap<bitcoin::Txid, &bitcoin::Transaction>, &str>,
    ) -> (FetchAnswers, Vec<Arc<CachedOutputs>>) {
        let Some(fetch) = self.take_fetch(block_hash, id) else {
            return Default::default();
        };
        let mut evicted = Vec::new();
        let mut results = HashMap::new();
        for txid in fetch.txids {
            let result = match index.as_ref().map(|index| index.get(&txid)) {
                Ok(Some(transaction)) => {
                    let outputs = Arc::new(CachedOutputs::new(transaction));
                    evicted.extend(self.put_outputs(txid, outputs.clone()));
                    Ok(outputs)
                }
                Ok(None) => {
                    self.invalidate_tx(&txid);
                    Err(format!(
                        "Transaction {txid} is not present in block {block_hash} reported by Bitcoin Core"
                    ))
                }
                Err(error) => {
                    self.invalidate_tx(&txid);
                    Err(error.to_string())
                }
            };
            results.insert(txid, result);
        }
        let answers = fetch
            .registrants
            .into_iter()
            .map(|(txid, registrant)| (registrant, results[&txid].clone()))
            .collect();
        (answers, evicted)
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

    fn find_outputs(
        &self,
        txid: bitcoin::Txid,
        block_hash: bitcoin::BlockHash,
    ) -> Option<OutputsLookup> {
        let lookup = self.lock().find_outputs(txid, block_hash);
        self.record_request(
            "transaction",
            matches!(lookup, Some(OutputsLookup::Cached(_))),
        );
        lookup
    }

    fn find_or_fetch_outputs(
        &self,
        txid: bitcoin::Txid,
        block_hash: bitcoin::BlockHash,
        requester: &kyoto::Requester,
    ) -> Result<(OutputsLookup, Option<RequestedFetch>), kyoto::error::FetchBlockError> {
        let mut cache = self.lock();
        if let Some(lookup) = cache.find_outputs(txid, block_hash) {
            return Ok((lookup, None));
        }
        let block = requester.request_block(block_hash)?;
        let (id, outputs) = cache.insert_fetch(block_hash, txid);
        Ok((OutputsLookup::Fetching(outputs), Some((id, block))))
    }

    fn downgrade(&self) -> Weak<Mutex<DepositLookupCache>> {
        Arc::downgrade(&self.inner)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DepositLookupCache> {
        DepositLookupCache::lock(&self.inner)
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
    group: DiscoveryGroup,
    result: Result<DepositStatus, DepositConfirmError>,
}

struct DepositDiscoveryContext {
    tip: HashCheckpoint,
    bitcoind_rpc: BitcoindRpc,
    requester: kyoto::Requester,
    deposit_lookup_cache: SharedDepositLookupCache,
    deposit_tracker: DepositTracker,
    generation: u64,
    fetch_seconds: Histogram,
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
    pending_deposit_checks: HashMap<DiscoveryGroup, Vec<DepositCheckRequest>>,
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

/// bitcoind is still catching up (-8 out of range, -28 warming up), overloaded,
/// or briefly unreachable; anything else will not clear by waiting.
fn is_transient_rpc_error(e: &corepc_client::client_sync::Error) -> bool {
    use jsonrpc::http::minreq_http::Error as TransportError;

    let corepc_client::client_sync::Error::JsonRpc(e) = e else {
        return false;
    };
    match e {
        jsonrpc::error::Error::Rpc(e) => matches!(e.code, -8 | -28),
        jsonrpc::error::Error::Transport(e) => match e.downcast_ref::<TransportError>() {
            // A refused connection and an HTTP error status arrive alike; 5xx
            // clears by waiting (503 is a full RPC work queue), 4xx never will.
            Some(TransportError::Http(e)) => e.status_code >= 500,
            // Connection-level only; a malformed reply, a protocol error or a
            // bad TLS or proxy setup will not fix itself.
            Some(TransportError::Minreq(e)) => {
                matches!(
                    e,
                    minreq::Error::IoError(_) | minreq::Error::AddressNotFound
                )
            }
            _ => false,
        },
        _ => false,
    }
}

#[derive(Clone)]
struct BitcoindRpc {
    client: Arc<corepc_client::client_sync::v29::Client>,
    charge: BitcoindCharge,
}

impl BitcoindRpc {
    fn new(client: Arc<corepc_client::client_sync::v29::Client>, charge: BitcoindCharge) -> Self {
        Self { client, charge }
    }

    async fn call<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&corepc_client::client_sync::v29::Client) -> T + Send + 'static,
        T: Send + 'static,
    {
        let call = match &self.charge {
            Some(charge) => Some(charge.call().await),
            None => None,
        };
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || {
            let _call = call;
            f(&client)
        })
        .await
        .expect("BitcoindRpc::call: spawn_blocking task panicked")
    }
}

fn release_discovery_token(
    tracker: &DepositTracker,
    token: Option<crate::deposit_tracker::ObservationToken>,
) {
    if let Some(token) = token {
        let _ = tracker.resolve_discovery(token, Err::<DepositStatus, ()>(()));
    }
}

fn recorded_in_block(
    tracker: &DepositTracker,
    outpoint: &bitcoin::OutPoint,
    block_info: HashCheckpoint,
) -> Option<DepositStatus> {
    tracker.recorded_status(outpoint).filter(|status| {
        matches!(
            status,
            DepositStatus::InBlock { checkpoint, .. } | DepositStatus::InvalidVout { checkpoint }
                if *checkpoint == block_info
        )
    })
}

struct BlockFetchTimer {
    fetch_seconds: Histogram,
    started: Instant,
}

impl BlockFetchTimer {
    fn start(fetch_seconds: &Histogram) -> Self {
        Self {
            fetch_seconds: fetch_seconds.clone(),
            started: Instant::now(),
        }
    }
}

impl Drop for BlockFetchTimer {
    fn drop(&mut self) {
        self.fetch_seconds
            .observe(self.started.elapsed().as_secs_f64());
    }
}

struct FetchWaiter {
    cache: Weak<Mutex<DepositLookupCache>>,
    block_info: HashCheckpoint,
    id: u64,
    deposit_tracker: DepositTracker,
    generation: u64,
    _slot: Option<OwnedSemaphorePermit>,
}

impl FetchWaiter {
    async fn wait(self, block: oneshot::Receiver<BlockAnswer>, timer: BlockFetchTimer) {
        let answer = block
            .await
            .unwrap_or(Err(kyoto::error::FetchBlockError::RecvError));
        drop(timer);
        let hash = self.block_info.hash;
        let block = answer
            .map_err(|e| format!("Failed to look up block {hash}: {e}"))
            .and_then(|fetched| {
                let fetched_hash = fetched.block.block_hash();
                if fetched.height == self.block_info.height && fetched_hash == hash {
                    Ok(fetched.block)
                } else {
                    Err(format!(
                        "Kyoto returned block {fetched_hash} at height {} for requested {hash} at height {}",
                        fetched.height, self.block_info.height,
                    ))
                }
            });
        let txids: Vec<bitcoin::Txid> = block
            .iter()
            .flat_map(|block| &block.txdata)
            .map(|transaction| transaction.compute_txid())
            .collect();
        if let Ok(block) = &block {
            self.deposit_tracker.apply_block_with_txids_if_current(
                self.generation,
                self.block_info,
                block,
                &txids,
            );
        }
        if let Some(cache) = self.cache.upgrade() {
            let index = block
                .as_ref()
                .map(|block| txids.iter().copied().zip(&block.txdata).collect())
                .map_err(String::as_str);
            let (answers, evicted) =
                DepositLookupCache::lock(&cache).finish_fetch(hash, self.id, &index);
            drop(evicted);
            for (registrant, outputs) in answers {
                let _ = registrant.send(outputs);
            }
        }
    }
}

impl Drop for FetchWaiter {
    fn drop(&mut self) {
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let fetch = DepositLookupCache::lock(&cache).take_fetch(self.block_info.hash, self.id);
        drop(fetch);
    }
}

/// A `MonitorClient` caller's reply channel and the instant it stops waiting.
struct Caller<T> {
    deadline: Instant,
    charge: BitcoindCharge,
    result_tx: oneshot::Sender<Result<T>>,
}

impl<T> Caller<T> {
    /// Run `f` on the blocking pool only if the caller is still waiting and
    /// `BITCOIND_RPC_BUDGET` fits before its deadline; `None` means skipped.
    async fn rpc<F, R>(
        &mut self,
        client: &Arc<corepc_client::client_sync::v29::Client>,
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&corepc_client::client_sync::v29::Client) -> R + Send + 'static,
        R: Send + 'static,
    {
        if self.result_tx.is_closed() {
            return None;
        }
        let deadline = self.deadline;
        let call = match &self.charge {
            Some(charge) => {
                let latest =
                    tokio::time::Instant::from_std(deadline.checked_sub(BITCOIND_RPC_BUDGET)?);
                tokio::select! {
                    biased;
                    () = self.result_tx.closed() => return None,
                    call = tokio::time::timeout_at(latest, charge.call()) => Some(call.ok()?),
                }
            }
            None => None,
        };
        let client = Arc::clone(client);
        // Checked on the blocking thread: a busy pool can hold the closure
        // back, and the caller's deadline does not wait for it.
        tokio::task::spawn_blocking(move || {
            let _call = call;
            (Instant::now() + BITCOIND_RPC_BUDGET <= deadline).then(|| f(&client))
        })
        .await
        .expect("Caller::rpc: spawn_blocking task panicked")
    }

    fn reply(self, result: Result<T>) {
        let _ = self.result_tx.send(result);
    }
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

        match self.deposit_tracker.discovery(&request.outpoint) {
            DepositDiscovery::Known(status) => self.start_deposit_check(tip, request, status),
            DepositDiscovery::Discover(token) => self.join_or_discover(tip, request, Some(token)),
            DepositDiscovery::Pending | DepositDiscovery::Untracked => {
                self.join_or_discover(tip, request, None)
            }
        }
    }

    fn join_or_discover(
        &mut self,
        tip: HashCheckpoint,
        request: DepositCheckRequest,
        token: Option<crate::deposit_tracker::ObservationToken>,
    ) {
        let outpoint = request.outpoint;
        let owner = request.owner();
        let joined = [owner, None]
            .into_iter()
            .map(|starter| (outpoint, starter))
            .find(|group| self.pending_deposit_checks.contains_key(group));
        if let Some(group) = joined {
            release_discovery_token(&self.deposit_tracker, token);
            let Some(requests) = self.pending_deposit_checks.get_mut(&group) else {
                return;
            };
            requests.retain(|queued| !queued.result_tx.is_closed());
            let queued = requests
                .iter()
                .filter(|queued| queued.owner() == owner)
                .count();
            if queued >= MAX_PENDING_DEPOSIT_CHECKS_PER_OUTPOINT_AND_CALLER {
                let _ = request.result_tx.send(Err(anyhow::anyhow!(
                    "Too many pending checks from this caller for Bitcoin deposit {outpoint}"
                )
                .into()));
            } else {
                requests.push(request);
            }
            return;
        }
        let discovery = match request.charge.as_ref().map(|charge| charge.try_discovery()) {
            Some(None) => {
                release_discovery_token(&self.deposit_tracker, token);
                let _ = request
                    .result_tx
                    .send(Err(DepositConfirmError::DiscoveriesFull));
                return;
            }
            Some(discovery) => discovery,
            None => None,
        };
        let group = (outpoint, owner);
        let context = self.deposit_discovery_context(tip, request.charge.clone());
        self.pending_deposit_checks.insert(group, vec![request]);
        self.deposit_discovery_workers
            .spawn(process_deposit_discovery(context, group, token, discovery));
    }

    fn deposit_discovery_context(
        &self,
        tip: HashCheckpoint,
        charge: BitcoindCharge,
    ) -> DepositDiscoveryContext {
        DepositDiscoveryContext {
            tip,
            bitcoind_rpc: BitcoindRpc::new(self.bitcoind_rpc.clone(), charge),
            requester: self.requester.clone(),
            deposit_lookup_cache: self.deposit_lookup_cache.clone(),
            deposit_tracker: self.deposit_tracker.clone(),
            generation: self.deposit_tracker.bitcoin_generation(),
            fetch_seconds: self.metrics.kyoto_block_fetch_seconds.clone(),
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

        let (outpoint, _) = result.group;
        let status = match result.token {
            Some(token) => {
                let own = result.result.as_ref().cloned().map_err(|_| ());
                match self.deposit_tracker.resolve_discovery(token, own) {
                    DiscoveryResolution::Complete(Ok(status)) => Ok(status),
                    DiscoveryResolution::Complete(Err(())) | DiscoveryResolution::Pending => {
                        result.result
                    }
                    DiscoveryResolution::Untracked => Err(anyhow::anyhow!(
                        "Bitcoin deposit request left the tracker during discovery"
                    )
                    .into()),
                }
            }
            None => self
                .deposit_tracker
                .recorded_status(&outpoint)
                .map_or(result.result, Ok),
        };
        let requests = self
            .pending_deposit_checks
            .remove(&result.group)
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
        let fetch_seconds = self.metrics.kyoto_block_fetch_seconds.clone();
        self.block_scan_workers.spawn(async move {
            let scan = AssertUnwindSafe(async {
                if retry_round > 0 {
                    tokio::time::sleep(BLOCK_SCAN_RETRY_BASE_DELAY * 2u32.pow(retry_round.min(5)))
                        .await;
                }
                fetch_block_for_scan(&requester, checkpoint, &fetch_seconds).await
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

    /// Kyoto re-syncs from its checkpoint on every build, so anchor as high as
    /// possible without passing `start_height`: mainnet reuses the soft-fork
    /// activation heights, everything else resolves the exact block.
    async fn resolve_start_checkpoint(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
        config: &MonitorConfig,
    ) -> Result<HashCheckpoint> {
        match config.network {
            bitcoin::Network::Bitcoin if config.start_height > 709_631 => {
                Ok(HashCheckpoint::taproot_activation())
            }
            bitcoin::Network::Bitcoin if config.start_height > 481_823 => {
                Ok(HashCheckpoint::segwit_activation())
            }
            _ => Self::checkpoint_at_height(bitcoind_rpc, config.start_height).await,
        }
    }

    /// Wait for bitcoind to have the block at `height`. A node still in initial
    /// block download reports it "out of range" just like a height past the tip.
    async fn checkpoint_at_height(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
        height: u32,
    ) -> Result<HashCheckpoint> {
        const RETRY_DELAY: Duration = Duration::from_secs(2);
        const LOG_INTERVAL: Duration = Duration::from_secs(30);

        let rpc = BitcoindRpc::new(bitcoind_rpc.clone(), None);
        let mut next_log = Instant::now();
        loop {
            match rpc.call(move |rpc| rpc.get_block_hash(height as u64)).await {
                Ok(raw) => {
                    let model = raw.into_model().map_err(|e| {
                        anyhow::anyhow!("Failed to parse getblockhash({height}) response: {e}")
                    })?;
                    info!("Anchoring Kyoto at start height {height} ({})", model.0);
                    return Ok(HashCheckpoint::new(height, model.0));
                }
                Err(e) if is_transient_rpc_error(&e) => {
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
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to fetch the block at start height {height}: {e}"
                    ));
                }
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    async fn bitcoind_height(
        bitcoind_rpc: &Arc<corepc_client::client_sync::v29::Client>,
    ) -> Option<u32> {
        BitcoindRpc::new(bitcoind_rpc.clone(), None)
            .call(|rpc| rpc.get_blockchain_info())
            .await
            .ok()
            .and_then(|info| info.into_model().ok())
            .map(|info| info.blocks)
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

                let start_checkpoint =
                    Self::resolve_start_checkpoint(&bitcoind_rpc, &config).await?;
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
            MonitorMessage::GetRecentFeeRate(conf_target, caller) => {
                self.rpc_workers.spawn(Self::get_recent_fee_rate(
                    self.bitcoind_rpc.clone(),
                    self.metrics.clone(),
                    self.config.network,
                    conf_target,
                    caller,
                ));
            }
            MonitorMessage::BroadcastTransaction(tx, caller) => {
                self.rpc_workers.spawn(Self::broadcast_transaction(
                    self.bitcoind_rpc.clone(),
                    tx,
                    caller,
                ));
            }
            MonitorMessage::TestMempoolAccept(tx, caller) => {
                self.rpc_workers.spawn(Self::test_mempool_accept(
                    self.bitcoind_rpc.clone(),
                    tx,
                    caller,
                ));
            }
            MonitorMessage::GetTransactionStatus(txid, caller) => {
                self.rpc_workers.spawn(Self::get_transaction_status(
                    self.bitcoind_rpc.clone(),
                    txid,
                    caller,
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
                    BitcoindRpc::new(bitcoind_rpc.clone(), None),
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
        network: bitcoin::Network,
        conf_target: u16,
        mut caller: Caller<FeeRate>,
    ) {
        // ECONOMICAL tracks spot fees more closely than the default
        // CONSERVATIVE, which blends in a long-horizon max.
        let rpc_result = caller
            .rpc(&bitcoind_rpc, move |rpc| {
                rpc.call::<corepc_client::types::v29::EstimateSmartFee>(
                    "estimatesmartfee",
                    &[
                        serde_json::json!(conf_target as u32),
                        serde_json::json!("ECONOMICAL"),
                    ],
                )
            })
            .await;
        let Some(rpc_result) = rpc_result else {
            caller.reply(Err(anyhow::anyhow!(
                "Fee estimate expired before its bitcoind RPC could start"
            )));
            return;
        };
        let result = rpc_result
            .map_err(anyhow::Error::from)
            .and_then(|estimate| fee_rate_from_estimate(&estimate, network, conf_target))
            .inspect(|fee_rate| {
                metrics
                    .btc_fee_rate_sat_per_kvb
                    .set((fee_rate.to_sat_per_kwu() * 4) as i64);
            });
        caller.reply(result);
    }

    async fn test_mempool_accept(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        tx: bitcoin::Transaction,
        mut caller: Caller<Vec<MempoolAcceptance>>,
    ) {
        let txid = tx.compute_txid();
        let Some(result) = caller
            .rpc(&bitcoind_rpc, move |rpc| rpc.test_mempool_accept(&[tx]))
            .await
        else {
            caller.reply(Err(anyhow::anyhow!(
                "testmempoolaccept for {txid} expired before its bitcoind RPC could start"
            )));
            return;
        };
        let results = result
            .map_err(anyhow::Error::from)
            .and_then(|accept| accept.into_model().map_err(anyhow::Error::from))
            .map(|accept| accept.results);
        caller.reply(results);
    }

    async fn broadcast_transaction(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        tx: bitcoin::Transaction,
        mut caller: Caller<()>,
    ) {
        // Broadcast via the bitcoind RPC, not kyoto's P2P submit_package, which
        // dropped its response or hung under load.
        let txid = tx.compute_txid();
        let Some(result) = caller
            .rpc(&bitcoind_rpc, move |rpc| rpc.send_raw_transaction(&tx))
            .await
        else {
            caller.reply(Err(anyhow::anyhow!(
                "Broadcast of {txid} expired before its bitcoind RPC could start"
            )));
            return;
        };
        match result {
            Ok(_) => {
                info!("Transaction {txid} broadcast via Bitcoin Core RPC");
                caller.reply(Ok(()));
            }
            Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(ref e)))
                if e.code == -27 =>
            {
                // RPC error -27: tx already confirmed on-chain ("outputs already in utxo
                // set"), so the broadcast succeeded. (A mempool duplicate returns Ok.)
                debug!("Transaction {txid} already confirmed on-chain");
                caller.reply(Ok(()));
            }
            Err(e) => {
                error!("Failed to broadcast transaction {txid}: {e}");
                caller.reply(Err(anyhow::anyhow!(e)));
            }
        }
    }

    async fn get_transaction_status(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        txid: bitcoin::Txid,
        mut caller: Caller<TxStatus>,
    ) {
        let rpc_result = caller
            .rpc(&bitcoind_rpc, move |rpc| {
                rpc.get_raw_transaction_verbose(txid)
            })
            .await;
        let Some(rpc_result) = rpc_result else {
            caller.reply(Err(anyhow::anyhow!(
                "Status lookup for {txid} expired before its bitcoind RPC could start"
            )));
            return;
        };
        let result = match rpc_result {
            Ok(tx_info) => match tx_info.into_model() {
                Ok(tx_info) => Ok(match (tx_info.block_hash, tx_info.confirmations) {
                    (Some(_), Some(confirmations)) if confirmations > 0 => TxStatus::Confirmed {
                        confirmations: confirmations as u32,
                    },
                    // Core's txindex can retain an orphaned block hash after a reorg
                    // even when the transaction is absent from the mempool. Let the
                    // existing NotFound recovery path rebroadcast it.
                    (Some(block_hash), _) => {
                        info!(
                            %txid,
                            %block_hash,
                            "Transaction found in a stale block; treating as not found for rebroadcast"
                        );
                        TxStatus::NotFound
                    }
                    (None, _) => TxStatus::InMempool,
                }),
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
        caller.reply(result);
    }
}

async fn fetch_block_for_scan(
    requester: &kyoto::Requester,
    checkpoint: HashCheckpoint,
    fetch_seconds: &Histogram,
) -> Result<bitcoin::Block> {
    let fetched = {
        let _timer = BlockFetchTimer::start(fetch_seconds);
        tokio::time::timeout(BLOCK_SCAN_TIMEOUT, requester.get_block(checkpoint.hash)).await
    };
    let indexed_block = fetched.map_err(|_| {
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
    group: DiscoveryGroup,
    token: Option<crate::deposit_tracker::ObservationToken>,
    discovery: Option<Held>,
) -> DepositDiscoveryWorkerResult {
    let _discovery = discovery;
    let _starters_place = context.bitcoind_rpc.charge.clone();
    let (outpoint, _) = group;
    let generation = context.generation;
    let lookup = AssertUnwindSafe(discover_deposit(context, outpoint));
    let result = match tokio::time::timeout(DEPOSIT_DISCOVERY_TIMEOUT, lookup.catch_unwind()).await
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
        group,
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
        expected_txout,
        confirmation_threshold,
        charge,
        mut result_tx,
    } = request;
    let check = tokio::time::timeout(
        DEPOSIT_CHECK_TIMEOUT,
        check_result_from_status(
            status,
            tip,
            confirmation_threshold,
            BitcoindRpc::new(bitcoind_rpc, charge),
            outpoint,
            expected_txout,
        ),
    );
    let result = tokio::select! {
        biased;
        () = result_tx.closed() => Err(anyhow::anyhow!(
            "Bitcoin deposit check for {outpoint} was abandoned by its caller"
        )
        .into()),
        result = check => result.unwrap_or(Err(DepositConfirmError::TimedOut)),
    };
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
    bitcoind_rpc: BitcoindRpc,
    outpoint: bitcoin::OutPoint,
    expected_txout: bitcoin::TxOut,
) -> Result<DepositConfirmation, DepositConfirmError> {
    match status {
        DepositStatus::Unchecked => unreachable!("discovery returned Unchecked"),
        DepositStatus::NotFound => Ok(DepositConfirmation::NotFound),
        DepositStatus::InMempool => Ok(DepositConfirmation::InMempool),
        DepositStatus::InvalidVout { .. } => Err(DepositConfirmError::InvalidVout {
            txid: outpoint.txid,
            vout: outpoint.vout,
        }),
        DepositStatus::InBlock {
            checkpoint,
            is_coinbase,
            txout,
        } => {
            if txout != expected_txout {
                return Err(DepositConfirmError::OutputMismatch {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    expected: expected_txout,
                    actual: txout,
                });
            }
            let confirmations = tip
                .height
                .saturating_add(1)
                .saturating_sub(checkpoint.height);
            let required_confirmations =
                effective_deposit_confirmation_threshold(confirmation_threshold, is_coinbase);
            if confirmations < required_confirmations {
                return Ok(DepositConfirmation::InsufficientConfirmations {
                    confirmations,
                    required_confirmations,
                });
            }
            check_unspent_at_tip(
                bitcoind_rpc,
                tip,
                outpoint,
                txout,
                confirmations,
                required_confirmations,
            )
            .await
        }
    }
}

async fn lookup_tx_block(
    bitcoind_rpc: BitcoindRpc,
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
    let tx_info = match bitcoind_rpc
        .call(move |rpc| {
            rpc.call::<RawTransactionLocation>(
                "getrawtransaction",
                &[
                    serde_json::Value::String(txid.to_string()),
                    serde_json::Value::Bool(true),
                ],
            )
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
    context: DepositDiscoveryContext,
    outpoint: bitcoin::OutPoint,
) -> Result<DepositStatus, DepositConfirmError> {
    let DepositDiscoveryContext {
        tip,
        bitcoind_rpc,
        requester,
        deposit_lookup_cache,
        deposit_tracker,
        generation,
        fetch_seconds,
    } = context;
    let txid = outpoint.txid;
    let charge = bitcoind_rpc.charge.clone();
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

    let lookup = match deposit_lookup_cache.find_outputs(txid, block_info.hash) {
        Some(lookup) => lookup,
        None => {
            if let Some(status) = recorded_in_block(&deposit_tracker, &outpoint, block_info) {
                return Ok(status);
            }
            let slot = match &charge {
                Some(charge) => {
                    let slot = charge.fetch_slot().await;
                    if let Some(status) = recorded_in_block(&deposit_tracker, &outpoint, block_info)
                    {
                        return Ok(status);
                    }
                    Some(slot)
                }
                None => None,
            };
            let (lookup, requested) = deposit_lookup_cache
                .find_or_fetch_outputs(txid, block_info.hash, &requester)
                .map_err(|e| anyhow::anyhow!("Failed to look up block {}: {e}", block_info.hash))?;
            if let Some((id, block)) = requested {
                let waiter = FetchWaiter {
                    cache: deposit_lookup_cache.downgrade(),
                    block_info,
                    id,
                    deposit_tracker,
                    generation,
                    _slot: slot,
                };
                tokio::spawn(waiter.wait(block, BlockFetchTimer::start(&fetch_seconds)));
            }
            lookup
        }
    };
    let cached = match lookup {
        OutputsLookup::Cached(cached) => cached,
        OutputsLookup::Fetching(outputs) => outputs
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Kyoto's fetch of block {} ended without an answer",
                    block_info.hash
                )
            })?
            .map_err(anyhow::Error::msg)?,
    };

    let Some(txout) = cached.outputs.get(outpoint.vout as usize) else {
        return Ok(DepositStatus::InvalidVout {
            checkpoint: block_info,
        });
    };
    Ok(DepositStatus::InBlock {
        checkpoint: block_info,
        is_coinbase: cached.is_coinbase,
        txout: txout.clone(),
    })
}

async fn get_best_block(bitcoind_rpc: &BitcoindRpc) -> Result<bitcoin::BlockHash> {
    bitcoind_rpc
        .call(move |rpc| rpc.call::<bitcoin::BlockHash>("getbestblockhash", &[]))
        .await
        .map_err(anyhow::Error::from)
}

async fn get_block_hash(bitcoind_rpc: &BitcoindRpc, height: u32) -> Result<bitcoin::BlockHash> {
    bitcoind_rpc
        .call(move |rpc| {
            rpc.call::<bitcoin::BlockHash>("getblockhash", &[serde_json::json!(height)])
        })
        .await
        .map_err(anyhow::Error::from)
}

async fn require_core_checkpoint(
    bitcoind_rpc: &BitcoindRpc,
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
    bitcoind_rpc: &BitcoindRpc,
    outpoint: bitcoin::OutPoint,
    include_mempool: bool,
) -> Result<Option<serde_json::Value>, corepc_client::client_sync::Error> {
    bitcoind_rpc
        .call(move |rpc| {
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

/// Rounds the BTC/kvB estimate up to the next sat/kwu. corepc's `into_model`
/// truncates to whole sat/vB, which turns a 0.93 sat/vB estimate into zero.
fn fee_rate_from_estimate(
    estimate: &corepc_client::types::v29::EstimateSmartFee,
    network: bitcoin::Network,
    conf_target: u16,
) -> Result<FeeRate> {
    let Some(btc_per_kvb) = estimate.fee_rate else {
        // Only regtest has no fee market to estimate. Anywhere else a guess would
        // price a withdrawal that can never be replaced.
        anyhow::ensure!(
            network == bitcoin::Network::Regtest,
            "bitcoind has no fee estimate for a {conf_target}-block target: {}",
            estimate.errors.as_deref().unwrap_or_default().join("; ")
        );
        warn!(
            conf_target,
            fallback_sat_per_kwu = FALLBACK_FEE_RATE_SAT_PER_KWU,
            "Node could not estimate fee rate; falling back to minimum relay fee"
        );
        return Ok(FeeRate::from_sat_per_kwu(FALLBACK_FEE_RATE_SAT_PER_KWU));
    };
    let sat_per_kvb = bitcoin::Amount::from_btc(btc_per_kvb)?.to_sat();
    Ok(FeeRate::from_sat_per_kwu(sat_per_kvb.div_ceil(4)))
}

async fn check_unspent_at_tip(
    bitcoind_rpc: BitcoindRpc,
    tip: HashCheckpoint,
    outpoint: bitcoin::OutPoint,
    txout: bitcoin::TxOut,
    confirmations: u32,
    required_confirmations: u32,
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
                "Deposit {}:{} confirmed with {confirmations}/{required_confirmations} confirmations",
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
        expected_txout: bitcoin::TxOut,
        confirmation_threshold: u32,
        charge: BitcoindCharge,
    ) -> Result<DepositConfirmation, DepositConfirmError> {
        let (tx, rx) = oneshot::channel();
        let request = DepositCheckRequest {
            outpoint,
            expected_txout,
            confirmation_threshold,
            charge,
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

    /// Round-trip a request through the monitor loop. The deadline travels with
    /// it, so a worker never starts an RPC the caller will not wait out.
    async fn request<T>(
        &self,
        message: impl FnOnce(Caller<T>) -> MonitorMessage,
        what: &str,
        charge: BitcoindCharge,
    ) -> Result<T> {
        let (result_tx, rx) = oneshot::channel();
        let deadline = Instant::now() + MONITOR_REQUEST_TIMEOUT;
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            self.tx
                .send(message(Caller {
                    deadline,
                    charge,
                    result_tx,
                }))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            rx.await.map_err(|e| anyhow::anyhow!(e))?
        })
        .await
        .map_err(|_| anyhow::anyhow!("{what} timed out waiting for the Bitcoin monitor"))?
    }

    pub async fn get_recent_fee_rate(
        &self,
        conf_target: u16,
        charge: BitcoindCharge,
    ) -> Result<FeeRate> {
        self.request(
            |caller| MonitorMessage::GetRecentFeeRate(conf_target, caller),
            "get_recent_fee_rate",
            charge,
        )
        .await
    }

    pub async fn broadcast_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        self.request(
            |caller| MonitorMessage::BroadcastTransaction(transaction, caller),
            "broadcast_transaction",
            None,
        )
        .await
    }

    pub async fn test_mempool_accept(
        &self,
        transaction: bitcoin::Transaction,
    ) -> Result<Vec<MempoolAcceptance>> {
        self.request(
            |caller| MonitorMessage::TestMempoolAccept(transaction, caller),
            "test_mempool_accept",
            None,
        )
        .await
    }

    pub async fn get_transaction_status(
        &self,
        txid: bitcoin::Txid,
        charge: BitcoindCharge,
    ) -> Result<TxStatus> {
        self.request(
            |caller| MonitorMessage::GetTransactionStatus(txid, caller),
            "get_transaction_status",
            charge,
        )
        .await
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
    GetRecentFeeRate(u16, Caller<FeeRate>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, Caller<()>),

    TestMempoolAccept(bitcoin::Transaction, Caller<Vec<MempoolAcceptance>>),

    // Query the status of a transaction (confirmed, in mempool, or not found).
    GetTransactionStatus(bitcoin::Txid, Caller<TxStatus>),
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

    fn deposit_txout() -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }
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
                expected_txout: deposit_txout(),
                confirmation_threshold: 100,
                charge: None,
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
            BitcoindRpc::new(monitor.bitcoind_rpc.clone(), None),
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
    fn fee_rate_from_estimate_keeps_sub_sat_per_vb_precision() {
        // 0.00000929 and 0.00070929 are live signet answers that `into_model`
        // truncated to 0 and 70 sat/vB.
        for (btc_per_kvb, sat_per_kwu) in [
            (0.00000929, 233),
            (0.00003999, 1_000),
            (0.00070929, 17_733),
            (0.000001, 25),
        ] {
            let estimate = corepc_client::types::v29::EstimateSmartFee {
                fee_rate: Some(btc_per_kvb),
                errors: None,
                blocks: 3,
            };
            let fee_rate = fee_rate_from_estimate(&estimate, bitcoin::Network::Bitcoin, 3).unwrap();
            assert_eq!(
                fee_rate.to_sat_per_kwu(),
                sat_per_kwu,
                "{btc_per_kvb} BTC/kvB"
            );
        }
    }

    #[test]
    fn fee_rate_from_estimate_refuses_a_missing_estimate_outside_regtest() {
        let estimate = corepc_client::types::v29::EstimateSmartFee {
            fee_rate: None,
            errors: Some(vec!["Insufficient data or no feerate found".to_string()]),
            blocks: 0,
        };
        for network in [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet4,
            bitcoin::Network::Signet,
        ] {
            let error = fee_rate_from_estimate(&estimate, network, 3).unwrap_err();
            assert!(error.to_string().contains("Insufficient data"), "{error}");
        }
        assert_eq!(
            fee_rate_from_estimate(&estimate, bitcoin::Network::Regtest, 3).unwrap(),
            FeeRate::from_sat_per_vb_unchecked(1)
        );
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
        cache.lock().invalidate_tx(&txid);

        assert!(cache.get_tx_block(&txid).is_none());
        assert_eq!(cache.get_block_height(&block_hash), Some(42));
    }

    #[test]
    fn deposit_lookup_cache_keeps_outputs_within_its_byte_budget() {
        let cache = SharedDepositLookupCache::new(Arc::new(fresh_metrics()));
        let cached = |script_bytes: usize| {
            Arc::new(CachedOutputs::new(&bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: Vec::new(),
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51; script_bytes]),
                }],
            }))
        };
        let half = DepositLookupCache::OUTPUT_CACHE_BYTES / 2;
        let [first, second, oversized] = [1, 2, 3].map(|seed| make_outpoint(seed).txid);

        cache.lock().put_outputs(first, cached(half));
        cache.lock().put_outputs(second, cached(half));
        cache
            .lock()
            .put_outputs(oversized, cached(DepositLookupCache::OUTPUT_CACHE_BYTES));

        assert!(cache.lock().outputs.peek(&first).is_none());
        assert_eq!(
            cache.lock().outputs.peek(&second).unwrap().outputs[0]
                .script_pubkey
                .len(),
            half
        );
        assert!(cache.lock().outputs.peek(&oversized).is_none());
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
        tracker.upsert_request(Address::new([1; 32]), outpoint);
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
            .insert((outpoint, None), vec![request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(stale_token),
            generation: stale_generation,
            group: (outpoint, None),
            result: Ok(DepositStatus::NotFound),
        }));

        assert_eq!(monitor.pending_deposit_checks[&(outpoint, None)].len(), 1);
        assert_eq!(tracker.discovery(&outpoint), DepositDiscovery::Pending);
    }

    #[tokio::test]
    async fn superseded_discovery_answers_its_own_group() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let outpoint = make_outpoint(1);
        let old_request_id = Address::new([1; 32]);
        tracker.upsert_request(old_request_id, outpoint);
        let DepositDiscovery::Discover(old_token) = tracker.discovery(&outpoint) else {
            panic!("expected old discovery token");
        };
        tracker.remove_request(&old_request_id);
        tracker.upsert_request(Address::new([2; 32]), outpoint);
        let DepositDiscovery::Discover(_new_token) = tracker.discovery(&outpoint) else {
            panic!("expected new discovery token");
        };
        let (request, _result_rx) = deposit_check_request_for(outpoint);
        monitor
            .pending_deposit_checks
            .insert((outpoint, None), vec![request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(old_token),
            generation: tracker.bitcoin_generation(),
            group: (outpoint, None),
            result: Ok(DepositStatus::NotFound),
        }));

        assert!(monitor.pending_deposit_checks.is_empty());
        assert_eq!(monitor.deposit_check_workers.len(), 1);
        assert_eq!(tracker.discovery(&outpoint), DepositDiscovery::Pending);
    }

    #[tokio::test]
    async fn failed_discovery_uses_a_superseding_block_scan_result() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics, tracker.clone());
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(Address::new([1; 32]), outpoint);
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
            .insert((outpoint, None), vec![request]);

        monitor.finish_deposit_discovery(Ok(DepositDiscoveryWorkerResult {
            token: Some(token),
            generation,
            group: (outpoint, None),
            result: Err(anyhow::anyhow!("stale discovery failure").into()),
        }));

        assert!(monitor.pending_deposit_checks.is_empty());
        assert_eq!(monitor.deposit_check_workers.len(), 1);
    }

    #[test]
    fn failed_block_scan_is_requeued_without_restarting_kyoto() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        tracker.upsert_request(Address::new([1; 32]), make_outpoint(1));
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
        assert_eq!(monitor.pending_deposit_checks[&(outpoint, None)].len(), 2);
    }

    async fn charge_for(
        limiter: &crate::btc_monitor::limits::BitcoindLimiter,
        caller: Address,
    ) -> Arc<crate::btc_monitor::limits::CallerCharge> {
        limiter
            .gate(
                caller,
                tokio::time::Instant::now() + Duration::from_secs(60),
            )
            .take_place()
            .await
            .unwrap()
            .unwrap()
    }

    fn in_use(gauge: &prometheus::IntGaugeVec, caller: Address) -> i64 {
        gauge.with_label_values(&[&caller.to_string()]).get()
    }

    async fn wait_for(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn an_abandoned_rpc_keeps_its_call_until_it_returns() {
        let metrics = Arc::new(fresh_metrics());
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics.clone());
        let caller = Address::new([7; 32]);
        let rpc = BitcoindRpc::new(
            Arc::new(corepc_client::client_sync::v29::Client::new(
                "http://127.0.0.1:1",
            )),
            Some(charge_for(&limiter, caller).await),
        );
        let (release, held) = std::sync::mpsc::channel::<()>();
        let worker = tokio::spawn(async move { rpc.call(move |_| held.recv()).await });
        wait_for(|| in_use(&metrics.peer_bitcoind_calls_in_use, caller) == 1).await;

        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert_eq!(in_use(&metrics.peer_bitcoind_calls_in_use, caller), 1);

        release.send(()).unwrap();
        wait_for(|| in_use(&metrics.peer_bitcoind_calls_in_use, caller) == 0).await;
    }

    #[tokio::test]
    async fn a_check_whose_caller_leaves_frees_its_place_and_makes_no_rpc() {
        let metrics = Arc::new(fresh_metrics());
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics.clone());
        let caller = Address::new([7; 32]);
        let charge = charge_for(&limiter, caller).await;
        let mut calls = Vec::new();
        for _ in 0..16 {
            calls.push(charge.call().await);
        }
        let rpcs = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let client = stub_bitcoind({
            let rpcs = rpcs.clone();
            move |req| {
                rpcs.fetch_add(1, Ordering::SeqCst);
                rpc_error(req, -1, "unexpected RPC")
            }
        })
        .await;
        let (mut request, result_rx) = deposit_check_request_for(make_outpoint(1));
        request.charge = Some(charge);
        let check = tokio::spawn(process_deposit_check(
            0,
            HashCheckpoint::new(200, block_hash(3)),
            client,
            request,
            DepositStatus::InBlock {
                checkpoint: HashCheckpoint::new(42, block_hash(2)),
                is_coinbase: false,
                txout: deposit_txout(),
            },
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(result_rx);
        wait_for(|| in_use(&metrics.peer_bitcoind_places_in_use, caller) == 0).await;
        calls.pop();
        check.await.unwrap();

        assert_eq!(rpcs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovery_keeps_its_starters_place_until_it_ends() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker);
        let (_kyoto_node, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();
        monitor.requester = kyoto_client.requester;
        monitor.synced = true;
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let outpoint = make_outpoint(1);
        monitor
            .deposit_lookup_cache
            .put_tx_block(outpoint.txid, HashCheckpoint::new(42, block_hash(2)));
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics.clone());
        let caller = Address::new([7; 32]);
        let (mut request, result_rx) = deposit_check_request_for(outpoint);
        request.charge = Some(charge_for(&limiter, caller).await);

        monitor.confirm_deposit(request);
        assert_eq!(monitor.deposit_discovery_workers.len(), 1);
        monitor.pending_deposit_checks.clear();
        drop(result_rx);
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(cache_requests(&metrics, "transaction", "miss"), 1);
        assert_eq!(in_use(&metrics.peer_bitcoind_places_in_use, caller), 1);
        assert_eq!(in_use(&metrics.peer_bitcoind_discoveries_in_use, caller), 1);
        monitor.deposit_discovery_workers.join_next().await;
        assert_eq!(in_use(&metrics.peer_bitcoind_places_in_use, caller), 0);
    }

    #[tokio::test]
    async fn a_callers_discovery_past_the_cap_is_refused_at_once() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker.clone());
        monitor.synced = true;
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics.clone());
        let caller = Address::new([7; 32]);
        let mut requests = Vec::new();
        let mut receivers = Vec::new();
        for seed in 0..65u8 {
            tracker.upsert_request(Address::new([seed; 32]), make_outpoint(seed));
            let (mut request, result_rx) = deposit_check_request_for(make_outpoint(seed));
            request.charge = Some(charge_for(&limiter, caller).await);
            requests.push(request);
            receivers.push(result_rx);
        }

        for request in requests {
            monitor.confirm_deposit(request);
        }

        assert_eq!(monitor.deposit_discovery_workers.len(), 64);
        assert!(matches!(
            receivers.pop().unwrap().await.unwrap(),
            Err(DepositConfirmError::DiscoveriesFull)
        ));
        assert!(matches!(
            tracker.discovery(&make_outpoint(64)),
            DepositDiscovery::Discover(_)
        ));
        assert_eq!(
            metrics
                .peer_bitcoind_requests_shed_total
                .with_label_values(&[&caller.to_string()])
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn a_caller_joins_only_its_own_discovery() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker);
        monitor.synced = true;
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics);
        let outpoint = make_outpoint(1);
        let first = Address::new([7; 32]);
        let second = Address::new([8; 32]);
        let mut receivers = Vec::new();

        for caller in [first, second, first] {
            let (mut request, result_rx) = deposit_check_request_for(outpoint);
            request.charge = Some(charge_for(&limiter, caller).await);
            monitor.confirm_deposit(request);
            receivers.push(result_rx);
        }

        assert_eq!(monitor.deposit_discovery_workers.len(), 2);
        assert_eq!(
            monitor.pending_deposit_checks[&(outpoint, Some(first))].len(),
            2
        );
        assert_eq!(
            monitor.pending_deposit_checks[&(outpoint, Some(second))].len(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_fetch_keeps_its_callers_slot_after_its_discovery_times_out() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker);
        let (kyoto_node, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();
        monitor.requester = kyoto_client.requester;
        monitor.synced = true;
        monitor.tip = Some(HashCheckpoint::new(42, block_hash(2)));
        let outpoint = make_outpoint(1);
        monitor
            .deposit_lookup_cache
            .put_tx_block(outpoint.txid, HashCheckpoint::new(42, block_hash(2)));
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics);
        let charge = charge_for(&limiter, Address::new([7; 32])).await;
        let (mut request, _result_rx) = deposit_check_request_for(outpoint);
        request.charge = Some(charge.clone());

        monitor.confirm_deposit(request);
        let discovery = monitor
            .deposit_discovery_workers
            .join_next()
            .await
            .unwrap()
            .unwrap();

        assert!(discovery.result.is_err());
        assert!(charge.fetch_slot().now_or_never().is_none());
        drop(kyoto_node);
        wait_for(|| charge.fetch_slot().now_or_never().is_some()).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovery_shares_an_outstanding_fetch_without_its_callers_slot() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker);
        let (_kyoto_node, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();
        monitor.requester = kyoto_client.requester;
        monitor.synced = true;
        let block = HashCheckpoint::new(42, block_hash(2));
        monitor.tip = Some(block);
        let [first, second] = [make_outpoint(1), make_outpoint(2)];
        for outpoint in [first, second] {
            monitor
                .deposit_lookup_cache
                .put_tx_block(outpoint.txid, block);
        }
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics);
        let _second_callers_slot = charge_for(&limiter, Address::new([8; 32]))
            .await
            .fetch_slot()
            .await;
        let mut receivers = Vec::new();

        for (outpoint, caller) in [(first, [7; 32]), (second, [8; 32])] {
            let (mut request, result_rx) = deposit_check_request_for(outpoint);
            request.charge = Some(charge_for(&limiter, Address::new(caller)).await);
            monitor.confirm_deposit(request);
            receivers.push(result_rx);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let cache = monitor.deposit_lookup_cache.lock();
        assert_eq!(cache.fetches.len(), 1);
        assert_eq!(
            cache.fetches[&block.hash].txids,
            HashSet::from([first.txid, second.txid])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovery_that_waited_for_its_slot_uses_a_recorded_block() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let mut monitor = test_monitor(metrics.clone(), tracker.clone());
        let (_kyoto_node, kyoto_client) = kyoto::Builder::new(bitcoin::Network::Bitcoin)
            .chain_state(kyoto::ChainState::Checkpoint(HashCheckpoint::from_genesis(
                bitcoin::Network::Bitcoin,
            )))
            .build();
        monitor.requester = kyoto_client.requester;
        monitor.synced = true;
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let checkpoint = HashCheckpoint::new(0, block.block_hash());
        monitor.tip = Some(checkpoint);
        let outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(Address::new([1; 32]), outpoint);
        monitor
            .deposit_lookup_cache
            .put_tx_block(outpoint.txid, checkpoint);
        let limiter = crate::btc_monitor::limits::BitcoindLimiter::new(metrics);
        let charge = charge_for(&limiter, Address::new([7; 32])).await;
        let slot = charge.fetch_slot().await;
        let (mut request, _result_rx) = deposit_check_request_for(outpoint);
        request.charge = Some(charge);

        monitor.confirm_deposit(request);
        tokio::time::sleep(Duration::from_secs(1)).await;
        tracker.apply_block_if_current(tracker.bitcoin_generation(), checkpoint, &block);
        drop(slot);
        let discovery = monitor
            .deposit_discovery_workers
            .join_next()
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            discovery.result.unwrap(),
            tracker.recorded_status(&outpoint).unwrap()
        );
        assert!(monitor.deposit_lookup_cache.lock().fetches.is_empty());
    }

    #[tokio::test]
    async fn a_discovery_uses_a_recorded_block_instead_of_fetching_it() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let monitor = test_monitor(metrics, tracker.clone());
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let checkpoint = HashCheckpoint::new(0, block.block_hash());
        let outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(Address::new([1; 32]), outpoint);
        tracker.apply_block_if_current(tracker.bitcoin_generation(), checkpoint, &block);
        monitor
            .deposit_lookup_cache
            .put_tx_block(outpoint.txid, checkpoint);

        let status = discover_deposit(
            monitor.deposit_discovery_context(checkpoint, None),
            outpoint,
        )
        .await
        .unwrap();

        assert_eq!(Some(status), tracker.recorded_status(&outpoint));
    }

    #[tokio::test]
    async fn a_fetch_answered_after_its_discovery_timed_out_records_the_deposit() {
        let metrics = Arc::new(fresh_metrics());
        let tracker = DepositTracker::new(metrics.clone());
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(Address::new([1; 32]), outpoint);
        let cache = SharedDepositLookupCache::new(metrics.clone());
        let block_info = HashCheckpoint::new(0, block.block_hash());
        let (id, timed_out) = cache.lock().insert_fetch(block_info.hash, outpoint.txid);
        drop(timed_out);
        let (answer_tx, answer) = oneshot::channel();
        answer_tx
            .send(Ok(kyoto::IndexedBlock {
                height: 0,
                block: block.clone(),
            }))
            .unwrap();

        FetchWaiter {
            cache: cache.downgrade(),
            block_info,
            id,
            deposit_tracker: tracker.clone(),
            generation: tracker.bitcoin_generation(),
            _slot: None,
        }
        .wait(
            answer,
            BlockFetchTimer::start(&metrics.kyoto_block_fetch_seconds),
        )
        .await;

        assert_eq!(
            tracker.recorded_status(&outpoint),
            Some(DepositStatus::InBlock {
                checkpoint: block_info,
                is_coinbase: true,
                txout: block.txdata[0].output[0].clone(),
            })
        );
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
        tracker.upsert_request(Address::new([1; 32]), outpoint);
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
        tracker.upsert_request(Address::new([1; 32]), make_outpoint(1));
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
        tracker.upsert_request(Address::new([1; 32]), outpoint);
        record_status(
            &tracker,
            &outpoint,
            DepositStatus::InBlock {
                checkpoint: block_info,
                is_coinbase: false,
                txout: deposit_txout(),
            },
        );
        let mut result_rxs = Vec::new();
        for vout in [0, 1] {
            let current = bitcoin::OutPoint { txid, vout };
            if vout == 1 {
                tracker.upsert_request(Address::new([2; 32]), current);
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
            DepositConfirmation::InsufficientConfirmations {
                confirmations: 9,
                required_confirmations: 100,
            }
        );
        assert_eq!(
            result_rxs.remove(0).await.unwrap().unwrap(),
            DepositConfirmation::NotFound
        );
        assert_eq!(cache_requests(&metrics, "tx_block", "hit"), 0);
        assert_eq!(cache_requests(&metrics, "tx_block", "miss"), 0);
    }

    #[tokio::test]
    async fn coinbase_deposit_check_reports_maturity_requirement() {
        let outpoint = make_outpoint(1);
        let result = check_result_from_status(
            DepositStatus::InBlock {
                checkpoint: HashCheckpoint::new(42, block_hash(2)),
                is_coinbase: true,
                txout: deposit_txout(),
            },
            HashCheckpoint::new(140, block_hash(3)),
            6,
            BitcoindRpc::new(
                Arc::new(corepc_client::client_sync::v29::Client::new(
                    "http://127.0.0.1:1",
                )),
                None,
            ),
            outpoint,
            deposit_txout(),
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            DepositConfirmation::InsufficientConfirmations {
                confirmations: 99,
                required_confirmations: 100,
            }
        );
    }

    #[tokio::test]
    async fn deposit_check_refuses_a_mismatched_output_without_rpc() {
        let outpoint = make_outpoint(1);
        let recorded = bitcoin::TxOut {
            value: deposit_txout().value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x60; 100_000]),
        };
        let result = check_result_from_status(
            DepositStatus::InBlock {
                checkpoint: HashCheckpoint::new(42, block_hash(2)),
                is_coinbase: false,
                txout: recorded.clone(),
            },
            HashCheckpoint::new(140, block_hash(3)),
            6,
            BitcoindRpc::new(
                Arc::new(corepc_client::client_sync::v29::Client::new(
                    "http://127.0.0.1:1",
                )),
                None,
            ),
            outpoint,
            deposit_txout(),
        )
        .await;

        assert!(
            matches!(
                &result,
                Err(DepositConfirmError::OutputMismatch { expected, actual, .. })
                    if *expected == deposit_txout() && *actual == recorded
            ),
            "{:?}",
            result.as_ref().map_err(ToString::to_string)
        );
        assert!(result.unwrap_err().to_string().len() < 300);
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
            Monitor::resolve_start_checkpoint(&rpc, &above_taproot)
                .await
                .unwrap(),
            HashCheckpoint::taproot_activation(),
        );

        let between_segwit_and_taproot = MonitorConfig {
            network: bitcoin::Network::Bitcoin,
            start_height: 500_000,
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::resolve_start_checkpoint(&rpc, &between_segwit_and_taproot)
                .await
                .unwrap(),
            HashCheckpoint::segwit_activation(),
        );
    }

    /// Answer a JSON-RPC request, echoing its id.
    fn rpc_reply(req: &str, result: serde_json::Value, error: serde_json::Value) -> String {
        let body = req.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        let id = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|req| req.get("id").cloned())
            .unwrap_or_default();
        serde_json::json!({ "result": result, "error": error, "id": id }).to_string()
    }

    fn rpc_error(req: &str, code: i32, message: &str) -> String {
        rpc_reply(
            req,
            serde_json::Value::Null,
            serde_json::json!({ "code": code, "message": message }),
        )
    }

    fn rpc_ok(req: &str, result: &str) -> String {
        rpc_reply(req, serde_json::json!(result), serde_json::Value::Null)
    }

    /// Serve JSON-RPC over loopback, answering each request body with `reply`.
    async fn stub_bitcoind(
        reply: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Arc<corepc_client::client_sync::v29::Client> {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reply = Arc::new(reply);

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let body = reply(&String::from_utf8_lossy(&buf[..n]));
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
        });

        Arc::new(corepc_client::client_sync::v29::Client::new(&format!(
            "http://{addr}"
        )))
    }

    #[tokio::test]
    async fn checkpoint_at_height_waits_out_a_lagging_bitcoind() {
        use std::sync::atomic::AtomicU32;
        use std::sync::atomic::Ordering;

        const HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        // `getblockhash` replies "out of range" this many times before the block lands.
        const LAGGING_REPLIES: u32 = 2;

        let block_hash_calls = Arc::new(AtomicU32::new(0));
        let rpc = stub_bitcoind({
            let block_hash_calls = block_hash_calls.clone();
            move |req| {
                if req.contains("\"getblockhash\"")
                    && block_hash_calls.fetch_add(1, Ordering::SeqCst) >= LAGGING_REPLIES
                {
                    rpc_ok(req, HASH)
                } else {
                    rpc_error(req, -8, "Block height out of range")
                }
            }
        })
        .await;

        // The old "-8 is permanent" path returned a genesis checkpoint on the first reply.
        let checkpoint = tokio::time::timeout(
            Duration::from_secs(60),
            Monitor::checkpoint_at_height(&rpc, 300_000),
        )
        .await
        .expect("checkpoint_at_height gave up instead of waiting for bitcoind")
        .unwrap();

        assert_eq!(checkpoint.height, 300_000);
        assert_eq!(checkpoint.hash.to_string(), HASH);
        assert!(block_hash_calls.load(Ordering::SeqCst) > LAGGING_REPLIES);
    }

    #[tokio::test]
    async fn checkpoint_at_height_gives_up_on_a_permanent_rpc_error() {
        let rpc = stub_bitcoind(|req| rpc_error(req, -32601, "Method not found")).await;

        let err = tokio::time::timeout(
            Duration::from_secs(60),
            Monitor::checkpoint_at_height(&rpc, 300_000),
        )
        .await
        .expect("checkpoint_at_height retried an error that will never clear")
        .unwrap_err();

        assert!(err.to_string().contains("start height 300000"), "{err}");
    }

    #[tokio::test]
    async fn checkpoint_at_height_gives_up_on_a_malformed_reply() {
        let rpc = stub_bitcoind(|_| "<html>not json</html>".to_string()).await;

        let err = tokio::time::timeout(
            Duration::from_secs(60),
            Monitor::checkpoint_at_height(&rpc, 300_000),
        )
        .await
        .expect("checkpoint_at_height retried a reply that will never parse")
        .unwrap_err();

        assert!(err.to_string().contains("start height 300000"), "{err}");
    }

    #[tokio::test]
    async fn orphaned_transaction_is_not_found() {
        // Legacy one-input, one-output fixture from rust-bitcoin's transaction tests.
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(concat!(
            "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece",
            "010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d79",
            "0221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c01",
            "21033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff",
            "0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000",
        ))
        .unwrap();
        let txid = tx.compute_txid();
        // txindex retains the old block hash even when the transaction is orphaned.
        let result = serde_json::json!({
            "hex": bitcoin::consensus::encode::serialize_hex(&tx),
            "txid": txid.to_string(),
            "hash": tx.compute_wtxid().to_string(),
            "size": tx.total_size(),
            "vsize": tx.vsize(),
            "weight": tx.weight().to_wu(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": [{
                "txid": tx.input[0].previous_output.txid.to_string(),
                "vout": tx.input[0].previous_output.vout,
                "scriptSig": {
                    "asm": tx.input[0].script_sig.to_asm_string(),
                    "hex": tx.input[0].script_sig.to_hex_string(),
                },
                "sequence": tx.input[0].sequence.to_consensus_u32(),
            }],
            "vout": [{
                "value": tx.output[0].value.to_btc(),
                "n": 0,
                "scriptPubKey": {
                    "asm": tx.output[0].script_pubkey.to_asm_string(),
                    "hex": tx.output[0].script_pubkey.to_hex_string(),
                    "type": "pubkeyhash",
                },
            }],
            "blockhash": block_hash(1).to_string(),
            "confirmations": 0,
        });
        let rpc = stub_bitcoind(move |req| {
            assert!(req.contains("\"getrawtransaction\""));
            rpc_reply(req, result.clone(), serde_json::Value::Null)
        })
        .await;
        let (result_tx, result_rx) = oneshot::channel();
        let caller = Caller {
            deadline: Instant::now() + MONITOR_REQUEST_TIMEOUT,
            charge: None,
            result_tx,
        };

        Monitor::get_transaction_status(rpc, txid, caller).await;

        assert_eq!(result_rx.await.unwrap().unwrap(), TxStatus::NotFound);
    }

    #[tokio::test]
    async fn caller_rpc_only_starts_inside_the_deadline() {
        let rpc = Arc::new(corepc_client::client_sync::v29::Client::new(
            "http://127.0.0.1:1",
        ));

        let (result_tx, _rx) = oneshot::channel::<Result<()>>();
        let mut fits = Caller {
            deadline: Instant::now() + MONITOR_REQUEST_TIMEOUT,
            charge: None,
            result_tx,
        };
        assert_eq!(fits.rpc(&rpc, |_| 1).await, Some(1));

        let (result_tx, _rx) = oneshot::channel::<Result<()>>();
        let mut too_late = Caller {
            deadline: Instant::now() + BITCOIND_RPC_BUDGET / 2,
            charge: None,
            result_tx,
        };
        assert_eq!(too_late.rpc(&rpc, |_| 1).await, None);

        let (result_tx, rx) = oneshot::channel::<Result<()>>();
        drop(rx);
        let mut gone = Caller {
            deadline: Instant::now() + MONITOR_REQUEST_TIMEOUT,
            charge: None,
            result_tx,
        };
        assert_eq!(gone.rpc(&rpc, |_| 1).await, None);
    }

    #[test]
    fn only_recoverable_transport_errors_are_retried() {
        use jsonrpc::http::minreq_http::Error as TransportError;
        use jsonrpc::http::minreq_http::HttpError;

        let http = |status_code| {
            corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Transport(Box::new(
                TransportError::Http(HttpError {
                    status_code,
                    body: String::new(),
                }),
            )))
        };
        assert!(is_transient_rpc_error(&http(503)));
        assert!(is_transient_rpc_error(&http(502)));
        assert!(!is_transient_rpc_error(&http(401)));
        assert!(!is_transient_rpc_error(&http(403)));

        // A 200 whose body is not JSON-RPC is a transport error too, and permanent.
        let malformed =
            corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Transport(Box::new(
                TransportError::Minreq(minreq::Error::SerdeJsonError(
                    serde_json::from_str::<serde_json::Value>("nope").unwrap_err(),
                )),
            )));
        assert!(!is_transient_rpc_error(&malformed));

        // Against a port nothing is listening on, so the retryable branch is
        // exercised on a real error rather than a hand-built one.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let refused = corepc_client::client_sync::v29::Client::new(&format!("http://{addr}"))
            .get_blockchain_info()
            .unwrap_err();
        assert!(is_transient_rpc_error(&refused), "{refused}");
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
