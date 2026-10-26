// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Bitcoin client: confirmation lookups over HTTP JSON-RPC.
//!
//! Why it exists: the withdrawal E3 and the deposit E1 are Bitcoin
//! confirmations. Bitcoin has no event stream to scan, so the auditor looks
//! each pending transaction up by txid.
//!
//! Why one height:
//! - A parent transaction creates an output that a dependent transaction spends.
//! - At one height, the dependent cannot have more confirmations than its parent.
//! - All lookups in a tick use one captured height, including lookups in different batches.
//! - New blocks between RPC responses must not complete a dependent machine before its parent is ready to close.
//! - Pool maintenance needs each complete flow's parent machine already closed or ready to close.
//!
//! How it works:
//! 1. At startup, the auditor reads Hashi's on-chain
//!    `bitcoin_confirmation_threshold` and gives it to the client. A
//!    transaction counts as confirmed at that depth, as it does for the
//!    committee. On mainnet, a threshold below `MAINNET_MIN_CONFIRMATIONS`
//!    stops the monitor.
//! 2. Before a pass, `synced_height` checks the node and returns its height.
//!    The node must follow `deployment.bitcoin_network`, be out of initial
//!    block download, and have a tip no older than `max_tip_age`, which the
//!    auditor sets to its `SOURCE_STALE_LIMIT`. At the first check, a node
//!    that reports its indexes must have a synced `txindex`. A failed check
//!    fails the pass, so a wrong node, or one with an older tip, becomes a
//!    `SourceStale` finding. Until its tip passes that age, a frozen node
//!    still gives lookup findings.
//!    All batches use this height to calculate confirmation depth.
//!    Blocks that arrive during the pass count on the next pass.
//! 3. `prefetch_confirmations` looks all pending txids up in batches of
//!    `HTTP_JSON_RPC_BATCH_SIZE`, with `HTTP_JSON_RPC_BATCHES_IN_FLIGHT`
//!    batches sent at once, and `lookup_confirmation` serves each one from
//!    that cache. A confirmed answer is kept across passes: a confirmation
//!    at the threshold depth does not change. `forget_unconfirmed` drops
//!    the rest at the start of each pass, so an unconfirmed transaction is
//!    looked up again. An answer for a txid no longer asked for is dropped.
//!    When a lookup fails, the batches that finished are kept, so the next
//!    pass asks only about the rest.
//! 4. A transaction at the threshold depth is returned with the time of
//!    its own block and the time of the block that gave it that depth.
//! 5. Requests are not paced: the node is the bridge's own. A request that
//!    fails to send, gets an HTTP 502, 503 or 504, or is rate limited is
//!    retried with exponential backoff, `MAX_REQUEST_RETRIES` times. Core
//!    answers a JSON-RPC error with HTTP 500, so 500 is not retried.
//!
//! Assumptions:
//! - The threshold is read once. A governance change takes effect in the
//!   monitor at its next restart.
//! - An unconfirmed answer is never reused across passes. So the auditor
//!   can stamp every answer with the pass's start time: the real lookup
//!   is no earlier. A cached confirmed answer does not need a time.
//! - The endpoint serves `getrawtransaction` with verbose output, which
//!   needs `txindex` or a hosted provider. A hosted provider that does not
//!   serve `getindexinfo` is not checked for an index.
//! - A request that still fails after the retries fails the pass, which
//!   is retried on the next tick.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::consensus::encode::deserialize_hex;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::domain::BtcConfirmation;
use crate::time::utc_timestamp;

/// Calls per JSON-RPC batch request.
const HTTP_JSON_RPC_BATCH_SIZE: usize = 100;
/// Confirmation batches sent at the same time. A probe of the testnet node
/// (2026-10-19) served eight batches of 100 at once fastest, with no errors.
const HTTP_JSON_RPC_BATCHES_IN_FLIGHT: usize = 8;
/// Txids between two progress log lines of a confirmation lookup.
const LOOKUP_PROGRESS_EVERY: usize = 10_000;
/// Retries of one request. The delays double from one second, so the
/// last retry comes about a minute after the first failure.
const MAX_REQUEST_RETRIES: usize = 6;
/// The lowest confirmation threshold the monitor accepts on Bitcoin
/// mainnet. Hashi's launch tool refuses a lower one there too.
pub const MAINNET_MIN_CONFIRMATIONS: u64 = 6;

/// The on-chain confirmation threshold, refused on mainnet below
/// `MAINNET_MIN_CONFIRMATIONS`.
pub fn checked_confirmation_threshold(threshold: u64, network: Network) -> anyhow::Result<u64> {
    anyhow::ensure!(
        network != Network::Bitcoin || threshold >= MAINNET_MIN_CONFIRMATIONS,
        "Hashi's bitcoin_confirmation_threshold is {threshold} on mainnet; \
         the monitor needs at least {MAINNET_MIN_CONFIRMATIONS}"
    );
    Ok(threshold)
}

/// What Bitcoin holds at an outpoint. `Missing` and `Spent` differ by the
/// transaction lookup, `Spent` and `Unspent` by the UTXO set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutpointState {
    /// The transaction is unknown or not confirmed deep enough, or it has no
    /// output at that vout.
    Missing,
    /// The output exists, and a confirmed transaction has spent it. With
    /// `include_mempool`, a mempool transaction also counts.
    Spent,
    /// The output exists and is in the UTXO set. Without `include_mempool`,
    /// a mempool spend does not change this.
    Unspent {
        /// The time of the block that holds the output.
        block_time: UnixSeconds,
    },
}

pub struct BtcRpcClient {
    transport: HttpJsonRpcTransport,
    confirmation_cache: RefCell<HashMap<Txid, Option<BtcConfirmation>>>,
    /// The chain the node must follow.
    network: Network,
    /// The oldest tip, in seconds, that counts as synced.
    max_tip_age: u64,
    /// Whether the node's `txindex` passed its check. It is checked once.
    txindex_checked: Cell<bool>,
}

struct HttpJsonRpcTransport {
    rpc_url: String,
    headers: BTreeMap<String, String>,
    /// Confirmations a transaction needs to count as confirmed.
    required_confirmations: u64,
}

#[derive(Deserialize)]
struct JsonRpcEnvelope {
    id: Value,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RawTransactionInfo {
    /// The serialized transaction.
    hex: String,
    blockhash: Option<String>,
    #[serde(default)]
    confirmations: u64,
}

#[derive(Deserialize)]
struct RawBlockHeader {
    time: u64,
    height: u64,
}

#[derive(Deserialize)]
struct BlockchainInfo {
    /// The chain name, as in `bitcoind -chain`.
    chain: String,
    blocks: u64,
    headers: u64,
    /// The time of the tip block.
    time: UnixSeconds,
    initialblockdownload: bool,
}

impl BlockchainInfo {
    /// Fail unless the node follows `network` and is synced at `now`, with
    /// a tip at most `max_tip_age` old. Core clears `initialblockdownload`
    /// once and never sets it again, so the tip time also catches a node
    /// that stopped getting blocks.
    fn ensure_synced(
        &self,
        network: Network,
        max_tip_age: u64,
        now: UnixSeconds,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.chain == network.to_core_arg(),
            "bitcoind follows chain {}, not {}",
            self.chain,
            network.to_core_arg()
        );
        anyhow::ensure!(
            !self.initialblockdownload && self.blocks >= self.headers,
            "bitcoind is not synced: initialblockdownload={}, blocks={}, headers={}",
            self.initialblockdownload,
            self.blocks,
            self.headers
        );
        anyhow::ensure!(
            now.saturating_sub(self.time) <= max_tip_age,
            "bitcoind tip at height {} is from {}, more than {max_tip_age} s ago",
            self.blocks,
            utc_timestamp(self.time)
        );
        Ok(())
    }
}

/// Fail unless a `getindexinfo` result shows a synced `txindex`.
fn ensure_txindex(index_info: &Value) -> anyhow::Result<()> {
    let synced = index_info
        .get("txindex")
        .context("bitcoind has no txindex; getrawtransaction needs one")?
        .get("synced")
        .and_then(Value::as_bool)
        .context("bitcoind getindexinfo has no txindex.synced")?;
    anyhow::ensure!(synced, "bitcoind txindex is still building");
    Ok(())
}

/// The answers of a confirmation lookup, and the first error if a batch
/// failed. The answers of the batches that finished are kept either way.
struct LookupOutcome {
    confirmations: HashMap<Txid, Option<BtcConfirmation>>,
    error: Option<anyhow::Error>,
}

/// A mined transaction before its block header is read.
struct MinedTx {
    block_hash: BlockHash,
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOut>,
}

impl RawTransactionInfo {
    /// The block hash, inputs, and outputs of a mined transaction.
    fn mined(self, txid: Txid) -> anyhow::Result<Option<MinedTx>> {
        let Some(block_hash) = self.blockhash else {
            debug!(%txid, "bitcoin tx found but not mined yet");
            return Ok(None);
        };
        if self.confirmations == 0 {
            return Ok(None);
        }

        let block_hash = BlockHash::from_str(&block_hash)
            .with_context(|| format!("invalid bitcoin block hash for {txid}"))?;
        let tx: Transaction = deserialize_hex(&self.hex)
            .with_context(|| format!("invalid bitcoin transaction hex for {txid}"))?;
        anyhow::ensure!(
            tx.compute_txid() == txid,
            "bitcoin returned transaction {} for {txid}",
            tx.compute_txid()
        );
        Ok(Some(MinedTx {
            block_hash,
            inputs: tx.input.iter().map(|input| input.previous_output).collect(),
            outputs: tx.output,
        }))
    }
}

impl BtcRpcClient {
    /// A client that counts a transaction as confirmed at
    /// `required_confirmations`, and a node as synced with a tip at most
    /// `max_tip_age` seconds old.
    pub fn new(
        cfg: &Config,
        required_confirmations: u64,
        max_tip_age: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transport: HttpJsonRpcTransport {
                rpc_url: cfg.btc.rpc_url.clone(),
                headers: cfg.btc.http_headers.clone(),
                required_confirmations,
            },
            confirmation_cache: RefCell::new(HashMap::new()),
            network: cfg.deployment.bitcoin_network,
            max_tip_age,
            txindex_checked: Cell::new(false),
        })
    }

    /// Return the node height after the synchronization check succeeds.
    /// See the module doc for the checks.
    pub fn synced_height(&self) -> anyhow::Result<u64> {
        let response = self
            .transport
            .call("getblockchaininfo", serde_json::json!([]))?;
        if let Some(error) = response.error {
            anyhow::bail!(
                "bitcoin getblockchaininfo failed: {} ({})",
                error.message,
                error.code
            );
        }
        let info: BlockchainInfo = serde_json::from_value(
            response
                .result
                .context("bitcoin getblockchaininfo response is missing its result")?,
        )
        .context("failed to parse bitcoin blockchain info")?;
        info.ensure_synced(self.network, self.max_tip_age, now_timestamp_secs())?;
        if !self.txindex_checked.get() {
            self.check_txindex()?;
            self.txindex_checked.set(true);
        }
        Ok(info.blocks)
    }

    /// Fail unless the node has a synced `txindex`. A node that does not
    /// serve `getindexinfo`, such as a hosted provider, passes.
    fn check_txindex(&self) -> anyhow::Result<()> {
        let response = self.transport.call("getindexinfo", serde_json::json!([]))?;
        if let Some(error) = response.error {
            // Method not found.
            if error.code == -32601 {
                info!("bitcoin endpoint does not serve getindexinfo; txindex not checked");
                return Ok(());
            }
            anyhow::bail!(
                "bitcoin getindexinfo failed: {} ({})",
                error.message,
                error.code
            );
        }
        ensure_txindex(
            &response
                .result
                .context("bitcoin getindexinfo response is missing its result")?,
        )
    }

    /// Drop the unconfirmed answers, so the next lookup asks again. The
    /// confirmed ones stay: a confirmation at the threshold depth does not
    /// change.
    pub fn forget_unconfirmed(&self) {
        self.confirmation_cache
            .borrow_mut()
            .retain(|_, confirmation| confirmation.is_some());
    }

    /// Fetch missing confirmations at `tip_height` and remove answers absent from `txids`.
    /// Keep completed batches if another batch fails.
    pub fn prefetch_confirmations(&self, txids: &[Txid], tip_height: u64) -> anyhow::Result<()> {
        let asked = txids.iter().copied().collect::<HashSet<_>>();
        let missing = {
            let cache = self.confirmation_cache.borrow();
            txids
                .iter()
                .filter(|txid| !matches!(cache.get(*txid), Some(Some(_))))
                .copied()
                .collect::<Vec<_>>()
        };
        info!(
            cached = txids.len() - missing.len(),
            looked_up = missing.len(),
            "bitcoin confirmations served from the cache"
        );
        let outcome = self.transport.lookup_confirmations(&missing, tip_height);
        let mut cache = self.confirmation_cache.borrow_mut();
        cache.extend(outcome.confirmations);
        cache.retain(|txid, _| asked.contains(txid));
        outcome.error.map_or(Ok(()), Err)
    }

    /// Query BTC RPC to check if a transaction is confirmed.
    /// Returns
    /// - `Ok(Some(confirmation))` if txid is confirmed,
    /// - `Ok(None)` if txid is not seen or txid is seen but not confirmed,
    /// - `Err(...)` for all other errors
    pub fn lookup_confirmation(&self, txid: Txid) -> anyhow::Result<Option<BtcConfirmation>> {
        if let Some(result) = self.confirmation_cache.borrow().get(&txid) {
            return Ok(result.clone());
        }
        let tip_height = self.synced_height()?;
        let result = self.transport.lookup_confirmation(txid, tip_height)?;
        self.confirmation_cache
            .borrow_mut()
            .insert(txid, result.clone());
        Ok(result)
    }

    /// The state of each outpoint on Bitcoin. The transactions are fetched
    /// fresh, and the confirmation cache is not touched. `include_mempool`
    /// also counts a spend in the mempool.
    pub fn lookup_outpoint_states(
        &self,
        outpoints: &[OutPoint],
        tip_height: u64,
        include_mempool: bool,
    ) -> anyhow::Result<HashMap<OutPoint, OutpointState>> {
        let txids = outpoints
            .iter()
            .map(|outpoint| outpoint.txid)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let outcome = self.transport.lookup_confirmations(&txids, tip_height);
        if let Some(error) = outcome.error {
            return Err(error);
        }

        // Only an output that exists can be in the UTXO set.
        let mut states = HashMap::with_capacity(outpoints.len());
        let mut existing = Vec::new();
        for outpoint in outpoints {
            let confirmation = outcome
                .confirmations
                .get(&outpoint.txid)
                .with_context(|| format!("missing bitcoin lookup result for {}", outpoint.txid))?;
            match confirmation {
                Some(confirmation) if (outpoint.vout as usize) < confirmation.outputs.len() => {
                    existing.push((*outpoint, confirmation.block_time));
                }
                _ => {
                    states.insert(*outpoint, OutpointState::Missing);
                }
            }
        }

        let existing_outpoints = existing
            .iter()
            .map(|(outpoint, _)| *outpoint)
            .collect::<Vec<_>>();
        let unspent = self
            .transport
            .lookup_unspent(&existing_outpoints, include_mempool)?;
        for (outpoint, block_time) in existing {
            let state = match unspent.get(&outpoint) {
                Some(true) => OutpointState::Unspent { block_time },
                Some(false) => OutpointState::Spent,
                None => anyhow::bail!("missing bitcoin gettxout result for {outpoint}"),
            };
            states.insert(outpoint, state);
        }
        Ok(states)
    }
}

#[cfg(test)]
impl BtcRpcClient {
    fn cached_confirmations(&self) -> usize {
        self.confirmation_cache.borrow().len()
    }
}

impl HttpJsonRpcTransport {
    fn call(&self, method: &str, params: Value) -> anyhow::Result<JsonRpcEnvelope> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "hashi-monitor",
            "method": method,
            "params": params,
        });
        serde_json::from_value(self.post_json(&body)?)
            .context("failed to decode bitcoin JSON-RPC response")
    }

    fn call_batch(&self, body: &[Value]) -> anyhow::Result<Vec<JsonRpcEnvelope>> {
        let body = Value::Array(body.to_vec());
        serde_json::from_value(self.post_json(&body)?)
            .context("failed to decode bitcoin JSON-RPC batch response")
    }

    /// Send one request. A send that fails, a timeout among them, an HTTP
    /// 502, 503 or 504 and a rate limit are retried with bounded exponential
    /// backoff. Core sends 503 when its work queue is full. Any other status
    /// goes to the JSON-RPC decoding: Core answers an RPC error with 500.
    fn post_json(&self, body: &Value) -> anyhow::Result<Value> {
        for attempt in 0..=MAX_REQUEST_RETRIES {
            let request = minreq::post(&self.rpc_url)
                .with_timeout(60)
                .with_headers(self.headers.clone())
                .with_json(body)
                .context("failed to encode bitcoin JSON-RPC request")?;
            let response = match request.send() {
                Ok(response) => response,
                Err(error) => {
                    Self::wait_before_retry(attempt, &format!("request failed: {error}"))?;
                    continue;
                }
            };

            if matches!(response.status_code, 429 | 502 | 503 | 504) {
                Self::wait_before_retry(attempt, &format!("HTTP {}", response.status_code))?;
                continue;
            }

            let response_body: Value = response.json().with_context(|| {
                format!(
                    "failed to decode bitcoin JSON-RPC response (HTTP {})",
                    response.status_code
                )
            })?;
            if json_rpc_rate_limited(&response_body) {
                Self::wait_before_retry(attempt, "rate limited")?;
                continue;
            }

            return Ok(response_body);
        }

        unreachable!("the retry loop either returns or errors")
    }

    fn wait_before_retry(attempt: usize, reason: &str) -> anyhow::Result<()> {
        if attempt == MAX_REQUEST_RETRIES {
            anyhow::bail!("bitcoin JSON-RPC {reason} after {MAX_REQUEST_RETRIES} retries");
        }

        let delay = Duration::from_secs(1 << attempt.min(5));
        warn!(
            retry = attempt + 1,
            max_retries = MAX_REQUEST_RETRIES,
            delay_secs = delay.as_secs(),
            reason,
            "bitcoin JSON-RPC request will be retried"
        );
        thread::sleep(delay);
        Ok(())
    }

    fn lookup_confirmation(
        &self,
        txid: Txid,
        tip_height: u64,
    ) -> anyhow::Result<Option<BtcConfirmation>> {
        self.lookup_confirmation_batch(&[txid], tip_height)?
            .remove(&txid)
            .with_context(|| format!("missing bitcoin lookup result for {txid}"))
    }

    /// Look every txid up, `HTTP_JSON_RPC_BATCHES_IN_FLIGHT` batches at a
    /// time. Each worker takes the next batch until none is left. The first
    /// failure stops the others at their next batch. The answers of the
    /// batches that finished are returned with that error.
    fn lookup_confirmations(&self, txids: &[Txid], tip_height: u64) -> LookupOutcome {
        let batches = txids.chunks(HTTP_JSON_RPC_BATCH_SIZE).collect::<Vec<_>>();
        let next_batch = AtomicUsize::new(0);
        let processed = AtomicUsize::new(0);
        let results = Mutex::new(Vec::with_capacity(batches.len()));
        thread::scope(|scope| {
            for _ in 0..HTTP_JSON_RPC_BATCHES_IN_FLIGHT.min(batches.len()) {
                scope.spawn(|| {
                    while let Some(batch) = batches.get(next_batch.fetch_add(1, Ordering::Relaxed))
                    {
                        let result = self.lookup_confirmation_batch(batch, tip_height);
                        if result.is_err() {
                            next_batch.store(batches.len(), Ordering::Relaxed);
                        }
                        let processed_txids =
                            processed.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();
                        if processed_txids.is_multiple_of(LOOKUP_PROGRESS_EVERY)
                            || processed_txids == txids.len()
                        {
                            info!(
                                processed_txids,
                                total_txids = txids.len(),
                                "bitcoin confirmation lookup progress"
                            );
                        }
                        results.lock().expect("a worker never panics").push(result);
                    }
                });
            }
        });
        let mut outcome = LookupOutcome {
            confirmations: HashMap::with_capacity(txids.len()),
            error: None,
        };
        for result in results.into_inner().expect("a worker never panics") {
            match result {
                Ok(confirmations) => outcome.confirmations.extend(confirmations),
                Err(error) => {
                    outcome.error.get_or_insert(error);
                }
            }
        }
        outcome
    }

    fn lookup_confirmation_batch(
        &self,
        txids: &[Txid],
        tip_height: u64,
    ) -> anyhow::Result<HashMap<Txid, Option<BtcConfirmation>>> {
        let requests = txids
            .iter()
            .enumerate()
            .map(|(id, txid)| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "getrawtransaction",
                    "params": [txid.to_string(), true],
                })
            })
            .collect::<Vec<_>>();
        let responses = self.call_batch(&requests)?;
        let mut seen = HashSet::with_capacity(txids.len());
        let mut mined = HashMap::with_capacity(txids.len());

        for response in responses {
            let index = response_index(&response, txids.len())?;
            anyhow::ensure!(
                seen.insert(index),
                "duplicate bitcoin getrawtransaction batch response ID {index}"
            );
            let txid = txids[index];
            if let Some(error) = response.error {
                if error.code == -5 {
                    mined.insert(txid, None);
                    continue;
                }
                anyhow::bail!(
                    "bitcoin getrawtransaction failed for {txid}: {} ({})",
                    error.message,
                    error.code
                );
            }
            let info: RawTransactionInfo = serde_json::from_value(
                response
                    .result
                    .context("bitcoin getrawtransaction batch response is missing its result")?,
            )
            .with_context(|| format!("failed to parse transaction info for {txid}"))?;
            mined.insert(txid, info.mined(txid)?);
        }
        anyhow::ensure!(
            seen.len() == txids.len(),
            "bitcoin getrawtransaction batch returned {}/{} responses",
            seen.len(),
            txids.len()
        );

        let mined_block_hashes = mined
            .values()
            .flatten()
            .map(|tx| tx.block_hash)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let confirmed_block_times = self.confirmed_block_times(&mined_block_hashes, tip_height)?;

        Ok(mined
            .into_iter()
            .map(|(txid, transaction)| {
                let confirmation = transaction.and_then(|tx| {
                    confirmed_block_times.get(&tx.block_hash).map(
                        |&(block_time, confirmed_time)| BtcConfirmation {
                            block_time,
                            confirmed_time,
                            inputs: tx.inputs,
                            outputs: tx.outputs,
                        },
                    )
                });
                (txid, confirmation)
            })
            .collect())
    }

    /// Return block and confirmation times for blocks deep enough at `tip_height`.
    /// The holding block counts as the first confirmation.
    fn confirmed_block_times(
        &self,
        block_hashes: &[BlockHash],
        tip_height: u64,
    ) -> anyhow::Result<HashMap<BlockHash, (UnixSeconds, UnixSeconds)>> {
        let mut headers = self.block_headers(block_hashes)?;
        let confirming_height =
            |header: &RawBlockHeader| header.height + self.required_confirmations - 1;
        headers.retain(|_, header| confirming_height(header) <= tip_height);
        let confirming_heights = headers
            .values()
            .map(confirming_height)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let confirming_hashes = self.block_hashes(&confirming_heights)?;
        let confirming_headers =
            self.block_headers(&confirming_hashes.values().copied().collect::<Vec<_>>())?;

        headers
            .iter()
            .map(|(hash, header)| {
                let height = confirming_height(header);
                let confirming_hash = confirming_hashes
                    .get(&height)
                    .with_context(|| format!("missing block hash at height {height}"))?;
                let confirming = confirming_headers
                    .get(confirming_hash)
                    .with_context(|| format!("missing block header for {confirming_hash}"))?;
                Ok((*hash, (header.time, confirming.time)))
            })
            .collect()
    }

    /// `getblockheader` for each hash, in batches.
    fn block_headers(
        &self,
        hashes: &[BlockHash],
    ) -> anyhow::Result<HashMap<BlockHash, RawBlockHeader>> {
        let mut headers = HashMap::with_capacity(hashes.len());
        for chunk in hashes.chunks(HTTP_JSON_RPC_BATCH_SIZE) {
            let requests = chunk
                .iter()
                .enumerate()
                .map(|(id, hash)| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "getblockheader",
                        "params": [hash.to_string(), true],
                    })
                })
                .collect::<Vec<_>>();
            let responses = self.call_batch(&requests)?;
            let mut seen = HashSet::with_capacity(chunk.len());
            for response in responses {
                let index = response_index(&response, chunk.len())?;
                anyhow::ensure!(
                    seen.insert(index),
                    "duplicate bitcoin getblockheader batch response ID {index}"
                );
                let block_hash = chunk[index];
                if let Some(error) = response.error {
                    anyhow::bail!(
                        "bitcoin getblockheader failed for {block_hash}: {} ({})",
                        error.message,
                        error.code
                    );
                }
                let header: RawBlockHeader = serde_json::from_value(
                    response
                        .result
                        .context("bitcoin getblockheader batch response is missing its result")?,
                )
                .with_context(|| format!("failed to parse block header for {block_hash}"))?;
                headers.insert(block_hash, header);
            }
            anyhow::ensure!(
                seen.len() == chunk.len(),
                "bitcoin getblockheader batch returned {}/{} responses",
                seen.len(),
                chunk.len()
            );
        }
        Ok(headers)
    }

    /// `getblockhash` for each height, in batches.
    fn block_hashes(&self, heights: &[u64]) -> anyhow::Result<HashMap<u64, BlockHash>> {
        let mut hashes = HashMap::with_capacity(heights.len());
        for chunk in heights.chunks(HTTP_JSON_RPC_BATCH_SIZE) {
            let requests = chunk
                .iter()
                .enumerate()
                .map(|(id, height)| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "getblockhash",
                        "params": [height],
                    })
                })
                .collect::<Vec<_>>();
            let responses = self.call_batch(&requests)?;
            let mut seen = HashSet::with_capacity(chunk.len());
            for response in responses {
                let index = response_index(&response, chunk.len())?;
                anyhow::ensure!(
                    seen.insert(index),
                    "duplicate bitcoin getblockhash batch response ID {index}"
                );
                let height = chunk[index];
                if let Some(error) = response.error {
                    anyhow::bail!(
                        "bitcoin getblockhash failed for height {height}: {} ({})",
                        error.message,
                        error.code
                    );
                }
                let hash: String = serde_json::from_value(
                    response
                        .result
                        .context("bitcoin getblockhash batch response is missing its result")?,
                )
                .with_context(|| format!("failed to parse block hash at height {height}"))?;
                let hash = BlockHash::from_str(&hash)
                    .with_context(|| format!("invalid bitcoin block hash at height {height}"))?;
                hashes.insert(height, hash);
            }
            anyhow::ensure!(
                seen.len() == chunk.len(),
                "bitcoin getblockhash batch returned {}/{} responses",
                seen.len(),
                chunk.len()
            );
        }
        Ok(hashes)
    }
}

impl HttpJsonRpcTransport {
    /// Whether each outpoint is in the UTXO set. `include_mempool` also
    /// counts a spend in the mempool. Callers pass outpoints that exist:
    /// `gettxout` answers null for a spent output and for one that never
    /// existed alike.
    fn lookup_unspent(
        &self,
        outpoints: &[OutPoint],
        include_mempool: bool,
    ) -> anyhow::Result<HashMap<OutPoint, bool>> {
        let mut unspent = HashMap::with_capacity(outpoints.len());
        for chunk in outpoints.chunks(HTTP_JSON_RPC_BATCH_SIZE) {
            let requests = chunk
                .iter()
                .enumerate()
                .map(|(id, outpoint)| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "gettxout",
                        "params": [outpoint.txid.to_string(), outpoint.vout, include_mempool],
                    })
                })
                .collect::<Vec<_>>();
            let responses = self.call_batch(&requests)?;
            let mut seen = HashSet::with_capacity(chunk.len());
            for response in responses {
                let index = response_index(&response, chunk.len())?;
                anyhow::ensure!(
                    seen.insert(index),
                    "duplicate bitcoin gettxout batch response ID {index}"
                );
                let outpoint = chunk[index];
                if let Some(error) = response.error {
                    anyhow::bail!(
                        "bitcoin gettxout failed for {outpoint}: {} ({})",
                        error.message,
                        error.code
                    );
                }
                let is_unspent = !matches!(response.result, None | Some(Value::Null));
                unspent.insert(outpoint, is_unspent);
            }
            anyhow::ensure!(
                seen.len() == chunk.len(),
                "bitcoin gettxout batch returned {}/{} responses",
                seen.len(),
                chunk.len()
            );
        }
        Ok(unspent)
    }
}

fn json_rpc_rate_limited(response: &Value) -> bool {
    let is_rate_limited = |envelope: &Value| {
        envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64)
            == Some(429)
    };

    match response {
        Value::Array(envelopes) => envelopes.iter().any(is_rate_limited),
        envelope => is_rate_limited(envelope),
    }
}

fn response_index(response: &JsonRpcEnvelope, batch_len: usize) -> anyhow::Result<usize> {
    let index = response
        .id
        .as_u64()
        .context("bitcoin JSON-RPC batch response ID is not an integer")?;
    let index =
        usize::try_from(index).context("bitcoin JSON-RPC batch response ID is too large")?;
    anyhow::ensure!(
        index < batch_len,
        "bitcoin JSON-RPC batch response ID {index} is outside batch of {batch_len}"
    );
    Ok(index)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::BufRead as _;
    use std::io::BufReader;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::Once;

    use anyhow::Result;
    use base64ct::Base64;
    use base64ct::Encoding as _;
    use bitcoin::Amount;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;
    use e2e_tests::BitcoinNodeBuilder;
    use e2e_tests::bitcoin_node::RPC_PASSWORD;
    use e2e_tests::bitcoin_node::RPC_USER;
    use tempfile::TempDir;

    use super::BlockchainInfo;
    use super::BtcRpcClient;
    use super::HttpJsonRpcTransport;
    use super::MAINNET_MIN_CONFIRMATIONS;
    use super::OutpointState;
    use super::ensure_txindex;
    use crate::config::BtcConfig;
    use crate::config::Config;
    use crate::test_utils::txid;

    static TRACING_INIT: Once = Once::new();

    fn init_test_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init();
        });
    }

    /// The test config pointed at a local regtest node with its basic auth.
    fn test_config(rpc_url: String) -> Config {
        let mut cfg = Config::for_tests();
        cfg.btc = BtcConfig {
            rpc_url,
            http_headers: BTreeMap::from([(
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    Base64::encode_string(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes())
                ),
            )]),
        };
        cfg
    }

    // Note that this test requires local bitcoind running.
    #[tokio::test]
    async fn lookup_btc_confirmation_with_local_regtest() -> Result<()> {
        init_test_tracing();

        let temp_dir = TempDir::new()?;
        let node = BitcoinNodeBuilder::new()
            .dir(temp_dir.path())
            .build()
            .await?;
        let cfg = test_config(node.rpc_url().to_string());
        let btc_rpc_client = BtcRpcClient::new(&cfg, MAINNET_MIN_CONFIRMATIONS, MAX_TIP_AGE)?;
        btc_rpc_client.synced_height()?;

        let unknown_txid = txid(7);
        let unknown = btc_rpc_client.lookup_confirmation(unknown_txid)?;
        assert!(
            unknown.is_none(),
            "expected unknown tx lookup to return none"
        );

        let destination = node.get_new_address()?;
        let txid = node.send_to_address(&destination, Amount::from_sat(50_000))?;

        let unconfirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(unconfirmed.is_none(), "expected unconfirmed transaction");
        assert_eq!(btc_rpc_client.cached_confirmations(), 2);

        node.generate_blocks(1)?;
        btc_rpc_client.forget_unconfirmed();
        assert_eq!(btc_rpc_client.cached_confirmations(), 0);

        let insufficiently_confirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(
            insufficiently_confirmed.is_none(),
            "expected one-confirmation transaction to remain pending"
        );

        let earlier_tip_height = btc_rpc_client.synced_height()?;
        node.generate_blocks(MAINNET_MIN_CONFIRMATIONS - 1)?;
        btc_rpc_client.prefetch_confirmations(&[txid], earlier_tip_height)?;
        assert!(
            btc_rpc_client.lookup_confirmation(txid)?.is_none(),
            "blocks after the captured tip must not confirm the transaction"
        );
        btc_rpc_client.forget_unconfirmed();

        let confirmed = btc_rpc_client
            .lookup_confirmation(txid)?
            .expect("expected confirmed transaction");
        // A confirmed answer survives a forget, and a prefetch keeps only
        // the txids asked for.
        btc_rpc_client.forget_unconfirmed();
        assert_eq!(btc_rpc_client.cached_confirmations(), 1);
        btc_rpc_client.prefetch_confirmations(&[txid], node.get_block_count()?)?;
        assert_eq!(btc_rpc_client.cached_confirmations(), 1);
        btc_rpc_client.prefetch_confirmations(&[], node.get_block_count()?)?;
        assert_eq!(btc_rpc_client.cached_confirmations(), 0);
        btc_rpc_client.prefetch_confirmations(&[txid], node.get_block_count()?)?;
        assert_eq!(btc_rpc_client.cached_confirmations(), 1);
        assert!(
            confirmed.outputs.iter().any(|output| {
                output.value == Amount::from_sat(50_000)
                    && output.script_pubkey == destination.script_pubkey()
            }),
            "expected the paid output among {:?}",
            confirmed.outputs
        );

        // The tip is exactly the block that gave the transaction its
        // confirmations, so its header time is the confirmed time.
        let tip_height = node.get_block_count()?;
        let tip_hash: String = node
            .rpc_client()
            .call("getblockhash", &[serde_json::json!(tip_height)])?;
        let tip_header: serde_json::Value = node.rpc_client().call(
            "getblockheader",
            &[serde_json::json!(tip_hash), serde_json::json!(true)],
        )?;
        assert_eq!(
            confirmed.confirmed_time,
            tip_header["time"].as_u64().unwrap()
        );
        assert!(confirmed.block_time <= confirmed.confirmed_time);

        Ok(())
    }

    /// Spend `outpoint` from the node's wallet to a fresh address, and mine it.
    fn spend_outpoint(
        node: &e2e_tests::bitcoin_node::BitcoinNodeHandle,
        outpoint: OutPoint,
    ) -> Result<()> {
        let rpc = node.rpc_client();
        let destination = node.get_new_address()?;
        let inputs =
            serde_json::json!([{ "txid": outpoint.txid.to_string(), "vout": outpoint.vout }]);
        let outputs = serde_json::json!({ destination.to_string(): 0.0004 });
        let unsigned: serde_json::Value = rpc.call("createrawtransaction", &[inputs, outputs])?;
        let signed: serde_json::Value = rpc.call("signrawtransactionwithwallet", &[unsigned])?;
        let signed_hex = signed["hex"].clone();
        let _txid: serde_json::Value = rpc.call("sendrawtransaction", &[signed_hex])?;
        Ok(())
    }

    // Note that this test requires local bitcoind running.
    #[tokio::test]
    async fn lookup_outpoint_states_with_local_regtest() -> Result<()> {
        init_test_tracing();

        let temp_dir = TempDir::new()?;
        let node = BitcoinNodeBuilder::new()
            .dir(temp_dir.path())
            .build()
            .await?;
        let cfg = test_config(node.rpc_url().to_string());
        let btc_rpc_client = BtcRpcClient::new(&cfg, MAINNET_MIN_CONFIRMATIONS, MAX_TIP_AGE)?;
        btc_rpc_client.synced_height()?;

        // Pay the wallet's own address so the test can spend the output later.
        let destination = node.get_new_address()?;
        let txid = node.send_to_address(&destination, Amount::from_sat(50_000))?;
        node.generate_blocks(MAINNET_MIN_CONFIRMATIONS)?;
        let paid = btc_rpc_client
            .lookup_confirmation(txid)?
            .expect("expected confirmed transaction");
        let vout = paid
            .outputs
            .iter()
            .position(|output| output.script_pubkey == destination.script_pubkey())
            .expect("the paid output") as u32;
        let outpoint = OutPoint { txid, vout };
        let out_of_range = OutPoint {
            txid,
            vout: paid.outputs.len() as u32,
        };
        let unknown = OutPoint {
            txid: Txid::from_slice(&[7u8; 32])?,
            vout: 0,
        };

        let states = btc_rpc_client.lookup_outpoint_states(
            &[outpoint, out_of_range, unknown],
            node.get_block_count()?,
            false,
        )?;
        assert_eq!(
            states[&outpoint],
            OutpointState::Unspent {
                block_time: paid.block_time
            }
        );
        assert_eq!(states[&out_of_range], OutpointState::Missing);
        assert_eq!(states[&unknown], OutpointState::Missing);

        spend_outpoint(&node, outpoint)?;
        let lookup = |include_mempool| -> Result<OutpointState> {
            let tip_height = node.get_block_count()?;
            let mut states =
                btc_rpc_client.lookup_outpoint_states(&[outpoint], tip_height, include_mempool)?;
            Ok(states.remove(&outpoint).unwrap())
        };

        // The spend is only in the mempool.
        assert!(matches!(lookup(false)?, OutpointState::Unspent { .. }));
        assert_eq!(lookup(true)?, OutpointState::Spent);

        node.generate_blocks(MAINNET_MIN_CONFIRMATIONS)?;
        assert_eq!(lookup(false)?, OutpointState::Spent);

        Ok(())
    }

    /// Accept one connection, read its request, and answer `response`.
    fn respond(listener: &TcpListener, response: &str) {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            let line = line.to_ascii_lowercase();
            if let Some(value) = line.strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; content_length]).unwrap();
        reader.into_inner().write_all(response.as_bytes()).unwrap();
    }

    #[test]
    fn a_server_error_is_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            respond(
                &listener,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            );
            let body = r#"{"result":7,"error":null,"id":"hashi-monitor"}"#;
            respond(
                &listener,
                &format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ),
            );
        });
        let transport = HttpJsonRpcTransport {
            rpc_url,
            headers: BTreeMap::new(),
            required_confirmations: MAINNET_MIN_CONFIRMATIONS,
        };

        let response = transport
            .call("getblockcount", serde_json::json!([]))
            .expect("the second answer is good");

        server.join().unwrap();
        assert_eq!(response.result, Some(serde_json::json!(7)));
    }

    #[test]
    fn undecodable_response_error_names_the_http_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            respond(
                &listener,
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
            );
        });
        let transport = HttpJsonRpcTransport {
            rpc_url,
            headers: BTreeMap::new(),
            required_confirmations: MAINNET_MIN_CONFIRMATIONS,
        };

        let error = transport
            .call("getblockchaininfo", serde_json::json!([]))
            .err()
            .expect("an empty 401 body is not JSON");

        server.join().unwrap();
        assert!(format!("{error:#}").contains("HTTP 401"), "{error:#}");
    }

    // `getblockchaininfo` from Bitcoin Core v31.1.0 regtest right after startup,
    // and after mining one block.
    const BLOCKCHAIN_INFO_IN_IBD: &str = r#"{
  "chain": "regtest",
  "blocks": 0,
  "headers": 0,
  "bestblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  "bits": "207fffff",
  "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
  "difficulty": 4.656542373906925e-10,
  "time": 1296688602,
  "mediantime": 1296688602,
  "verificationprogress": 2.029297116700384e-06,
  "initialblockdownload": true,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000002",
  "size_on_disk": 293,
  "pruned": false,
  "warnings": [
  ]
}"#;
    const BLOCKCHAIN_INFO_SYNCED: &str = r#"{
  "chain": "regtest",
  "blocks": 1,
  "headers": 1,
  "bestblockhash": "319d7684f104511d0353185c4da1728474caf9181af97e99ddac6d6b84d8149a",
  "bits": "207fffff",
  "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
  "difficulty": 4.656542373906925e-10,
  "time": 1789469064,
  "mediantime": 1789469064,
  "verificationprogress": 1,
  "initialblockdownload": false,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000004",
  "size_on_disk": 590,
  "pruned": false,
  "warnings": [
  ]
}"#;

    fn blockchain_info(json: &str) -> BlockchainInfo {
        serde_json::from_str(json).expect("valid getblockchaininfo result")
    }

    /// The oldest tip the tests accept, in seconds.
    const MAX_TIP_AGE: u64 = 3 * 60 * 60;

    /// Check `info` on regtest at its own tip time.
    fn ensure_synced_at_tip(info: &BlockchainInfo) -> anyhow::Result<()> {
        info.ensure_synced(Network::Regtest, MAX_TIP_AGE, info.time)
    }

    #[test]
    fn node_in_initial_block_download_is_not_synced() {
        let error = ensure_synced_at_tip(&blockchain_info(BLOCKCHAIN_INFO_IN_IBD))
            .expect_err("a node in initial block download is not synced");
        assert!(
            error.to_string().contains("initialblockdownload=true"),
            "{error}"
        );
    }

    #[test]
    fn caught_up_node_is_synced() {
        ensure_synced_at_tip(&blockchain_info(BLOCKCHAIN_INFO_SYNCED)).unwrap();
    }

    #[test]
    fn node_behind_its_best_header_is_not_synced() {
        let mut info = blockchain_info(BLOCKCHAIN_INFO_SYNCED);
        info.headers = info.blocks + 1;
        assert!(ensure_synced_at_tip(&info).is_err());
    }

    #[test]
    fn node_on_another_chain_is_refused() {
        let info = blockchain_info(BLOCKCHAIN_INFO_SYNCED);
        let error = info
            .ensure_synced(Network::Signet, MAX_TIP_AGE, info.time)
            .expect_err("a regtest node does not serve signet");
        assert!(error.to_string().contains("chain regtest"), "{error}");
    }

    #[test]
    fn node_with_an_old_tip_is_not_synced() {
        let info = blockchain_info(BLOCKCHAIN_INFO_SYNCED);
        info.ensure_synced(Network::Regtest, MAX_TIP_AGE, info.time + MAX_TIP_AGE)
            .unwrap();
        assert!(
            info.ensure_synced(Network::Regtest, MAX_TIP_AGE, info.time + MAX_TIP_AGE + 1)
                .is_err()
        );
    }

    #[test]
    fn only_a_synced_txindex_passes() {
        use serde_json::json;

        ensure_txindex(&json!({"txindex": {"synced": true, "best_block_height": 7}})).unwrap();
        let building =
            ensure_txindex(&json!({"txindex": {"synced": false, "best_block_height": 3}}));
        assert!(building.unwrap_err().to_string().contains("still building"));
        let none = ensure_txindex(&json!({}));
        assert!(none.unwrap_err().to_string().contains("no txindex"));
    }

    /// A client of a one-request server that answers `response`.
    fn client_answered_by(response: &'static str) -> (BtcRpcClient, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = Config::for_tests();
        cfg.btc.rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || respond(&listener, response));
        let client = BtcRpcClient::new(&cfg, MAINNET_MIN_CONFIRMATIONS, MAX_TIP_AGE).unwrap();
        (client, server)
    }

    #[test]
    fn an_endpoint_without_getindexinfo_passes_the_txindex_check() {
        // Core answers an unknown method with HTTP 404 and code -32601.
        let (client, server) = client_answered_by(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 75\r\n\r\n\
             {\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}",
        );
        client.check_txindex().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn a_getindexinfo_error_fails_the_txindex_check() {
        let (client, server) = client_answered_by(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 62\r\n\r\n\
             {\"result\":null,\"error\":{\"code\":-1,\"message\":\"failure\"},\"id\":1}",
        );
        let error = client.check_txindex().unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("getindexinfo failed"), "{error}");
    }

    #[test]
    fn mainnet_refuses_a_confirmation_threshold_below_six() {
        use super::checked_confirmation_threshold;

        assert!(checked_confirmation_threshold(5, Network::Bitcoin).is_err());
        assert_eq!(
            checked_confirmation_threshold(6, Network::Bitcoin).unwrap(),
            6
        );
        assert_eq!(
            checked_confirmation_threshold(2, Network::Regtest).unwrap(),
            2
        );
    }
}
