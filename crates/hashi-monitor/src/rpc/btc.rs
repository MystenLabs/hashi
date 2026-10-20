// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Bitcoin client: confirmation lookups over HTTP JSON-RPC.
//!
//! Why it exists: the withdrawal E3 and the deposit E1 are Bitcoin
//! confirmations. Bitcoin has no event stream to scan, so the auditor looks
//! each pending transaction up by txid.
//!
//! How it works:
//! 1. Before a pass, `ensure_synced` fails while bitcoind lags its peers,
//!    since a lagging node reports recent transactions as unconfirmed.
//! 2. `prefetch_confirmations` looks all pending txids up in batches of
//!    `HTTP_JSON_RPC_BATCH_SIZE`, with `HTTP_JSON_RPC_BATCHES_IN_FLIGHT`
//!    batches sent at once, and `lookup_confirmation` serves each one from
//!    that cache. The cache is cleared at the start of each pass, so an
//!    unconfirmed transaction is looked up again next pass.
//! 3. A transaction with at least `MIN_CONFIRMATIONS` confirmations is
//!    returned with the time of its own block and the time of the block that
//!    gave it `MIN_CONFIRMATIONS`.
//! 4. Requests are not paced: the node is the bridge's own. A request that
//!    fails to send, gets an HTTP 502, 503 or 504, or is rate limited is
//!    retried with exponential backoff, `MAX_REQUEST_RETRIES` times. Core
//!    answers a JSON-RPC error with HTTP 500, so 500 is not retried.
//!
//! Assumptions:
//! - The endpoint serves `getrawtransaction` with verbose output, which
//!   needs `txindex` or a hosted provider.
//! - A request that still fails after the retries fails the pass, which
//!   is retried on the next tick.

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
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::consensus::encode::deserialize_hex;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::domain::BtcConfirmation;

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
const MIN_CONFIRMATIONS: u64 = 6;

/// What Bitcoin holds at an outpoint. `Missing` and `Spent` differ by the
/// transaction lookup, `Spent` and `Unspent` by the UTXO set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutpointState {
    /// The transaction is unknown or not confirmed deep enough, or it has no
    /// output at that vout.
    Missing,
    /// The output exists, and a confirmed transaction has spent it.
    Spent,
    /// The output exists and is in the UTXO set. A mempool spend does not
    /// change this.
    Unspent {
        /// The time of the block that holds the output.
        block_time: UnixSeconds,
    },
}

pub struct BtcRpcClient {
    transport: HttpJsonRpcTransport,
    confirmation_cache: RefCell<HashMap<Txid, Option<BtcConfirmation>>>,
}

struct HttpJsonRpcTransport {
    rpc_url: String,
    headers: BTreeMap<String, String>,
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
    blocks: u64,
    headers: u64,
    initialblockdownload: bool,
}

impl BlockchainInfo {
    fn ensure_synced(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.initialblockdownload && self.blocks >= self.headers,
            "bitcoind is not synced: initialblockdownload={}, blocks={}, headers={}",
            self.initialblockdownload,
            self.blocks,
            self.headers
        );
        Ok(())
    }
}

/// A transaction mined at least `MIN_CONFIRMATIONS` deep, before its block
/// header is read.
struct ConfirmedTx {
    block_hash: BlockHash,
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOut>,
}

impl RawTransactionInfo {
    /// The block hash, inputs and outputs of a sufficiently confirmed transaction.
    fn confirmed(self, txid: Txid) -> anyhow::Result<Option<ConfirmedTx>> {
        let Some(block_hash) = self.blockhash else {
            debug!(%txid, "bitcoin tx found but not mined yet");
            return Ok(None);
        };
        if self.confirmations < MIN_CONFIRMATIONS {
            debug!(
                %txid,
                confirmations = self.confirmations,
                required_confirmations = MIN_CONFIRMATIONS,
                "bitcoin tx has insufficient confirmation depth"
            );
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
        Ok(Some(ConfirmedTx {
            block_hash,
            inputs: tx.input.iter().map(|input| input.previous_output).collect(),
            outputs: tx.output,
        }))
    }
}

impl BtcRpcClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            transport: HttpJsonRpcTransport {
                rpc_url: cfg.btc.rpc_url.clone(),
                headers: cfg.btc.http_headers.clone(),
            },
            confirmation_cache: RefCell::new(HashMap::new()),
        })
    }

    /// Fail while bitcoind lags its peers: a lagging node reports recent
    /// transactions as unconfirmed, which reads as a missing Bitcoin event.
    pub fn ensure_synced(&self) -> anyhow::Result<()> {
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
        info.ensure_synced()
    }

    /// Start a fresh lookup cycle. Confirmed and unconfirmed results are shared
    /// by all outpoints from the same transaction within one audit tick, while
    /// later ticks still retry transactions that were previously unconfirmed.
    pub fn clear_confirmation_cache(&self) {
        self.confirmation_cache.borrow_mut().clear();
    }

    pub fn prefetch_confirmations(&self, txids: &[Txid]) -> anyhow::Result<()> {
        let confirmations = self.transport.lookup_confirmations(txids)?;
        self.confirmation_cache.borrow_mut().extend(confirmations);
        Ok(())
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
        let result = self.transport.lookup_confirmation(txid)?;
        self.confirmation_cache
            .borrow_mut()
            .insert(txid, result.clone());
        Ok(result)
    }

    /// The state of each outpoint on Bitcoin. The transactions are fetched
    /// fresh, so the result does not depend on the confirmation cache.
    pub fn lookup_outpoint_states(
        &self,
        outpoints: &[OutPoint],
    ) -> anyhow::Result<HashMap<OutPoint, OutpointState>> {
        let txids = outpoints
            .iter()
            .map(|outpoint| outpoint.txid)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        self.prefetch_confirmations(&txids)?;

        // Only an output that exists can be in the UTXO set.
        let mut states = HashMap::with_capacity(outpoints.len());
        let mut existing = Vec::new();
        for outpoint in outpoints {
            match self.lookup_confirmation(outpoint.txid)? {
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
        let unspent = self.transport.lookup_unspent(&existing_outpoints)?;
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

    fn lookup_confirmation(&self, txid: Txid) -> anyhow::Result<Option<BtcConfirmation>> {
        let response = self.call(
            "getrawtransaction",
            serde_json::json!([txid.to_string(), true]),
        )?;
        if let Some(error) = response.error {
            if error.code == -5 {
                debug!(%txid, "bitcoin tx not found in mempool or chain yet");
                return Ok(None);
            }
            anyhow::bail!(
                "bitcoin getrawtransaction failed for {txid}: {} ({})",
                error.message,
                error.code
            );
        }
        let tx_info: RawTransactionInfo = serde_json::from_value(
            response
                .result
                .context("bitcoin getrawtransaction response is missing its result")?,
        )
        .with_context(|| format!("failed to parse transaction info for {txid}"))?;
        let Some(ConfirmedTx {
            block_hash,
            inputs,
            outputs,
        }) = tx_info.confirmed(txid)?
        else {
            return Ok(None);
        };

        let times = self.confirmation_times(&[block_hash])?;
        let (block_time, confirmed_time) = times
            .get(&block_hash)
            .copied()
            .with_context(|| format!("missing block times for {block_hash}"))?;
        Ok(Some(BtcConfirmation {
            block_time,
            confirmed_time,
            inputs,
            outputs,
        }))
    }

    /// Look every txid up, `HTTP_JSON_RPC_BATCHES_IN_FLIGHT` batches at a
    /// time. Each worker takes the next batch until none is left. The first
    /// failure stops the others at their next batch and fails the lookup.
    fn lookup_confirmations(
        &self,
        txids: &[Txid],
    ) -> anyhow::Result<HashMap<Txid, Option<BtcConfirmation>>> {
        let batches = txids.chunks(HTTP_JSON_RPC_BATCH_SIZE).collect::<Vec<_>>();
        let next_batch = AtomicUsize::new(0);
        let processed = AtomicUsize::new(0);
        let results = Mutex::new(Vec::with_capacity(batches.len()));
        thread::scope(|scope| {
            for _ in 0..HTTP_JSON_RPC_BATCHES_IN_FLIGHT.min(batches.len()) {
                scope.spawn(|| {
                    while let Some(batch) = batches.get(next_batch.fetch_add(1, Ordering::Relaxed))
                    {
                        let result = self.lookup_confirmation_batch(batch);
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
        let mut confirmations = HashMap::with_capacity(txids.len());
        for result in results.into_inner().expect("a worker never panics") {
            confirmations.extend(result?);
        }
        Ok(confirmations)
    }

    fn lookup_confirmation_batch(
        &self,
        txids: &[Txid],
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
        let mut confirmed = HashMap::with_capacity(txids.len());

        for response in responses {
            let index = response_index(&response, txids.len())?;
            anyhow::ensure!(
                seen.insert(index),
                "duplicate bitcoin getrawtransaction batch response ID {index}"
            );
            let txid = txids[index];
            if let Some(error) = response.error {
                if error.code == -5 {
                    confirmed.insert(txid, None);
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
            confirmed.insert(txid, info.confirmed(txid)?);
        }
        anyhow::ensure!(
            seen.len() == txids.len(),
            "bitcoin getrawtransaction batch returned {}/{} responses",
            seen.len(),
            txids.len()
        );

        let unique_block_hashes = confirmed
            .values()
            .flatten()
            .map(|tx| tx.block_hash)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let times = self.confirmation_times(&unique_block_hashes)?;

        confirmed
            .into_iter()
            .map(|(txid, confirmed)| {
                let confirmation = confirmed
                    .map(|tx| {
                        let (block_time, confirmed_time) =
                            times.get(&tx.block_hash).copied().with_context(|| {
                                format!("missing block times for {}", tx.block_hash)
                            })?;
                        Ok::<_, anyhow::Error>(BtcConfirmation {
                            block_time,
                            confirmed_time,
                            inputs: tx.inputs,
                            outputs: tx.outputs,
                        })
                    })
                    .transpose()?;
                Ok((txid, confirmation))
            })
            .collect()
    }

    /// For each block that holds a confirmed transaction: its own time, and
    /// the time of the block `MIN_CONFIRMATIONS - 1` above it. Core counts the
    /// holding block as the first confirmation, so that block is the one that
    /// gave the transaction `MIN_CONFIRMATIONS`.
    fn confirmation_times(
        &self,
        block_hashes: &[BlockHash],
    ) -> anyhow::Result<HashMap<BlockHash, (UnixSeconds, UnixSeconds)>> {
        let headers = self.block_headers(block_hashes)?;
        let confirming_height = |header: &RawBlockHeader| header.height + MIN_CONFIRMATIONS - 1;
        let confirming_heights = headers
            .values()
            .map(confirming_height)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let confirming_hashes = self.block_hashes(&confirming_heights)?;
        let confirming_headers =
            self.block_headers(&confirming_hashes.values().copied().collect::<Vec<_>>())?;

        block_hashes
            .iter()
            .map(|hash| {
                let header = headers
                    .get(hash)
                    .with_context(|| format!("missing block header for {hash}"))?;
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
    /// Whether each outpoint is in the UTXO set, with the mempool excluded.
    /// Callers pass outpoints that exist: `gettxout` answers null for a spent
    /// output and for one that never existed alike.
    fn lookup_unspent(&self, outpoints: &[OutPoint]) -> anyhow::Result<HashMap<OutPoint, bool>> {
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
                        "params": [outpoint.txid.to_string(), outpoint.vout, false],
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
    use super::MIN_CONFIRMATIONS;
    use super::OutpointState;
    use crate::config::BtcConfig;
    use crate::config::Config;
    use crate::domain::DepositEventType;
    use crate::domain::DepositId;
    use crate::domain::MonitorDepositEvent;
    use crate::test_utils::confirmation;
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
        let btc_rpc_client = BtcRpcClient::new(&cfg)?;
        btc_rpc_client.ensure_synced()?;

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

        node.generate_blocks(1)?;
        btc_rpc_client.clear_confirmation_cache();

        let insufficiently_confirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(
            insufficiently_confirmed.is_none(),
            "expected one-confirmation transaction to remain pending"
        );

        node.generate_blocks(MIN_CONFIRMATIONS - 1)?;
        btc_rpc_client.clear_confirmation_cache();

        let confirmed = btc_rpc_client
            .lookup_confirmation(txid)?
            .expect("expected confirmed transaction");
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
        node.generate_blocks(MIN_CONFIRMATIONS)?;
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
        let btc_rpc_client = BtcRpcClient::new(&cfg)?;
        btc_rpc_client.ensure_synced()?;

        // Pay the wallet's own address so the test can spend the output later.
        let destination = node.get_new_address()?;
        let txid = node.send_to_address(&destination, Amount::from_sat(50_000))?;
        node.generate_blocks(MIN_CONFIRMATIONS)?;
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

        let states = btc_rpc_client.lookup_outpoint_states(&[outpoint, out_of_range, unknown])?;
        assert_eq!(
            states[&outpoint],
            OutpointState::Unspent {
                block_time: paid.block_time
            }
        );
        assert_eq!(states[&out_of_range], OutpointState::Missing);
        assert_eq!(states[&unknown], OutpointState::Missing);

        spend_outpoint(&node, outpoint)?;

        let states = btc_rpc_client.lookup_outpoint_states(&[outpoint])?;
        assert_eq!(states[&outpoint], OutpointState::Spent);

        Ok(())
    }

    #[test]
    fn a_confirmation_builds_the_deposit_event_of_its_output() {
        let script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        let confirmation = confirmation(40_000, script_pubkey.clone());
        let txid = txid(9);

        assert_eq!(
            MonitorDepositEvent::from_btc(&confirmation, DepositId::new(txid, 1)),
            Some(MonitorDepositEvent {
                event_type: DepositEventType::E1BtcConfirmed,
                timestamp_secs: 90,
                deposit_id: DepositId::new(txid, 1),
                amount: 40_000,
                script_pubkey,
            })
        );
        assert_eq!(
            MonitorDepositEvent::from_btc(&confirmation, DepositId::new(txid, 2)),
            None
        );
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

    #[test]
    fn node_in_initial_block_download_is_not_synced() {
        let error = blockchain_info(BLOCKCHAIN_INFO_IN_IBD)
            .ensure_synced()
            .expect_err("a node in initial block download is not synced");
        assert!(
            error.to_string().contains("initialblockdownload=true"),
            "{error}"
        );
    }

    #[test]
    fn caught_up_node_is_synced() {
        blockchain_info(BLOCKCHAIN_INFO_SYNCED)
            .ensure_synced()
            .unwrap();
    }

    #[test]
    fn node_behind_its_best_header_is_not_synced() {
        let mut info = blockchain_info(BLOCKCHAIN_INFO_SYNCED);
        info.headers = info.blocks + 1;
        assert!(info.ensure_synced().is_err());
    }
}
