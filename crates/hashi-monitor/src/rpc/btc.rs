// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use bitcoin::BlockHash;
use bitcoin::Txid;
use hashi_types::guardian::time_utils::UnixSeconds;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::config::Config;

const HTTP_JSON_RPC_BATCH_SIZE: usize = 20;
const HTTP_JSON_RPC_BATCH_DELAY: Duration = Duration::from_millis(250);
const MAX_RATE_LIMIT_RETRIES: usize = 6;

pub struct BtcRpcClient {
    transport: HttpJsonRpcTransport,
    confirmation_cache: RefCell<HashMap<Txid, Option<UnixSeconds>>>,
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
    blockhash: Option<String>,
}

#[derive(Deserialize)]
struct RawBlockHeader {
    time: u64,
}

impl BtcRpcClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            transport: HttpJsonRpcTransport {
                rpc_url: cfg.btc.resolve_rpc_url()?,
                headers: cfg.btc.http_headers.clone(),
            },
            confirmation_cache: RefCell::new(HashMap::new()),
        })
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
    /// - `Ok(Some(block_time))` if txid is confirmed,
    /// - `Ok(None)` if txid is not seen or txid is seen but not confirmed,
    /// - `Err(...)` for all other errors
    pub fn lookup_confirmation(&self, txid: Txid) -> anyhow::Result<Option<UnixSeconds>> {
        if let Some(result) = self.confirmation_cache.borrow().get(&txid) {
            return Ok(*result);
        }
        let result = self.transport.lookup_confirmation(txid)?;
        self.confirmation_cache.borrow_mut().insert(txid, result);
        Ok(result)
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

    /// Pace requests so a historical audit does not exhaust a provider's
    /// rolling throughput bucket, and retry the standard HTTP/JSON-RPC 429
    /// responses with bounded exponential backoff.
    fn post_json(&self, body: &Value) -> anyhow::Result<Value> {
        for attempt in 0..=MAX_RATE_LIMIT_RETRIES {
            let response = minreq::post(&self.rpc_url)
                .with_timeout(60)
                .with_headers(self.headers.clone())
                .with_json(body)
                .context("failed to encode bitcoin JSON-RPC request")?
                .send()
                .context("bitcoin JSON-RPC request failed")?;

            if response.status_code == 429 {
                Self::wait_before_rate_limit_retry(attempt)?;
                continue;
            }

            let response_body: Value = response
                .json()
                .context("failed to decode bitcoin JSON-RPC response")?;
            if json_rpc_rate_limited(&response_body) {
                Self::wait_before_rate_limit_retry(attempt)?;
                continue;
            }

            thread::sleep(HTTP_JSON_RPC_BATCH_DELAY);
            return Ok(response_body);
        }

        unreachable!("rate-limit retry loop either returns or errors")
    }

    fn wait_before_rate_limit_retry(attempt: usize) -> anyhow::Result<()> {
        if attempt == MAX_RATE_LIMIT_RETRIES {
            anyhow::bail!(
                "bitcoin JSON-RPC remained rate limited after {MAX_RATE_LIMIT_RETRIES} retries"
            );
        }

        let delay = Duration::from_secs(1 << attempt.min(5));
        warn!(
            retry = attempt + 1,
            max_retries = MAX_RATE_LIMIT_RETRIES,
            delay_secs = delay.as_secs(),
            "bitcoin JSON-RPC rate limited; retrying"
        );
        thread::sleep(delay);
        Ok(())
    }

    fn lookup_confirmation(&self, txid: Txid) -> anyhow::Result<Option<UnixSeconds>> {
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
        let Some(block_hash) = tx_info.blockhash else {
            debug!(%txid, "bitcoin tx found but not mined yet");
            return Ok(None);
        };
        let block_hash = BlockHash::from_str(&block_hash)
            .with_context(|| format!("invalid bitcoin block hash for {txid}"))?;

        let response = self.call(
            "getblockheader",
            serde_json::json!([block_hash.to_string(), true]),
        )?;
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
                .context("bitcoin getblockheader response is missing its result")?,
        )
        .with_context(|| format!("failed to parse block header for {block_hash}"))?;
        Ok(Some(header.time))
    }

    fn lookup_confirmations(
        &self,
        txids: &[Txid],
    ) -> anyhow::Result<HashMap<Txid, Option<UnixSeconds>>> {
        let mut confirmations = HashMap::with_capacity(txids.len());
        for (batch_index, chunk) in txids.chunks(HTTP_JSON_RPC_BATCH_SIZE).enumerate() {
            confirmations.extend(self.lookup_confirmation_batch(chunk)?);
            let processed_txids = ((batch_index + 1) * HTTP_JSON_RPC_BATCH_SIZE).min(txids.len());
            if processed_txids % 200 == 0 || processed_txids == txids.len() {
                info!(
                    processed_txids,
                    total_txids = txids.len(),
                    "bitcoin confirmation lookup progress"
                );
            }
        }
        Ok(confirmations)
    }

    fn lookup_confirmation_batch(
        &self,
        txids: &[Txid],
    ) -> anyhow::Result<HashMap<Txid, Option<UnixSeconds>>> {
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
        let mut block_hashes = HashMap::with_capacity(txids.len());

        for response in responses {
            let index = response_index(&response, txids.len())?;
            anyhow::ensure!(
                seen.insert(index),
                "duplicate bitcoin getrawtransaction batch response ID {index}"
            );
            let txid = txids[index];
            if let Some(error) = response.error {
                if error.code == -5 {
                    block_hashes.insert(txid, None);
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
            let block_hash = info
                .blockhash
                .map(|hash| {
                    BlockHash::from_str(&hash)
                        .with_context(|| format!("invalid bitcoin block hash for {txid}"))
                })
                .transpose()?;
            block_hashes.insert(txid, block_hash);
        }
        anyhow::ensure!(
            seen.len() == txids.len(),
            "bitcoin getrawtransaction batch returned {}/{} responses",
            seen.len(),
            txids.len()
        );

        let unique_block_hashes = block_hashes
            .values()
            .flatten()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut block_times = HashMap::with_capacity(unique_block_hashes.len());
        for hashes in unique_block_hashes.chunks(HTTP_JSON_RPC_BATCH_SIZE) {
            let requests = hashes
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
            let mut seen = HashSet::with_capacity(hashes.len());
            for response in responses {
                let index = response_index(&response, hashes.len())?;
                anyhow::ensure!(
                    seen.insert(index),
                    "duplicate bitcoin getblockheader batch response ID {index}"
                );
                let block_hash = hashes[index];
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
                block_times.insert(block_hash, header.time);
            }
            anyhow::ensure!(
                seen.len() == hashes.len(),
                "bitcoin getblockheader batch returned {}/{} responses",
                seen.len(),
                hashes.len()
            );
        }

        block_hashes
            .into_iter()
            .map(|(txid, block_hash)| {
                let confirmation = block_hash
                    .map(|hash| {
                        block_times
                            .get(&hash)
                            .copied()
                            .with_context(|| format!("missing block time for {hash}"))
                    })
                    .transpose()?;
                Ok((txid, confirmation))
            })
            .collect()
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
    use std::sync::Once;

    use anyhow::Result;
    use base64ct::Base64;
    use base64ct::Encoding as _;
    use bitcoin::Amount;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;
    use e2e_tests::BitcoinNodeBuilder;
    use e2e_tests::bitcoin_node::RPC_PASSWORD;
    use e2e_tests::bitcoin_node::RPC_USER;
    use tempfile::TempDir;

    use super::BtcRpcClient;
    use crate::config::BtcConfig;
    use crate::config::Config;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;
    use crate::domain::WithdrawalEventType;
    use hashi_types::guardian::UnresolvedS3Config;

    static TRACING_INIT: Once = Once::new();

    fn init_test_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init();
        });
    }

    fn test_config(rpc_url: String) -> Config {
        Config {
            next_event_delays: NextEventDelays::new(vec![
                (WithdrawalEventType::E1HashiApproved, 100),
                (WithdrawalEventType::E2GuardianApproved, 200),
            ])
            .expect("valid next event delays"),
            clock_skew: 10,
            withdrawal_predecessor_lookback: 60 * 60,
            guardian_s3: UnresolvedS3Config {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
                access_key: Some("access-key".to_string()),
                secret_key: Some("secret-key".to_string()),
                retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
            },
            pcr_allowlist: hashi_types::guardian::PcrAllowlist::new(
                hashi_types::guardian::BuildPcrs::new("", vec![]),
                vec![],
            )
            .expect("valid PCR allowlist"),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
                package_id: format!("0x{}", "11".repeat(32)),
            },
            btc: BtcConfig {
                rpc_url,
                http_headers: BTreeMap::from([(
                    "Authorization".to_string(),
                    format!(
                        "Basic {}",
                        Base64::encode_string(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes())
                    ),
                )]),
            },
        }
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

        let unknown_txid = Txid::from_slice(&[7u8; 32])?;
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

        let confirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(confirmed.is_some(), "expected confirmed transaction");

        Ok(())
    }
}
