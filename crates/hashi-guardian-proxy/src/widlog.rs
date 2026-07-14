// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only access to the guardian's S3 withdrawal log — the wid cache's
//! durable tier. The enclave writes one `Success` record per signed withdrawal
//! *before* releasing the signatures and fails closed if the write fails
//! (`withdraw_mode/standard.rs`), so every signature a node has seen has a
//! record here; the proxy never writes.
//!
//! Keys are `withdraw/YYYY/MM/DD/HH/success-{seq:020}-{session}-wid{wid}.json`,
//! with the wid only a suffix — so a lookup walks hour buckets newest-first.
//! The request's `seq` bounds the walk: a retried wid was signed at `seq` or
//! `seq - 1` (the node's mirror trails the guardian by at most the reconcile
//! snap), so once two consecutive success-bearing buckets top out below
//! `seq - 1` the record can't be further back (two, not one, so a forward
//! clock step can't hide it behind a single future-labelled bucket). Exhausted
//! prefixes are a definitive miss; hitting the LIST cap is NOT — the caller
//! must fail closed on it, never forward.

use crate::metrics::ProxyMetrics;
use aws_sdk_s3::error::DisplayErrorContext;
use hashi_types::guardian::log::S3_DIR_WITHDRAW;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use tracing::warn;

// A terminating scan needs ~4 tree walks + 2-3 bucket lists; the cap only
// trips on a seq far below everything in the log (e.g. a rogue client).
const SCAN_LIST_CAP: usize = 100;

const SUCCESS_KEY_PREFIX: &str = "success-";

#[derive(Debug)]
pub enum WidLogError {
    /// A LIST or GET failed; the lookup is indeterminate.
    Store(anyhow::Error),
    /// The scan exceeded `SCAN_LIST_CAP` without terminating.
    CapExceeded,
}

/// A parsed `Success` record for a wid.
pub struct FoundSuccess {
    /// The seq the guardian consumed the wid at (`request_data.seq`).
    pub consumed_seq: u64,
    /// Timestamp of the log record, reused as the replayed response timestamp.
    pub timestamp_ms: u64,
    pub response: StandardWithdrawalResponse,
}

/// Minimal object-store surface the scanner needs. `list_dirs` is an S3
/// delimiter listing (returns immediate sub-prefixes), `list_keys` a plain
/// prefix listing in ascending key order, both fully paginated.
#[tonic::async_trait]
pub trait LogStore: Send + Sync + 'static {
    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
    async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;
}

/// Find the newest `Success` record for `wid`, walking hour buckets newest to
/// oldest. `Ok(None)` is a *definitive* miss (safe to forward to the enclave);
/// any `Err` means the lookup is indeterminate and the caller must fail closed.
pub async fn find_success_record<L: LogStore>(
    log: &L,
    wid: &WithdrawalID,
    request_seq: u64,
    metrics: &ProxyMetrics,
) -> Result<Option<FoundSuccess>, WidLogError> {
    let suffix = format!("-wid{wid}.json");
    let threshold = request_seq.saturating_sub(1);
    let mut lists_used = 0usize;
    let mut strikes = 0u32;

    let scan = async {
        for year in list_desc(log, &format!("{S3_DIR_WITHDRAW}/"), &mut lists_used).await? {
            for month in list_desc(log, &year, &mut lists_used).await? {
                for day in list_desc(log, &month, &mut lists_used).await? {
                    for hour in list_desc(log, &day, &mut lists_used).await? {
                        let keys = list_keys_capped(
                            log,
                            &format!("{hour}{SUCCESS_KEY_PREFIX}"),
                            &mut lists_used,
                        )
                        .await?;
                        if keys.is_empty() {
                            // Failure-only bucket: says nothing about the seq bound.
                            continue;
                        }

                        // Newest (max-seq) candidate first within the bucket.
                        for key in keys.iter().rev().filter(|k| k.ends_with(&suffix)) {
                            let bytes = log.get(key).await.map_err(WidLogError::Store)?;
                            match parse_success(&bytes, wid) {
                                Ok(found) => return Ok(Some(found)),
                                Err(e) => {
                                    // Skip (schema skew): a miss re-signs and heals;
                                    // failing closed would wedge until a proxy fix.
                                    metrics.record_parse_failures.inc();
                                    warn!(key, error = %e, "unreadable success record for wid; skipping");
                                }
                            }
                        }

                        let bucket_max = keys.iter().rev().find_map(|k| parse_success_seq(k));
                        match bucket_max {
                            Some(max) if max < threshold => {
                                strikes += 1;
                                if strikes >= 2 {
                                    return Ok(None);
                                }
                            }
                            Some(_) => strikes = 0,
                            // Only unparseable success keys: indeterminate.
                            None => {}
                        }
                    }
                }
            }
        }
        // Walked every existing bucket: the record does not exist.
        Ok(None)
    };
    let result = scan.await;
    metrics.scan_lists.observe(lists_used as f64);
    result
}

async fn list_desc<L: LogStore>(
    log: &L,
    prefix: &str,
    lists_used: &mut usize,
) -> Result<Vec<String>, WidLogError> {
    charge_list(lists_used)?;
    let mut dirs = log.list_dirs(prefix).await.map_err(WidLogError::Store)?;
    dirs.sort_unstable();
    dirs.reverse();
    Ok(dirs)
}

async fn list_keys_capped<L: LogStore>(
    log: &L,
    prefix: &str,
    lists_used: &mut usize,
) -> Result<Vec<String>, WidLogError> {
    charge_list(lists_used)?;
    log.list_keys(prefix).await.map_err(WidLogError::Store)
}

fn charge_list(lists_used: &mut usize) -> Result<(), WidLogError> {
    *lists_used += 1;
    if *lists_used > SCAN_LIST_CAP {
        return Err(WidLogError::CapExceeded);
    }
    Ok(())
}

/// Parse the zero-padded seq out of a `.../success-{seq:020}-...` key.
fn parse_success_seq(key: &str) -> Option<u64> {
    let name = key.rsplit('/').next()?;
    let rest = name.strip_prefix(SUCCESS_KEY_PREFIX)?;
    rest.get(..20)?.parse().ok()
}

fn parse_success(bytes: &[u8], wid: &WithdrawalID) -> anyhow::Result<FoundSuccess> {
    let record: LogRecord = serde_json::from_slice(bytes)?;
    let timestamp_ms = record.timestamp_ms;
    let LogMessage::Withdrawal(message) = record.message else {
        anyhow::bail!("not a withdrawal record");
    };
    let WithdrawalLogMessage::Success {
        request_data,
        response,
        ..
    } = *message
    else {
        anyhow::bail!("not a success record");
    };
    anyhow::ensure!(
        request_data.wid == *wid,
        "record is for wid {}, expected {}",
        request_data.wid,
        wid
    );
    Ok(FoundSuccess {
        consumed_seq: request_data.seq,
        timestamp_ms,
        response,
    })
}

/// The guardian's log bucket over the AWS SDK, read-only. Credentials come
/// from the default provider chain (task role on Fargate, env vars for MinIO).
pub struct S3LogStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3LogStore {
    pub async fn connect(bucket: String, region: String) -> Self {
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&aws_config);
        if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
            builder = builder.force_path_style(true);
        }
        Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket,
        }
    }

    /// One-key LIST to prove bucket access at boot (an empty result is fine —
    /// the withdraw log may not exist yet).
    pub async fn probe(&self) -> anyhow::Result<()> {
        self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{S3_DIR_WITHDRAW}/"))
            .max_keys(1)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("list {}: {}", self.bucket, DisplayErrorContext(e)))?;
        Ok(())
    }
}

#[tonic::async_trait]
impl LogStore for S3LogStore {
    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut dirs = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .delimiter("/")
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page
                .map_err(|e| anyhow::anyhow!("list dirs {prefix}: {}", DisplayErrorContext(e)))?;
            dirs.extend(
                page.common_prefixes()
                    .iter()
                    .filter_map(|p| p.prefix().map(String::from)),
            );
        }
        Ok(dirs)
    }

    async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page
                .map_err(|e| anyhow::anyhow!("list keys {prefix}: {}", DisplayErrorContext(e)))?;
            keys.extend(
                page.contents()
                    .iter()
                    .filter_map(|o| o.key().map(String::from)),
            );
        }
        Ok(keys)
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("get {key}: {}", DisplayErrorContext(e)))?;
        let bytes = object
            .body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("read {key}: {e}"))?;
        Ok(bytes.into_bytes().to_vec())
    }
}

#[cfg(test)]
pub(crate) mod test_store {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Network;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    /// A genuine `LogRecord` for a Success, serialized exactly as the enclave
    /// writes it, keyed by `LogRecord::object_key()`.
    pub(crate) fn success_record_json(
        wid: WithdrawalID,
        seq: u64,
        timestamp_ms: u64,
        response: StandardWithdrawalResponse,
    ) -> (String, Vec<u8>) {
        let signed_request =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let (request_sign, request_data) = signed_request.into_parts();
        let mut request_data: StandardWithdrawalRequestWire = request_data.into();
        request_data.seq = seq;

        let signing_key = GuardianSignKeyPair::from([9u8; 32]);
        let record = LogRecord::new_at_timestamp(
            "test-session".to_string(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid: bitcoin::Txid::from_slice(&[3u8; 32]).unwrap(),
                request_data,
                request_sign,
                response,
                post_state: hashi_types::guardian::LimiterState {
                    num_tokens_available: 0,
                    last_updated_at: 0,
                    next_seq: seq + 1,
                },
            })),
            &signing_key,
            timestamp_ms,
        );
        let key = record.object_key().to_string();
        (key, serde_json::to_vec(&record).unwrap())
    }

    /// In-memory `LogStore` with S3 listing semantics (delimiter dirs, ascending
    /// keys) and failure toggles.
    #[derive(Default)]
    pub(crate) struct MemStore {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        pub(crate) fail_lists: AtomicBool,
        pub(crate) fail_gets: AtomicBool,
        pub(crate) list_calls: AtomicUsize,
    }

    impl MemStore {
        pub(crate) fn insert(&self, key: impl Into<String>, bytes: Vec<u8>) {
            self.objects.lock().unwrap().insert(key.into(), bytes);
        }
    }

    #[tonic::async_trait]
    impl LogStore for MemStore {
        async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_lists.load(Ordering::SeqCst) {
                anyhow::bail!("simulated list failure");
            }
            let objects = self.objects.lock().unwrap();
            let mut dirs: Vec<String> = objects
                .keys()
                .filter_map(|k| {
                    let rest = k.strip_prefix(prefix)?;
                    let end = rest.find('/')?;
                    Some(format!("{prefix}{}", &rest[..=end]))
                })
                .collect();
            dirs.dedup();
            Ok(dirs)
        }

        async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_lists.load(Ordering::SeqCst) {
                anyhow::bail!("simulated list failure");
            }
            let objects = self.objects.lock().unwrap();
            Ok(objects
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
            if self.fail_gets.load(Ordering::SeqCst) {
                anyhow::bail!("simulated get failure");
            }
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no such key {key}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_store::success_record_json;
    use super::test_store::MemStore;
    use super::*;
    use std::sync::atomic::Ordering;

    fn test_metrics() -> ProxyMetrics {
        ProxyMetrics::new()
    }

    fn wid(byte: u8) -> WithdrawalID {
        WithdrawalID::new([byte; 32])
    }

    fn mock_response() -> StandardWithdrawalResponse {
        StandardWithdrawalResponse {
            enclave_signatures: vec![],
        }
    }

    // 2023-11-14T22 bucket, per the envelope.rs key tests.
    const TS_HOUR_A: u64 = 1_700_000_000_000;
    // One hour later.
    const TS_HOUR_B: u64 = TS_HOUR_A + 3_600_000;
    // One hour before A.
    const TS_HOUR_Z: u64 = TS_HOUR_A - 3_600_000;

    #[tokio::test]
    async fn finds_record_in_newest_bucket() {
        let store = MemStore::default();
        let (key, bytes) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);

        let found = find_success_record(&store, &wid(0xaa), 7, &test_metrics())
            .await
            .unwrap()
            .expect("record should be found");
        assert_eq!(found.consumed_seq, 7);
        assert_eq!(found.timestamp_ms, TS_HOUR_A);
    }

    #[tokio::test]
    async fn empty_store_is_a_definitive_miss() {
        let store = MemStore::default();
        // request_seq 0 exercises the saturating threshold too.
        let result = find_success_record(&store, &wid(0xaa), 0, &test_metrics())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn failure_only_buckets_never_terminate_the_scan() {
        let store = MemStore::default();
        // Newer bucket holds only failure records (not listed by the success-
        // prefix); the wid's Success sits one bucket older.
        store.insert(
            "withdraw/2023/11/14/23/failure-test-session-wid0xdead-00000001.json",
            b"{}".to_vec(),
        );
        let (key, bytes) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);

        let found = find_success_record(&store, &wid(0xaa), 7, &test_metrics())
            .await
            .unwrap();
        assert!(found.is_some(), "failure-only bucket must be walked past");
    }

    #[tokio::test]
    async fn bumped_seq_retry_still_finds_the_record() {
        // The reconcile snap bumps the node's seq to S+1; threshold slack must
        // keep the bucket holding seq S inside the scan.
        let store = MemStore::default();
        let (key, bytes) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);

        let found = find_success_record(&store, &wid(0xaa), 8, &test_metrics())
            .await
            .unwrap();
        assert_eq!(found.unwrap().consumed_seq, 7);
    }

    #[tokio::test]
    async fn scan_stops_after_two_low_buckets() {
        let store = MemStore::default();
        // Two success-bearing buckets both below threshold: the wid is absent
        // and the scan must stop without walking further back.
        let (key_b, bytes_b) = success_record_json(wid(0xbb), 5, TS_HOUR_B, mock_response());
        let (key_a, bytes_a) = success_record_json(wid(0xcc), 4, TS_HOUR_A, mock_response());
        let (key_z, bytes_z) = success_record_json(wid(0xdd), 3, TS_HOUR_Z, mock_response());
        store.insert(key_b, bytes_b);
        store.insert(key_a, bytes_a);
        store.insert(key_z, bytes_z);

        let result = find_success_record(&store, &wid(0xaa), 20, &test_metrics())
            .await
            .unwrap();
        assert!(result.is_none());
        // Tree walks + the two bucket lists, but never the third (oldest) bucket:
        // year/month/day each listed once (same day), hours once, buckets B and A.
        let calls = store.list_calls.load(Ordering::SeqCst);
        assert!(
            calls <= 7,
            "scan should stop after two strikes, used {calls} lists"
        );
    }

    #[tokio::test]
    async fn forward_skewed_bucket_does_not_hide_the_record() {
        // Enclave clock jumped ahead: a future-labelled bucket holds seq 5 (below
        // threshold), while the wid's record at seq 9 sits in an older bucket.
        // One low bucket must not terminate the scan.
        let store = MemStore::default();
        let (key_skew, bytes_skew) = success_record_json(wid(0xbb), 5, TS_HOUR_B, mock_response());
        let (key, bytes) = success_record_json(wid(0xaa), 9, TS_HOUR_A, mock_response());
        store.insert(key_skew, bytes_skew);
        store.insert(key, bytes);

        let found = find_success_record(&store, &wid(0xaa), 10, &test_metrics())
            .await
            .unwrap();
        assert_eq!(found.unwrap().consumed_seq, 9);
    }

    #[tokio::test]
    async fn list_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, bytes) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);
        store.fail_lists.store(true, Ordering::SeqCst);

        let result = find_success_record(&store, &wid(0xaa), 7, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::Store(_))));
    }

    #[tokio::test]
    async fn get_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, bytes) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);
        store.fail_gets.store(true, Ordering::SeqCst);

        let result = find_success_record(&store, &wid(0xaa), 7, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::Store(_))));
    }

    #[tokio::test]
    async fn unparseable_matching_record_degrades_to_a_miss() {
        let store = MemStore::default();
        let (key, _) = success_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, b"not json".to_vec());

        let metrics = test_metrics();
        let result = find_success_record(&store, &wid(0xaa), 7, &metrics)
            .await
            .unwrap();
        assert!(result.is_none());
        assert_eq!(metrics.record_parse_failures.get(), 1);
    }

    #[tokio::test]
    async fn scan_cap_is_an_error_not_a_miss() {
        let store = MemStore::default();
        // A deep history whose seqs all clear the threshold (never a strike):
        // enough day buckets that the scan must give up at the cap.
        for day in 1..=28 {
            for hour in [4u64, 10, 16] {
                let ts = 1_690_000_000_000 + ((day * 24 + hour) * 3_600_000);
                let (key, bytes) = success_record_json(wid(0xbb), 1000 + day, ts, mock_response());
                store.insert(key, bytes);
            }
        }

        let result = find_success_record(&store, &wid(0xaa), 2, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::CapExceeded)));
    }

    #[test]
    fn success_seq_parses_from_real_key_shape() {
        let (key, _) = success_record_json(wid(0xaa), 42, TS_HOUR_A, mock_response());
        assert_eq!(parse_success_seq(&key), Some(42));
        assert_eq!(
            parse_success_seq("withdraw/2023/11/14/22/failure-s-wid0xaa-0000.json"),
            None
        );
    }

    #[test]
    fn wid_suffix_matches_the_real_key_shape() {
        // The scanner's suffix filter must match the withdrawal success-key
        // pattern exactly; a drift here silently disables the durable tier.
        let w = wid(0xcd);
        let (key, _) = success_record_json(w, 7, TS_HOUR_A, mock_response());
        assert!(key.ends_with(&format!("-wid{w}.json")));
    }
}
