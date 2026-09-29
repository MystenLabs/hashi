// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only access to the guardian's S3 withdrawal log — the wid cache's
//! durable tier. The enclave writes one record per signed withdrawal
//! *before* releasing the signatures and fails closed if the write fails
//! (`withdraw_mode/standard_withdrawal.rs`), so every signature a node has seen has a
//! record here; the proxy never writes.
//!
//! Keys are `withdraw/YYYY/MM/DD/HH/{seq:020}-{session}-wid{wid}.json`,
//! with the wid only a suffix — so a lookup walks hour buckets newest-first.
//! The request's `seq` bounds the walk: a retried wid was signed at `seq` or
//! `seq - 1` (the node's mirror trails the guardian by at most the reconcile
//! snap), so once two consecutive non-empty buckets top out below
//! `seq - 1` the record can't be further back (two, not one, so a forward
//! clock step can't hide it behind a single future-labelled bucket). Exhausted
//! prefixes are a definitive miss; hitting the LIST cap is NOT — the caller
//! must fail closed on it, never forward.

use crate::log_store::LogStore;
use crate::metrics::ProxyMetrics;
use hashi_types::guardian::log::S3_DIR_WITHDRAW;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use tracing::warn;

// A terminating scan needs ~4 tree walks + 2-3 bucket lists; the cap only
// trips on a seq far below everything in the log (e.g. a rogue client).
const SCAN_LIST_CAP: usize = 100;

#[derive(Debug)]
pub enum WidLogError {
    /// A LIST or GET failed; the lookup is indeterminate.
    Store(anyhow::Error),
    /// The scan exceeded `SCAN_LIST_CAP` without terminating.
    CapExceeded,
}

/// A parsed withdrawal record for a wid.
pub struct FoundWithdrawal {
    /// The seq the guardian consumed the wid at (`request_data.seq`).
    pub consumed_seq: u64,
    /// Timestamp of the log record, reused as the replayed response timestamp.
    pub timestamp_ms: u64,
    pub response: StandardWithdrawalResponse,
}

/// Find the newest withdrawal record for `wid`, walking hour buckets newest to
/// oldest. `Ok(None)` is a *definitive* miss (safe to forward to the enclave);
/// any `Err` means the lookup is indeterminate and the caller must fail closed.
pub async fn find_withdrawal_record<L: LogStore>(
    log: &L,
    wid: &WithdrawalID,
    request_seq: u64,
    metrics: &ProxyMetrics,
) -> Result<Option<FoundWithdrawal>, WidLogError> {
    let suffix = format!("-wid{wid}.json");
    let threshold = request_seq.saturating_sub(1);
    let mut lists_used = 0usize;
    let mut strikes = 0u32;

    let scan = async {
        for year in list_desc(log, &format!("{S3_DIR_WITHDRAW}/"), &mut lists_used).await? {
            for month in list_desc(log, &year, &mut lists_used).await? {
                for day in list_desc(log, &month, &mut lists_used).await? {
                    for hour in list_desc(log, &day, &mut lists_used).await? {
                        let keys = list_keys_capped(log, &hour, &mut lists_used).await?;
                        if keys.is_empty() {
                            // An empty listing says nothing about the seq bound.
                            continue;
                        }

                        // Newest (max-seq) candidate first within the bucket.
                        for key in keys.iter().rev().filter(|k| k.ends_with(&suffix)) {
                            let bytes = log.get(key).await.map_err(WidLogError::Store)?;
                            match parse_withdrawal(&bytes, wid) {
                                Ok(found) => return Ok(Some(found)),
                                Err(e) => {
                                    // Skip (schema skew): a miss re-signs and heals;
                                    // failing closed would wedge until a proxy fix.
                                    metrics.record_parse_failures.inc();
                                    warn!(key, error = %e, "unreadable withdrawal record for wid; skipping");
                                }
                            }
                        }

                        let bucket_max = keys.iter().rev().find_map(|k| parse_withdrawal_seq(k));
                        match bucket_max {
                            Some(max) if max < threshold => {
                                strikes += 1;
                                if strikes >= 2 {
                                    return Ok(None);
                                }
                            }
                            Some(_) => strikes = 0,
                            // Only unparseable withdrawal keys: indeterminate.
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

/// Parse the zero-padded seq out of a `.../{seq:020}-...` key.
fn parse_withdrawal_seq(key: &str) -> Option<u64> {
    let name = key.rsplit('/').next()?;
    name.get(..20)?.parse().ok()
}

fn parse_withdrawal(bytes: &[u8], wid: &WithdrawalID) -> anyhow::Result<FoundWithdrawal> {
    let record: LogRecord = serde_json::from_slice(bytes)?;
    let entry = record.into_entry_unchecked();
    let timestamp_ms = entry.timestamp_ms();
    let message = entry
        .into_message()
        .into_withdrawal()
        .ok_or_else(|| anyhow::anyhow!("not a withdrawal record"))?;
    let WithdrawalLogMessage {
        request_data,
        response,
        ..
    } = *message;
    anyhow::ensure!(
        request_data.wid == *wid,
        "record is for wid {}, expected {}",
        request_data.wid,
        wid
    );
    Ok(FoundWithdrawal {
        consumed_seq: request_data.seq,
        timestamp_ms,
        response,
    })
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Network;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;

    /// A genuine withdrawal `LogRecord`, serialized exactly as the enclave
    /// writes it, keyed by `LogRecord::object_key()`.
    pub(crate) fn withdrawal_record_json(
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
            "test-session".into(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage {
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
}

#[cfg(test)]
mod tests {
    use super::test_utils::withdrawal_record_json;
    use super::*;
    use crate::log_store::test_store::MemStore;
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
        let (key, bytes) = withdrawal_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);

        let found = find_withdrawal_record(&store, &wid(0xaa), 7, &test_metrics())
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
        let result = find_withdrawal_record(&store, &wid(0xaa), 0, &test_metrics())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn bumped_seq_retry_still_finds_the_record() {
        // The reconcile snap bumps the node's seq to S+1; threshold slack must
        // keep the bucket holding seq S inside the scan.
        let store = MemStore::default();
        let (key, bytes) = withdrawal_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);

        let found = find_withdrawal_record(&store, &wid(0xaa), 8, &test_metrics())
            .await
            .unwrap();
        assert_eq!(found.unwrap().consumed_seq, 7);
    }

    #[tokio::test]
    async fn scan_stops_after_two_low_buckets() {
        let store = MemStore::default();
        // Two non-empty buckets both below threshold: the wid is absent
        // and the scan must stop without walking further back.
        let (key_b, bytes_b) = withdrawal_record_json(wid(0xbb), 5, TS_HOUR_B, mock_response());
        let (key_a, bytes_a) = withdrawal_record_json(wid(0xcc), 4, TS_HOUR_A, mock_response());
        let (key_z, bytes_z) = withdrawal_record_json(wid(0xdd), 3, TS_HOUR_Z, mock_response());
        store.insert(key_b, bytes_b);
        store.insert(key_a, bytes_a);
        store.insert(key_z, bytes_z);

        let result = find_withdrawal_record(&store, &wid(0xaa), 20, &test_metrics())
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
        let (key_skew, bytes_skew) =
            withdrawal_record_json(wid(0xbb), 5, TS_HOUR_B, mock_response());
        let (key, bytes) = withdrawal_record_json(wid(0xaa), 9, TS_HOUR_A, mock_response());
        store.insert(key_skew, bytes_skew);
        store.insert(key, bytes);

        let found = find_withdrawal_record(&store, &wid(0xaa), 10, &test_metrics())
            .await
            .unwrap();
        assert_eq!(found.unwrap().consumed_seq, 9);
    }

    #[tokio::test]
    async fn list_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, bytes) = withdrawal_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);
        store.fail_lists.store(true, Ordering::SeqCst);

        let result = find_withdrawal_record(&store, &wid(0xaa), 7, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::Store(_))));
    }

    #[tokio::test]
    async fn get_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, bytes) = withdrawal_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, bytes);
        store.fail_gets.store(true, Ordering::SeqCst);

        let result = find_withdrawal_record(&store, &wid(0xaa), 7, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::Store(_))));
    }

    #[tokio::test]
    async fn unparseable_matching_record_degrades_to_a_miss() {
        let store = MemStore::default();
        let (key, _) = withdrawal_record_json(wid(0xaa), 7, TS_HOUR_A, mock_response());
        store.insert(key, b"not json".to_vec());

        let metrics = test_metrics();
        let result = find_withdrawal_record(&store, &wid(0xaa), 7, &metrics)
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
                let (key, bytes) =
                    withdrawal_record_json(wid(0xbb), 1000 + day, ts, mock_response());
                store.insert(key, bytes);
            }
        }

        let result = find_withdrawal_record(&store, &wid(0xaa), 2, &test_metrics()).await;
        assert!(matches!(result, Err(WidLogError::CapExceeded)));
    }

    #[test]
    fn withdrawal_seq_parses_from_real_key_shape() {
        let (key, _) = withdrawal_record_json(wid(0xaa), 42, TS_HOUR_A, mock_response());
        assert_eq!(parse_withdrawal_seq(&key), Some(42));
        assert_eq!(
            parse_withdrawal_seq("withdraw/2023/11/14/22/unknown-s-wid0xaa.json"),
            None
        );
    }

    #[test]
    fn wid_suffix_matches_the_real_key_shape() {
        // The scanner's suffix filter must match the withdrawal key
        // pattern exactly; a drift here silently disables the durable tier.
        let w = wid(0xcd);
        let (key, _) = withdrawal_record_json(w, 7, TS_HOUR_A, mock_response());
        assert!(key.ends_with(&format!("-wid{w}.json")));
    }
}
