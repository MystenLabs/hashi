// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! An in-memory index of the wids in the S3 withdrawal log.
//!
//! Why it exists: the enclave writes one record to S3 for each withdrawal
//! that it signs, before it returns the signatures
//! (`withdraw_mode/standard_withdrawal.rs`). When a node retries a wid, the
//! proxy must return the recorded response and must not ask the enclave to
//! sign again. The proxy only reads the log. It never writes to it.
//!
//! How the index fills: the log has one directory per hour. A background
//! task (the tail) waits until an hour directory can get no more writes,
//! which is `DIR_WRITES_COMPLETION_DELAY` after the hour ends. Then it lists
//! the keys in that directory and stores the wid and seq of each key. At
//! startup, the proxy fills the index for the last `RETENTION` before it
//! serves requests. The index does not store responses. A retry after a
//! forward finds the new key in the current hour directory.
//!
//! How a lookup works:
//! 1. Look in the index. On a hit, fetch the record from S3 and build the
//!    response from it.
//! 2. If not found, list the hour directories that the tail has not indexed
//!    yet. These are the current hour, the hour after it, and sometimes the
//!    hour before it. Add their keys to the index and look again.
//! 3. If still not found, the wid is not in the log. The caller forwards the
//!    request to the enclave.
//!
//! If S3 fails at any step, the lookup returns an error and the caller fails
//! closed.
//!
//! Assumptions:
//! - The enclave clock is at most `DIR_WRITES_COMPLETION_DELAY` behind the
//!   proxy clock, and at most one hour ahead of it.
//! - A record is visible in S3 as soon as the PUT of the enclave returns.
//! - A node retries a wid within `RETENTION`.

use crate::log_store::LogStore;
use crate::metrics::ProxyMetrics;
use anyhow::Context as _;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::SignedLogEntry;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::proto;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use tracing::error;
use tracing::warn;

const TAIL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const RETENTION: Duration = Duration::from_hours(30 * 24);

/// A LIST or GET failed. The lookup is indeterminate.
#[derive(Debug)]
pub struct WidLogError(pub anyhow::Error);

/// The withdrawal that the index found for a wid.
pub struct Hit {
    /// The seq at which the guardian consumed the wid.
    pub consumed_seq: u64,
    pub response: proto::SignedStandardWithdrawalResponse,
}

struct Entry {
    seq: u64,
    /// The time when the record was written. The tail evicts entries older than `RETENTION`.
    written_at: UnixSeconds,
    /// The S3 key of the record. The lookup fetches it on a hit.
    key: String,
}

struct State {
    entries: HashMap<WithdrawalID, Entry>,
    /// The first hour directory that the tail has not indexed.
    cursor: S3HourDirectory,
}

impl State {
    /// Keep one entry for a wid. Two seqs mean the enclave signed the wid
    /// twice, so log an error and keep the highest seq. Two different keys
    /// at one seq are an error.
    fn put(&mut self, wid: WithdrawalID, entry: Entry) {
        let Some(existing) = self.entries.get(&wid) else {
            self.entries.insert(wid, entry);
            return;
        };
        if entry.seq != existing.seq {
            // Note(sid): is the error! sufficient to alert us?
            error!(
                %wid,
                seq = existing.seq,
                other_seq = entry.seq,
                "Wid has withdrawal records at two seqs; the enclave signed it twice."
            );
            if entry.seq > existing.seq {
                self.entries.insert(wid, entry);
            }
            return;
        }
        if entry.key != existing.key {
            error!(
                %wid,
                seq = entry.seq,
                old = existing.key,
                new = entry.key,
                "Wid has two withdrawal records at one seq."
            );
        }
    }
}

pub struct WidLogIndex<L> {
    log: L,
    state: Mutex<State>,
    metrics: Arc<ProxyMetrics>,
}

impl<L: LogStore> WidLogIndex<L> {
    /// Make an index that starts `RETENTION` before `now`. `tick` fills it.
    pub fn new(log: L, metrics: Arc<ProxyMetrics>, now: UnixSeconds) -> Self {
        let start = now.saturating_sub(RETENTION.as_secs());
        let cursor =
            S3HourDirectory::withdraw(start).expect("current time is within the calendar range");
        Self {
            log,
            state: Mutex::new(State {
                entries: HashMap::new(),
                cursor,
            }),
            metrics,
        }
    }

    /// Run the tail forever. Spawn it after the first `tick` filled the index.
    pub async fn tail_forever(self: Arc<Self>) {
        loop {
            tokio::time::sleep(TAIL_INTERVAL).await;
            if let Err(e) = self.tick(now_timestamp_secs()).await {
                self.metrics.widlog_tail_failures.inc();
                warn!(error = %e, "Wid index tail failed; retrying next tick.");
            }
        }
    }

    /// Index each hour directory whose writes completed before `now`. Then
    /// evict entries older than `RETENTION`. If the store fails, keep the
    /// cursor for the next tick and return the error.
    pub async fn tick(&self, now: UnixSeconds) -> anyhow::Result<()> {
        let result = self.index_complete_hours(now).await;
        let mut state = self.lock();
        let oldest = now.saturating_sub(RETENTION.as_secs());
        state.entries.retain(|_, entry| entry.written_at >= oldest);
        self.metrics
            .widlog_index_size
            .set(state.entries.len() as i64);
        self.metrics
            .widlog_cursor_lag_seconds
            .set(now.saturating_sub(state.cursor.to_unix_seconds()) as i64);
        result
    }

    /// Move the cursor to the first hour that is still open at `now`.
    async fn index_complete_hours(&self, now: UnixSeconds) -> anyhow::Result<()> {
        loop {
            let cursor = self.lock().cursor.clone();
            if now < cursor.write_completion_time() {
                return Ok(());
            }
            self.index_hour(&cursor).await?;
            self.lock().cursor = cursor
                .next_dir()
                .expect("hour directory within the calendar range");
        }
    }

    /// Index the seq and wid of each key in `dir`. Skip a key that is not canonical.
    async fn index_hour(&self, dir: &S3HourDirectory) -> anyhow::Result<()> {
        let keys = self
            .log
            .list_keys(&dir.to_string())
            .await
            .with_context(|| format!("list {dir}"))?;
        let written_at = dir.to_unix_seconds();
        let mut state = self.lock();
        for key in keys {
            let Some((seq, wid)) = WithdrawalLogMessage::parse_object_key(&key) else {
                self.metrics.record_parse_failures.inc();
                warn!(key, "Noncanonical withdrawal log key; skipping.");
                continue;
            };
            state.put(
                wid,
                Entry {
                    seq,
                    written_at,
                    key,
                },
            );
        }
        Ok(())
    }

    /// Find the withdrawal for `wid`. `Ok(None)` is a definite miss, so the
    /// caller can forward. On `Err`, the caller must fail closed.
    pub async fn lookup(
        &self,
        wid: &WithdrawalID,
        now: UnixSeconds,
    ) -> Result<Option<Hit>, WidLogError> {
        if let Some(hit) = self.hit(wid).await? {
            return Ok(Some(hit));
        }
        // Index the hours that the tail has not reached, through the hour
        // after `now` for a writer whose clock is ahead.
        let last = S3HourDirectory::withdraw(now)
            .and_then(|dir| dir.next_dir())
            .expect("current time is within the calendar range");
        let mut dir = self.lock().cursor.clone();
        while dir.to_unix_seconds() <= last.to_unix_seconds() {
            self.index_hour(&dir).await.map_err(WidLogError)?;
            dir = dir
                .next_dir()
                .expect("hour directory within the calendar range");
        }
        self.hit(wid).await
    }

    /// Return the indexed withdrawal for `wid`, with its record fetched from S3.
    async fn hit(&self, wid: &WithdrawalID) -> Result<Option<Hit>, WidLogError> {
        let entry = self
            .lock()
            .entries
            .get(wid)
            .map(|entry| (entry.seq, entry.key.clone()));
        let Some((seq, key)) = entry else {
            return Ok(None);
        };
        let found = self.fetch(&key, wid).await?;
        Ok(Some(Hit {
            consumed_seq: seq,
            response: synthesize_response(&found),
        }))
    }

    /// GET and parse one record. A record that does not parse is an error:
    /// the enclave signed the wid, so a forward would sign it again.
    async fn fetch(&self, key: &str, wid: &WithdrawalID) -> Result<FoundWithdrawal, WidLogError> {
        let bytes = self.log.get(key).await.map_err(WidLogError)?;
        parse_withdrawal(&bytes, wid)
            .inspect_err(|_| self.metrics.record_parse_failures.inc())
            .with_context(|| format!("parse {key}"))
            .map_err(WidLogError)
    }

    // No critical section spans an `.await`, so a sync mutex keeps the handler
    // future `Send`. A panic aborts the process (`abort_on_panic` in main).
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("wid index mutex poisoned")
    }

    #[cfg(test)]
    pub(crate) fn log(&self) -> &L {
        &self.log
    }

    /// An index that has tailed `log` to the current hour.
    #[cfg(test)]
    pub(crate) async fn ready_for_tests(log: L, metrics: Arc<ProxyMetrics>) -> Arc<Self> {
        let now = now_timestamp_secs();
        let index = Arc::new(Self::new(log, metrics, now));
        index.tick(now).await.expect("tail an in-memory store");
        index
    }
}

struct FoundWithdrawal {
    /// The timestamp of the log record. The replayed response uses it.
    timestamp_ms: u64,
    response: StandardWithdrawalResponse,
}

fn parse_withdrawal(bytes: &[u8], wid: &WithdrawalID) -> anyhow::Result<FoundWithdrawal> {
    let record: SignedLogEntry = serde_json::from_slice(bytes)?;
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
        timestamp_ms,
        response,
    })
}

fn synthesize_response(found: &FoundWithdrawal) -> proto::SignedStandardWithdrawalResponse {
    proto::SignedStandardWithdrawalResponse {
        data: Some(proto::StandardWithdrawalResponseData {
            enclave_signatures: found
                .response
                .enclave_signatures
                .iter()
                .map(|sig| sig.to_vec().into())
                .collect(),
        }),
        timestamp_ms: Some(found.timestamp_ms),
        // The enclave signs the response envelope after the S3 write, so the
        // record has no envelope signature. Nodes require 64 bytes but do not
        // verify them (`into_data_unchecked`). Zeros are not a valid signature.
        signature: Some(vec![0u8; 64].into()),
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Network;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::SignedLogEntry;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;

    /// A genuine withdrawal `SignedLogEntry`, serialized as the enclave writes
    /// it, with the key from `SignedLogEntry::object_key()`.
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
        let record = SignedLogEntry::new_at_timestamp(
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

    const HOUR: UnixSeconds = 3_600;
    /// 2023-11-14T22:00:00Z, the hour of the timestamp in the envelope.rs key tests.
    const HOUR_0: UnixSeconds = 1_699_999_200;
    /// 20 minutes into hour 3: hours 0 to 2 are complete, hour 3 is open.
    const NOW: UnixSeconds = HOUR_0 + 3 * HOUR + 20 * 60;

    fn ms(secs: UnixSeconds) -> u64 {
        secs * 1_000
    }

    fn wid(byte: u8) -> WithdrawalID {
        WithdrawalID::new([byte; 32])
    }

    fn mock_response() -> StandardWithdrawalResponse {
        StandardWithdrawalResponse {
            enclave_signatures: vec![],
        }
    }

    fn record(store: &MemStore, wid: WithdrawalID, seq: u64, at: UnixSeconds) {
        let (key, bytes) = withdrawal_record_json(wid, seq, ms(at), mock_response());
        store.insert(key, bytes);
    }

    fn index(store: MemStore) -> WidLogIndex<MemStore> {
        WidLogIndex::new(store, Arc::new(ProxyMetrics::new()), NOW)
    }

    async fn ready_index(store: MemStore) -> WidLogIndex<MemStore> {
        let index = index(store);
        index.tick(NOW).await.unwrap();
        index
    }

    fn cursor(index: &WidLogIndex<MemStore>) -> UnixSeconds {
        index.lock().cursor.to_unix_seconds()
    }

    #[tokio::test]
    async fn tail_indexes_complete_hours_and_stops_at_the_current_one() {
        let store = MemStore::default();
        // Three hours back: the reconcile case that the old seq-bounded walk missed.
        record(&store, wid(0xaa), 7, HOUR_0 + 60);
        record(&store, wid(0xbb), 8, HOUR_0 + HOUR);
        record(&store, wid(0xcc), 9, NOW);
        let index = ready_index(store).await;

        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
        assert_eq!(index.metrics.widlog_index_size.get(), 2);
        assert_eq!(index.metrics.widlog_cursor_lag_seconds.get(), 20 * 60);

        let lists_before = index.log.list_calls.load(Ordering::SeqCst);
        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 7);
        assert_eq!(hit.response.timestamp_ms, Some(ms(HOUR_0 + 60)));
        assert_eq!(index.log.list_calls.load(Ordering::SeqCst), lists_before);

        // The current hour is not indexed, so the lookup lists hour 3 and hour 4.
        let hit = index.lookup(&wid(0xcc), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 9);
        assert_eq!(
            index.log.list_calls.load(Ordering::SeqCst),
            lists_before + 2
        );
    }

    #[tokio::test]
    async fn tail_waits_for_the_completion_delay() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 2 * HOUR + 60);
        let index = index(store);
        // Five minutes into hour 3: hour 2 can still receive writes.
        let now = HOUR_0 + 3 * HOUR + 5 * 60;
        index.tick(now).await.unwrap();

        assert_eq!(cursor(&index), HOUR_0 + 2 * HOUR);
        // Hours 2, 3, and 4 are listed.
        let lists = index.log.list_calls.load(Ordering::SeqCst);
        assert!(index.lookup(&wid(0xaa), now).await.unwrap().is_some());
        assert_eq!(index.log.list_calls.load(Ordering::SeqCst), lists + 3);

        index.tick(NOW).await.unwrap();
        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
    }

    #[tokio::test]
    async fn empty_log_is_a_definite_miss() {
        let index = ready_index(MemStore::default()).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn record_in_the_next_hour_is_found() {
        // The clock of the writer is ahead of the proxy clock.
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 4 * HOUR + 60);
        let index = ready_index(store).await;
        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 7);
    }

    #[tokio::test]
    async fn open_hour_keys_are_indexed_by_a_lookup() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, NOW);
        record(&store, wid(0xbb), 8, NOW);
        let index = ready_index(store).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());

        // Both wids are now in the index, so no more LISTs.
        let lists = index.log.list_calls.load(Ordering::SeqCst);
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());
        assert!(index.lookup(&wid(0xbb), NOW).await.unwrap().is_some());
        assert_eq!(index.log.list_calls.load(Ordering::SeqCst), lists);
    }

    #[tokio::test]
    async fn duplicate_wid_keeps_the_highest_seq() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 5, HOUR_0 + 60);
        record(&store, wid(0xaa), 9, HOUR_0 + HOUR);
        record(&store, wid(0xbb), 2, NOW);
        record(&store, wid(0xbb), 4, NOW + 60);
        let index = ready_index(store).await;

        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 9);
        let hit = index.lookup(&wid(0xbb), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 4);
    }

    #[tokio::test]
    async fn tail_relists_a_key_that_a_lookup_indexed() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, NOW);
        let index = ready_index(store).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());

        // Two hours later the tail lists hour 3 and sees the same key again.
        let later = NOW + 2 * HOUR;
        index.tick(later).await.unwrap();
        assert_eq!(index.metrics.widlog_index_size.get(), 1);
        let hit = index.lookup(&wid(0xaa), later).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 7);
    }

    #[tokio::test]
    async fn entries_are_evicted_after_retention() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 60);
        let index = ready_index(store).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());

        let later = NOW + RETENTION.as_secs();
        index.tick(later).await.unwrap();
        assert_eq!(index.metrics.widlog_index_size.get(), 0);
        assert!(index.lookup(&wid(0xaa), later).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn noncanonical_key_is_skipped_and_counted() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 60);
        store.insert("withdraw/2023/11/14/22/junk.json", b"{}".to_vec());
        let index = ready_index(store).await;

        assert_eq!(index.metrics.record_parse_failures.get(), 1);
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn tail_list_failure_leaves_the_cursor_in_place() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 60);
        store.fail_lists.store(true, Ordering::SeqCst);
        let index = index(store);
        let start = cursor(&index);

        assert!(index.tick(NOW).await.is_err());
        assert_eq!(cursor(&index), start);

        index.log.fail_lists.store(false, Ordering::SeqCst);
        index.tick(NOW).await.unwrap();
        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn unreadable_record_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, _) = withdrawal_record_json(wid(0xaa), 7, ms(HOUR_0 + 60), mock_response());
        store.insert(key, b"not json".to_vec());
        let (key, _) = withdrawal_record_json(wid(0xbb), 8, ms(NOW), mock_response());
        store.insert(key, b"not json".to_vec());
        let index = ready_index(store).await;

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
        assert!(index.lookup(&wid(0xbb), NOW).await.is_err());
        assert_eq!(index.metrics.record_parse_failures.get(), 2);
    }

    #[tokio::test]
    async fn get_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        record(&store, wid(0xaa), 7, HOUR_0 + 60);
        let index = ready_index(store).await;
        index.log.fail_gets.store(true, Ordering::SeqCst);

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
    }

    #[tokio::test]
    async fn lookup_list_failure_is_an_error_not_a_miss() {
        let index = ready_index(MemStore::default()).await;
        index.log.fail_lists.store(true, Ordering::SeqCst);

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
    }

    #[test]
    fn wid_suffix_matches_the_real_key_shape() {
        // The key parser must accept the exact key shape that the enclave
        // writes. A drift here makes the index skip each key.
        let w = wid(0xcd);
        let (key, _) = withdrawal_record_json(w, 7, ms(HOUR_0), mock_response());
        assert!(key.ends_with(&format!("-wid{w}.json")));
        assert_eq!(WithdrawalLogMessage::parse_object_key(&key), Some((7, w)));
    }
}
