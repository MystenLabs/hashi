// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! An in-memory index of the wids in the S3 withdrawal log.
//!
//! Why it exists: the enclave writes one withdrawal log to S3 for each
//! withdrawal that it signs, before it returns the signatures
//! (`withdraw_mode/standard_withdrawal.rs`). When a node retries a wid, the
//! proxy must return the recorded response and must not ask the enclave to
//! sign again. The proxy only reads the log. It never writes to it.
//!
//! How the index fills: the log has one directory per hour. A background
//! task (the tail) waits until an hour directory can get no more writes,
//! which is `DIR_WRITES_COMPLETION_DELAY` after the hour ends. Then it lists
//! the keys in that directory and stores the wid and seq of each key. At
//! startup, the proxy fills the index for the last `RETENTION` before it
//! serves requests. The index does not store the responses that this proxy
//! forwards. A retry after a forward finds the new key in the current hour
//! directory.
//!
//! How a lookup works:
//! 1. Look in the index. On a hit, return the cached response. If there is
//!    none yet, fetch the withdrawal log from S3, build the response, and
//!    cache it.
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
//! - A withdrawal log is visible in S3 as soon as the PUT of the enclave returns.
//! - A node retries a wid within `RETENTION`.

use crate::log_store::LogStore;
use crate::metrics::ProxyMetrics;
use anyhow::Context as _;
use hashi_types::guardian::proto_conversions::standard_withdrawal_response_signed_to_pb;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::GuardianResponse;
use hashi_types::guardian::GuardianSignature;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::SignedLogEntry;
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
    /// The start of the hour directory of the key. The tail evicts entries older than `RETENTION`.
    hour_start: UnixSeconds,
    /// The S3 key of the withdrawal log. The first hit fetches it.
    key: String,
    /// The response built from the withdrawal log, after the first hit.
    response: Option<proto::SignedStandardWithdrawalResponse>,
}

struct State {
    entries: HashMap<WithdrawalID, Entry>,
    /// The first hour directory that the tail has not indexed.
    cursor: S3HourDirectory,
}

impl State {
    /// Add the entry for a listed key. Two seqs mean the enclave
    /// signed the wid twice, so log an error and keep the highest seq. Two
    /// different keys at one seq must not occur, so return an error.
    fn add_entry(&mut self, wid: WithdrawalID, entry: Entry) -> anyhow::Result<()> {
        let Some(existing) = self.entries.get(&wid) else {
            self.entries.insert(wid, entry);
            return Ok(());
        };
        if entry.seq != existing.seq {
            // Note(sid): is the error! sufficient to alert us?
            error!(
                %wid,
                seq = existing.seq,
                other_seq = entry.seq,
                "Wid has withdrawal logs at two seqs; the enclave signed it twice."
            );
            if entry.seq > existing.seq {
                self.entries.insert(wid, entry);
            }
            return Ok(());
        }
        anyhow::ensure!(
            entry.key == existing.key,
            "wid {wid} has two withdrawal logs at seq {}: {} and {}",
            entry.seq,
            existing.key,
            entry.key
        );
        Ok(())
    }

    /// Move the cursor to the next hour directory.
    fn advance_cursor(&mut self) {
        self.cursor = self
            .cursor
            .next_dir()
            .expect("hour directory within the calendar range");
    }

    /// Build the response from the withdrawal log fetched for `wid`, cache
    /// it on the entry, and return the hit. The log must name the entry's
    /// key and must be a withdrawal log for `wid`.
    fn attach_withdrawal_log(
        &mut self,
        wid: &WithdrawalID,
        withdrawal_log: LogEntry,
    ) -> anyhow::Result<Hit> {
        let entry = self
            .entries
            .get_mut(wid)
            .ok_or_else(|| anyhow::anyhow!("wid {wid} left the index during the GET"))?;
        anyhow::ensure!(
            withdrawal_log.object_key() == entry.key,
            "withdrawal log names key {}, expected {}",
            withdrawal_log.object_key(),
            entry.key
        );
        let message = withdrawal_log
            .message()
            .as_withdrawal()
            .ok_or_else(|| anyhow::anyhow!("not a withdrawal log"))?;
        anyhow::ensure!(
            message.request_data.wid == *wid,
            "withdrawal log is for wid {}, expected {wid}",
            message.request_data.wid
        );
        let response =
            GuardianResponse::new(message.response.clone(), withdrawal_log.timestamp_ms());
        // The enclave signs the response envelope after the S3 write, so the
        // withdrawal log has no envelope signature. Nodes require 64 bytes but
        // do not verify them (`into_data_unchecked`). Zeros are not a valid signature.
        let signature = GuardianSignature::from([0u8; 64]);
        let response = standard_withdrawal_response_signed_to_pb(GuardianSigned::from_parts(
            response, signature,
        ));
        entry.response = Some(response.clone());
        Ok(Hit {
            consumed_seq: entry.seq,
            response,
        })
    }
}

pub struct WidLogIndex<L> {
    store: L,
    state: Mutex<State>,
    metrics: Arc<ProxyMetrics>,
}

impl<L: LogStore> WidLogIndex<L> {
    /// Make an index that starts `RETENTION` before `now`. `tick` fills it.
    pub fn new(store: L, metrics: Arc<ProxyMetrics>, now: UnixSeconds) -> Self {
        let start = now.saturating_sub(RETENTION.as_secs());
        let cursor =
            S3HourDirectory::withdraw(start).expect("current time is within the calendar range");
        Self {
            store,
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
        state.entries.retain(|_, entry| entry.hour_start >= oldest);
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
            self.lock().advance_cursor();
        }
    }

    /// Index the seq and wid of each key in `dir`. A key that is not
    /// canonical fails the index, and the hour adds no entries.
    async fn index_hour(&self, dir: &S3HourDirectory) -> anyhow::Result<()> {
        let prefix = dir.to_string();
        let keys = self
            .store
            .list_keys(&prefix)
            .await
            .with_context(|| format!("list {dir}"))?;
        let hour_start = dir.to_unix_seconds();
        let entries = keys
            .into_iter()
            .map(|key| {
                let (seq, wid) = WithdrawalLogMessage::parse_object_key(&prefix, &key)?;
                let entry = Entry {
                    seq,
                    hour_start,
                    key,
                    response: None,
                };
                Ok((wid, entry))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut state = self.lock();
        for (wid, entry) in entries {
            state.add_entry(wid, entry)?;
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

    /// Return the indexed withdrawal for `wid`. The first hit fetches the
    /// withdrawal log from S3 and caches the response built from it.
    async fn hit(&self, wid: &WithdrawalID) -> Result<Option<Hit>, WidLogError> {
        let key = {
            let state = self.lock();
            let Some(entry) = state.entries.get(wid) else {
                return Ok(None);
            };
            if let Some(response) = &entry.response {
                return Ok(Some(Hit {
                    consumed_seq: entry.seq,
                    response: response.clone(),
                }));
            }
            entry.key.clone()
        };
        let withdrawal_log = self.fetch_withdrawal_log(&key).await?;
        let hit = self
            .lock()
            .attach_withdrawal_log(wid, withdrawal_log)
            .map_err(WidLogError)?;
        Ok(Some(hit))
    }

    /// GET and parse one withdrawal log. A log that does not parse is an
    /// error: the enclave signed the wid, so a forward would sign it again.
    async fn fetch_withdrawal_log(&self, key: &str) -> Result<LogEntry, WidLogError> {
        let bytes = self.store.get(key).await.map_err(WidLogError)?;
        serde_json::from_slice::<SignedLogEntry>(&bytes)
            .map(SignedLogEntry::into_entry_unchecked)
            .with_context(|| format!("parse {key}"))
            .map_err(WidLogError)
    }

    // No critical section spans an `.await`, so a sync mutex keeps the handler
    // future `Send`. A panic aborts the process (`abort_on_panic` in main).
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("wid index mutex poisoned")
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &L {
        &self.store
    }

    /// An index that has tailed `log` to the current hour.
    #[cfg(test)]
    pub(crate) async fn ready_for_tests(store: L, metrics: Arc<ProxyMetrics>) -> Arc<Self> {
        let now = now_timestamp_secs();
        let index = Arc::new(Self::new(store, metrics, now));
        index.tick(now).await.expect("tail an in-memory store");
        index
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
    use hashi_types::guardian::StandardWithdrawalResponse;

    /// A genuine withdrawal `SignedLogEntry`, serialized as the enclave writes
    /// it, with the key from `SignedLogEntry::object_key()`.
    pub(crate) fn withdrawal_log_json(
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
        let withdrawal_log = SignedLogEntry::new_at_timestamp(
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
        let key = withdrawal_log.object_key().to_string();
        (key, serde_json::to_vec(&withdrawal_log).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::withdrawal_log_json;
    use super::*;
    use crate::log_store::test_store::MemStore;
    use hashi_types::guardian::StandardWithdrawalResponse;
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

    fn write_withdrawal_log(store: &MemStore, wid: WithdrawalID, seq: u64, at: UnixSeconds) {
        let (key, bytes) = withdrawal_log_json(wid, seq, ms(at), mock_response());
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
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        write_withdrawal_log(&store, wid(0xbb), 8, HOUR_0 + HOUR);
        write_withdrawal_log(&store, wid(0xcc), 9, NOW);
        let index = ready_index(store).await;

        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
        assert_eq!(index.metrics.widlog_index_size.get(), 2);
        assert_eq!(index.metrics.widlog_cursor_lag_seconds.get(), 20 * 60);

        let lists_before = index.store.list_calls.load(Ordering::SeqCst);
        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 7);
        assert_eq!(hit.response.timestamp_ms, Some(ms(HOUR_0 + 60)));
        assert_eq!(index.store.list_calls.load(Ordering::SeqCst), lists_before);

        // The current hour is not indexed, so the lookup lists hour 3 and hour 4.
        let hit = index.lookup(&wid(0xcc), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 9);
        assert_eq!(
            index.store.list_calls.load(Ordering::SeqCst),
            lists_before + 2
        );
    }

    #[tokio::test]
    async fn tail_waits_for_the_completion_delay() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 2 * HOUR + 60);
        let index = index(store);
        // Five minutes into hour 3: hour 2 can still receive writes.
        let now = HOUR_0 + 3 * HOUR + 5 * 60;
        index.tick(now).await.unwrap();

        assert_eq!(cursor(&index), HOUR_0 + 2 * HOUR);
        // Hours 2, 3, and 4 are listed.
        let lists = index.store.list_calls.load(Ordering::SeqCst);
        assert!(index.lookup(&wid(0xaa), now).await.unwrap().is_some());
        assert_eq!(index.store.list_calls.load(Ordering::SeqCst), lists + 3);

        index.tick(NOW).await.unwrap();
        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
    }

    #[tokio::test]
    async fn empty_log_is_a_definite_miss() {
        let index = ready_index(MemStore::default()).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn log_in_the_next_hour_is_found() {
        // The clock of the writer is ahead of the proxy clock.
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 4 * HOUR + 60);
        let index = ready_index(store).await;
        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 7);
    }

    #[tokio::test]
    async fn open_hour_keys_are_indexed_by_a_lookup() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, NOW);
        write_withdrawal_log(&store, wid(0xbb), 8, NOW);
        let index = ready_index(store).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());

        // Both wids are now in the index, so no more LISTs.
        let lists = index.store.list_calls.load(Ordering::SeqCst);
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());
        assert!(index.lookup(&wid(0xbb), NOW).await.unwrap().is_some());
        assert_eq!(index.store.list_calls.load(Ordering::SeqCst), lists);
    }

    #[tokio::test]
    async fn duplicate_wid_keeps_the_highest_seq() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 5, HOUR_0 + 60);
        write_withdrawal_log(&store, wid(0xaa), 9, HOUR_0 + HOUR);
        write_withdrawal_log(&store, wid(0xbb), 2, NOW);
        write_withdrawal_log(&store, wid(0xbb), 4, NOW + 60);
        let index = ready_index(store).await;

        let hit = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 9);
        let hit = index.lookup(&wid(0xbb), NOW).await.unwrap().unwrap();
        assert_eq!(hit.consumed_seq, 4);
    }

    #[tokio::test]
    async fn second_hit_uses_the_cached_response() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        let index = ready_index(store).await;
        let first = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();

        index.store.fail_gets.store(true, Ordering::SeqCst);
        let second = index.lookup(&wid(0xaa), NOW).await.unwrap().unwrap();
        assert_eq!(second.response, first.response);
    }

    #[tokio::test]
    async fn two_keys_at_one_seq_fail_the_index() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + HOUR + 60);
        let index = index(store);

        let error = index.tick(NOW).await.unwrap_err().to_string();
        assert!(error.contains("two withdrawal logs at seq 7"), "{error}");
        assert_eq!(cursor(&index), HOUR_0 + HOUR);
        assert!(index.lookup(&wid(0xbb), NOW).await.is_err());
    }

    #[tokio::test]
    async fn withdrawal_log_under_another_key_is_an_error() {
        let store = MemStore::default();
        let (_, bytes) = withdrawal_log_json(wid(0xaa), 7, ms(HOUR_0 + 60), mock_response());
        let (key, _) = withdrawal_log_json(wid(0xaa), 7, ms(HOUR_0 + HOUR), mock_response());
        store.insert(key, bytes);
        let index = ready_index(store).await;

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
    }

    #[tokio::test]
    async fn tail_relists_a_key_that_a_lookup_indexed() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, NOW);
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
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        let index = ready_index(store).await;
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());

        let later = NOW + RETENTION.as_secs();
        index.tick(later).await.unwrap();
        assert_eq!(index.metrics.widlog_index_size.get(), 0);
        assert!(index.lookup(&wid(0xaa), later).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn noncanonical_key_fails_the_index() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        store.insert("withdraw/2023/11/14/22/junk.json", b"{}".to_vec());
        let index = index(store);

        let error = index.tick(NOW).await.unwrap_err().to_string();
        assert!(error.contains("noncanonical withdrawal log key"), "{error}");
        assert_eq!(cursor(&index), HOUR_0);
        // The hour added no entries, so the good wid is not served either.
        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
        assert!(index.lookup(&wid(0xbb), NOW).await.is_err());
    }

    #[tokio::test]
    async fn tail_list_failure_leaves_the_cursor_in_place() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        store.fail_lists.store(true, Ordering::SeqCst);
        let index = index(store);
        let start = cursor(&index);

        assert!(index.tick(NOW).await.is_err());
        assert_eq!(cursor(&index), start);

        index.store.fail_lists.store(false, Ordering::SeqCst);
        index.tick(NOW).await.unwrap();
        assert_eq!(cursor(&index), HOUR_0 + 3 * HOUR);
        assert!(index.lookup(&wid(0xaa), NOW).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn unreadable_withdrawal_log_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, _) = withdrawal_log_json(wid(0xaa), 7, ms(HOUR_0 + 60), mock_response());
        store.insert(key, b"not json".to_vec());
        let (key, _) = withdrawal_log_json(wid(0xbb), 8, ms(NOW), mock_response());
        store.insert(key, b"not json".to_vec());
        let index = ready_index(store).await;

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
        assert!(index.lookup(&wid(0xbb), NOW).await.is_err());
    }

    #[tokio::test]
    async fn get_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        write_withdrawal_log(&store, wid(0xaa), 7, HOUR_0 + 60);
        let index = ready_index(store).await;
        index.store.fail_gets.store(true, Ordering::SeqCst);

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
    }

    #[tokio::test]
    async fn lookup_list_failure_is_an_error_not_a_miss() {
        let index = ready_index(MemStore::default()).await;
        index.store.fail_lists.store(true, Ordering::SeqCst);

        assert!(index.lookup(&wid(0xaa), NOW).await.is_err());
    }

    #[test]
    fn key_parser_accepts_the_real_key_shape() {
        // The key parser must accept the exact key shape that the enclave
        // writes. A drift here fails the index on the first key.
        let w = wid(0xcd);
        let (key, _) = withdrawal_log_json(w, 7, ms(HOUR_0), mock_response());
        let prefix = S3HourDirectory::withdraw(HOUR_0).unwrap().to_string();
        assert_eq!(
            WithdrawalLogMessage::parse_object_key(&prefix, &key).unwrap(),
            (7, w)
        );
    }
}
