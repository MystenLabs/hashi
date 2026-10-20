// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor's snapshot: what survives a restart.
//!
//! Why it exists: without it, every restart would re-audit from the bridge's
//! genesis to rebuild the UTXO pool, and report every old finding again.
//!
//! How it works:
//! 1. After each state check, the auditor saves a `Snapshot`: the previous
//!    check's restart start, the UTXO pool as it is now, and the deployment
//!    it audits. The pool is ahead of the restart start. That is safe: the
//!    pool skips every operation it already applied, so the replay changes
//!    nothing in it.
//! 2. The bucket holds the snapshot as several objects. `SNAPSHOT_KEY` is
//!    a small manifest with the restart start, the held UTXOs and the number
//!    of spent entries. The spent record only grows, so it is kept apart in
//!    `spent/NNNNN.json` files of `SPENT_SEGMENT_ENTRIES` entries each, in
//!    the order the pool spent them. A full file never changes again.
//! 3. A save writes the files that hold new entries and then the manifest.
//!    The manifest is last, so a crash leaves a file that is ahead of it.
//!    A load reads only as many entries as the manifest counts.
//! 4. At startup it loads the snapshot, resumes from the restart start with
//!    the pool unless another deployment saved it, and saves its own start.
//!
//! Assumptions:
//! - Only the monitor writes the bucket. A later restart start skips the
//!   audit of everything before it.
//! - The snapshot is durable. Without it, the next start is a first run from
//!   genesis, which needs a Sui node that keeps the history.

use std::sync::Mutex;
use std::time::Instant;

use anyhow::Context;
use futures::StreamExt;
use futures::TryStreamExt;
use hashi_types::guardian::time::UnixSeconds;
use object_store::ObjectStore;
use object_store::PutPayload;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path;
use serde::Deserialize;
use serde::Serialize;

use crate::audit::pool::SpentUtxoWire;
use crate::audit::pool::UtxoPool;
use crate::audit::pool::UtxoWire;
use crate::config::Config;

/// The object that holds the manifest.
const SNAPSHOT_KEY: &str = "snapshot.json";

/// How many spent entries one file holds. A full file is about 4 MB, and a
/// save writes at most the one file that is not full.
const SPENT_SEGMENT_ENTRIES: usize = 10_000;

/// How many spent files a load reads at once.
const LOAD_PARALLELISM: usize = 8;

/// What the continuous auditor keeps between runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// The guardian bucket and Hashi package audited. Progress through one
    /// deployment says nothing about another, such as a redeployed devnet.
    pub guardian_bucket: String,
    pub package_id: String,
    /// Where a restart resumes: at or before every flow not yet verified.
    pub restart_start: UnixSeconds,
    pub pool: UtxoPool,
}

impl Snapshot {
    pub fn new(cfg: &Config, restart_start: UnixSeconds, pool: UtxoPool) -> Self {
        Self {
            guardian_bucket: cfg.deployment.bucket_info.name.clone(),
            package_id: cfg.sui.package_id.clone(),
            restart_start,
            pool,
        }
    }

    /// Whether the snapshot was saved auditing the deployment in `cfg`.
    pub fn is_for(&self, cfg: &Config) -> bool {
        self.guardian_bucket == cfg.deployment.bucket_info.name
            && self.package_id == cfg.sui.package_id
    }
}

/// The object at `SNAPSHOT_KEY`. Unknown fields are ignored, so an older
/// monitor still resumes from a newer one's snapshot, and its next save drops
/// them.
#[derive(Deserialize, Serialize)]
struct Manifest {
    guardian_bucket: String,
    package_id: String,
    /// Kept as a UTC timestamp string, so an operator can read and edit it.
    #[serde(with = "crate::time::utc_timestamp_serde")]
    restart_start: UnixSeconds,
    utxos: Vec<UtxoWire>,
    /// How many spent entries the snapshot has, from the first file on.
    spent_count: usize,
}

/// The bucket that keeps the snapshot.
pub struct SnapshotStore {
    store: Box<dyn ObjectStore>,
    /// How many spent entries the bucket holds, as of the last load or save.
    saved_spent: Mutex<usize>,
    /// How many spent entries one file holds.
    segment_entries: usize,
}

impl SnapshotStore {
    /// The GCS bucket `bucket`. Credentials come from the environment, or on
    /// GKE from the pod's workload identity.
    pub fn gcs(bucket: &str) -> anyhow::Result<Self> {
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .with_context(|| format!("failed to set up the snapshot bucket {bucket}"))?;
        Ok(Self::new(Box::new(store), SPENT_SEGMENT_ENTRIES))
    }

    fn new(store: Box<dyn ObjectStore>, segment_entries: usize) -> Self {
        Self {
            store,
            saved_spent: Mutex::new(0),
            segment_entries,
        }
    }

    fn segment_key(index: usize) -> Path {
        Path::from(format!("spent/{index:05}.json"))
    }

    /// The saved snapshot, or `None` if there is none.
    pub async fn load(&self) -> anyhow::Result<Option<Snapshot>> {
        let bytes = match self.store.get(&Path::from(SNAPSHOT_KEY)).await {
            Ok(object) => object.bytes().await,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => Err(error),
        }
        .context("failed to read the snapshot")?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("failed to parse the snapshot")?;

        let files = manifest.spent_count.div_ceil(self.segment_entries);
        let mut segments = futures::stream::iter(0..files)
            .map(|index| self.read_segment(index))
            .buffered(LOAD_PARALLELISM);
        let mut spent = Vec::with_capacity(manifest.spent_count);
        let mut index = 0;
        while let Some(segment) = segments.try_next().await? {
            // The last file may hold more than the manifest counts.
            let wanted =
                (manifest.spent_count - index * self.segment_entries).min(self.segment_entries);
            anyhow::ensure!(
                segment.len() >= wanted,
                "the snapshot needs {wanted} spent entries in {} but it holds {}",
                Self::segment_key(index),
                segment.len(),
            );
            spent.extend(segment.into_iter().take(wanted));
            index += 1;
        }
        drop(segments);

        *self.saved_spent.lock().expect("saved_spent lock") = manifest.spent_count;
        Ok(Some(Snapshot {
            guardian_bucket: manifest.guardian_bucket,
            package_id: manifest.package_id,
            restart_start: manifest.restart_start,
            pool: UtxoPool::from_wire(manifest.utxos, spent),
        }))
    }

    async fn read_segment(&self, index: usize) -> anyhow::Result<Vec<SpentUtxoWire>> {
        let key = Self::segment_key(index);
        let bytes = self
            .store
            .get(&key)
            .await
            .with_context(|| format!("failed to read {key}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read {key}"))?;
        serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {key}"))
    }

    /// Replace the saved snapshot of the deployment in `cfg`. It writes the
    /// spent files that hold new entries, then the manifest. The pool is
    /// borrowed, since a copy of the spent record is large.
    pub async fn save(
        &self,
        cfg: &Config,
        restart_start: UnixSeconds,
        pool: &UtxoPool,
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        let spent_count = pool.spent_len();
        let saved = *self.saved_spent.lock().expect("saved_spent lock");
        let mut bytes_written = 0;
        let mut files_written = 0;

        if spent_count > 0 && spent_count != saved {
            // From the file that held the last saved entry through the last.
            let first = saved.min(spent_count) / self.segment_entries;
            let last = (spent_count - 1) / self.segment_entries;
            for index in first..=last {
                let start = index * self.segment_entries;
                let end = (start + self.segment_entries).min(spent_count);
                let bytes = serde_json::to_vec(&pool.spent_to_wire(start..end))?;
                bytes_written += bytes.len();
                files_written += 1;
                self.store
                    .put(&Self::segment_key(index), PutPayload::from(bytes))
                    .await
                    .with_context(|| format!("failed to write {}", Self::segment_key(index)))?;
            }
        }

        let manifest = Manifest {
            guardian_bucket: cfg.deployment.bucket_info.name.clone(),
            package_id: cfg.sui.package_id.clone(),
            restart_start,
            utxos: pool.held_to_wire(),
            spent_count,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        bytes_written += bytes.len();
        self.store
            .put(&Path::from(SNAPSHOT_KEY), PutPayload::from(bytes))
            .await
            .context("failed to write the snapshot")?;

        *self.saved_spent.lock().expect("saved_spent lock") = spent_count;
        tracing::info!(
            spent_entries = spent_count,
            spent_files_written = files_written,
            bytes_written,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "saved the snapshot"
        );
        Ok(())
    }
}

#[cfg(test)]
impl SnapshotStore {
    pub(crate) fn in_memory() -> Self {
        Self::in_memory_with_segments(SPENT_SEGMENT_ENTRIES)
    }

    fn in_memory_with_segments(segment_entries: usize) -> Self {
        Self::new(
            Box::new(object_store::memory::InMemory::new()),
            segment_entries,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::pool::SpentUtxo;
    use crate::audit::pool::Utxo;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::UtxoOrigin;
    use crate::test_utils::txid;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;

    /// A pool that holds one UTXO.
    fn pool_with_a_utxo() -> UtxoPool {
        let mut pool = UtxoPool::default();
        let deposit = ConfirmedDeposit {
            deposit_id: DepositId::new(txid(1), 0),
            amount: 1_000,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            block_time: 1_699_999_000,
        };
        assert!(pool.add_deposit(&deposit).is_none());
        pool
    }

    /// The `index`th spent entry of a test pool.
    fn spent_entry(index: u32) -> SpentUtxoWire {
        SpentUtxoWire {
            outpoint: OutPoint {
                txid: txid(2),
                vout: index,
            },
            spent: SpentUtxo {
                utxo: Utxo {
                    amount: 1_000 + u64::from(index),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                    origin: UtxoOrigin::Deposit,
                    first_seen: 1_699_999_000,
                },
                spent_by: txid(3),
            },
        }
    }

    /// A pool that holds one UTXO and `count` spent ones.
    fn pool_with_spent(count: u32) -> UtxoPool {
        let held = pool_with_a_utxo().held_to_wire();
        UtxoPool::from_wire(held, (0..count).map(spent_entry).collect())
    }

    async fn put(store: &SnapshotStore, key: &Path, bytes: Vec<u8>) {
        store.store.put(key, PutPayload::from(bytes)).await.unwrap();
    }

    async fn store_holding(json: serde_json::Value) -> SnapshotStore {
        let store = SnapshotStore::in_memory();
        put(
            &store,
            &Path::from(SNAPSHOT_KEY),
            json.to_string().into_bytes(),
        )
        .await;
        store
    }

    #[tokio::test]
    async fn a_snapshot_round_trips_through_the_store() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory();
        assert_eq!(store.load().await.unwrap(), None);

        let snapshot = Snapshot::new(&cfg, 1_700_000_000, pool_with_a_utxo());
        store
            .save(&cfg, snapshot.restart_start, &snapshot.pool)
            .await
            .unwrap();

        assert_eq!(store.load().await.unwrap(), Some(snapshot));
    }

    #[tokio::test]
    async fn a_spent_record_over_several_files_round_trips() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory_with_segments(3);
        let snapshot = Snapshot::new(&cfg, 1_700_000_000, pool_with_spent(7));

        store
            .save(&cfg, snapshot.restart_start, &snapshot.pool)
            .await
            .unwrap();

        assert_eq!(store.load().await.unwrap(), Some(snapshot));
        for index in 0..3 {
            let key = SnapshotStore::segment_key(index);
            assert!(store.store.get(&key).await.is_ok(), "{key}");
        }
    }

    #[tokio::test]
    async fn a_save_leaves_the_full_files_alone() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory_with_segments(3);
        store.save(&cfg, 1, &pool_with_spent(7)).await.unwrap();
        // A mark in the first file shows whether a later save writes it again.
        let first = SnapshotStore::segment_key(0);
        put(&store, &first, b"[]".to_vec()).await;

        store.save(&cfg, 2, &pool_with_spent(8)).await.unwrap();

        let after = store
            .store
            .get(&first)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(after.as_ref(), b"[]");
        let last = store
            .store
            .get(&SnapshotStore::segment_key(2))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let entries: Vec<SpentUtxoWire> = serde_json::from_slice(&last).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn a_load_ignores_entries_a_crashed_save_wrote_after_the_manifest() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory_with_segments(3);
        let saved = Snapshot::new(&cfg, 1_700_000_000, pool_with_spent(5));
        store
            .save(&cfg, saved.restart_start, &saved.pool)
            .await
            .unwrap();
        // The next save wrote its last file and crashed before the manifest.
        let ahead = pool_with_spent(7).spent_to_wire(3..7);
        put(
            &store,
            &SnapshotStore::segment_key(1),
            serde_json::to_vec(&ahead).unwrap(),
        )
        .await;

        let loaded = store.load().await.unwrap().unwrap();

        assert_eq!(loaded, saved);
    }

    #[tokio::test]
    async fn a_missing_spent_file_is_an_error() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory_with_segments(3);
        store.save(&cfg, 1, &pool_with_spent(7)).await.unwrap();
        store
            .store
            .delete(&SnapshotStore::segment_key(1))
            .await
            .unwrap();

        let error = format!("{:#}", store.load().await.unwrap_err());

        assert!(error.contains("spent/00001.json"), "{error}");
    }

    #[tokio::test]
    async fn a_snapshot_with_fields_this_monitor_does_not_know_still_loads() {
        let store = store_holding(serde_json::json!({
            "guardian_bucket": "bucket",
            "package_id": "0x1",
            "restart_start": "2023-11-14T22:13:20Z",
            "utxos": [],
            "spent_count": 0,
            "guardian_cursor": 1_700_000_000,
        }))
        .await;

        let loaded = store.load().await.unwrap().unwrap();

        assert_eq!(loaded.restart_start, 1_700_000_000);
    }

    #[tokio::test]
    async fn a_snapshot_without_a_pool_is_an_error() {
        let store = store_holding(serde_json::json!({
            "guardian_bucket": "bucket",
            "package_id": "0x1",
            "restart_start": "2023-11-14T22:13:20Z",
        }))
        .await;

        let error = format!("{:#}", store.load().await.unwrap_err());

        assert!(error.contains("failed to parse the snapshot"), "{error}");
    }

    #[tokio::test]
    async fn an_unreadable_snapshot_is_an_error() {
        let store = SnapshotStore::in_memory();
        put(&store, &Path::from(SNAPSHOT_KEY), b"{".to_vec()).await;

        let error = format!("{:#}", store.load().await.unwrap_err());

        assert!(error.contains("failed to parse the snapshot"), "{error}");
    }

    #[test]
    fn a_snapshot_is_only_for_the_deployment_that_saved_it() {
        let cfg = Config::for_tests();
        let snapshot = Snapshot::new(&cfg, 1_700_000_000, UtxoPool::default());
        assert!(snapshot.is_for(&cfg));

        let mut redeployed = cfg.clone();
        redeployed.sui.package_id = format!("0x{}", "22".repeat(32));
        assert!(!snapshot.is_for(&redeployed));

        let mut other_guardian = cfg;
        other_guardian.deployment.bucket_info.name = "other-bucket".to_string();
        assert!(!snapshot.is_for(&other_guardian));
    }
}
