// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor's snapshot: the whole audit state, so a restart
//! continues where the last run stopped.
//!
//! Why it exists: without it, every restart would re-audit from the bridge's
//! genesis to rebuild the UTXO pool, and report every old finding again.
//!
//! How it works:
//! 1. After each state check, the auditor saves a `Snapshot`: the deployment
//!    it audits, its `AuditState`, and the UTXO pool. The audit state is the
//!    position of each poller, every open state machine, the suspect spends
//!    of the last pool check, and the time of the last finding of each
//!    category. All of it is taken at one instant.
//! 2. A restart loads the machines, restores the finding times, and resumes
//!    each poller at its saved position. It reads no event twice and skips
//!    none, so no flow is cut in two.
//! 3. The bucket holds the snapshot as several objects. `SNAPSHOT_KEY` is a
//!    manifest with the audit state, the held UTXOs and the number of spent
//!    entries. The spent record only grows, so it is kept apart in
//!    `spent/NNNNN.json` files of `SPENT_SEGMENT_ENTRIES` entries each, in
//!    the order the pool spent them. A full file never changes again.
//! 4. A save writes the files that hold new entries and then the manifest.
//!    The manifest is last, so a crash leaves a file that is ahead of it.
//!    A load reads only as many entries as the manifest counts.
//!
//! Assumptions:
//! - Only the monitor writes the bucket.
//! - A snapshot of another `SNAPSHOT_VERSION` fails the load. The operator
//!   deletes it, and the next start is a first run from genesis.
//! - The snapshot is durable. Without it, the next start is a first run from
//!   genesis, which needs a Sui node that keeps the history.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Context;
use bitcoin::OutPoint;
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
use crate::audit::pool::SuspectSpend;
use crate::audit::pool::UtxoPool;
use crate::audit::pool::UtxoWire;
use crate::config::Config;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;

/// The object that holds the manifest.
const SNAPSHOT_KEY: &str = "snapshot.json";

/// The format of the snapshot. Change it when a saved type changes.
const SNAPSHOT_VERSION: u32 = 1;

/// How many spent entries one file holds. A full file is about 4 MB, and a
/// save writes at most the one file that is not full.
const SPENT_SEGMENT_ENTRIES: usize = 10_000;

/// How many spent files a load reads at once.
const LOAD_PARALLELISM: usize = 8;

/// What the continuous auditor keeps between runs.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    /// The guardian bucket and Hashi package audited. Progress through one
    /// deployment says nothing about another, such as a redeployed devnet.
    pub guardian_bucket: String,
    pub package_id: String,
    pub state: AuditState,
    pub pool: UtxoPool,
}

/// The auditor's state apart from the UTXO pool.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuditState {
    /// The first Sui checkpoint not yet scanned.
    pub sui_next_checkpoint: u64,
    /// The first guardian hourly directory not yet read. Kept as a UTC
    /// timestamp string, so an operator can read it.
    #[serde(with = "crate::time::utc_timestamp_serde")]
    pub guardian_cursor: UnixSeconds,
    pub withdrawals: Vec<WithdrawalStateMachine>,
    pub deposits: Vec<DepositStateMachine>,
    /// The spends the last pool check saw, still waiting for the Sui cursor.
    pub suspect_spends: Vec<(OutPoint, SuspectSpend)>,
    /// The time of the last finding, by category label.
    pub last_findings: BTreeMap<String, UnixSeconds>,
}

impl Snapshot {
    pub fn new(cfg: &Config, state: AuditState, pool: UtxoPool) -> Self {
        Self {
            guardian_bucket: cfg.deployment.bucket_info.name.clone(),
            package_id: cfg.sui.package_id.clone(),
            state,
            pool,
        }
    }

    /// Whether the snapshot was saved auditing the deployment in `cfg`.
    pub fn is_for(&self, cfg: &Config) -> bool {
        self.guardian_bucket == cfg.deployment.bucket_info.name
            && self.package_id == cfg.sui.package_id
    }
}

/// The object at `SNAPSHOT_KEY`.
#[derive(Deserialize, Serialize)]
struct Manifest {
    version: u32,
    guardian_bucket: String,
    package_id: String,
    #[serde(flatten)]
    state: AuditState,
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
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let Version { version } =
            serde_json::from_slice(&bytes).context("failed to parse the snapshot")?;
        anyhow::ensure!(
            version == SNAPSHOT_VERSION,
            "the snapshot has version {version}, but this monitor needs version {SNAPSHOT_VERSION}. Delete the snapshot to run again from genesis",
        );
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
            state: manifest.state,
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
        state: AuditState,
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
            version: SNAPSHOT_VERSION,
            guardian_bucket: cfg.deployment.bucket_info.name.clone(),
            package_id: cfg.sui.package_id.clone(),
            state,
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
    use crate::domain::WithdrawalEventType;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::test_utils::deposit_request;
    use crate::test_utils::txid;
    use crate::timing::Timing;
    use bitcoin::ScriptBuf;

    /// A state with one open withdrawal, one open deposit and a finding time.
    fn state() -> AuditState {
        let approval = hashi_approval();
        let mut withdrawal = WithdrawalStateMachine::new(approval.clone(), &Timing::for_tests());
        let signature = crate::domain::MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            timestamp_secs: approval.timestamp_secs + 60,
            ..approval
        };
        assert!(
            withdrawal
                .add_event(signature, &Timing::for_tests())
                .is_empty()
        );
        AuditState {
            sui_next_checkpoint: 1_234,
            guardian_cursor: 1_700_000_000,
            withdrawals: vec![withdrawal],
            deposits: vec![DepositStateMachine::new(deposit_request())],
            suspect_spends: vec![(
                OutPoint {
                    txid: txid(4),
                    vout: 0,
                },
                SuspectSpend {
                    asked_at: 1_700_000_100,
                    amount: 2_000,
                },
            )],
            last_findings: BTreeMap::from([("safety".to_string(), 1_700_000_500)]),
        }
    }

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

    async fn save(store: &SnapshotStore, snapshot: &Snapshot) {
        store
            .save(&Config::for_tests(), snapshot.state.clone(), &snapshot.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_snapshot_round_trips_through_the_store() {
        let store = SnapshotStore::in_memory();
        assert_eq!(store.load().await.unwrap(), None);

        let snapshot = Snapshot::new(&Config::for_tests(), state(), pool_with_a_utxo());
        save(&store, &snapshot).await;

        assert_eq!(store.load().await.unwrap(), Some(snapshot));
    }

    #[tokio::test]
    async fn a_spent_record_over_several_files_round_trips() {
        let store = SnapshotStore::in_memory_with_segments(3);
        let snapshot = Snapshot::new(&Config::for_tests(), state(), pool_with_spent(7));

        save(&store, &snapshot).await;

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
        store
            .save(&cfg, state(), &pool_with_spent(7))
            .await
            .unwrap();
        // A mark in the first file shows whether a later save writes it again.
        let first = SnapshotStore::segment_key(0);
        put(&store, &first, b"[]".to_vec()).await;

        store
            .save(&cfg, state(), &pool_with_spent(8))
            .await
            .unwrap();

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
        let store = SnapshotStore::in_memory_with_segments(3);
        let saved = Snapshot::new(&Config::for_tests(), state(), pool_with_spent(5));
        save(&store, &saved).await;
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
        let store = SnapshotStore::in_memory_with_segments(3);
        save(
            &store,
            &Snapshot::new(&Config::for_tests(), state(), pool_with_spent(7)),
        )
        .await;
        store
            .store
            .delete(&SnapshotStore::segment_key(1))
            .await
            .unwrap();

        let error = format!("{:#}", store.load().await.unwrap_err());

        assert!(error.contains("spent/00001.json"), "{error}");
    }

    #[tokio::test]
    async fn a_snapshot_of_another_version_or_none_is_an_error() {
        let store = SnapshotStore::in_memory();
        let key = Path::from(SNAPSHOT_KEY);

        put(&store, &key, br#"{"version": 0}"#.to_vec()).await;
        let error = format!("{:#}", store.load().await.unwrap_err());
        assert!(error.contains("Delete the snapshot"), "{error}");

        put(&store, &key, b"{".to_vec()).await;
        let error = format!("{:#}", store.load().await.unwrap_err());
        assert!(error.contains("failed to parse the snapshot"), "{error}");
    }

    #[test]
    fn a_snapshot_is_only_for_the_deployment_that_saved_it() {
        let cfg = Config::for_tests();
        let snapshot = Snapshot::new(&cfg, state(), UtxoPool::default());
        assert!(snapshot.is_for(&cfg));

        let mut redeployed = cfg.clone();
        redeployed.sui.package_id = format!("0x{}", "22".repeat(32));
        assert!(!snapshot.is_for(&redeployed));

        let mut other_guardian = cfg;
        other_guardian.deployment.bucket_info.name = "other-bucket".to_string();
        assert!(!snapshot.is_for(&other_guardian));
    }
}
