// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor's snapshot: what survives a restart.
//!
//! Why it exists: without it, every restart would re-audit from the bridge's
//! genesis to rebuild the UTXO pool, and report every old finding again.
//!
//! How it works:
//! 1. After each state check, the auditor saves a `Snapshot` as JSON under
//!    `SNAPSHOT_KEY` in a GCS bucket: the previous check's restart start,
//!    the UTXO pool as it is now, and the deployment it audits. The pool is
//!    ahead of the restart start. That is safe: the pool skips every
//!    operation it already applied, so the replay changes nothing in it.
//! 2. At startup it loads the snapshot, resumes from the restart start with
//!    the pool unless another deployment saved it, and saves its own start.
//!
//! Assumptions:
//! - Only the monitor writes the bucket. A later restart start skips the
//!   audit of everything before it.
//! - The snapshot is durable. Without it, the next start is a first run from
//!   genesis, which needs a Sui node that keeps the history.

use anyhow::Context;
use hashi_types::guardian::time::UnixSeconds;
use object_store::ObjectStore;
use object_store::PutPayload;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path;
use serde::Deserialize;
use serde::Serialize;

use crate::audit::pool::UtxoPool;
use crate::config::Config;

/// The object that holds the snapshot.
const SNAPSHOT_KEY: &str = "snapshot.json";

/// What the continuous auditor keeps between runs. Unknown fields are
/// ignored, so an older monitor still resumes from a newer one's snapshot,
/// and its next save drops them.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Snapshot {
    /// The guardian bucket and Hashi package audited. Progress through one
    /// deployment says nothing about another, such as a redeployed devnet.
    pub guardian_bucket: String,
    pub package_id: String,
    /// Where a restart resumes: at or before every flow not yet verified.
    /// Kept as a UTC timestamp string, so an operator can read and edit it.
    #[serde(with = "crate::time::utc_timestamp_serde")]
    pub restart_start: UnixSeconds,
    /// The UTXO pool. A snapshot without one does not load. Delete it to
    /// start again from genesis.
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

/// The bucket that keeps the snapshot.
pub struct SnapshotStore {
    store: Box<dyn ObjectStore>,
}

impl SnapshotStore {
    /// The GCS bucket `bucket`. Credentials come from the environment, or on
    /// GKE from the pod's workload identity.
    pub fn gcs(bucket: &str) -> anyhow::Result<Self> {
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .with_context(|| format!("failed to set up the snapshot bucket {bucket}"))?;
        Ok(Self {
            store: Box::new(store),
        })
    }

    /// The saved snapshot, or `None` if there is none.
    pub async fn load(&self) -> anyhow::Result<Option<Snapshot>> {
        let bytes = match self.store.get(&Path::from(SNAPSHOT_KEY)).await {
            Ok(object) => object.bytes().await,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => Err(error),
        }
        .context("failed to read the snapshot")?;
        let snapshot = serde_json::from_slice(&bytes).context("failed to parse the snapshot")?;
        Ok(Some(snapshot))
    }

    /// Replace the saved snapshot.
    pub async fn save(&self, snapshot: &Snapshot) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        self.store
            .put(&Path::from(SNAPSHOT_KEY), PutPayload::from(bytes))
            .await
            .context("failed to write the snapshot")?;
        Ok(())
    }
}

#[cfg(test)]
impl SnapshotStore {
    pub(crate) fn in_memory() -> Self {
        Self {
            store: Box::new(object_store::memory::InMemory::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::test_utils::txid;
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

    async fn store_holding(json: serde_json::Value) -> SnapshotStore {
        let store = SnapshotStore::in_memory();
        store
            .store
            .put(
                &Path::from(SNAPSHOT_KEY),
                PutPayload::from(json.to_string().into_bytes()),
            )
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn a_snapshot_round_trips_through_the_store() {
        let cfg = Config::for_tests();
        let store = SnapshotStore::in_memory();
        assert_eq!(store.load().await.unwrap(), None);

        let snapshot = Snapshot::new(&cfg, 1_700_000_000, pool_with_a_utxo());
        store.save(&snapshot).await.unwrap();

        assert_eq!(store.load().await.unwrap(), Some(snapshot));
    }

    #[tokio::test]
    async fn a_snapshot_with_fields_this_monitor_does_not_know_still_loads() {
        let store = store_holding(serde_json::json!({
            "guardian_bucket": "bucket",
            "package_id": "0x1",
            "restart_start": "2023-11-14T22:13:20Z",
            "pool": serde_json::to_value(UtxoPool::default()).unwrap(),
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
        store
            .store
            .put(&Path::from(SNAPSHOT_KEY), PutPayload::from_static(b"{"))
            .await
            .unwrap();

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
