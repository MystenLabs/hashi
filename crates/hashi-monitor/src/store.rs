// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The continuous auditor's snapshot: the whole audit state, so a restart
//! continues where the last run stopped.
//!
//! Why it exists: without it, every restart would re-audit from the bridge's
//! genesis to rebuild the UTXO pool, and report every old finding again.
//!
//! How it works:
//! 1. About once an hour, the auditor saves a `Snapshot`: the deployment
//!    it audits, its `AuditState`, and the UTXO pool. The audit state is the
//!    position of each poller, every open state machine, the suspect spends
//!    of the last pool check. All of it is taken at one instant.
//! 2. A restart loads the machines and resumes each poller at its saved
//!    position. It reads no event twice and skips none, so no flow is cut
//!    in two.
//! 3. The bucket holds the snapshot as one object, `SNAPSHOT_KEY`. A save
//!    replaces it whole.
//!
//! Assumptions:
//! - Only the monitor writes the bucket.
//! - A snapshot of another `SNAPSHOT_VERSION` fails the load. The operator
//!   deletes it, and the next start is a first run from genesis.
//! - The snapshot is durable. Without it, the next start is a first run from
//!   genesis, which needs a Sui node that keeps the history.

use std::time::Instant;

use anyhow::Context;
use bitcoin::OutPoint;
use hashi_types::guardian::time::UnixSeconds;
use object_store::ObjectStore;
use object_store::PutPayload;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path;
use serde::Deserialize;
use serde::Serialize;

use crate::config::Config;
use crate::domain::utxo_pool::SuspectSpend;
use crate::domain::utxo_pool::UtxoPool;
use crate::domain::utxo_pool::UtxoWire;
use crate::rpc::guardian::GuardianCursor;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;

/// The object that holds the snapshot.
const SNAPSHOT_KEY: &str = "snapshot.json";

/// The format of the snapshot. Change it when a saved type changes.
const SNAPSHOT_VERSION: u32 = 1;

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
    /// The guardian directory read now, and its seq state.
    pub guardian_cursor: GuardianCursor,
    pub withdrawals: Vec<WithdrawalStateMachine>,
    pub deposits: Vec<DepositStateMachine>,
    /// The spends the last pool check saw, still waiting for the Sui cursor.
    pub suspect_spends: Vec<(OutPoint, SuspectSpend)>,
    /// Since when the hBTC supply has exceeded the pool value, if it does.
    pub hbtc_supply_above_pool_since: Option<UnixSeconds>,
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
struct StoredSnapshot {
    version: u32,
    guardian_bucket: String,
    package_id: String,
    #[serde(flatten)]
    state: AuditState,
    utxos: Vec<UtxoWire>,
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
        let stored: StoredSnapshot =
            serde_json::from_slice(&bytes).context("failed to parse the snapshot")?;
        Ok(Some(Snapshot {
            guardian_bucket: stored.guardian_bucket,
            package_id: stored.package_id,
            state: stored.state,
            pool: UtxoPool::from_wire(stored.utxos),
        }))
    }

    /// Replace the saved snapshot of the deployment in `cfg`.
    pub async fn save(
        &self,
        cfg: &Config,
        state: AuditState,
        pool: &UtxoPool,
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        // Before the save, so a save that runs out of memory still leaves its size.
        tracing::info!(
            withdrawals = state.withdrawals.len(),
            deposits = state.deposits.len(),
            suspect_spends = state.suspect_spends.len(),
            utxos = pool.len(),
            "saving the snapshot"
        );
        let stored = StoredSnapshot {
            version: SNAPSHOT_VERSION,
            guardian_bucket: cfg.deployment.bucket_info.name.clone(),
            package_id: cfg.sui.package_id.clone(),
            state,
            utxos: pool.held_to_wire(),
        };
        let bytes = serde_json::to_vec_pretty(&stored)?;
        let bytes_written = bytes.len();
        self.store
            .put(&Path::from(SNAPSHOT_KEY), PutPayload::from(bytes))
            .await
            .context("failed to write the snapshot")?;

        tracing::info!(
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
    use crate::domain::WithdrawalEventType;
    use crate::rpc::sui::tests::hashi_approval;
    use crate::test_utils::deposit_request;
    use crate::test_utils::txid;
    use crate::timing::Timing;
    use bitcoin::ScriptBuf;
    use hashi_types::guardian::s3::S3HourDirectory;

    /// A state with one open withdrawal, one open deposit and a suspect spend.
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
            guardian_cursor: GuardianCursor::new(S3HourDirectory::withdraw(1_700_000_000).unwrap()),
            withdrawals: vec![withdrawal],
            deposits: vec![DepositStateMachine::new(deposit_request())],
            suspect_spends: vec![(
                OutPoint {
                    txid: txid(4),
                    vout: 0,
                },
                SuspectSpend {
                    checked_at: 1_700_000_100,
                    amount: 2_000,
                },
            )],
            hbtc_supply_above_pool_since: Some(1_700_000_600),
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
