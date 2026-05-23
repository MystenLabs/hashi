// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Live update path — subscribe to checkpoints and apply each
//! transaction's object effects as a [`sui_ecs::ChangeSet`].
//!
//! Unlike the event-driven watcher in [`crate::onchain::watcher`], this
//! reads raw object effects: every transaction whose `changed_objects`
//! mention an id in our world produces an Object insert / removal,
//! which the framework propagates through the registered Derived
//! components.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use sui_ecs::ChangeSet;
use sui_ecs::World;
use sui_ecs::ingest::IngestError;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::ExecutedTransaction;
use sui_rpc::proto::sui::rpc::v2::Object as ProtoObject;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use std::sync::RwLock;
use tokio::sync::broadcast;
use tokio::sync::watch;
use tracing::warn;

use super::CheckpointInfo;
use super::Notification;

/// Long-running subscription loop. Drains the checkpoint subscription
/// stream into the world, retrying with backoff on transport errors.
///
/// `owner` is the parent `OnchainState` handle. After each successfully
/// applied checkpoint the watcher calls `owner.rebuild_clients()` so
/// the per-validator gRPC pool reflects any `MemberInfo` rotations
/// from that checkpoint without a separate notification path.
pub async fn run(
    mut client: Client,
    world: Arc<RwLock<World>>,
    checkpoint_tx: watch::Sender<CheckpointInfo>,
    notifications: broadcast::Sender<Notification>,
    owner: super::OnchainState,
) -> Result<()> {
    let read_mask = FieldMask::from_paths([
        // Per-transaction effects — what changed and how.
        "transactions.effects.changed_objects",
        // Checkpoint-level object pool (deduplicated). We pull new
        // values from here when applying.
        "objects.objects.object_id",
        "objects.objects.bcs",
        // Checkpoint summary fields we surface to consumers.
        "sequence_number",
        "summary.timestamp_ms",
        "summary.epoch",
    ]);

    loop {
        let mut stream = match client
            .subscription_client()
            .subscribe_checkpoints(
                SubscribeCheckpointsRequest::default().with_read_mask(read_mask.clone()),
            )
            .await
        {
            Ok(s) => s.into_inner(),
            Err(e) => {
                warn!("subscribe_checkpoints failed: {e}; retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        while let Some(item) = stream.next().await {
            let response = match item {
                Ok(r) => r,
                Err(e) => {
                    warn!("checkpoint stream error: {e}; reconnecting");
                    break;
                }
            };
            let Some(checkpoint) = response.checkpoint.as_ref() else {
                continue;
            };
            if let Err(e) = apply_checkpoint(
                &world,
                checkpoint,
                &checkpoint_tx,
                &notifications,
                &owner,
            )
            .await
            {
                warn!("apply_checkpoint failed: {e}");
            }
        }
    }
}

/// Apply every transaction in a checkpoint to `world`, one batch per
/// transaction. For each per-tx commit, accumulate the
/// [`sui_ecs::CommitReport`] entries for `MemberInfoEntry` /
/// `RichMemberInfo` and hand them to the owning `OnchainState` so the
/// gRPC client pool only rebuilds the validators whose info actually
/// changed — no per-checkpoint full rebuild.
pub async fn apply_checkpoint(
    world: &RwLock<World>,
    ckpt: &Checkpoint,
    checkpoint_tx: &watch::Sender<CheckpointInfo>,
    _notifications: &broadcast::Sender<Notification>,
    owner: &super::OnchainState,
) -> Result<()> {
    use std::collections::HashSet;
    use sui_sdk_types::Address;

    use super::components::{MemberInfoEntry, RichMemberInfo};

    let pool = build_pool(ckpt);

    // Union of entity ids whose `RichMemberInfo` was touched across
    // every transaction in this checkpoint. We rebuild clients for
    // these (and only these) once the whole checkpoint has been
    // applied so consumers see a single coherent pool view per
    // checkpoint heartbeat. Also tracks `MemberInfoEntry` writes so
    // even entries that never produce a `RichMemberInfo` (e.g. BLS
    // bytes fail to decode) still trigger an orphan sweep.
    let mut touched_members: HashSet<Address> = HashSet::new();
    let mut any_member_change = false;

    for tx in &ckpt.transactions {
        let changeset = changeset_from_tx(tx, &pool)?;
        let report = {
            let mut w = world.write().expect("world lock poisoned");
            changeset.apply(&mut w)
        };
        touched_members.extend(report.changed::<RichMemberInfo>());
        if report.any_changed::<MemberInfoEntry>() {
            any_member_change = true;
        }
    }

    if any_member_change {
        owner.refresh_clients_for(touched_members.iter().copied());
    }

    // Surface checkpoint metadata to consumers.
    let info = CheckpointInfo {
        height: ckpt.sequence_number.unwrap_or(0),
        timestamp_ms: ckpt
            .summary
            .as_ref()
            .and_then(|s| s.timestamp.as_ref())
            .map(|t| (t.seconds * 1_000) as u64 + (t.nanos / 1_000_000) as u64)
            .unwrap_or(0),
        epoch: ckpt.summary.as_ref().and_then(|s| s.epoch).unwrap_or(0),
    };
    let _ = checkpoint_tx.send_replace(info);

    Ok(())
}

fn build_pool(ckpt: &Checkpoint) -> HashMap<&str, &ProtoObject> {
    let mut pool = HashMap::new();
    if let Some(set) = ckpt.objects.as_ref() {
        for obj in &set.objects {
            if let Some(id) = obj.object_id.as_deref() {
                pool.insert(id, obj);
            }
        }
    }
    pool
}

/// Build a ChangeSet from one transaction's effects, sourcing post-tx
/// object values from `pool` (which is the checkpoint-level deduped
/// pool). Falls back to the per-tx `objects` field if a particular id
/// isn't in `pool`, so this works for both pooling strategies.
fn changeset_from_tx(
    tx: &ExecutedTransaction,
    pool: &HashMap<&str, &ProtoObject>,
) -> Result<ChangeSet, IngestError> {
    // Merge: start with checkpoint-level pool, layer per-tx pool on top
    // (per-tx may have richer field-mask coverage if the server chose
    // to populate it).
    let mut combined: HashMap<&str, &ProtoObject> = pool.clone();
    if let Some(set) = tx.objects.as_ref() {
        for obj in &set.objects {
            if let Some(id) = obj.object_id.as_deref() {
                combined.insert(id, obj);
            }
        }
    }

    // Reuse the upstream ChangeSet logic by constructing a synthetic
    // ExecutedTransaction view: clone the effects, take the pool as the
    // object source. Since we already have the proto pieces in hand,
    // build the ChangeSet directly from the changed_objects list.
    let effects = tx
        .effects
        .as_ref()
        .ok_or(IngestError::MissingEffects)?;

    let mut upserts = Vec::new();
    let mut removals = Vec::new();

    for changed in &effects.changed_objects {
        let id_str = changed
            .object_id
            .as_deref()
            .ok_or(IngestError::MissingChangedObjectId)?;
        let id: sui_sdk_types::Address =
            id_str
                .parse()
                .map_err(|source| IngestError::InvalidObjectId {
                    raw: id_str.to_owned(),
                    source,
                })?;

        let state = changed
            .output_state
            .and_then(|s| proto::changed_object::OutputObjectState::try_from(s).ok())
            .unwrap_or(proto::changed_object::OutputObjectState::Unknown);

        use proto::changed_object::OutputObjectState as O;
        match state {
            O::ObjectWrite | O::PackageWrite => {
                let proto = combined.get(id_str).copied().ok_or(
                    IngestError::MissingObjectValue { id, state },
                )?;
                // Decode straight from the BCS field rather than going
                // through the proto-to-sdk-types field-by-field
                // conversion — the read mask only includes `bcs`.
                let bytes = proto
                    .bcs
                    .as_ref()
                    .and_then(|b| b.value.as_ref())
                    .ok_or(IngestError::MissingObjectValue { id, state })?;
                let object: sui_sdk_types::Object = bcs::from_bytes(bytes).map_err(|e| {
                    IngestError::Conversion(sui_rpc::proto::TryFromProtoError::invalid(
                        "bcs",
                        e.to_string(),
                    ))
                })?;
                upserts.push(object);
            }
            O::DoesNotExist => {
                removals.push(id);
            }
            O::AccumulatorWrite | O::Unknown => {}
            _ => {}
        }
    }

    Ok(ChangeSet { upserts, removals })
}
