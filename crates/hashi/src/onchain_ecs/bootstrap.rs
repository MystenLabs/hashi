// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Initial scrape of on-chain state into the ECS world.
//!
//! Unlike the event-driven bootstrap in [`crate::onchain`], this just
//! reads the live object set: fetch the Hashi root object, find the bag
//! ids it points to, list dynamic fields of each bag and insert every
//! resulting object. The registered [`components`](super::components)
//! derive parsed values from each `Object` automatically.

use anyhow::{Context, Result, anyhow};
use futures::TryStreamExt;
use sui_ecs::World;
use sui_rpc::Client;
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::{
    DynamicField, GetObjectRequest, ListDynamicFieldsRequest, Object as ProtoObject,
};
use sui_sdk_types::{Address, Identifier, Object, StructTag, TypeTag, bcs::ToBcs};
use tap::Pipe;

use hashi_types::move_types;

use super::CheckpointInfo;
use super::components::{BitcoinStateField, HashiRoot};

/// Scrape the Hashi state into `world` and return the checkpoint
/// information captured at the start of the scrape.
///
/// The fetched objects are committed as one big `MutationBatch` per
/// stage so the derived components materialize against a consistent
/// snapshot rather than firing incrementally.
pub async fn scrape(
    mut client: Client,
    hashi_object_id: Address,
    package_id: Address,
    world_lock: &std::sync::RwLock<World>,
) -> Result<CheckpointInfo> {
    // Stage 1: Hashi root and the BitcoinState dynamic field.
    let (checkpoint, hashi_object) =
        fetch_object_with_checkpoint(&mut client, hashi_object_id).await?;

    let bitcoin_state_field_id = derive_bitcoin_state_field_id(hashi_object_id, package_id);
    let btc_object = fetch_object(&mut client, bitcoin_state_field_id).await?;

    // Apply stage 1 atomically.
    let (members_bag, committees_bag, proposals_active, proposals_executed) = {
        let mut world = world_lock.write().expect("world lock poisoned");
        let mut batch = world.batch();
        batch
            .insert::<Object>(hashi_object_id, hashi_object)
            .insert::<Object>(bitcoin_state_field_id, btc_object);
        batch.commit();

        let hashi = world
            .get::<HashiRoot>(hashi_object_id)
            .ok_or_else(|| anyhow!("Hashi root object did not parse as hashi::hashi::Hashi"))?;

        (
            hashi.0.committees.members.id,
            hashi.0.committees.committees.id,
            hashi.0.proposals.active.id,
            hashi.0.proposals.executed.id,
        )
    };

    // We also want the BitcoinState's nested bag ids — those live in
    // the BitcoinStateField's parsed value.
    let (deposit_requests_bag, withdrawal_requests_bag, utxo_records_bag) = {
        let world = world_lock.read().expect("world lock poisoned");
        let bs = world
            .get::<BitcoinStateField>(bitcoin_state_field_id)
            .ok_or_else(|| anyhow!("BitcoinState dynamic field did not parse"))?;
        (
            bs.0.value.deposit_queue.requests.id,
            bs.0.value.withdrawal_queue.requests.id,
            bs.0.value.utxo_pool.utxo_records.id,
        )
    };

    // Stage 2: list dynamic fields of each interesting bag and ingest
    // every field/child object we find. The framework filters via
    // registered Derived components — we don't need to know up front
    // which objects belong to which kind.
    let bag_ids = [
        members_bag,
        committees_bag,
        proposals_active,
        proposals_executed,
        deposit_requests_bag,
        withdrawal_requests_bag,
        utxo_records_bag,
    ];

    let objects = futures::future::try_join_all(
        bag_ids
            .iter()
            .map(|bag_id| list_bag_objects(client.clone(), *bag_id)),
    )
    .await?;

    {
        let mut world = world_lock.write().expect("world lock poisoned");
        let mut batch = world.batch();
        for bag_objects in objects {
            for (id, obj) in bag_objects {
                batch.insert::<Object>(id, obj);
            }
        }
        batch.commit();
    }

    Ok(checkpoint)
}

async fn fetch_object(client: &mut Client, id: Address) -> Result<Object> {
    let response = client
        .ledger_client()
        .get_object(GetObjectRequest::new(&id).with_read_mask(FieldMask::from_paths([
            ProtoObject::path_builder().owner().finish(),
            ProtoObject::path_builder().contents().finish(),
            ProtoObject::path_builder().object_id(),
            ProtoObject::path_builder().version(),
            ProtoObject::path_builder().object_type(),
        ])))
        .await
        .with_context(|| format!("fetching {id}"))?;
    Object::try_from(response.get_ref().object())
        .with_context(|| format!("converting proto Object for {id}"))
}

async fn fetch_object_with_checkpoint(
    client: &mut Client,
    id: Address,
) -> Result<(CheckpointInfo, Object)> {
    let response = client
        .ledger_client()
        .get_object(GetObjectRequest::new(&id).with_read_mask(FieldMask::from_paths([
            ProtoObject::path_builder().owner().finish(),
            ProtoObject::path_builder().contents().finish(),
            ProtoObject::path_builder().object_id(),
            ProtoObject::path_builder().version(),
            ProtoObject::path_builder().object_type(),
        ])))
        .await
        .with_context(|| format!("fetching {id}"))?;
    let checkpoint = CheckpointInfo {
        height: response
            .checkpoint_height()
            .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?,
        timestamp_ms: response
            .timestamp_ms()
            .ok_or_else(|| anyhow!("response missing X_SUI_TIMESTAMP_MS header"))?,
        epoch: response
            .epoch()
            .ok_or_else(|| anyhow!("response missing X_SUI_EPOCH header"))?,
    };
    let obj = Object::try_from(response.get_ref().object())
        .with_context(|| format!("converting proto Object for {id}"))?;
    Ok((checkpoint, obj))
}

fn derive_bitcoin_state_field_id(hashi_id: Address, package_id: Address) -> Address {
    let key = move_types::BitcoinStateKey { dummy_field: false };
    let key_type = TypeTag::Struct(Box::new(StructTag::new(
        package_id,
        Identifier::from_static("bitcoin_state"),
        Identifier::from_static("BitcoinStateKey"),
        vec![],
    )));
    hashi_id.derive_dynamic_child_id(&key_type, &key.to_bcs().unwrap())
}

/// List every dynamic field of `bag_id` and return `(object_id, Object)`
/// pairs for both the field wrapper itself and (when present) the child
/// object behind a dynamic object field.
async fn list_bag_objects(
    client: Client,
    bag_id: Address,
) -> Result<Vec<(Address, Object)>> {
    let mut stream = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(bag_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().field_object().owner().finish(),
                    DynamicField::path_builder().field_object().contents().finish(),
                    DynamicField::path_builder().field_object().object_id(),
                    DynamicField::path_builder().field_object().version(),
                    DynamicField::path_builder().field_object().object_type(),
                    DynamicField::path_builder().child_object().owner().finish(),
                    DynamicField::path_builder().child_object().contents().finish(),
                    DynamicField::path_builder().child_object().object_id(),
                    DynamicField::path_builder().child_object().version(),
                    DynamicField::path_builder().child_object().object_type(),
                ])),
        )
        .pipe(Box::pin);

    let mut out = Vec::new();
    while let Some(df) = stream.try_next().await? {
        if let Some(proto) = df.field_object.as_ref()
            && let Ok(obj) = Object::try_from(proto)
        {
            out.push((obj.object_id(), obj));
        }
        if let Some(proto) = df.child_object.as_ref()
            && let Ok(obj) = Object::try_from(proto)
        {
            out.push((obj.object_id(), obj));
        }
    }
    Ok(out)
}
