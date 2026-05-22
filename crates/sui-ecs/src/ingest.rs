// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ingest layer — translate Sui gRPC payloads into [`ChangeSet`]s and
//! apply them to a [`World`].
//!
//! The framework intentionally does *not* own the gRPC client. The
//! caller is responsible for opening a [`sui_rpc::Client`], picking a
//! field mask, and driving the stream; we just provide the conversions
//! from the resulting protobuf messages into the typed change shape the
//! `World` consumes, plus an `apply` that wraps each application in a
//! [`MutationBatch`] so per-transaction atomicity holds.
//!
//! Two ingest paths are supported:
//!
//! - **Bootstrap** — a stream of `proto::Object` (from
//!   `Client::list_owned_objects` or any other paginated listing) is
//!   drained with [`apply_object_stream`], inserting each object via the
//!   `Object` component.
//! - **Live updates** — an `ExecutedTransaction` from
//!   `subscription_client().subscribe_checkpoints` is converted via
//!   [`ChangeSet::from_executed_transaction`] and applied with
//!   [`ChangeSet::apply`].
//!
//! Per-transaction is the atomicity boundary the user picked: each
//! `ChangeSet::apply` opens one batch, applies the upserts and removals
//! together, then commits — so a derivation only sees the post-tx state
//! and runs at most once per touched entity per tx.

use std::collections::HashMap;

use futures::Stream;
use futures::StreamExt;
use sui_rpc::proto::TryFromProtoError;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc::proto::sui::rpc::v2::changed_object::OutputObjectState;
use sui_sdk_types::{Address, AddressParseError, Object};

use crate::world::World;

/// Errors produced while translating gRPC payloads into a [`ChangeSet`]
/// or while pulling Objects off a bootstrap stream.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("ExecutedTransaction is missing its effects")]
    MissingEffects,

    #[error("ChangedObject is missing its object_id")]
    MissingChangedObjectId,

    #[error("invalid object id `{raw}`: {source}")]
    InvalidObjectId {
        raw: String,
        #[source]
        source: AddressParseError,
    },

    #[error(
        "ChangedObject {id} has output_state {state:?} but no matching value \
         in ExecutedTransaction.objects — the request needs the \
         `objects.objects.*` fields in its read mask"
    )]
    MissingObjectValue { id: Address, state: OutputObjectState },

    #[error("proto-to-sdk-types conversion failed: {0}")]
    Conversion(#[from] TryFromProtoError),

    #[error(transparent)]
    Grpc(#[from] tonic::Status),
}

/// One transaction's worth of object effects, classified into operations
/// the `World` understands. Construct via
/// [`ChangeSet::from_executed_transaction`] and apply with
/// [`ChangeSet::apply`].
#[derive(Debug, Default)]
pub struct ChangeSet {
    /// Objects whose post-transaction value should be written. Covers
    /// both create and mutate — they're indistinguishable to the World
    /// because both end with "this entity now has these contents".
    pub upserts: Vec<Object>,

    /// Object ids that should no longer have an `Object` component.
    /// Covers explicit deletions and wraps (where the id still exists
    /// but the object is no longer live). v0 does not distinguish the
    /// two; downstream code that needs to can add a `Wrapped` component
    /// driven off whatever signal it cares about.
    pub removals: Vec<Address>,
}

impl ChangeSet {
    /// Build a `ChangeSet` from a single `ExecutedTransaction`.
    ///
    /// The transaction's `effects.changed_objects` is the source of
    /// truth for *what* changed; the new values are pulled from
    /// `objects.objects` (the `ObjectSet`). Both must be populated by
    /// the caller's read mask.
    pub fn from_executed_transaction(
        tx: &proto::ExecutedTransaction,
    ) -> Result<Self, IngestError> {
        let effects = tx.effects.as_ref().ok_or(IngestError::MissingEffects)?;

        // Index post-tx object values by their stringified id so we can
        // pair them with the corresponding ChangedObject entry in a
        // single pass below.
        let mut object_by_id: HashMap<&str, &proto::Object> = HashMap::new();
        if let Some(set) = tx.objects.as_ref() {
            for obj in &set.objects {
                if let Some(id) = obj.object_id.as_deref() {
                    object_by_id.insert(id, obj);
                }
            }
        }

        let mut upserts = Vec::new();
        let mut removals = Vec::new();

        for changed in &effects.changed_objects {
            let id_str = changed
                .object_id
                .as_deref()
                .ok_or(IngestError::MissingChangedObjectId)?;
            let id: Address = id_str
                .parse()
                .map_err(|source| IngestError::InvalidObjectId {
                    raw: id_str.to_owned(),
                    source,
                })?;

            let state = output_state(changed);

            match state {
                OutputObjectState::ObjectWrite | OutputObjectState::PackageWrite => {
                    let proto_obj = object_by_id.get(id_str).ok_or(
                        IngestError::MissingObjectValue { id, state },
                    )?;
                    upserts.push(Object::try_from(*proto_obj)?);
                }
                OutputObjectState::DoesNotExist => {
                    removals.push(id);
                }
                OutputObjectState::AccumulatorWrite | OutputObjectState::Unknown => {
                    // AccumulatorWrite is a Sui execution-layer concept
                    // that doesn't fit the "the object has these
                    // contents now" shape we apply to the World. v0
                    // leaves these alone; downstream code that needs
                    // them can extract via the raw effects.
                }
                // `OutputObjectState` is `#[non_exhaustive]`; treat
                // anything we don't know about as ignored rather than
                // silently misclassified.
                _ => {}
            }
        }

        Ok(Self { upserts, removals })
    }

    /// Apply this ChangeSet to `world` as a single batch — one logical
    /// transaction per Sui transaction. Consumes the ChangeSet so its
    /// owned `Object` values can move directly into storage.
    pub fn apply(self, world: &mut World) {
        let mut batch = world.batch();
        for obj in self.upserts {
            let id = obj.object_id();
            batch.insert::<Object>(id, obj);
        }
        for id in self.removals {
            batch.remove::<Object>(id);
        }
        batch.commit();
    }

    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.removals.is_empty()
    }
}

fn output_state(changed: &proto::ChangedObject) -> OutputObjectState {
    changed
        .output_state
        .and_then(|s| OutputObjectState::try_from(s).ok())
        .unwrap_or(OutputObjectState::Unknown)
}

/// Drain a stream of proto `Object`s (typically the output of
/// `Client::list_owned_objects`) into the world. Inserts every object
/// as a single batch so the post-bootstrap state is consistent in one
/// shot.
///
/// Suitable for the bootstrap path only — the live-update path needs
/// per-transaction batching via [`ChangeSet`].
pub async fn apply_object_stream<S>(world: &mut World, stream: S) -> Result<usize, IngestError>
where
    S: Stream<Item = Result<proto::Object, tonic::Status>>,
{
    let mut stream = std::pin::pin!(stream);
    let mut batch = world.batch();
    let mut count = 0usize;

    while let Some(item) = stream.next().await {
        let proto_obj = item?;
        let obj = Object::try_from(&proto_obj)?;
        let id = obj.object_id();
        batch.insert::<Object>(id, obj);
        count += 1;
    }

    batch.commit();
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::stream;
    use sui_sdk_types::{Digest, Identifier, MoveStruct, ObjectData, Owner, StructTag};

    use crate::base;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    fn make_object(id: Address) -> Object {
        let tag = StructTag::new(
            Address::TWO,
            Identifier::new("test").unwrap(),
            Identifier::new("Thing").unwrap(),
            Vec::new(),
        );
        let ms = MoveStruct::new(tag, true, 1, id.as_bytes().to_vec()).unwrap();
        Object::new(
            ObjectData::Struct(ms),
            Owner::Address(addr(0xAA)),
            Digest::ZERO,
            0,
        )
    }

    #[test]
    fn changeset_apply_inserts_and_removes() {
        let mut world = World::new();
        base::install(&mut world);

        let a = addr(0x11);
        let b = addr(0x12);
        ChangeSet {
            upserts: vec![make_object(a), make_object(b)],
            removals: vec![],
        }
        .apply(&mut world);

        assert!(world.contains::<Object>(a));
        assert!(world.contains::<Object>(b));

        ChangeSet {
            upserts: vec![],
            removals: vec![a],
        }
        .apply(&mut world);

        assert!(!world.contains::<Object>(a));
        assert!(world.contains::<Object>(b));
    }

    #[tokio::test]
    async fn apply_object_stream_bootstraps_from_proto_objects() {
        let mut world = World::new();
        base::install(&mut world);

        let ids = [addr(0x21), addr(0x22), addr(0x23)];
        let proto_objs: Vec<Result<proto::Object, tonic::Status>> = ids
            .iter()
            .map(|id| Ok(proto::Object::from(make_object(*id))))
            .collect();

        let count = apply_object_stream(&mut world, stream::iter(proto_objs))
            .await
            .expect("ingest");
        assert_eq!(count, 3);

        for id in &ids {
            assert!(world.contains::<Object>(*id), "object {id} should be present");
        }
    }

    #[tokio::test]
    async fn apply_object_stream_propagates_gprc_errors() {
        let mut world = World::new();
        base::install(&mut world);

        let items: Vec<Result<proto::Object, tonic::Status>> = vec![
            Ok(proto::Object::from(make_object(addr(0x31)))),
            Err(tonic::Status::aborted("test failure")),
        ];

        let err = apply_object_stream(&mut world, stream::iter(items))
            .await
            .expect_err("should propagate the tonic error");
        assert!(matches!(err, IngestError::Grpc(_)));
    }
}
