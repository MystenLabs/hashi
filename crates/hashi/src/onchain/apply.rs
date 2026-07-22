// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Structural apply of one transaction's changed objects into the
//! mirror.
//!
//! The unit of work is a [`TxView`]: the full post-state of every
//! object a Hashi-touching transaction wrote, plus the ids it deleted.
//! [`apply_transaction`] routes each object by ownership (see
//! [`super::route`]) and updates the matching `types::Hashi` map, so
//! the mirror no longer depends on events — a Move mutation with no
//! `event::emit` still arrives here as an object write.
//!
//! Side effects that used to ride the event path (limiter advance,
//! notifications) are returned as [`Effect`]s derived from state
//! transitions; the caller owns acting on them.

use std::collections::HashMap;

use anyhow::Context;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc::proto::sui::rpc::v2::changed_object::OutputObjectState;
use sui_sdk_types::Address;
use sui_sdk_types::Object;
use sui_sdk_types::Owner;
use sui_sdk_types::TypeTag;

use hashi_types::move_types;
use hashi_types::move_types::is_dof_wrapper;

use super::route::ObjectIndex;
use super::route::RoutingTable;
use super::route::Slot;
use super::route::TrackedKind;
use super::types;

/// One successful transaction's object changes, decoded from the gRPC
/// payload into `sui_sdk_types` values.
#[derive(Debug)]
pub(super) struct TxView {
    pub checkpoint: u64,
    /// Zero-based position within the checkpoint. Together with
    /// `checkpoint` this is the transaction's total order on the chain;
    /// the watcher ratchets over `(checkpoint, transaction_index)` so a
    /// transaction delivered by both replay and the live stream applies
    /// exactly once.
    pub transaction_index: u64,
    /// The transaction's checkpoint timestamp; drives the limiter
    /// advance and the withdrawal duration metrics.
    pub timestamp_ms: u64,
    pub changes: Vec<TxChange>,
}

impl TxView {
    /// The transaction's position in the chain's total order.
    pub(super) fn position(&self) -> (u64, u64) {
        (self.checkpoint, self.transaction_index)
    }
}

#[derive(Debug)]
pub(super) enum TxChange {
    /// A created or mutated object, at its post-transaction state.
    Written(Box<Object>),
    /// The object no longer exists after this transaction (deleted or
    /// wrapped). Ids are never reused on Sui, so removal needs no
    /// version guard: within each ordered source a write for this id
    /// always precedes its deletion, and re-applying an overlap replays
    /// the write and the deletion in order.
    Deleted { id: Address },
}

/// Objects keyed by (id, version), BCS-decoded from a proto
/// `ObjectSet`. The set carries both input and output versions of the
/// same id, so the version is part of the key; each changed object is
/// paired with its output version.
type ObjectPool = HashMap<(Address, u64), Object>;

/// Decode a transaction's proto `ObjectSet` into an [`ObjectPool`].
/// Requires the `bcs` field in the read mask.
fn decode_object_pool(set: Option<&proto::ObjectSet>) -> anyhow::Result<ObjectPool> {
    let mut objects = ObjectPool::new();
    let Some(set) = set else {
        return Ok(objects);
    };
    for obj in &set.objects {
        let Some(bytes) = obj.bcs.as_ref().and_then(|b| b.value.as_ref()) else {
            continue;
        };
        let object: Object =
            bcs::from_bytes(bytes).context("failed to BCS-decode an object from an object set")?;
        objects.insert((object.object_id(), object.version()), object);
    }
    Ok(objects)
}

impl TxView {
    /// Decode a proto `ExecutedTransaction` (as delivered by the
    /// filtered transaction stream) into a `TxView`, sourcing
    /// post-state objects from its per-transaction object set. Returns
    /// `Ok(None)` for transactions that did not execute successfully —
    /// their object changes are gas-only and carry no Hashi state.
    pub(super) fn from_proto(tx: &proto::ExecutedTransaction) -> anyhow::Result<Option<Self>> {
        let mut pool = decode_object_pool(tx.objects.as_ref())?;
        let effects = tx
            .effects
            .as_ref()
            .context("ExecutedTransaction is missing effects")?;
        if !effects
            .status
            .as_ref()
            .context("TransactionEffects is missing status")?
            .success()
        {
            return Ok(None);
        }

        let mut changes = Vec::new();
        for changed in &effects.changed_objects {
            let id: Address = changed
                .object_id
                .as_deref()
                .context("ChangedObject is missing object_id")?
                .parse()
                .context("invalid ChangedObject object_id")?;
            let state = changed
                .output_state
                .and_then(|s| OutputObjectState::try_from(s).ok())
                .unwrap_or(OutputObjectState::Unknown);
            match state {
                OutputObjectState::ObjectWrite | OutputObjectState::PackageWrite => {
                    let version = changed
                        .output_version
                        .context("written ChangedObject is missing output_version")?;
                    let object = pool.remove(&(id, version)).with_context(|| {
                        let mut available: Vec<String> = pool
                            .keys()
                            .map(|(id, version)| format!("{id}@v{version}"))
                            .collect();
                        available.sort();
                        available.truncate(8);
                        format!(
                            "object {id} v{version} not in the object set ({} present: \
                             [{}]) — the read mask needs objects.objects.bcs",
                            pool.len(),
                            available.join(", ")
                        )
                    })?;
                    changes.push(TxChange::Written(Box::new(object)));
                }
                OutputObjectState::DoesNotExist => changes.push(TxChange::Deleted { id }),
                // Accumulator writes and unknown future states don't
                // fit the object-contents shape; ignore them.
                _ => {}
            }
        }

        Ok(Some(Self {
            checkpoint: tx.checkpoint(),
            transaction_index: tx.transaction_index(),
            timestamp_ms: tx
                .timestamp
                .and_then(|t| proto_to_timestamp_ms(t).ok())
                .unwrap_or(0),
            changes,
        }))
    }
}

/// A side effect derived from a state transition during apply. The
/// caller (the watcher) owns notifications, the limiter, and metrics.
#[derive(Debug)]
pub(super) enum Effect {
    /// A member's `MemberInfo` entry was written.
    ValidatorInfoUpdated(Address),
    /// The root's `pending_epoch_change` became set for this epoch.
    ReconfigStarted(u64),
    /// The root's `UpgradeCap` now points at a new package id. The
    /// cap's version counter is not the package version, so the caller
    /// reconciles versions via `list_package_versions`.
    PackageUpgraded { package: Address },
    /// A withdrawal transaction transitioned to fully signed in this
    /// transaction (2-of-2 witness complete). Drives the local limiter
    /// and the pick-to-sign metric.
    WithdrawalTxnFullySigned(Box<types::WithdrawalTransaction>),
    /// A withdrawal transaction left the in-flight bag (confirmed and
    /// moved to the historical record, or deleted).
    WithdrawalTxnRemoved(Box<types::WithdrawalTransaction>),
}

#[derive(Debug, Default)]
pub(super) struct ApplyOutcome {
    pub effects: Vec<Effect>,
    /// Objects owned by a UID we don't recognize, or carrying a type no
    /// handler decodes. Every entry is a potential mirror gap; the
    /// caller surfaces them as the lossless-coverage tripwire.
    pub unrouted: Vec<(Address, String)>,
}

/// Apply one successful transaction's changes to the mirror.
///
/// Order matters within a transaction: the root and `BitcoinState` are
/// applied first (they carry the container UIDs), then DOF wrappers
/// (they extend the routing table), then remaining writes (committee
/// handoffs last, because their certificate references a committee that
/// may be written in the same transaction), then deletions, which route
/// through the object index rather than the routing table so no
/// pre-deletion contents are needed.
pub(super) fn apply_transaction(
    hashi: &mut types::Hashi,
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    tx: &TxView,
) -> ApplyOutcome {
    let mut out = ApplyOutcome::default();

    // Pass 1: the Hashi root and the BitcoinState dynamic field.
    for change in &tx.changes {
        let TxChange::Written(obj) = change else {
            continue;
        };
        if obj.object_id() == routing.hashi_id() {
            apply_root(hashi, routing, index, obj, &mut out);
        } else if obj.object_id() == routing.bitcoin_state_field_id() {
            apply_bitcoin_state(routing, index, obj, &mut out);
        }
    }

    // Pass 2: DOF wrappers, so values created in the same transaction
    // can resolve their container.
    for change in &tx.changes {
        let TxChange::Written(obj) = change else {
            continue;
        };
        let Some(struct_) = obj.as_struct() else {
            continue;
        };
        if is_dof_wrapper(struct_.object_type()) {
            apply_wrapper(routing, index, obj, &mut out);
        }
    }

    // Pass 3: all other writes, in two rounds. Writes that register an
    // interior container go first (a tob entry or per-user request bag
    // is rewritten in the same transaction that touches its children,
    // because the child mutation bumps the embedded container's size),
    // so those children route as known-ignored instead of unrouted.
    // Committee handoffs are deferred past both rounds.
    let mut handoffs: Vec<&Object> = Vec::new();
    let mut deferred: Vec<&Object> = Vec::new();
    for change in &tx.changes {
        let TxChange::Written(obj) = change else {
            continue;
        };
        let id = obj.object_id();
        if id == routing.hashi_id() || id == routing.bitcoin_state_field_id() {
            continue;
        }
        let Some(struct_) = obj.as_struct() else {
            // Package writes: the upgrade effect is derived from the
            // root's UpgradeCap change, not the package object.
            continue;
        };
        if is_dof_wrapper(struct_.object_type()) {
            continue;
        }
        if is_committee_handoff(struct_.object_type()) {
            handoffs.push(obj);
            continue;
        }
        let registers_interior = matches!(obj.owner(), Owner::Object(parent)
        if matches!(
            routing.resolve_owner(parent),
            Some(Slot::Tob | Slot::UserRequests)
        ));
        if registers_interior {
            apply_write(hashi, routing, index, obj, &mut out);
        } else {
            deferred.push(obj);
        }
    }
    for obj in deferred {
        apply_write(hashi, routing, index, obj, &mut out);
    }

    // Pass 4: committee handoffs, after any same-transaction committee.
    for obj in handoffs {
        apply_write(hashi, routing, index, obj, &mut out);
    }

    // Pass 5: deletions, routed by what the mirror knows the id to be.
    for change in &tx.changes {
        let TxChange::Deleted { id } = change else {
            continue;
        };
        let Some(entry) = index.remove(id) else {
            continue;
        };
        retire(hashi, routing, id, &entry.kind, &mut out.effects);
    }

    out
}

/// True when the struct tag is a `Field<CommitteeHandoffKey, CommitteeHandoff>`.
fn is_committee_handoff(tag: &sui_sdk_types::StructTag) -> bool {
    move_types::is_field_with_value(tag, "committee_set", "CommitteeHandoff")
}

fn apply_root(
    hashi: &mut types::Hashi,
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    obj: &Object,
    out: &mut ApplyOutcome,
) {
    let id = obj.object_id();
    if index.is_stale_write(&id, obj.version()) {
        return;
    }
    let Some(struct_) = obj.as_struct() else {
        return;
    };
    let root: move_types::Hashi = match bcs::from_bytes(struct_.contents()) {
        Ok(root) => root,
        Err(e) => {
            tracing::error!("failed to decode the Hashi root object: {e}");
            return;
        }
    };
    routing.set_root_containers(&root);

    let move_types::Hashi {
        id: _,
        committees,
        config,
        versioning,
        treasury: _,
        proposals: _,
        tob: _,
        num_consumed_presigs,
    } = root;

    let new_config = super::convert_move_config(config, versioning);
    if let (Some(old), Some(new)) = (&hashi.config.upgrade_cap, &new_config.upgrade_cap)
        && old.package != new.package
    {
        out.effects.push(Effect::PackageUpgraded {
            package: new.package,
        });
    }
    // The cap always points at the latest package version; keep the
    // hashi-package set (the mirror-gap tripwire's scope) current.
    if let Some(cap) = &new_config.upgrade_cap {
        routing.register_package(cap.package);
    }
    hashi.config = new_config;
    hashi.num_consumed_presigs = num_consumed_presigs;

    let new_pending = committees.pending_epoch_change.as_ref().map(|p| p.epoch);
    if let Some(epoch) = new_pending
        && hashi.committees.pending_epoch_change() != new_pending
    {
        out.effects.push(Effect::ReconfigStarted(epoch));
    }
    hashi
        .committees
        .set_epoch(committees.epoch)
        .set_pending_epoch_change(new_pending)
        .set_mpc_public_key(committees.mpc_public_key);

    index.record(id, obj.version(), TrackedKind::HashiRoot);
}

fn apply_bitcoin_state(
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    obj: &Object,
    _out: &mut ApplyOutcome,
) {
    let id = obj.object_id();
    if index.is_stale_write(&id, obj.version()) {
        return;
    }
    let Some(struct_) = obj.as_struct() else {
        return;
    };
    let field: move_types::Field<move_types::BitcoinStateKey, move_types::BitcoinState> =
        match bcs::from_bytes(struct_.contents()) {
            Ok(field) => field,
            Err(e) => {
                tracing::error!("failed to decode the BitcoinState dynamic field: {e}");
                return;
            }
        };
    routing.set_bitcoin_state_containers(&field.value);
    index.record(id, obj.version(), TrackedKind::BitcoinStateField);
}

fn apply_wrapper(
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    obj: &Object,
    out: &mut ApplyOutcome,
) {
    let id = obj.object_id();
    let Owner::Object(container) = obj.owner() else {
        out.unrouted
            .push((id, "DOF wrapper not object-owned".into()));
        return;
    };
    // Our container set is closed and known a priori (root and
    // BitcoinState inner UIDs), so a wrapper under an unknown container
    // belongs to some foreign object a root-touching transaction also
    // mutated. Don't register or track it.
    if routing.slot_of_container(container).is_none() {
        tracing::debug!(wrapper = %id, container = %container,
            "ignoring a DOF wrapper under a foreign container");
        return;
    }
    // Registration is idempotent, so it runs even for stale replayed
    // writes — the mapping must exist for value routing regardless.
    routing.register_wrapper(id, *container);
    if index.is_stale_write(&id, obj.version()) {
        return;
    }
    index.record(
        id,
        obj.version(),
        TrackedKind::DofWrapper {
            container: *container,
        },
    );
}

fn apply_write(
    hashi: &mut types::Hashi,
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    obj: &Object,
    out: &mut ApplyOutcome,
) {
    let id = obj.object_id();
    let Some(struct_) = obj.as_struct() else {
        return;
    };
    let slot = match obj.owner() {
        // Address-owned objects (gas coins, user funds) are not part
        // of the mirrored state.
        Owner::Address(_) => return,
        // Immutable objects (packages) carry no mirrored state either.
        Owner::Immutable => return,
        Owner::Object(parent) => match routing.resolve_owner(parent) {
            Some(slot) => Some(slot),
            // A value whose wrapper isn't in this transaction and isn't
            // registered: fall back to what the mirror already knows
            // the id to be.
            None => index.get(&id).and_then(|e| slot_for_kind(&e.kind)),
        },
        // The only hashi shared object is the root, handled in pass 1;
        // other shared objects a root-touching transaction mutates
        // (e.g. the system CoinRegistry) are foreign state.
        _ => {
            tracing::debug!(object = %id, "ignoring a foreign shared object");
            return;
        }
    };
    let Some(slot) = slot else {
        // An unroutable object is a mirror gap only when it carries a
        // hashi-package type; foreign objects under foreign owners are
        // expected companions of root-touching transactions.
        if routing.is_hashi_package(struct_.object_type().address()) {
            out.unrouted.push((id, struct_.object_type().to_string()));
        } else {
            tracing::debug!(object = %id, r#type = %struct_.object_type(),
                "ignoring a foreign object-owned write");
        }
        return;
    };

    if index.is_stale_write(&id, obj.version()) {
        return;
    }

    let tag = struct_.object_type();
    let contents = struct_.contents();
    let new_kind = match slot {
        Slot::Members => decode::<move_types::Field<Address, move_types::MemberInfo>>(
            contents, &id,
        )
        .map(|field| {
            let info = super::convert_move_member_info(field.value);
            let validator = info.validator_address;
            hashi.committees.update_validator(info);
            out.effects.push(Effect::ValidatorInfoUpdated(validator));
            TrackedKind::Member(validator)
        }),
        Slot::Committees => {
            // The committees bag is heterogeneous: per-epoch committees
            // and committee handoffs, distinguished by value type.
            if is_committee_handoff(tag) {
                decode::<
                    move_types::Field<
                        move_types::CommitteeHandoffKey,
                        move_types::CommitteeHandoff,
                    >,
                >(contents, &id)
                .and_then(|field| {
                    let from_epoch = field.name.epoch;
                    apply_committee_handoff(hashi, from_epoch, field.value)
                        .then_some(TrackedKind::CommitteeHandoff(from_epoch))
                })
            } else if move_types::is_field_with_value(tag, "committee", "Committee") {
                decode::<move_types::Field<u64, move_types::Committee>>(contents, &id).map(
                    |field| {
                        let epoch = field.name;
                        hashi
                            .committees
                            .committees_mut()
                            .insert(epoch, super::convert_move_committee(field.value));
                        TrackedKind::Committee(epoch)
                    },
                )
            } else {
                None
            }
        }
        Slot::UtxoRecords => decode::<move_types::Field<types::UtxoId, move_types::UtxoRecord>>(
            contents, &id,
        )
        .map(|field| {
            let utxo_id = field.value.utxo.id;
            hashi.utxo_pool.utxo_records.insert(utxo_id, field.value);
            TrackedKind::UtxoRecord(utxo_id)
        }),
        Slot::SpentUtxos => {
            decode::<move_types::Field<types::UtxoId, u64>>(contents, &id).map(|field| {
                hashi.utxo_pool.spent_utxos.insert(field.name, field.value);
                TrackedKind::SpentUtxo(field.name)
            })
        }
        Slot::DepositRequests => {
            decode::<move_types::DepositRequest>(contents, &id).map(|request| {
                let request_id = request.id;
                hashi.deposit_queue.requests.insert(request_id, request);
                TrackedKind::DepositRequest(request_id)
            })
        }
        Slot::WithdrawalRequests => {
            decode::<move_types::WithdrawalRequest>(contents, &id).map(|request| {
                let request_id = request.id;
                hashi.withdrawal_queue.requests.insert(request_id, request);
                TrackedKind::WithdrawalRequest(request_id)
            })
        }
        Slot::WithdrawalTxns => {
            decode::<move_types::WithdrawalTransaction>(contents, &id).map(|txn| {
                let txn_id = txn.id;
                let was_fully_signed = hashi
                    .withdrawal_queue
                    .withdrawal_txns
                    .get(&txn_id)
                    .is_some_and(|t| t.is_fully_signed());
                if !was_fully_signed && txn.is_fully_signed() {
                    out.effects
                        .push(Effect::WithdrawalTxnFullySigned(Box::new(txn.clone())));
                }
                hashi.withdrawal_queue.withdrawal_txns.insert(txn_id, txn);
                TrackedKind::WithdrawalTxn(txn_id)
            })
        }
        Slot::Treasury => {
            let type_tag = TypeTag::Struct(Box::new(tag.clone()));
            if let Some(cap) = types::TreasuryCap::try_from_contents(&type_tag, contents) {
                let coin_type = cap.coin_type.clone();
                hashi.treasury.treasury_caps.insert(coin_type.clone(), cap);
                Some(TrackedKind::TreasuryCap(coin_type))
            } else if let Some(cap) = types::MetadataCap::try_from_contents(&type_tag, contents) {
                let coin_type = cap.coin_type.clone();
                hashi.treasury.metadata_caps.insert(coin_type.clone(), cap);
                Some(TrackedKind::MetadataCap(coin_type))
            } else {
                None
            }
        }
        Slot::ProposalsActive | Slot::ProposalsExecuted => {
            let type_tag = TypeTag::Struct(Box::new(tag.clone()));
            super::decode_proposal(&type_tag, contents).map(|proposal| {
                let executed = slot == Slot::ProposalsExecuted;
                let proposal_id = proposal.id;
                let bucket = if executed {
                    &mut hashi.proposals.executed
                } else {
                    &mut hashi.proposals.active
                };
                bucket.insert(proposal_id, proposal);
                TrackedKind::Proposal {
                    executed,
                    id: proposal_id,
                }
            })
        }
        Slot::Tob => {
            // Not mirrored, but the entry's LinkedTable UID owns dealer
            // submission nodes; register it so they route as ignored.
            decode::<move_types::Field<super::TobKey, move_types::EpochCertsV1>>(contents, &id).map(
                |field| {
                    routing.register_interior(field.value.certs.id, Slot::TobCerts);
                    TrackedKind::Ignored
                },
            )
        }
        Slot::UserRequests => {
            // Same shape: each per-user value is a Bag with its own UID.
            decode::<move_types::Field<Address, move_types::Bag>>(contents, &id).map(|field| {
                routing.register_interior(field.value.id, Slot::UserRequestBag);
                TrackedKind::Ignored
            })
        }
        Slot::DepositProcessed
        | Slot::WithdrawalProcessed
        | Slot::ConfirmedTxns
        | Slot::TobCerts
        | Slot::UserRequestBag => Some(TrackedKind::Ignored),
    };

    let Some(new_kind) = new_kind else {
        out.unrouted.push((id, struct_.object_type().to_string()));
        return;
    };

    // A write whose meaning changed is a move between containers (e.g.
    // a proposal executing, a withdrawal txn confirming): retire the
    // old mirror entry before the new one takes over.
    if let Some(old) = index.get(&id)
        && old.kind != new_kind
    {
        let old_kind = old.kind.clone();
        retire(hashi, routing, &id, &old_kind, &mut out.effects);
    }

    index.record(id, obj.version(), new_kind);
}

/// Insert a committee handoff, converting through the raw Move
/// committee its certificate signs. Returns false when the referenced
/// committee is unknown (the mirror can't validate the cert shape).
fn apply_committee_handoff(
    hashi: &mut types::Hashi,
    from_epoch: u64,
    handoff: move_types::CommitteeHandoff,
) -> bool {
    let Some(next_committee) = hashi.committees.committees().get(&handoff.next_epoch) else {
        tracing::error!(
            from_epoch,
            next_epoch = handoff.next_epoch,
            "committee handoff references a committee the mirror doesn't hold"
        );
        return false;
    };
    let raw = move_types::Committee::from(next_committee);
    match super::convert_move_committee_handoff(handoff, raw) {
        Ok(signed) => {
            hashi
                .committees
                .committee_handoffs_mut()
                .insert(from_epoch, signed);
            true
        }
        Err(e) => {
            tracing::error!(from_epoch, "invalid committee handoff: {e}");
            false
        }
    }
}

/// Remove whatever the mirror holds for a retired object id. Used both
/// for deletions and for cross-container moves.
fn retire(
    hashi: &mut types::Hashi,
    routing: &mut RoutingTable,
    id: &Address,
    kind: &TrackedKind,
    effects: &mut Vec<Effect>,
) {
    match kind {
        TrackedKind::HashiRoot | TrackedKind::BitcoinStateField => {
            tracing::error!(?kind, "refusing to retire a root object");
        }
        TrackedKind::DofWrapper { .. } => {
            routing.remove_wrapper(id);
        }
        TrackedKind::Member(validator) => {
            hashi.committees.remove_validator(validator);
        }
        TrackedKind::Committee(epoch) => {
            hashi.committees.committees_mut().remove(epoch);
        }
        TrackedKind::CommitteeHandoff(epoch) => {
            hashi.committees.committee_handoffs_mut().remove(epoch);
        }
        TrackedKind::UtxoRecord(utxo_id) => {
            hashi.utxo_pool.utxo_records.remove(utxo_id);
        }
        TrackedKind::SpentUtxo(utxo_id) => {
            hashi.utxo_pool.spent_utxos.remove(utxo_id);
        }
        TrackedKind::DepositRequest(id) => {
            hashi.deposit_queue.requests.remove(id);
        }
        TrackedKind::WithdrawalRequest(id) => {
            hashi.withdrawal_queue.requests.remove(id);
        }
        TrackedKind::WithdrawalTxn(id) => {
            if let Some(txn) = hashi.withdrawal_queue.withdrawal_txns.remove(id) {
                effects.push(Effect::WithdrawalTxnRemoved(Box::new(txn)));
            }
        }
        TrackedKind::TreasuryCap(coin_type) => {
            hashi.treasury.treasury_caps.remove(coin_type);
        }
        TrackedKind::MetadataCap(coin_type) => {
            hashi.treasury.metadata_caps.remove(coin_type);
        }
        TrackedKind::Proposal { executed, id } => {
            let bucket = if *executed {
                &mut hashi.proposals.executed
            } else {
                &mut hashi.proposals.active
            };
            bucket.remove(id);
        }
        TrackedKind::Ignored => {}
    }
}

/// Slot equivalent of an already-tracked kind, used to route value-only
/// mutations whose wrapper is neither in the transaction nor registered.
fn slot_for_kind(kind: &TrackedKind) -> Option<Slot> {
    match kind {
        TrackedKind::HashiRoot
        | TrackedKind::BitcoinStateField
        | TrackedKind::DofWrapper { .. } => None,
        TrackedKind::Member(_) => Some(Slot::Members),
        TrackedKind::Committee(_) | TrackedKind::CommitteeHandoff(_) => Some(Slot::Committees),
        TrackedKind::UtxoRecord(_) => Some(Slot::UtxoRecords),
        TrackedKind::SpentUtxo(_) => Some(Slot::SpentUtxos),
        TrackedKind::DepositRequest(_) => Some(Slot::DepositRequests),
        TrackedKind::WithdrawalRequest(_) => Some(Slot::WithdrawalRequests),
        TrackedKind::WithdrawalTxn(_) => Some(Slot::WithdrawalTxns),
        TrackedKind::TreasuryCap(_) | TrackedKind::MetadataCap(_) => Some(Slot::Treasury),
        TrackedKind::Proposal { executed, .. } => Some(if *executed {
            Slot::ProposalsExecuted
        } else {
            Slot::ProposalsActive
        }),
        TrackedKind::Ignored => None,
    }
}

/// Decode a routed object's contents. On failure, log and return
/// `None`; the caller records the object as unrouted (the tripwire).
fn decode<T: serde::de::DeserializeOwned>(contents: &[u8], id: &Address) -> Option<T> {
    match bcs::from_bytes(contents) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::error!("failed to BCS-decode routed object {id}: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use hashi_types::bitcoin_txid::BitcoinTxid;
    use sui_sdk_types::Digest;
    use sui_sdk_types::Identifier;
    use sui_sdk_types::MoveStruct;
    use sui_sdk_types::ObjectData;
    use sui_sdk_types::StructTag;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32]).unwrap()
    }

    const PACKAGE: u8 = 0xAA;

    fn hashi_id() -> Address {
        addr(0x01)
    }
    fn bs_field_id() -> Address {
        addr(0x02)
    }
    fn members_id() -> Address {
        addr(0x11)
    }
    fn committees_id() -> Address {
        addr(0x12)
    }
    fn treasury_id() -> Address {
        addr(0x13)
    }
    fn active_id() -> Address {
        addr(0x14)
    }
    fn executed_id() -> Address {
        addr(0x15)
    }
    fn tob_id() -> Address {
        addr(0x16)
    }
    fn dep_requests_id() -> Address {
        addr(0x21)
    }
    fn dep_processed_id() -> Address {
        addr(0x22)
    }
    fn wdr_requests_id() -> Address {
        addr(0x23)
    }
    fn wdr_processed_id() -> Address {
        addr(0x24)
    }
    fn withdrawal_txns_id() -> Address {
        addr(0x25)
    }
    fn confirmed_txns_id() -> Address {
        addr(0x26)
    }
    fn utxo_records_id() -> Address {
        addr(0x27)
    }
    fn spent_utxos_id() -> Address {
        addr(0x28)
    }
    fn user_requests_id() -> Address {
        addr(0x29)
    }

    fn tag(package: Address, module: &str, name: &str, params: Vec<TypeTag>) -> StructTag {
        StructTag::new(
            package,
            Identifier::new(module).unwrap(),
            Identifier::new(name).unwrap(),
            params,
        )
    }

    fn field_tag(name_type: TypeTag, value_type: TypeTag) -> StructTag {
        tag(
            Address::TWO,
            "dynamic_field",
            "Field",
            vec![name_type, value_type],
        )
    }

    fn hashi_struct(module: &str, name: &str, params: Vec<TypeTag>) -> TypeTag {
        TypeTag::Struct(Box::new(tag(addr(PACKAGE), module, name, params)))
    }

    fn wrapper_tag() -> StructTag {
        let wrapper_name = TypeTag::Struct(Box::new(tag(
            Address::TWO,
            "dynamic_object_field",
            "Wrapper",
            vec![TypeTag::Address],
        )));
        field_tag(wrapper_name, TypeTag::Address)
    }

    fn obj(tag: StructTag, version: u64, owner: Owner, contents: Vec<u8>) -> Object {
        let move_struct = MoveStruct::new(tag, true, version, contents).unwrap();
        Object::new(ObjectData::Struct(move_struct), owner, Digest::ZERO, 0)
    }

    fn tx(changes: Vec<TxChange>) -> TxView {
        TxView {
            checkpoint: 1,
            transaction_index: 0,
            timestamp_ms: 1_000,
            changes,
        }
    }

    fn written(object: Object) -> TxChange {
        TxChange::Written(Box::new(object))
    }

    /// Mirror state plus routing/index, pre-seeded with the container
    /// UIDs the way a bootstrap scrape would.
    struct Fixture {
        hashi: types::Hashi,
        routing: RoutingTable,
        index: ObjectIndex,
    }

    impl Fixture {
        fn new() -> Self {
            let mut routing = RoutingTable::new(hashi_id(), bs_field_id());
            routing.set_root_containers(&move_root(0, None, None));
            routing.set_bitcoin_state_containers(&move_bitcoin_state());
            routing.register_package(addr(PACKAGE));

            let hashi = types::Hashi {
                id: hashi_id(),
                committees: types::CommitteeSet::new(members_id(), committees_id()),
                config: types::Config {
                    config: BTreeMap::new(),
                    enabled_versions: BTreeSet::new(),
                    upgrade_cap: None,
                },
                treasury: types::Treasury {
                    id: treasury_id(),
                    treasury_caps: BTreeMap::new(),
                    metadata_caps: BTreeMap::new(),
                },
                deposit_queue: types::DepositRequestQueue {
                    id: dep_requests_id(),
                    requests: BTreeMap::new(),
                    processed_id: dep_processed_id(),
                },
                withdrawal_queue: types::WithdrawalRequestQueue {
                    requests_id: wdr_requests_id(),
                    requests: BTreeMap::new(),
                    processed_id: wdr_processed_id(),
                    withdrawal_txns_id: withdrawal_txns_id(),
                    withdrawal_txns: BTreeMap::new(),
                    confirmed_txns_id: confirmed_txns_id(),
                },
                utxo_pool: types::UtxoPool {
                    utxo_records_id: utxo_records_id(),
                    utxo_records: BTreeMap::new(),
                    spent_utxos_id: spent_utxos_id(),
                    spent_utxos: BTreeMap::new(),
                },
                proposals: types::Proposals {
                    active_id: active_id(),
                    executed_id: executed_id(),
                    active: BTreeMap::new(),
                    executed: BTreeMap::new(),
                },
                tob_id: tob_id(),
                num_consumed_presigs: 0,
            };

            Self {
                hashi,
                routing,
                index: ObjectIndex::new(),
            }
        }

        fn apply(&mut self, tx: &TxView) -> ApplyOutcome {
            apply_transaction(&mut self.hashi, &mut self.routing, &mut self.index, tx)
        }
    }

    fn bag(id: Address) -> move_types::Bag {
        move_types::Bag { id, size: 0 }
    }

    fn move_root(
        num_consumed_presigs: u64,
        pending_epoch: Option<u64>,
        upgrade_cap_package: Option<Address>,
    ) -> move_types::Hashi {
        // Round-trip through the BCS encoder twin because several of
        // the nested structs only derive Deserialize.
        bcs::from_bytes(&root_bytes(
            num_consumed_presigs,
            pending_epoch,
            upgrade_cap_package,
        ))
        .unwrap()
    }

    fn move_bitcoin_state() -> move_types::BitcoinState {
        move_types::BitcoinState {
            id: addr(0x03),
            deposit_queue: move_types::DepositRequestQueue {
                requests: bag(dep_requests_id()),
                processed: bag(dep_processed_id()),
            },
            withdrawal_queue: move_types::WithdrawalRequestQueue {
                requests: bag(wdr_requests_id()),
                processed: bag(wdr_processed_id()),
                withdrawal_txns: bag(withdrawal_txns_id()),
                confirmed_txns: bag(confirmed_txns_id()),
            },
            utxo_pool: move_types::UtxoPool {
                utxo_records: bag(utxo_records_id()),
                spent_utxos: bag(spent_utxos_id()),
            },
            user_requests: move_types::Table {
                id: user_requests_id(),
                size: 0,
            },
        }
    }

    // ---- BCS encoder twins for Deserialize-only move types ----------

    #[derive(serde_derive::Serialize)]
    struct FieldEnc<N: serde::Serialize, V: serde::Serialize> {
        id: Address,
        name: N,
        value: V,
    }

    #[derive(serde_derive::Serialize)]
    struct BagEnc {
        id: Address,
        size: u64,
    }

    impl BagEnc {
        fn new(id: Address) -> Self {
            Self { id, size: 0 }
        }
    }

    #[derive(serde_derive::Serialize)]
    struct CommitteeSetEnc {
        members: BagEnc,
        epoch: u64,
        committees: BagEnc,
        pending_epoch_change: Option<PendingEnc>,
        mpc_public_key: Vec<u8>,
    }

    #[derive(serde_derive::Serialize)]
    struct PendingEnc {
        epoch: u64,
        committee_handoff_cert: Option<move_types::CommitteeSignature>,
    }

    #[derive(serde_derive::Serialize)]
    struct VersioningEnc {
        enabled_versions: VecSetEnc,
        upgrade_cap: Option<UpgradeCapEnc>,
    }

    #[derive(serde_derive::Serialize)]
    struct VecSetEnc {
        contents: Vec<u64>,
    }

    #[derive(serde_derive::Serialize)]
    struct UpgradeCapEnc {
        id: Address,
        package: Address,
        version: u64,
        policy: u8,
    }

    #[derive(serde_derive::Serialize)]
    struct HashiEnc {
        id: Address,
        committees: CommitteeSetEnc,
        config: move_types::Config,
        versioning: VersioningEnc,
        treasury: TreasuryEnc,
        proposals: ProposalsEnc,
        tob: BagEnc,
        num_consumed_presigs: u64,
    }

    #[derive(serde_derive::Serialize)]
    struct TreasuryEnc {
        objects: BagEnc,
    }

    #[derive(serde_derive::Serialize)]
    struct ProposalsEnc {
        active: BagEnc,
        executed: BagEnc,
    }

    #[derive(serde_derive::Serialize)]
    struct MemberInfoEnc {
        validator_address: Address,
        operator_address: Address,
        next_epoch_public_key: Vec<u8>,
        endpoint_url: String,
        tls_public_key: Vec<u8>,
        next_epoch_encryption_public_key: Vec<u8>,
        extra_fields: move_types::Config,
    }

    #[derive(serde_derive::Serialize)]
    struct UtxoRecordEnc {
        utxo: move_types::Utxo,
        produced_by: Option<Address>,
        spent_by: Option<Address>,
        spent_epoch: Option<u64>,
    }

    fn root_bytes(
        num_consumed_presigs: u64,
        pending_epoch: Option<u64>,
        upgrade_cap_package: Option<Address>,
    ) -> Vec<u8> {
        bcs::to_bytes(&HashiEnc {
            id: hashi_id(),
            committees: CommitteeSetEnc {
                members: BagEnc::new(members_id()),
                epoch: 7,
                committees: BagEnc::new(committees_id()),
                pending_epoch_change: pending_epoch.map(|epoch| PendingEnc {
                    epoch,
                    committee_handoff_cert: None,
                }),
                mpc_public_key: vec![9u8; 4],
            },
            config: move_types::Config::from_entries(vec![]),
            versioning: VersioningEnc {
                enabled_versions: VecSetEnc { contents: vec![1] },
                upgrade_cap: upgrade_cap_package.map(|package| UpgradeCapEnc {
                    id: addr(0x40),
                    package,
                    version: 1,
                    policy: 0,
                }),
            },
            treasury: TreasuryEnc {
                objects: BagEnc::new(treasury_id()),
            },
            proposals: ProposalsEnc {
                active: BagEnc::new(active_id()),
                executed: BagEnc::new(executed_id()),
            },
            tob: BagEnc::new(tob_id()),
            num_consumed_presigs,
        })
        .unwrap()
    }

    fn utxo(byte: u8, vout: u32, amount: u64) -> move_types::Utxo {
        move_types::Utxo {
            id: move_types::UtxoId {
                txid: BitcoinTxid::from(addr(byte)),
                vout,
            },
            amount,
            derivation_path: None,
        }
    }

    fn utxo_field_object(field_id: Address, version: u64, amount: u64) -> Object {
        let record_utxo = utxo(0x77, 0, amount);
        let contents = bcs::to_bytes(&FieldEnc {
            id: field_id,
            name: record_utxo.id,
            value: UtxoRecordEnc {
                utxo: record_utxo,
                produced_by: None,
                spent_by: None,
                spent_epoch: None,
            },
        })
        .unwrap();
        obj(
            field_tag(
                hashi_struct("utxo", "UtxoId", vec![]),
                hashi_struct("utxo_pool", "UtxoRecord", vec![]),
            ),
            version,
            Owner::Object(utxo_records_id()),
            contents,
        )
    }

    fn withdrawal_txn(value_id: Address, fully_signed: bool) -> move_types::WithdrawalTransaction {
        move_types::WithdrawalTransaction {
            id: value_id,
            txid: BitcoinTxid::from(addr(0x66)),
            request_ids: vec![],
            inputs: vec![utxo(0x77, 0, 1_000)],
            withdrawal_outputs: vec![],
            change_outputs: vec![],
            created_timestamp_ms: 5,
            signed_timestamp_ms: fully_signed.then_some(6),
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: move_types::SigningBatch {
                signatures: vec![if fully_signed {
                    move_types::MpcSig::Signed(vec![1, 2, 3])
                } else {
                    move_types::MpcSig::Pending(0)
                }],
                epoch: 7,
            },
            guardian_signatures: fully_signed.then(|| vec![vec![4, 5, 6]]),
        }
    }

    fn withdrawal_txn_object(
        value: &move_types::WithdrawalTransaction,
        version: u64,
        owner: Address,
    ) -> Object {
        obj(
            tag(
                addr(PACKAGE),
                "withdrawal_queue",
                "WithdrawalTransaction",
                vec![],
            ),
            version,
            Owner::Object(owner),
            bcs::to_bytes(value).unwrap(),
        )
    }

    fn wrapper_object(
        wrapper_id: Address,
        value_id: Address,
        version: u64,
        container: Address,
    ) -> Object {
        let contents = bcs::to_bytes(&FieldEnc {
            id: wrapper_id,
            name: value_id,
            value: value_id,
        })
        .unwrap();
        obj(wrapper_tag(), version, Owner::Object(container), contents)
    }

    // ---- tests ------------------------------------------------------

    #[test]
    fn utxo_record_write_then_eventless_cleanup_delete() {
        let mut fixture = Fixture::new();
        let field_id = addr(0x50);

        let out = fixture.apply(&tx(vec![written(utxo_field_object(field_id, 1, 1_000))]));
        assert!(out.unrouted.is_empty());
        assert_eq!(fixture.hashi.utxo_pool.utxo_records.len(), 1);

        // The cleanup transaction deletes the Field object with no
        // event; the mirror must still drop the record.
        let out = fixture.apply(&tx(vec![TxChange::Deleted { id: field_id }]));
        assert!(out.unrouted.is_empty());
        assert!(fixture.hashi.utxo_pool.utxo_records.is_empty());
        assert!(fixture.index.get(&field_id).is_none());
    }

    #[test]
    fn stale_and_duplicate_writes_are_skipped() {
        let mut fixture = Fixture::new();
        let field_id = addr(0x50);

        fixture.apply(&tx(vec![written(utxo_field_object(field_id, 2, 2_000))]));
        // An older version replayed out of order must not clobber.
        fixture.apply(&tx(vec![written(utxo_field_object(field_id, 1, 1_000))]));
        // A duplicate of the current version is a no-op.
        fixture.apply(&tx(vec![written(utxo_field_object(field_id, 2, 2_000))]));

        let record = fixture
            .hashi
            .utxo_pool
            .utxo_records
            .values()
            .next()
            .unwrap();
        assert_eq!(record.utxo.amount, 2_000);
    }

    #[test]
    fn withdrawal_txn_lifecycle_signing_and_confirmation() {
        let mut fixture = Fixture::new();
        let wrapper1 = addr(0x51);
        let value_id = addr(0x52);

        // Committed: wrapper and value created together.
        let unsigned = withdrawal_txn(value_id, false);
        let out = fixture.apply(&tx(vec![
            written(wrapper_object(wrapper1, value_id, 1, withdrawal_txns_id())),
            written(withdrawal_txn_object(&unsigned, 1, wrapper1)),
        ]));
        assert!(out.unrouted.is_empty());
        assert!(out.effects.is_empty());
        assert_eq!(fixture.hashi.withdrawal_queue.withdrawal_txns.len(), 1);

        // Finalized: value-only mutation (the wrapper is not part of
        // the transaction) flips it to fully signed exactly once.
        let signed = withdrawal_txn(value_id, true);
        let out = fixture.apply(&tx(vec![written(withdrawal_txn_object(
            &signed, 2, wrapper1,
        ))]));
        assert!(
            matches!(out.effects.as_slice(), [Effect::WithdrawalTxnFullySigned(txn)] if txn.id == value_id)
        );

        // Replay of the same frame: no duplicate effect.
        let out = fixture.apply(&tx(vec![written(withdrawal_txn_object(
            &signed, 2, wrapper1,
        ))]));
        assert!(out.effects.is_empty());

        // Confirmed: the value moves to the confirmed_txns bag (new
        // wrapper, old wrapper deleted).
        let wrapper2 = addr(0x53);
        let out = fixture.apply(&tx(vec![
            written(wrapper_object(wrapper2, value_id, 3, confirmed_txns_id())),
            written(withdrawal_txn_object(&signed, 3, wrapper2)),
            TxChange::Deleted { id: wrapper1 },
        ]));
        assert!(
            matches!(out.effects.as_slice(), [Effect::WithdrawalTxnRemoved(txn)] if txn.id == value_id)
        );
        assert!(fixture.hashi.withdrawal_queue.withdrawal_txns.is_empty());
    }

    #[test]
    fn member_write_updates_validator_and_delete_removes_it() {
        let mut fixture = Fixture::new();
        let field_id = addr(0x54);
        let validator = addr(0x55);

        // The G1 identity element, as the Move contract stores it for a
        // not-yet-registered key.
        let mut identity_g1 = vec![0u8; 96];
        identity_g1[0] = 0x40;

        let contents = bcs::to_bytes(&FieldEnc {
            id: field_id,
            name: validator,
            value: MemberInfoEnc {
                validator_address: validator,
                operator_address: addr(0x56),
                next_epoch_public_key: identity_g1,
                endpoint_url: "https://validator.example.com".to_owned(),
                tls_public_key: vec![7u8; 32],
                next_epoch_encryption_public_key: vec![0u8; 32],
                extra_fields: move_types::Config::from_entries(vec![]),
            },
        })
        .unwrap();
        let object = obj(
            field_tag(
                TypeTag::Address,
                hashi_struct("committee_set", "MemberInfo", vec![]),
            ),
            1,
            Owner::Object(members_id()),
            contents,
        );

        let out = fixture.apply(&tx(vec![written(object)]));
        assert!(out.unrouted.is_empty());
        assert!(
            matches!(out.effects.as_slice(), [Effect::ValidatorInfoUpdated(v)] if *v == validator)
        );
        assert!(fixture.hashi.committees.members().contains_key(&validator));

        let out = fixture.apply(&tx(vec![TxChange::Deleted { id: field_id }]));
        assert!(out.effects.is_empty());
        assert!(!fixture.hashi.committees.members().contains_key(&validator));
    }

    #[test]
    fn root_write_updates_scalars_and_emits_transition_effects() {
        let mut fixture = Fixture::new();
        let root_tag = tag(addr(PACKAGE), "hashi", "Hashi", vec![]);
        let pkg_a = addr(0x60);
        let pkg_b = addr(0x61);

        let out = fixture.apply(&tx(vec![written(obj(
            root_tag.clone(),
            1,
            Owner::Shared(1),
            root_bytes(5, None, Some(pkg_a)),
        ))]));
        assert!(out.effects.is_empty());
        assert_eq!(fixture.hashi.num_consumed_presigs, 5);
        assert_eq!(fixture.hashi.committees.epoch(), 7);
        assert_eq!(fixture.hashi.committees.pending_epoch_change(), None);

        // Pending epoch change appears: exactly one ReconfigStarted.
        let out = fixture.apply(&tx(vec![written(obj(
            root_tag.clone(),
            2,
            Owner::Shared(1),
            root_bytes(6, Some(8), Some(pkg_a)),
        ))]));
        assert!(matches!(
            out.effects.as_slice(),
            [Effect::ReconfigStarted(8)]
        ));
        assert_eq!(fixture.hashi.committees.pending_epoch_change(), Some(8));

        // Same pending value again: no repeat notification.
        let out = fixture.apply(&tx(vec![written(obj(
            root_tag.clone(),
            3,
            Owner::Shared(1),
            root_bytes(6, Some(8), Some(pkg_a)),
        ))]));
        assert!(out.effects.is_empty());

        // The upgrade cap now points at a new package.
        let out = fixture.apply(&tx(vec![written(obj(
            root_tag,
            4,
            Owner::Shared(1),
            root_bytes(6, Some(8), Some(pkg_b)),
        ))]));
        assert!(
            matches!(out.effects.as_slice(), [Effect::PackageUpgraded { package }] if *package == pkg_b)
        );
    }

    #[test]
    fn proposal_moves_from_active_to_executed() {
        let mut fixture = Fixture::new();
        let wrapper1 = addr(0x62);
        let wrapper2 = addr(0x63);
        let proposal_id = addr(0x64);

        let proposal = move_types::Proposal {
            id: proposal_id,
            creator: addr(0x65),
            votes: vec![],
            quorum_threshold_bps: 5_000,
            created_timestamp_ms: 42,
            executed_timestamp_ms: None,
            metadata: move_types::VecMap { contents: vec![] },
            data: move_types::UpdateConfig {
                entries: move_types::VecMap { contents: vec![] },
            },
        };
        let proposal_tag = tag(
            addr(PACKAGE),
            "proposal",
            "Proposal",
            vec![hashi_struct("update_config", "UpdateConfig", vec![])],
        );

        let out = fixture.apply(&tx(vec![
            written(wrapper_object(wrapper1, proposal_id, 1, active_id())),
            written(obj(
                proposal_tag.clone(),
                1,
                Owner::Object(wrapper1),
                bcs::to_bytes(&proposal).unwrap(),
            )),
        ]));
        assert!(out.unrouted.is_empty());
        assert!(fixture.hashi.proposals.active.contains_key(&proposal_id));
        assert!(fixture.hashi.proposals.executed.is_empty());

        // Execution moves the object between bags.
        let out = fixture.apply(&tx(vec![
            written(wrapper_object(wrapper2, proposal_id, 2, executed_id())),
            written(obj(
                proposal_tag,
                2,
                Owner::Object(wrapper2),
                bcs::to_bytes(&proposal).unwrap(),
            )),
            TxChange::Deleted { id: wrapper1 },
        ]));
        assert!(out.unrouted.is_empty());
        assert!(fixture.hashi.proposals.active.is_empty());
        assert!(fixture.hashi.proposals.executed.contains_key(&proposal_id));
    }

    #[test]
    fn unknown_owner_trips_the_unrouted_counter() {
        let mut fixture = Fixture::new();
        let out = fixture.apply(&tx(vec![written(obj(
            tag(addr(PACKAGE), "mystery", "Widget", vec![]),
            1,
            Owner::Object(addr(0x99)),
            addr(0x70).as_bytes().to_vec(),
        ))]));
        assert_eq!(out.unrouted.len(), 1);
    }

    #[test]
    fn foreign_objects_do_not_trip_the_unrouted_counter() {
        let mut fixture = Fixture::new();
        // A foreign-typed object under a foreign owner (e.g. a system
        // registry's child), as `finish_publish` legitimately produces.
        let out = fixture.apply(&tx(vec![written(obj(
            tag(
                Address::TWO,
                "coin_registry",
                "Currency",
                vec![TypeTag::U64],
            ),
            1,
            Owner::Object(addr(0x98)),
            addr(0x72).as_bytes().to_vec(),
        ))]));
        assert!(out.unrouted.is_empty());

        // A foreign shared object (the registry itself).
        let out = fixture.apply(&tx(vec![written(obj(
            tag(Address::TWO, "coin_registry", "CoinRegistry", vec![]),
            1,
            Owner::Shared(1),
            addr(0x73).as_bytes().to_vec(),
        ))]));
        assert!(out.unrouted.is_empty());

        // A foreign DOF wrapper under a foreign container is neither
        // registered nor tracked.
        let out = fixture.apply(&tx(vec![written(wrapper_object(
            addr(0x74),
            addr(0x75),
            1,
            addr(0x99),
        ))]));
        assert!(out.unrouted.is_empty());
        assert_eq!(fixture.index.len(), 0);
    }

    #[test]
    fn address_owned_objects_are_ignored_silently() {
        let mut fixture = Fixture::new();
        let out = fixture.apply(&tx(vec![written(obj(
            tag(Address::TWO, "coin", "Coin", vec![TypeTag::U64]),
            1,
            Owner::Address(addr(0x99)),
            addr(0x71).as_bytes().to_vec(),
        ))]));
        assert!(out.unrouted.is_empty());
        assert!(out.effects.is_empty());
        assert_eq!(fixture.index.len(), 0);
    }
}
