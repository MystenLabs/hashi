// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ownership-based routing for the object-driven mirror.
//!
//! Every object the watcher receives is routed to a logical slot by
//! walking its ownership: a dynamic field's owner is a container UID
//! embedded in the Hashi root or `BitcoinState`, and a dynamic object
//! field's owner is a wrapper `Field` whose own owner is a container
//! UID. The [`RoutingTable`] holds both mappings; the [`ObjectIndex`]
//! remembers, per applied object id, its last-applied version (for
//! idempotent replay) and what the object means (so deletions and moves
//! can retire the right mirror entry without needing the object's
//! pre-deletion contents).

// Wired into the watcher in a follow-up PR; exercised by unit tests
// until then.
#![allow(dead_code)]

use std::collections::BTreeMap;

use sui_sdk_types::Address;
use sui_sdk_types::TypeTag;

use hashi_types::move_types;

use super::types::UtxoId;

/// A logical position in the mirrored state. Routing an object to a
/// slot decides which `types::Hashi` map it lands in — or that it is
/// known and deliberately not mirrored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Slot {
    // Plain-Bag containers whose Field values are mirrored.
    Members,
    Committees,
    UtxoRecords,
    SpentUtxos,
    // ObjectBag containers whose child objects are mirrored.
    DepositRequests,
    WithdrawalRequests,
    WithdrawalTxns,
    Treasury,
    ProposalsActive,
    ProposalsExecuted,
    // Known containers that are deliberately not mirrored. Routing an
    // object here is not an error; it just doesn't update the mirror.
    DepositProcessed,
    WithdrawalProcessed,
    ConfirmedTxns,
    Tob,
    /// The `LinkedTable` inside a `tob` bag entry (`EpochCertsV1.certs`);
    /// its children are dealer submission nodes.
    TobCerts,
    /// The `BitcoinState.user_requests` table of per-user request bags.
    UserRequests,
    /// One per-user `Bag` stored as a `user_requests` value.
    UserRequestBag,
}

impl Slot {
    /// Whether objects routed to this slot update the mirror.
    pub(super) fn is_mirrored(self) -> bool {
        match self {
            Slot::Members
            | Slot::Committees
            | Slot::UtxoRecords
            | Slot::SpentUtxos
            | Slot::DepositRequests
            | Slot::WithdrawalRequests
            | Slot::WithdrawalTxns
            | Slot::Treasury
            | Slot::ProposalsActive
            | Slot::ProposalsExecuted => true,
            Slot::DepositProcessed
            | Slot::WithdrawalProcessed
            | Slot::ConfirmedTxns
            | Slot::Tob
            | Slot::TobCerts
            | Slot::UserRequests
            | Slot::UserRequestBag => false,
        }
    }
}

/// Container UIDs and DOF wrappers, resolved to slots.
#[derive(Debug)]
pub(super) struct RoutingTable {
    hashi_id: Address,
    bitcoin_state_field_id: Address,
    /// Container UID (a `Bag`/`ObjectBag`/`Table` id embedded in the
    /// root or `BitcoinState`, or an interior container learned from a
    /// mirrored write) -> the slot its children belong to.
    containers: BTreeMap<Address, Slot>,
    /// DOF wrapper field id -> the container UID that owns the wrapper.
    /// A DOF value's owner is its wrapper, so this is the extra hop
    /// needed to route values. Maintained from wrapper writes/deletes
    /// in the stream and populated wholesale by the scrape.
    wrapper_parents: BTreeMap<Address, Address>,
}

impl RoutingTable {
    pub(super) fn new(hashi_id: Address, bitcoin_state_field_id: Address) -> Self {
        Self {
            hashi_id,
            bitcoin_state_field_id,
            containers: BTreeMap::new(),
            wrapper_parents: BTreeMap::new(),
        }
    }

    pub(super) fn hashi_id(&self) -> Address {
        self.hashi_id
    }

    pub(super) fn bitcoin_state_field_id(&self) -> Address {
        self.bitcoin_state_field_id
    }

    /// (Re)register the container UIDs embedded in the Hashi root.
    /// Inner UIDs are stable for an object's lifetime, so after the
    /// first call this is a no-op refresh.
    pub(super) fn set_root_containers(&mut self, root: &move_types::Hashi) {
        self.containers
            .insert(root.committees.members.id, Slot::Members);
        self.containers
            .insert(root.committees.committees.id, Slot::Committees);
        self.containers
            .insert(root.treasury.objects.id, Slot::Treasury);
        self.containers
            .insert(root.proposals.active.id, Slot::ProposalsActive);
        self.containers
            .insert(root.proposals.executed.id, Slot::ProposalsExecuted);
        self.containers.insert(root.tob.id, Slot::Tob);
    }

    /// (Re)register the container UIDs embedded in `BitcoinState`.
    pub(super) fn set_bitcoin_state_containers(&mut self, state: &move_types::BitcoinState) {
        self.containers
            .insert(state.deposit_queue.requests.id, Slot::DepositRequests);
        self.containers
            .insert(state.deposit_queue.processed.id, Slot::DepositProcessed);
        self.containers
            .insert(state.withdrawal_queue.requests.id, Slot::WithdrawalRequests);
        self.containers.insert(
            state.withdrawal_queue.processed.id,
            Slot::WithdrawalProcessed,
        );
        self.containers.insert(
            state.withdrawal_queue.withdrawal_txns.id,
            Slot::WithdrawalTxns,
        );
        self.containers.insert(
            state.withdrawal_queue.confirmed_txns.id,
            Slot::ConfirmedTxns,
        );
        self.containers
            .insert(state.utxo_pool.utxo_records.id, Slot::UtxoRecords);
        self.containers
            .insert(state.utxo_pool.spent_utxos.id, Slot::SpentUtxos);
        self.containers
            .insert(state.user_requests.id, Slot::UserRequests);
    }

    /// Register an interior container discovered while applying a
    /// routed write (e.g. the `LinkedTable` inside a tob entry), so its
    /// children route to a known-ignored slot instead of tripping the
    /// unrouted counter.
    pub(super) fn register_interior(&mut self, id: Address, slot: Slot) {
        self.containers.insert(id, slot);
    }

    pub(super) fn register_wrapper(&mut self, wrapper: Address, container: Address) {
        self.wrapper_parents.insert(wrapper, container);
    }

    pub(super) fn remove_wrapper(&mut self, wrapper: &Address) {
        self.wrapper_parents.remove(wrapper);
    }

    pub(super) fn slot_of_container(&self, id: &Address) -> Option<Slot> {
        self.containers.get(id).copied()
    }

    /// Resolve the owner UID of an object-owned object to a slot:
    /// either the owner is a container UID directly (plain dynamic
    /// field), or it is a DOF wrapper one hop below a container.
    pub(super) fn resolve_owner(&self, owner: &Address) -> Option<Slot> {
        if let Some(slot) = self.containers.get(owner) {
            return Some(*slot);
        }
        let container = self.wrapper_parents.get(owner)?;
        self.containers.get(container).copied()
    }
}

/// What an applied object id means to the mirror. Carried per id so a
/// later deletion or cross-bag move can retire the right entry without
/// the object's pre-state contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TrackedKind {
    HashiRoot,
    BitcoinStateField,
    /// A DOF wrapper field. Retiring it prunes `wrapper_parents`.
    DofWrapper {
        container: Address,
    },
    Member(Address),
    Committee(u64),
    CommitteeHandoff(u64),
    UtxoRecord(UtxoId),
    SpentUtxo(UtxoId),
    DepositRequest(Address),
    WithdrawalRequest(Address),
    WithdrawalTxn(Address),
    TreasuryCap(TypeTag),
    MetadataCap(TypeTag),
    Proposal {
        executed: bool,
        id: Address,
    },
    /// Routed to a known-unmirrored slot; tracked only for versioning.
    Ignored,
}

#[derive(Debug)]
pub(super) struct TrackedObject {
    pub version: u64,
    pub kind: TrackedKind,
}

/// Last-applied version and meaning per object id.
#[derive(Debug, Default)]
pub(super) struct ObjectIndex {
    entries: BTreeMap<Address, TrackedObject>,
}

impl ObjectIndex {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn get(&self, id: &Address) -> Option<&TrackedObject> {
        self.entries.get(id)
    }

    /// True when a write at `version` is stale — i.e. the mirror has
    /// already applied this version or a newer one. Replayed and
    /// duplicated frames hit this.
    pub(super) fn is_stale_write(&self, id: &Address, version: u64) -> bool {
        self.entries
            .get(id)
            .is_some_and(|entry| entry.version >= version)
    }

    pub(super) fn record(&mut self, id: Address, version: u64, kind: TrackedKind) {
        self.entries.insert(id, TrackedObject { version, kind });
    }

    pub(super) fn remove(&mut self, id: &Address) -> Option<TrackedObject> {
        self.entries.remove(id)
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Everything a bootstrap scrape learns beyond the mirrored values:
/// the routing table, the per-object index, and the minimum checkpoint
/// height any scrape response was served at. Replaying the filtered
/// transaction stream from `floor` (in order, through the tip)
/// converges the mirror even where a page was served behind another —
/// index versions make re-applied writes idempotent.
#[derive(Debug)]
pub(super) struct MirrorSeed {
    pub routing: RoutingTable,
    pub index: ObjectIndex,
    pub floor: u64,
}

impl MirrorSeed {
    pub(super) fn new(hashi_id: Address, bitcoin_state_field_id: Address) -> Self {
        Self {
            routing: RoutingTable::new(hashi_id, bitcoin_state_field_id),
            index: ObjectIndex::new(),
            floor: u64::MAX,
        }
    }

    /// Fold one response's serving height into the replay floor.
    pub(super) fn observe_height(&mut self, height: u64) {
        self.floor = self.floor.min(height);
    }

    /// Merge the per-container seed entries a scrape helper produced.
    pub(super) fn absorb(&mut self, seed: ContainerSeed) {
        self.observe_height(seed.height);
        for (id, version, kind) in seed.entries {
            if let TrackedKind::DofWrapper { container } = &kind {
                self.routing.register_wrapper(id, *container);
            }
            self.index.record(id, version, kind);
        }
        for (id, slot) in seed.interior {
            self.routing.register_interior(id, slot);
        }
    }
}

/// One scrape helper's contribution to the [`MirrorSeed`].
#[derive(Debug)]
pub(super) struct ContainerSeed {
    /// The minimum checkpoint height across this helper's pages.
    pub height: u64,
    /// (object id, version, meaning) triples for the index.
    pub entries: Vec<(Address, u64, TrackedKind)>,
    /// Interior containers discovered inside mirrored values.
    pub interior: Vec<(Address, Slot)>,
}

impl Default for ContainerSeed {
    fn default() -> Self {
        Self {
            // The neutral element for the min-fold: a helper that read
            // no pages must not drag the replay floor down.
            height: u64::MAX,
            entries: Vec::new(),
            interior: Vec::new(),
        }
    }
}

impl ContainerSeed {
    pub(super) fn merge(&mut self, other: ContainerSeed) {
        self.height = self.height.min(other.height);
        self.entries.extend(other.entries);
        self.interior.extend(other.interior);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32]).unwrap()
    }

    fn bag(id: Address) -> move_types::Bag {
        move_types::Bag { id, size: 0 }
    }

    fn routing_with_bitcoin_state() -> (RoutingTable, move_types::BitcoinState) {
        let state = move_types::BitcoinState {
            id: addr(0x10),
            deposit_queue: move_types::DepositRequestQueue {
                requests: bag(addr(0x11)),
                processed: bag(addr(0x12)),
            },
            withdrawal_queue: move_types::WithdrawalRequestQueue {
                requests: bag(addr(0x13)),
                processed: bag(addr(0x14)),
                withdrawal_txns: bag(addr(0x15)),
                confirmed_txns: bag(addr(0x16)),
            },
            utxo_pool: move_types::UtxoPool {
                utxo_records: bag(addr(0x17)),
                spent_utxos: bag(addr(0x18)),
            },
            user_requests: move_types::Table {
                id: addr(0x19),
                size: 0,
            },
        };
        let mut routing = RoutingTable::new(addr(0x01), addr(0x02));
        routing.set_bitcoin_state_containers(&state);
        (routing, state)
    }

    #[test]
    fn resolve_owner_routes_container_uids_directly() {
        let (routing, _) = routing_with_bitcoin_state();
        assert_eq!(routing.resolve_owner(&addr(0x17)), Some(Slot::UtxoRecords));
        assert_eq!(
            routing.resolve_owner(&addr(0x14)),
            Some(Slot::WithdrawalProcessed)
        );
        assert_eq!(routing.resolve_owner(&addr(0x77)), None);
    }

    #[test]
    fn resolve_owner_routes_dof_values_through_their_wrapper() {
        let (mut routing, _) = routing_with_bitcoin_state();
        let wrapper = addr(0x20);
        routing.register_wrapper(wrapper, addr(0x15));
        assert_eq!(routing.resolve_owner(&wrapper), Some(Slot::WithdrawalTxns));

        routing.remove_wrapper(&wrapper);
        assert_eq!(routing.resolve_owner(&wrapper), None);
    }

    #[test]
    fn wrapper_under_unknown_container_does_not_resolve() {
        let (mut routing, _) = routing_with_bitcoin_state();
        let wrapper = addr(0x21);
        routing.register_wrapper(wrapper, addr(0x99));
        assert_eq!(routing.resolve_owner(&wrapper), None);
    }

    #[test]
    fn stale_write_detection_is_version_monotonic() {
        let mut index = ObjectIndex::new();
        let id = addr(0x30);
        assert!(!index.is_stale_write(&id, 5));

        index.record(id, 5, TrackedKind::Ignored);
        assert!(index.is_stale_write(&id, 4));
        assert!(index.is_stale_write(&id, 5));
        assert!(!index.is_stale_write(&id, 6));
    }
}
