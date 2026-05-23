// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Component trait and per-type storage.
//!
//! A component is a piece of typed state attached to a Sui object. The
//! trait is intentionally empty so that `sui_sdk_types::Object`,
//! framework-provided components, and user-defined enrichment types are
//! all first-class without needing newtype wrappers.

use std::any::Any;
use std::collections::{HashMap, HashSet};

use sui_sdk_types::Address;

/// A piece of typed state attached to an entity (Sui object).
///
/// Each component type C has at most one value per entity. Storage is
/// sparse: `HashMap<Address, C>` per registered component, kept inside
/// the `World`.
pub trait Component: 'static + Send + Sync + Sized {}

/// Storage for a single component type. One instance per registered C.
///
/// Tracks two independent dirty channels:
///
/// - `propagation_dirty` — drained by the reactive scheduler as it
///   walks the dependency graph. Empty by the time `run_scheduler`
///   returns.
/// - `committed_dirty` — accumulates the same set of writes but
///   survives the scheduler. The caller drains it via the
///   `CommitReport` returned from `MutationBatch::commit` (or
///   `World::insert` / `remove`). This is what lets external consumers
///   reason about "which entities changed in this commit" without
///   diffing snapshots themselves.
pub(crate) struct Storage<C: Component> {
    data: HashMap<Address, C>,
    propagation_dirty: HashSet<Address>,
    committed_dirty: HashSet<Address>,
}

impl<C: Component> Storage<C> {
    pub(crate) fn new() -> Self {
        Self {
            data: HashMap::new(),
            propagation_dirty: HashSet::new(),
            committed_dirty: HashSet::new(),
        }
    }

    pub(crate) fn get(&self, id: Address) -> Option<&C> {
        self.data.get(&id)
    }

    pub(crate) fn insert(&mut self, id: Address, value: C) -> Option<C> {
        self.propagation_dirty.insert(id);
        self.committed_dirty.insert(id);
        self.data.insert(id, value)
    }

    pub(crate) fn remove(&mut self, id: Address) -> Option<C> {
        self.propagation_dirty.insert(id);
        self.committed_dirty.insert(id);
        self.data.remove(&id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Address, &C)> + '_ {
        self.data.iter().map(|(id, c)| (*id, c))
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn drain_propagation_dirty(&mut self) -> impl Iterator<Item = Address> + '_ {
        self.propagation_dirty.drain()
    }

    pub(crate) fn drain_committed_dirty(&mut self) -> impl Iterator<Item = Address> + '_ {
        self.committed_dirty.drain()
    }
}

/// Type-erased component storage. The `World` keeps these behind
/// `Box<dyn AnyStorage>` keyed by `TypeId::of::<C>()`; downcasting back
/// to `Storage<C>` happens at the access boundary.
///
/// Both `drain_*_erased` variants are surfaced at the erased level so
/// the scheduler can walk every component type uniformly without
/// needing to know each concrete `C`.
pub(crate) trait AnyStorage: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn drain_propagation_dirty_erased(&mut self) -> Vec<Address>;
    fn drain_committed_dirty_erased(&mut self) -> Vec<Address>;
}

impl<C: Component> AnyStorage for Storage<C> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn drain_propagation_dirty_erased(&mut self) -> Vec<Address> {
        self.drain_propagation_dirty().collect()
    }

    fn drain_committed_dirty_erased(&mut self) -> Vec<Address> {
        self.drain_committed_dirty().collect()
    }
}
