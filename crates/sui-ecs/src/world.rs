// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `World` — the central store of components, indexes, and the wiring
//! that keeps them consistent.

use std::any::{Any, TypeId};
use std::collections::HashMap;

use sui_sdk_types::Address;

use crate::component::{AnyStorage, Component, Storage};
use crate::index::{AnyIndexStorage, Driver, Index, IndexBuilder};

/// Central state container.
///
/// Holds one `Storage<C>` per registered component type and one
/// `I::Storage` per registered index. Component types are looked up by
/// `TypeId::of::<C>()`; indexes by `TypeId::of::<I>()`. Drivers are kept
/// in a map keyed by the driving component's `TypeId`, so a single
/// component write only walks the (small) set of indexes that depend on
/// it.
///
/// Concurrency lives one layer up: wrap a `World` in a `RwLock` (or
/// finer-grained synchronization) at the application boundary. The
/// methods on `World` itself are sync and take `&self` / `&mut self`.
pub struct World {
    components: HashMap<TypeId, Box<dyn AnyStorage>>,
    indexes: HashMap<TypeId, Box<dyn AnyIndexStorage>>,
    /// Drivers indexed by the *driving component*'s TypeId. On a write to
    /// component `C`, we look up this list and fan out to each driver.
    drivers: HashMap<TypeId, Vec<Driver>>,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> Self {
        Self {
            components: HashMap::new(),
            indexes: HashMap::new(),
            drivers: HashMap::new(),
        }
    }

    /// Register a component type. Idempotent. Must be called before any
    /// insert/remove for `C`.
    pub fn register<C: Component>(&mut self) -> &mut Self {
        self.components
            .entry(TypeId::of::<C>())
            .or_insert_with(|| Box::new(Storage::<C>::new()));
        self
    }

    /// Begin registering an index. Use the returned builder to wire it to
    /// one or more driving components.
    pub fn register_index<I: Index>(&mut self) -> IndexBuilder<'_, I> {
        self.indexes
            .entry(TypeId::of::<I>())
            .or_insert_with(|| Box::new(I::Storage::default()));
        IndexBuilder::new(self)
    }

    // ---- reads --------------------------------------------------------------

    pub fn get<C: Component>(&self, id: Address) -> Option<&C> {
        self.storage::<C>()?.get(id)
    }

    pub fn contains<C: Component>(&self, id: Address) -> bool {
        self.get::<C>(id).is_some()
    }

    pub fn iter<C: Component>(&self) -> impl Iterator<Item = (Address, &C)> + '_ {
        self.storage::<C>().into_iter().flat_map(|s| s.iter())
    }

    pub fn len<C: Component>(&self) -> usize {
        self.storage::<C>().map_or(0, |s| s.len())
    }

    pub fn is_empty<C: Component>(&self) -> bool {
        self.len::<C>() == 0
    }

    pub fn index<I: Index>(&self) -> Option<&I::Storage> {
        self.indexes
            .get(&TypeId::of::<I>())?
            .as_any()
            .downcast_ref::<I::Storage>()
    }

    // ---- writes -------------------------------------------------------------

    /// Insert (or replace) a component value, firing index drivers.
    ///
    /// For groups of mutations that should land atomically from a reader's
    /// perspective (e.g. one Sui transaction's effects), wrap the writes
    /// in a `batch()` and hold the surrounding `RwLock` write guard for
    /// the duration.
    pub fn insert<C: Component>(&mut self, id: Address, value: C) -> Option<C> {
        // Split the borrow so the driver loop can touch `indexes` while
        // we still hold a reference to the new value in `components`.
        let Self {
            components,
            indexes,
            drivers,
        } = self;

        let storage = component_storage_mut::<C>(components)
            .expect("component not registered");
        let old = storage.insert(id, value);
        let new = storage
            .get(id)
            .expect("just inserted, must be present");

        if let Some(driver_list) = drivers.get(&TypeId::of::<C>()) {
            for driver in driver_list {
                let idx = indexes
                    .get_mut(&driver.index_type)
                    .expect("driver references unregistered index");
                // An insert that replaces an existing value is logically a
                // remove(old) + insert(new) from the index's perspective.
                if let Some(old_val) = &old {
                    (driver.on_remove)(idx.as_mut(), id, old_val as &dyn Any);
                }
                (driver.on_insert)(idx.as_mut(), id, new as &dyn Any);
            }
        }

        old
    }

    pub fn remove<C: Component>(&mut self, id: Address) -> Option<C> {
        let Self {
            components,
            indexes,
            drivers,
        } = self;

        let storage = component_storage_mut::<C>(components)
            .expect("component not registered");
        let old = storage.remove(id);

        if let Some(old_val) = &old
            && let Some(driver_list) = drivers.get(&TypeId::of::<C>())
        {
            for driver in driver_list {
                let idx = indexes
                    .get_mut(&driver.index_type)
                    .expect("driver references unregistered index");
                (driver.on_remove)(idx.as_mut(), id, old_val as &dyn Any);
            }
        }

        old
    }

    /// Start a per-transaction mutation batch.
    ///
    /// At v0 the batch is a thin grouping wrapper — writes hit storage and
    /// fire drivers eagerly. Once the reactive scheduler lands, `commit()`
    /// will be where derived recomputes run and dirty sets are drained.
    pub fn batch(&mut self) -> MutationBatch<'_> {
        MutationBatch { world: self }
    }

    // ---- internal accessors -------------------------------------------------

    fn storage<C: Component>(&self) -> Option<&Storage<C>> {
        self.components
            .get(&TypeId::of::<C>())?
            .as_any()
            .downcast_ref::<Storage<C>>()
    }

    pub(crate) fn drivers_mut(&mut self) -> &mut HashMap<TypeId, Vec<Driver>> {
        &mut self.drivers
    }
}

fn component_storage_mut<C: Component>(
    components: &mut HashMap<TypeId, Box<dyn AnyStorage>>,
) -> Option<&mut Storage<C>> {
    components
        .get_mut(&TypeId::of::<C>())?
        .as_any_mut()
        .downcast_mut::<Storage<C>>()
}

/// Group of mutations applied to the same `World` as a single logical
/// transaction.
///
/// At v0 this is a thin convenience wrapper around per-write `insert` /
/// `remove`. The intended evolution: hold the World's write lock for the
/// batch's lifetime, defer derived-component recomputation until
/// `commit()`, and surface a report of touched entities for the
/// downstream reactive scheduler.
pub struct MutationBatch<'a> {
    world: &'a mut World,
}

impl<'a> MutationBatch<'a> {
    pub fn insert<C: Component>(&mut self, id: Address, value: C) -> &mut Self {
        self.world.insert::<C>(id, value);
        self
    }

    pub fn remove<C: Component>(&mut self, id: Address) -> &mut Self {
        self.world.remove::<C>(id);
        self
    }

    /// Finalize the batch. v0 is a no-op; the future reactive scheduler
    /// will run derived recomputes and return a touched-entity report.
    pub fn commit(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Index, OneToMany};

    // A tiny synthetic component + index pair, used to exercise the
    // World plumbing without needing to construct a real
    // `sui_sdk_types::Object` (which has non-trivial BCS invariants).
    struct Owner(Address);
    impl Component for Owner {}

    struct OwnedBy;
    impl Index for OwnedBy {
        type Storage = OneToMany<Address, Address>;
    }

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    fn make_world() -> World {
        let mut world = World::new();
        world.register::<Owner>();
        world
            .register_index::<OwnedBy>()
            .driven_by::<Owner>()
            .on_insert(|idx, child, owner| {
                idx.add(owner.0, child);
            })
            .on_remove(|idx, child, owner| {
                idx.remove(&owner.0, &child);
            })
            .register();
        world
    }

    #[test]
    fn insert_adds_to_index() {
        let mut world = make_world();
        let parent = addr(1);
        let child = addr(2);

        world.insert::<Owner>(child, Owner(parent));

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent), 1);
        assert!(idx.get(&parent).any(|c| *c == child));
    }

    #[test]
    fn replacing_owner_moves_index_entry() {
        let mut world = make_world();
        let parent_a = addr(1);
        let parent_b = addr(2);
        let child = addr(3);

        world.insert::<Owner>(child, Owner(parent_a));
        world.insert::<Owner>(child, Owner(parent_b));

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent_a), 0, "old owner bucket should drain");
        assert_eq!(idx.count(&parent_b), 1, "new owner bucket should fill");
    }

    #[test]
    fn remove_clears_index_entry() {
        let mut world = make_world();
        let parent = addr(1);
        let child = addr(2);

        world.insert::<Owner>(child, Owner(parent));
        let old = world.remove::<Owner>(child);
        assert!(old.is_some());

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent), 0);
    }

    #[test]
    fn batch_groups_writes() {
        let mut world = make_world();
        let parent = addr(1);

        {
            let mut batch = world.batch();
            batch
                .insert::<Owner>(addr(2), Owner(parent))
                .insert::<Owner>(addr(3), Owner(parent))
                .insert::<Owner>(addr(4), Owner(parent));
            batch.commit();
        }

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent), 3);
    }

    #[test]
    fn missing_component_yields_empty_views() {
        let world = World::new();
        // Not registered — reads return empty rather than panicking.
        assert_eq!(world.len::<Owner>(), 0);
        assert!(world.get::<Owner>(addr(1)).is_none());
        assert_eq!(world.iter::<Owner>().count(), 0);
    }
}
