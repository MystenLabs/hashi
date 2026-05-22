// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `World` — the central store of components, indexes, and the wiring
//! that keeps them consistent.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sui_sdk_types::Address;

use crate::component::{AnyStorage, Component, Storage};
use crate::index::{AnyIndexStorage, Driver, Index, IndexBuilder};
use crate::scheduler::{Derivation, Derived, topo_sort};

/// Central state container.
///
/// Holds one `Storage<C>` per registered component type and one
/// `I::Storage` per registered index. Component types are looked up by
/// `TypeId::of::<C>()`; indexes by `TypeId::of::<I>()`. Drivers are kept
/// in a map keyed by the driving component's `TypeId`, so a single
/// component write only walks the (small) set of indexes that depend on
/// it.
///
/// Derived components are computed lazily by the scheduler — see
/// `register_derived` and `MutationBatch::commit` for the contract.
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
    /// Registered derivations, keyed by the derived component's TypeId.
    derivations: HashMap<TypeId, Derivation>,
    /// Reverse map: for each input component (base or derived), the list
    /// of derivations that read it. Used to translate a dirty storage
    /// entry into a set of derivations that need to recompute.
    dependents: HashMap<TypeId, Vec<TypeId>>,
    /// Cached topological order over `derivations`. Invalidated to `None`
    /// whenever a new derivation is registered.
    topo_cache: Option<Vec<TypeId>>,
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
            derivations: HashMap::new(),
            dependents: HashMap::new(),
            topo_cache: None,
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

    /// Register a derived component. The derivation will be recomputed
    /// automatically whenever any of its declared dependencies changes.
    ///
    /// Register all derivations *before* inserting data — the initial
    /// computation happens at the first batch commit that touches each
    /// derivation's dependencies. Re-registration is a logic error and
    /// will panic.
    pub fn register_derived<D: Derived>(&mut self) -> &mut Self {
        let key = TypeId::of::<D>();
        assert!(
            !self.derivations.contains_key(&key),
            "derivation already registered for this type",
        );
        self.register::<D>();
        let derivation = Derivation::new::<D>();
        for dep in &derivation.deps {
            self.dependents.entry(*dep).or_default().push(key);
        }
        self.derivations.insert(key, derivation);
        self.topo_cache = None;
        self
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

    /// Insert (or replace) a component value as a one-off transaction.
    ///
    /// Equivalent to `world.batch().insert(id, value).commit()` and
    /// therefore *does* run the scheduler. For multiple writes that
    /// should land atomically, use `batch()` and call `commit()` once at
    /// the end.
    pub fn insert<C: Component>(&mut self, id: Address, value: C) -> Option<C> {
        let old = self.apply_insert::<C>(id, value);
        self.run_scheduler();
        old
    }

    pub fn remove<C: Component>(&mut self, id: Address) -> Option<C> {
        let old = self.apply_remove::<C>(id);
        self.run_scheduler();
        old
    }

    /// Start a per-transaction mutation batch. Writes hit storage and
    /// fire index drivers eagerly inside the batch; derived components
    /// recompute when `commit()` is called.
    pub fn batch(&mut self) -> MutationBatch<'_> {
        MutationBatch { world: self }
    }

    // ---- internal write path used by batch + direct entry points -----------

    /// Apply an insert to component storage and fire any index drivers,
    /// but do not run the scheduler. Used internally by the public
    /// `insert` method and by `MutationBatch::insert`.
    pub(crate) fn apply_insert<C: Component>(
        &mut self,
        id: Address,
        value: C,
    ) -> Option<C> {
        // Split the borrow so the driver loop can touch `indexes` while
        // we still hold a reference to the new value in `components`.
        let Self {
            components,
            indexes,
            drivers,
            ..
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

    pub(crate) fn apply_remove<C: Component>(&mut self, id: Address) -> Option<C> {
        let Self {
            components,
            indexes,
            drivers,
            ..
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

    // ---- scheduler ----------------------------------------------------------

    /// Drive derived-component recomputation to a fixed point.
    ///
    /// Drains per-storage dirty sets, translates them into per-derivation
    /// work, then walks derivations in topological order so each one sees
    /// its (now up-to-date) inputs. Calls into `apply_insert` /
    /// `apply_remove` for the derived storage, which in turn marks those
    /// storages dirty — the loop picks that up and propagates forward.
    pub(crate) fn run_scheduler(&mut self) {
        if self.derivations.is_empty() {
            // No derivations registered, but we still need to clear the
            // per-storage dirty sets so they don't grow unboundedly across
            // commits.
            self.drain_all_dirty();
            return;
        }

        let topo = self.ensure_topo();

        let mut work: HashMap<TypeId, HashSet<Address>> = HashMap::new();
        self.propagate_dirty_into(&mut work);

        for derived_ty in topo {
            let Some(entities) = work.remove(&derived_ty) else {
                continue;
            };
            let recompute = Arc::clone(
                &self
                    .derivations
                    .get(&derived_ty)
                    .expect("topo lists only registered derivations")
                    .recompute,
            );
            for entity in entities {
                (recompute)(self, entity);
            }
            // The recompute calls dirtied this derivation's storage and
            // possibly fired its indexes; propagate to its dependents so
            // they get picked up by their turn in the topo order.
            self.propagate_dirty_into(&mut work);
        }
    }

    /// Drain every storage's dirty set, translating each (component,
    /// entity) entry into work items in `work` keyed by the derivations
    /// that depend on that component.
    fn propagate_dirty_into(&mut self, work: &mut HashMap<TypeId, HashSet<Address>>) {
        let Self {
            components,
            dependents,
            ..
        } = self;
        for (component_ty, storage) in components.iter_mut() {
            let dirty = storage.drain_dirty_erased();
            if dirty.is_empty() {
                continue;
            }
            let Some(deps) = dependents.get(component_ty) else {
                continue;
            };
            for dep_ty in deps {
                let bucket = work.entry(*dep_ty).or_default();
                bucket.extend(dirty.iter().copied());
            }
        }
    }

    fn drain_all_dirty(&mut self) {
        for storage in self.components.values_mut() {
            let _ = storage.drain_dirty_erased();
        }
    }

    fn ensure_topo(&mut self) -> Vec<TypeId> {
        if self.topo_cache.is_none() {
            self.topo_cache = Some(topo_sort(&self.derivations));
        }
        self.topo_cache
            .as_ref()
            .expect("set above")
            .clone()
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
/// Individual `insert` / `remove` calls update component storage and fire
/// index drivers eagerly. Derived components do *not* recompute until
/// `commit()`. This keeps multi-component writes consistent from
/// dependents' point of view: each derivation runs at most once per batch
/// per entity, against the final state of all base components.
pub struct MutationBatch<'a> {
    world: &'a mut World,
}

impl<'a> MutationBatch<'a> {
    pub fn insert<C: Component>(&mut self, id: Address, value: C) -> &mut Self {
        self.world.apply_insert::<C>(id, value);
        self
    }

    pub fn remove<C: Component>(&mut self, id: Address) -> &mut Self {
        self.world.apply_remove::<C>(id);
        self
    }

    /// Finalize the batch: run the reactive scheduler so any derived
    /// components dependent on the writes above get recomputed.
    pub fn commit(self) {
        self.world.run_scheduler();
    }
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

    // ---- scheduler tests ----------------------------------------------------

    /// A derived component that doubles whatever value lives in `Owner` —
    /// silly but lets us check the scheduler propagates correctly without
    /// having to plumb through anything more elaborate.
    struct OwnerHigh(Address);
    impl Component for OwnerHigh {}
    impl crate::scheduler::Derived for OwnerHigh {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<Owner>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            world.get::<Owner>(entity).map(|o| OwnerHigh(o.0))
        }
    }

    #[test]
    fn derived_recomputes_on_base_change() {
        let mut world = World::new();
        world.register::<Owner>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        world.insert::<Owner>(entity, Owner(addr(1)));
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(1)));

        world.insert::<Owner>(entity, Owner(addr(2)));
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(2)));
    }

    #[test]
    fn derived_removed_when_base_removed() {
        let mut world = World::new();
        world.register::<Owner>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        world.insert::<Owner>(entity, Owner(addr(1)));
        assert!(world.contains::<OwnerHigh>(entity));

        world.remove::<Owner>(entity);
        assert!(!world.contains::<OwnerHigh>(entity));
    }

    /// Second-level derivation, depends on the first one — exercises
    /// topo-order propagation across a chain.
    struct OwnerHighHigh(Address);
    impl Component for OwnerHighHigh {}
    impl crate::scheduler::Derived for OwnerHighHigh {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<OwnerHigh>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            world.get::<OwnerHigh>(entity).map(|h| OwnerHighHigh(h.0))
        }
    }

    #[test]
    fn derivation_chain_propagates_in_topo_order() {
        let mut world = World::new();
        world.register::<Owner>();
        world.register_derived::<OwnerHigh>();
        world.register_derived::<OwnerHighHigh>();

        let entity = addr(7);
        world.insert::<Owner>(entity, Owner(addr(42)));

        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(42)));
        assert_eq!(
            world.get::<OwnerHighHigh>(entity).map(|o| o.0),
            Some(addr(42))
        );
    }

    #[test]
    fn batch_defers_derived_until_commit() {
        let mut world = World::new();
        world.register::<Owner>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        {
            let mut batch = world.batch();
            batch.insert::<Owner>(entity, Owner(addr(1)));
            // Mid-batch: derived has not recomputed yet.
            assert!(!batch.world.contains::<OwnerHigh>(entity));
            batch.insert::<Owner>(entity, Owner(addr(2)));
            assert!(!batch.world.contains::<OwnerHigh>(entity));
            batch.commit();
        }
        // Post-commit: derived sees the final base value, not the
        // intermediate one.
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(2)));
    }
}
