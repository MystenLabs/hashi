// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `World` — the central store of components, indexes, and the wiring
//! that keeps them consistent.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use sui_sdk_types::{Address, Object, Owner};

use crate::base::UidToContainer;
use crate::component::{AnyStorage, Component, Storage};
use crate::index::{AnyIndexStorage, Driver, Index, IndexBuilder, OneToOne};
use crate::scheduler::{Derivation, Derived};

/// Central state container.
///
/// Holds one `Storage<C>` per registered component type, one
/// `I::Storage` per registered index, and the wiring that keeps both
/// consistent through index drivers and the reactive scheduler.
///
/// Ordering note: recomputes are sequenced by the Sui object-ownership
/// graph — children before parents — not by derivation-dependency
/// topology. See [`crate::scheduler`] for the rationale.
///
/// Concurrency lives one layer up: wrap a `World` in a `RwLock` (or
/// finer-grained synchronization) at the application boundary. The
/// methods on `World` itself are sync and take `&self` / `&mut self`.
pub struct World {
    components: HashMap<TypeId, Box<dyn AnyStorage>>,
    indexes: HashMap<TypeId, Box<dyn AnyIndexStorage>>,
    /// Drivers indexed by the *driving component*'s TypeId. On a write
    /// to component `C`, we look up this list and fan out to each
    /// driver.
    drivers: HashMap<TypeId, Vec<Driver>>,
    /// Registered derivations, keyed by the derived component's TypeId.
    derivations: HashMap<TypeId, Derivation>,
    /// Reverse map: for each input component (base or derived), the
    /// list of derivations that read it. Used during scheduler
    /// propagation to fan storage dirty entries out to interested
    /// derivations.
    dependents: HashMap<TypeId, Vec<TypeId>>,
    /// Container entities whose set of children changed during the
    /// current batch — captured by `apply_insert::<Object>` and
    /// `apply_remove::<Object>` whenever a write actually re-parents
    /// the object. Drained by the scheduler to dirty aggregating
    /// derivations for both the old and new parent.
    ownership_invalidations: HashSet<Address>,
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
            ownership_invalidations: HashSet::new(),
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

    /// Begin registering an index. Use the returned builder to wire it
    /// to one or more driving components.
    pub fn register_index<I: Index>(&mut self) -> IndexBuilder<'_, I> {
        self.indexes
            .entry(TypeId::of::<I>())
            .or_insert_with(|| Box::new(I::Storage::default()));
        IndexBuilder::new(self)
    }

    /// Register a derived component. The derivation will be recomputed
    /// automatically whenever any of its declared dependencies changes
    /// (subject to `aggregates_children()` semantics).
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

    /// Resolve an entity to its parent container in the ownership graph,
    /// if any. Returns `None` for top-level objects whose owner is not
    /// another object (address-owned, shared, immutable, etc.).
    ///
    /// Handles nested-UID ownership: an `Owner::Object(uid)` whose
    /// `uid` is an embedded UID inside some other top-level object is
    /// lifted to that container via the built-in `UidToContainer`
    /// index. If the index isn't registered or the uid isn't tracked,
    /// the raw uid is returned (treated as if it were a top-level id).
    pub fn parent_of(&self, entity: Address) -> Option<Address> {
        let obj = self.get::<Object>(entity)?;
        match obj.owner() {
            Owner::Object(uid) => Some(self.resolve_container(*uid)),
            // `Owner` is `#[non_exhaustive]`; address-like / shared /
            // immutable variants don't participate in object ownership.
            _ => None,
        }
    }

    fn resolve_container(&self, uid: Address) -> Address {
        self.indexes
            .get(&TypeId::of::<UidToContainer>())
            .and_then(|s| s.as_any().downcast_ref::<OneToOne<Address, Address>>())
            .and_then(|idx| idx.get(&uid).copied())
            .unwrap_or(uid)
    }

    // ---- writes -------------------------------------------------------------

    /// Insert (or replace) a component value as a one-off transaction.
    ///
    /// Equivalent to `world.batch().insert(id, value).commit()` and
    /// therefore *does* run the scheduler. For multiple writes that
    /// should land atomically, use `batch()` and call `commit()` once
    /// at the end.
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
    ///
    /// Object writes additionally snapshot old / new parent ids so that
    /// re-parent events can be replayed to aggregating derivations
    /// during the scheduler pass.
    pub(crate) fn apply_insert<C: Component>(
        &mut self,
        id: Address,
        value: C,
    ) -> Option<C> {
        let is_object = TypeId::of::<C>() == TypeId::of::<Object>();
        let old_parent = if is_object { self.parent_of(id) } else { None };

        let old = self.apply_insert_inner::<C>(id, value);

        if is_object {
            let new_parent = self.parent_of(id);
            if old_parent != new_parent {
                if let Some(p) = old_parent {
                    self.ownership_invalidations.insert(p);
                }
                if let Some(p) = new_parent {
                    self.ownership_invalidations.insert(p);
                }
            }
        }

        old
    }

    pub(crate) fn apply_remove<C: Component>(&mut self, id: Address) -> Option<C> {
        let is_object = TypeId::of::<C>() == TypeId::of::<Object>();
        let old_parent = if is_object { self.parent_of(id) } else { None };

        let old = self.apply_remove_inner::<C>(id);

        if is_object && let Some(p) = old_parent {
            // Object went away; old parent has lost this child.
            self.ownership_invalidations.insert(p);
        }

        old
    }

    fn apply_insert_inner<C: Component>(&mut self, id: Address, value: C) -> Option<C> {
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
                // An insert that replaces an existing value is logically
                // a remove(old) + insert(new) from the index's
                // perspective.
                if let Some(old_val) = &old {
                    (driver.on_remove)(idx.as_mut(), id, old_val as &dyn Any);
                }
                (driver.on_insert)(idx.as_mut(), id, new as &dyn Any);
            }
        }

        old
    }

    fn apply_remove_inner<C: Component>(&mut self, id: Address) -> Option<C> {
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
    /// Each pass: drain storage dirty sets and the ownership
    /// invalidation queue into a per-entity work map, ownership-topo
    /// over the dirty entities so children come before parents,
    /// recompute every dirty derivation at each entity in that order.
    /// Loops until no more work is produced — which terminates because
    /// derivation deps form a DAG and ownership is acyclic.
    pub(crate) fn run_scheduler(&mut self) {
        if self.derivations.is_empty() {
            // No derivations registered, but still drain the dirty
            // sets and ownership queue so they don't accumulate across
            // commits.
            self.drain_all_dirty();
            self.ownership_invalidations.clear();
            return;
        }

        let mut work: HashMap<Address, HashSet<TypeId>> = HashMap::new();
        self.propagate_dirty_into(&mut work);

        while !work.is_empty() {
            let dirty_entities: HashSet<Address> = work.keys().copied().collect();
            let topo = ownership_topo(&dirty_entities, self);

            for entity in topo {
                let Some(derivations) = work.remove(&entity) else {
                    continue;
                };
                for d_ty in derivations {
                    let recompute = Arc::clone(
                        &self
                            .derivations
                            .get(&d_ty)
                            .expect("dirty derivation must be registered")
                            .recompute,
                    );
                    (recompute)(self, entity);
                }
            }

            // Recompute writes mark storage dirty for downstream
            // derivations; pick those up before deciding to exit.
            self.propagate_dirty_into(&mut work);
        }
    }

    /// Drain per-storage dirty sets and the ownership invalidation
    /// queue into the per-entity work map.
    fn propagate_dirty_into(&mut self, work: &mut HashMap<Address, HashSet<TypeId>>) {
        // Phase A: drain every storage's dirty set and translate each
        // (component, entity) entry into work entries. Aggregating
        // derivations get dirtied for the entity's *parent*; everyone
        // else gets dirtied for the entity itself.
        //
        // Collect first so we don't hold a borrow on `components` while
        // calling `parent_of` (which reads from `components`).
        let dirty_per_type: Vec<(TypeId, Vec<Address>)> = self
            .components
            .iter_mut()
            .filter_map(|(ty, s)| {
                let dirty = s.drain_dirty_erased();
                (!dirty.is_empty()).then_some((*ty, dirty))
            })
            .collect();

        for (component_ty, dirty) in dirty_per_type {
            let Some(deps_list) = self.dependents.get(&component_ty).cloned() else {
                continue;
            };
            for dep_ty in deps_list {
                let aggregates = self
                    .derivations
                    .get(&dep_ty)
                    .expect("dependent derivation must be registered")
                    .aggregates_children;
                // Same-entity propagation always applies: a derivation
                // that reads `component_ty` cares about its own value
                // for `entity`, regardless of whether it also folds
                // over children.
                for &entity in &dirty {
                    work.entry(entity).or_default().insert(dep_ty);
                }
                // Aggregating derivations *additionally* care about
                // changes at the entity's children, so a child's dep
                // change dirties the derivation for the parent too.
                if aggregates {
                    for &entity in &dirty {
                        if let Some(parent) = self.parent_of(entity) {
                            work.entry(parent).or_default().insert(dep_ty);
                        }
                    }
                }
            }
        }

        // Phase B: drain ownership invalidations and dirty every
        // aggregating derivation for each affected parent. This is what
        // delivers the "old owner lost a child" and "new owner gained a
        // child" notifications even when the child itself isn't part of
        // any aggregator's dependency list.
        let invalidations: Vec<Address> = self.ownership_invalidations.drain().collect();
        if !invalidations.is_empty() {
            let aggregating: Vec<TypeId> = self
                .derivations
                .iter()
                .filter_map(|(ty, d)| d.aggregates_children.then_some(*ty))
                .collect();
            for parent in invalidations {
                for d_ty in &aggregating {
                    work.entry(parent).or_default().insert(*d_ty);
                }
            }
        }
    }

    fn drain_all_dirty(&mut self) {
        for storage in self.components.values_mut() {
            let _ = storage.drain_dirty_erased();
        }
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

/// Topologically sort a set of dirty entities by the ownership graph so
/// that children come before parents. Edges run child → parent. Panics
/// if a cycle is detected — Sui object ownership is acyclic by
/// construction, so a cycle is necessarily a bug.
fn ownership_topo(dirty: &HashSet<Address>, world: &World) -> Vec<Address> {
    if dirty.is_empty() {
        return Vec::new();
    }

    // Restrict the parent map to edges where the parent is also in the
    // dirty set — entities whose parent isn't dirty have no in-dirty
    // edge and are root candidates in the local sort.
    let mut parent_of: HashMap<Address, Address> = HashMap::new();
    for &e in dirty {
        if let Some(p) = world.parent_of(e)
            && dirty.contains(&p)
        {
            parent_of.insert(e, p);
        }
    }

    // In-degree of `parent` = number of dirty children pointing at it.
    let mut in_degree: HashMap<Address, usize> = dirty.iter().map(|&e| (e, 0)).collect();
    for parent in parent_of.values() {
        *in_degree.entry(*parent).or_insert(0) += 1;
    }

    let mut queue: VecDeque<Address> = in_degree
        .iter()
        .filter_map(|(&e, &d)| (d == 0).then_some(e))
        .collect();

    let mut order: Vec<Address> = Vec::with_capacity(dirty.len());
    while let Some(node) = queue.pop_front() {
        order.push(node);
        if let Some(&parent) = parent_of.get(&node) {
            let d = in_degree
                .get_mut(&parent)
                .expect("parent registered in in_degree");
            *d -= 1;
            if *d == 0 {
                queue.push_back(parent);
            }
        }
    }

    assert_eq!(
        order.len(),
        dirty.len(),
        "cycle detected in object ownership graph"
    );
    order
}

/// Group of mutations applied to the same `World` as a single logical
/// transaction.
///
/// Individual `insert` / `remove` calls update component storage and
/// fire index drivers eagerly. Derived components do *not* recompute
/// until `commit()`. This keeps multi-component writes consistent from
/// dependents' point of view: each derivation runs against the final
/// state of all base components.
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
    use crate::base;
    use crate::index::{Index, OneToMany};

    use sui_sdk_types::{
        Digest, Identifier, MoveStruct, Object, ObjectData, Owner, StructTag,
    };

    // ---- helpers ------------------------------------------------------------

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    fn object_owned_by(id: Address, owner: Owner) -> Object {
        let tag = StructTag::new(
            Address::TWO,
            Identifier::new("test").unwrap(),
            Identifier::new("Thing").unwrap(),
            Vec::new(),
        );
        let ms = MoveStruct::new(tag, true, 1, id.as_bytes().to_vec()).unwrap();
        Object::new(ObjectData::Struct(ms), owner, Digest::ZERO, 0)
    }

    // ---- existing tests using a synthetic Owner component ------------------

    struct OwnerComp(Address);
    impl Component for OwnerComp {}

    struct OwnedBy;
    impl Index for OwnedBy {
        type Storage = OneToMany<Address, Address>;
    }

    fn make_world() -> World {
        let mut world = World::new();
        world.register::<OwnerComp>();
        world
            .register_index::<OwnedBy>()
            .driven_by::<OwnerComp>()
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

        world.insert::<OwnerComp>(child, OwnerComp(parent));

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

        world.insert::<OwnerComp>(child, OwnerComp(parent_a));
        world.insert::<OwnerComp>(child, OwnerComp(parent_b));

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent_a), 0, "old owner bucket should drain");
        assert_eq!(idx.count(&parent_b), 1, "new owner bucket should fill");
    }

    #[test]
    fn remove_clears_index_entry() {
        let mut world = make_world();
        let parent = addr(1);
        let child = addr(2);

        world.insert::<OwnerComp>(child, OwnerComp(parent));
        let old = world.remove::<OwnerComp>(child);
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
                .insert::<OwnerComp>(addr(2), OwnerComp(parent))
                .insert::<OwnerComp>(addr(3), OwnerComp(parent))
                .insert::<OwnerComp>(addr(4), OwnerComp(parent));
            batch.commit();
        }

        let idx = world.index::<OwnedBy>().unwrap();
        assert_eq!(idx.count(&parent), 3);
    }

    #[test]
    fn missing_component_yields_empty_views() {
        let world = World::new();
        assert_eq!(world.len::<OwnerComp>(), 0);
        assert!(world.get::<OwnerComp>(addr(1)).is_none());
        assert_eq!(world.iter::<OwnerComp>().count(), 0);
    }

    // ---- same-entity derivation chain (fixed-point iteration) --------------

    struct OwnerHigh(Address);
    impl Component for OwnerHigh {}
    impl Derived for OwnerHigh {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<OwnerComp>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            world.get::<OwnerComp>(entity).map(|o| OwnerHigh(o.0))
        }
    }

    #[test]
    fn derived_recomputes_on_base_change() {
        let mut world = World::new();
        world.register::<OwnerComp>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        world.insert::<OwnerComp>(entity, OwnerComp(addr(1)));
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(1)));

        world.insert::<OwnerComp>(entity, OwnerComp(addr(2)));
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(2)));
    }

    #[test]
    fn derived_removed_when_base_removed() {
        let mut world = World::new();
        world.register::<OwnerComp>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        world.insert::<OwnerComp>(entity, OwnerComp(addr(1)));
        assert!(world.contains::<OwnerHigh>(entity));

        world.remove::<OwnerComp>(entity);
        assert!(!world.contains::<OwnerHigh>(entity));
    }

    struct OwnerHighHigh(Address);
    impl Component for OwnerHighHigh {}
    impl Derived for OwnerHighHigh {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<OwnerHigh>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            world.get::<OwnerHigh>(entity).map(|h| OwnerHighHigh(h.0))
        }
    }

    #[test]
    fn same_entity_derivation_chain_converges_via_fixed_point() {
        let mut world = World::new();
        world.register::<OwnerComp>();
        world.register_derived::<OwnerHigh>();
        world.register_derived::<OwnerHighHigh>();

        let entity = addr(7);
        world.insert::<OwnerComp>(entity, OwnerComp(addr(42)));

        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(42)));
        assert_eq!(
            world.get::<OwnerHighHigh>(entity).map(|o| o.0),
            Some(addr(42))
        );
    }

    #[test]
    fn batch_defers_derived_until_commit() {
        let mut world = World::new();
        world.register::<OwnerComp>();
        world.register_derived::<OwnerHigh>();

        let entity = addr(7);
        {
            let mut batch = world.batch();
            batch.insert::<OwnerComp>(entity, OwnerComp(addr(1)));
            assert!(!batch.world.contains::<OwnerHigh>(entity));
            batch.insert::<OwnerComp>(entity, OwnerComp(addr(2)));
            assert!(!batch.world.contains::<OwnerHigh>(entity));
            batch.commit();
        }
        assert_eq!(world.get::<OwnerHigh>(entity).map(|o| o.0), Some(addr(2)));
    }

    // ---- ownership-aware tests ---------------------------------------------

    /// Aggregating derivation: each entity's value is the number of
    /// direct children, *including* those owned via a nested UID
    /// (e.g. dynamic fields). Uses `RootedTraversal::children_of` which
    /// already lifts uid-owners up to their container.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ChildCount(usize);
    impl Component for ChildCount {}
    impl Derived for ChildCount {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<Object>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            use crate::base::RootedTraversal;
            Some(ChildCount(world.children_of(entity).len()))
        }
        fn aggregates_children() -> bool {
            true
        }
    }

    fn world_with_aggregate() -> World {
        let mut w = World::new();
        base::install(&mut w);
        w.register_derived::<ChildCount>();
        w
    }

    #[test]
    fn aggregating_derivation_fires_on_child_changes() {
        let mut world = world_with_aggregate();
        let parent = addr(0x10);
        let kid_a = addr(0x11);
        let kid_b = addr(0x12);

        // Bring the parent into the world so it can hold a derived
        // value. Its owner is irrelevant for the test.
        world.insert::<Object>(
            parent,
            object_owned_by(parent, Owner::Address(addr(0xAA))),
        );
        // Bootstrap: no children yet.
        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(0))
        );

        // Adding a child should re-fire ChildCount for the parent.
        world.insert::<Object>(kid_a, object_owned_by(kid_a, Owner::Object(parent)));
        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(1))
        );

        world.insert::<Object>(kid_b, object_owned_by(kid_b, Owner::Object(parent)));
        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(2))
        );
    }

    #[test]
    fn reparent_dirties_both_old_and_new_parent() {
        let mut world = world_with_aggregate();
        let p_old = addr(0x20);
        let p_new = addr(0x21);
        let kid = addr(0x22);

        world.insert::<Object>(
            p_old,
            object_owned_by(p_old, Owner::Address(addr(0xAA))),
        );
        world.insert::<Object>(
            p_new,
            object_owned_by(p_new, Owner::Address(addr(0xAA))),
        );
        world.insert::<Object>(kid, object_owned_by(kid, Owner::Object(p_old)));

        assert_eq!(
            world.get::<ChildCount>(p_old).copied(),
            Some(ChildCount(1))
        );
        assert_eq!(
            world.get::<ChildCount>(p_new).copied(),
            Some(ChildCount(0))
        );

        // Re-parent: kid now belongs to p_new. Both ChildCounts should
        // refresh.
        world.insert::<Object>(kid, object_owned_by(kid, Owner::Object(p_new)));

        assert_eq!(
            world.get::<ChildCount>(p_old).copied(),
            Some(ChildCount(0)),
            "old parent should reflect the lost child"
        );
        assert_eq!(
            world.get::<ChildCount>(p_new).copied(),
            Some(ChildCount(1)),
            "new parent should reflect the gained child"
        );
    }

    #[test]
    fn deleting_child_dirties_parent_aggregate() {
        let mut world = world_with_aggregate();
        let parent = addr(0x30);
        let kid = addr(0x31);

        world.insert::<Object>(
            parent,
            object_owned_by(parent, Owner::Address(addr(0xAA))),
        );
        world.insert::<Object>(kid, object_owned_by(kid, Owner::Object(parent)));
        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(1))
        );

        world.remove::<Object>(kid);
        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(0))
        );
    }

    #[test]
    fn aggregating_resolves_nested_uid_parent() {
        // parent (top-level object) embeds `inner_uid`. The child
        // declares Owner::Object(inner_uid). The aggregator at parent
        // should still see this child because UidToContainer lifts the
        // uid to the container.
        use crate::base::NestedUids;

        let mut world = world_with_aggregate();
        let parent = addr(0x40);
        let inner_uid = addr(0x41);
        let kid = addr(0x42);

        world.insert::<Object>(
            parent,
            object_owned_by(parent, Owner::Address(addr(0xAA))),
        );
        // Register the nested UID — this is what UidToContainer uses
        // to lift inner_uid up to parent.
        world.insert::<NestedUids>(parent, NestedUids(Box::new([inner_uid])));

        world.insert::<Object>(kid, object_owned_by(kid, Owner::Object(inner_uid)));

        assert_eq!(
            world.get::<ChildCount>(parent).copied(),
            Some(ChildCount(1)),
            "aggregator should see kid via nested-uid lift"
        );
    }

    /// Subtree-balance pattern: each entity sums its own value plus
    /// the values from all descendants. Exercises ownership-topo
    /// ordering within a single derivation's dirty set: parents must
    /// see fresh children, so children must be recomputed first.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Subtree(u64);
    impl Component for Subtree {}
    impl Derived for Subtree {
        fn dependencies() -> Vec<TypeId> {
            vec![TypeId::of::<Object>()]
        }
        fn compute(world: &World, entity: Address) -> Option<Self> {
            use crate::base::{OwnedByObject, RootedTraversal};
            // Each entity contributes 1; aggregate over direct
            // children's Subtree values. (Direct, not transitive — the
            // recursion happens via the children already having their
            // Subtree computed in the same scheduler pass.)
            let _ = world.index::<OwnedByObject>(); // hint at the index dependency
            let from_kids: u64 = world
                .children_of(entity)
                .into_iter()
                .filter_map(|c| world.get::<Subtree>(c).copied())
                .map(|s| s.0)
                .sum();
            Some(Subtree(1 + from_kids))
        }
        fn aggregates_children() -> bool {
            true
        }
    }

    #[test]
    fn ownership_topo_orders_children_before_parents() {
        let mut world = World::new();
        base::install(&mut world);
        world.register_derived::<Subtree>();

        let root = addr(0x50);
        let mid = addr(0x51);
        let leaf = addr(0x52);

        // Apply all three inserts as a single batch so they share one
        // scheduler pass. The aggregator at `root` reads from `mid`,
        // and `mid` from `leaf`, so processing order has to respect
        // the ownership hierarchy.
        {
            let mut batch = world.batch();
            batch.insert::<Object>(root, object_owned_by(root, Owner::Address(addr(0xAA))));
            batch.insert::<Object>(mid, object_owned_by(mid, Owner::Object(root)));
            batch.insert::<Object>(leaf, object_owned_by(leaf, Owner::Object(mid)));
            batch.commit();
        }

        assert_eq!(world.get::<Subtree>(leaf).copied(), Some(Subtree(1)));
        assert_eq!(world.get::<Subtree>(mid).copied(), Some(Subtree(2)));
        assert_eq!(world.get::<Subtree>(root).copied(), Some(Subtree(3)));
    }
}
