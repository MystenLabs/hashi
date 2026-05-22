// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Indexes — derived, framework-maintained views over component data.
//!
//! Unlike components, indexes are never written by user code directly.
//! Instead, each index is wired to one or more *driving components*: when
//! a driving component is inserted or removed, the framework runs the
//! registered `on_insert` / `on_remove` hook to keep the index in sync.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::marker::PhantomData;

use sui_sdk_types::Address;

use crate::component::Component;
use crate::world::World;

/// A derived view over component data.
///
/// An `Index` is a *type-level marker* — the trait carries the storage
/// shape as an associated type, but the actual storage instance is owned
/// by the `World`. Each implementor is usually a zero-sized struct.
pub trait Index: 'static + Send + Sync {
    type Storage: IndexStorage + Default;
}

/// Marker trait for the concrete storage shape an index uses. Implemented
/// for `OneToOne` and `OneToMany`; user code can implement it for custom
/// shapes too (the trait is empty).
pub trait IndexStorage: 'static + Send + Sync {}

// ---- built-in index shapes --------------------------------------------------

/// A one-to-one map. Each key maps to exactly one value.
///
/// Useful when there is a functional relation from one side of the index
/// to the other (e.g. nested UID → top-level container).
pub struct OneToOne<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> Default for OneToOne<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<K, V> OneToOne<K, V>
where
    K: Eq + Hash,
{
    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k)
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        self.map.iter()
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.map.insert(k, v)
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.map.remove(k)
    }
}

impl<K, V> IndexStorage for OneToOne<K, V>
where
    K: 'static + Send + Sync + Eq + Hash,
    V: 'static + Send + Sync,
{
}

/// A one-to-many map. Each key maps to a set of values.
///
/// Useful for reverse indexes such as "what objects are owned by this
/// address" or "what objects share this type tag".
pub struct OneToMany<K, V> {
    map: HashMap<K, HashSet<V>>,
}

impl<K, V> Default for OneToMany<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<K, V> OneToMany<K, V>
where
    K: Eq + Hash,
    V: Eq + Hash,
{
    pub fn get(&self, k: &K) -> impl Iterator<Item = &V> + '_ {
        self.map.get(k).into_iter().flat_map(|s| s.iter())
    }

    pub fn count(&self, k: &K) -> usize {
        self.map.get(k).map_or(0, |s| s.len())
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> + '_ {
        self.map.keys()
    }

    /// Add `v` to the set at `k`. Returns `true` if the value was newly
    /// inserted (the set didn't already contain it).
    pub fn add(&mut self, k: K, v: V) -> bool {
        self.map.entry(k).or_default().insert(v)
    }

    /// Remove `v` from the set at `k`. Returns `true` if it was present.
    /// Drops the entry entirely if the set becomes empty, so iteration
    /// over `keys()` never sees an empty bucket.
    pub fn remove(&mut self, k: &K, v: &V) -> bool {
        let Some(set) = self.map.get_mut(k) else {
            return false;
        };
        let removed = set.remove(v);
        if set.is_empty() {
            self.map.remove(k);
        }
        removed
    }
}

impl<K, V> IndexStorage for OneToMany<K, V>
where
    K: 'static + Send + Sync + Eq + Hash,
    V: 'static + Send + Sync + Eq + Hash,
{
}

// ---- type-erased index storage ---------------------------------------------

/// Type-erased index storage. The `World` keeps these behind
/// `Box<dyn AnyIndexStorage>` keyed by `TypeId::of::<I>()`; the driver
/// closures downcast to the concrete `I::Storage` at the access boundary.
pub(crate) trait AnyIndexStorage: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<S: IndexStorage> AnyIndexStorage for S {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ---- drivers ---------------------------------------------------------------

/// Erased driver callback. The first argument is the index storage to
/// mutate; the second is the entity id whose component changed; the
/// third is the typed component value re-erased through `&dyn Any` so
/// the driver can downcast it back to the concrete `C` it expects.
pub(crate) type DriverFn =
    Box<dyn Fn(&mut dyn AnyIndexStorage, Address, &dyn Any) + Send + Sync>;

/// A registered handler that updates an index in response to changes on a
/// driving component. Stored type-erased so the World can keep a uniform
/// list of drivers per component.
pub(crate) struct Driver {
    pub(crate) index_type: TypeId,
    pub(crate) on_insert: DriverFn,
    pub(crate) on_remove: DriverFn,
}

/// Fluent registration for an index. Returned by `World::register_index`.
///
/// Call `.driven_by::<C>()` to declare which component drives updates and
/// then `.on_insert(...).on_remove(...).register()` to install the hooks.
/// Multiple drivers per index are supported — call `register_index` again
/// for a second `driven_by`.
pub struct IndexBuilder<'a, I: Index> {
    world: &'a mut World,
    _marker: PhantomData<fn() -> I>,
}

impl<'a, I: Index> IndexBuilder<'a, I> {
    pub(crate) fn new(world: &'a mut World) -> Self {
        Self {
            world,
            _marker: PhantomData,
        }
    }

    pub fn driven_by<C: Component>(self) -> IndexDriverBuilder<'a, I, C> {
        IndexDriverBuilder {
            world: self.world,
            on_insert: None,
            on_remove: None,
            _marker: PhantomData,
        }
    }
}

/// Typed driver hook before erasure. Carries the concrete index storage
/// and component types so the registration site is type-checked end to
/// end; the closure is erased to `DriverFn` once `register` is called.
type TypedHook<I, C> =
    Box<dyn Fn(&mut <I as Index>::Storage, Address, &C) + Send + Sync>;

/// PhantomData of contravariant (`fn(I) -> C`-style) markers. Keeps the
/// builder invariant over both type params without holding any value.
type IndexDriverMarker<I, C> = PhantomData<(fn() -> I, fn() -> C)>;

/// Second stage of the fluent registration: collect typed hooks before
/// erasing and installing them.
pub struct IndexDriverBuilder<'a, I: Index, C: Component> {
    world: &'a mut World,
    on_insert: Option<TypedHook<I, C>>,
    on_remove: Option<TypedHook<I, C>>,
    _marker: IndexDriverMarker<I, C>,
}

impl<'a, I: Index, C: Component> IndexDriverBuilder<'a, I, C> {
    pub fn on_insert(
        mut self,
        f: impl Fn(&mut I::Storage, Address, &C) + Send + Sync + 'static,
    ) -> Self {
        self.on_insert = Some(Box::new(f));
        self
    }

    pub fn on_remove(
        mut self,
        f: impl Fn(&mut I::Storage, Address, &C) + Send + Sync + 'static,
    ) -> Self {
        self.on_remove = Some(Box::new(f));
        self
    }

    /// Install the driver. Returns the `World` so registration can chain.
    pub fn register(self) -> &'a mut World {
        // Default to a no-op so the user can specify only one side if the
        // index is naturally append-only or remove-only.
        let typed_insert = self
            .on_insert
            .unwrap_or_else(|| Box::new(|_, _, _| {}));
        let typed_remove = self
            .on_remove
            .unwrap_or_else(|| Box::new(|_, _, _| {}));

        let erased_insert: DriverFn = Box::new(move |idx, id, val| {
            let idx = idx
                .as_any_mut()
                .downcast_mut::<I::Storage>()
                .expect("index storage type mismatch");
            let val = val
                .downcast_ref::<C>()
                .expect("component type mismatch in driver");
            typed_insert(idx, id, val);
        });
        let erased_remove: DriverFn = Box::new(move |idx, id, val| {
            let idx = idx
                .as_any_mut()
                .downcast_mut::<I::Storage>()
                .expect("index storage type mismatch");
            let val = val
                .downcast_ref::<C>()
                .expect("component type mismatch in driver");
            typed_remove(idx, id, val);
        });

        let driver = Driver {
            index_type: TypeId::of::<I>(),
            on_insert: erased_insert,
            on_remove: erased_remove,
        };
        self.world
            .drivers_mut()
            .entry(TypeId::of::<C>())
            .or_default()
            .push(driver);
        self.world
    }
}
