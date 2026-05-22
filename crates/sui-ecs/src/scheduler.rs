// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Reactive scheduler for derived components.
//!
//! A *derived* component is one whose value is computed from other
//! components (base or derived) rather than written directly by user
//! code. Derivations are registered with
//! [`World::register_derived`](crate::World::register_derived) and
//! recomputed automatically when their inputs change.
//!
//! # Ordering: entity ownership, not component type
//!
//! The scheduler orders recomputes by the Sui object-ownership graph,
//! not by the derivation dependency graph: when a batch commits,
//! children are always recomputed before their parents. This matches
//! the natural direction for aggregating derivations (where a parent's
//! value reads its children's), and re-parenting events propagate to
//! both the old and new parent so they each get a chance to recompute.
//!
//! Same-entity derivation chains (`A → B → C` all at one entity) still
//! converge: the scheduler runs a fixed-point loop and each iteration
//! drains storage dirty sets, so on iteration N+1 the freshly-dirtied
//! downstream derivation gets picked up.
//!
//! Ownership cycles are a bug — the framework panics if it sees one
//! while building the topological order.

use std::any::TypeId;
use std::sync::Arc;

use sui_sdk_types::Address;

use crate::component::Component;
use crate::world::World;

/// A component whose value is derived from other components.
///
/// `compute` may return `None` to signal "no value for this entity right
/// now" — the framework will remove any existing value of `Self` for
/// that entity, which in turn dirties downstream derivations.
///
/// `dependencies()` must return the same list every time it's called;
/// the framework relies on the declaration being stable.
pub trait Derived: Component {
    fn dependencies() -> Vec<TypeId>;

    fn compute(world: &World, entity: Address) -> Option<Self>;

    /// If `true`, the framework treats this derivation as aggregating
    /// over child entities. Any change to a declared dependency at a
    /// child of `E` will dirty this derivation for `E` (rather than for
    /// the child). Re-parenting events additionally dirty the
    /// derivation for both the old and new parent so each gets a chance
    /// to reflect the lost / gained child.
    ///
    /// Children are resolved via `Owner::Object(uid)` lifted through
    /// the built-in `UidToContainer` index, so dynamic fields nested
    /// inside the parent count as children of the container.
    ///
    /// Defaults to `false`; flip it on per-derivation when you actually
    /// fold over children.
    fn aggregates_children() -> bool {
        false
    }
}

/// Erased recompute callback. Captures the concrete `D` so the World
/// can store a uniform `Arc<dyn Fn>` per derivation regardless of type.
pub(crate) type RecomputeFn = Arc<dyn Fn(&mut World, Address) + Send + Sync>;

pub(crate) struct Derivation {
    pub(crate) deps: Vec<TypeId>,
    pub(crate) aggregates_children: bool,
    pub(crate) recompute: RecomputeFn,
}

impl Derivation {
    pub(crate) fn new<D: Derived>() -> Self {
        Self {
            deps: D::dependencies(),
            aggregates_children: D::aggregates_children(),
            recompute: Arc::new(|world, entity| match D::compute(world, entity) {
                Some(value) => {
                    world.apply_insert::<D>(entity, value);
                }
                None => {
                    world.apply_remove::<D>(entity);
                }
            }),
        }
    }
}
