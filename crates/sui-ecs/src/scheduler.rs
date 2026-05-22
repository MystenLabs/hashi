// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Reactive scheduler for derived components.
//!
//! A *derived* component is one whose value is computed from other
//! components (base or derived) rather than written directly by user
//! code. Derivations are registered with [`World::register_derived`] and
//! recomputed automatically when their inputs change.
//!
//! Concretely, every time a [`MutationBatch`](crate::MutationBatch) is
//! committed:
//!
//! 1. The scheduler drains the per-storage dirty sets to find which
//!    entities changed for which component types.
//! 2. It walks the *dependents* map to translate "entity E's component C
//!    changed" into "every derivation that reads C needs to recompute for
//!    E".
//! 3. It processes derivations in topological order, so a derivation `D`
//!    that depends on another derivation `B` always sees `B`'s updated
//!    value.
//! 4. After each derivation runs, any new dirty entries on its own
//!    storage are propagated forward to its dependents.
//!
//! The dependency graph is a DAG by construction — cycles panic at the
//! point of detection so they fail loudly in tests rather than diverging
//! silently at runtime.

use std::any::TypeId;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use sui_sdk_types::Address;

use crate::component::Component;
use crate::world::World;

/// A component whose value is derived from other components.
///
/// `compute` may return `None` to signal "no value for this entity right
/// now" — the framework will remove any existing value of `Self` for that
/// entity, which in turn dirties downstream derivations.
///
/// `dependencies()` must return the same list every time it's called; the
/// framework caches the dependency graph and assumes it's stable.
pub trait Derived: Component {
    fn dependencies() -> Vec<TypeId>;

    fn compute(world: &World, entity: Address) -> Option<Self>;
}

/// Erased recompute callback. Captures the concrete `D` so the World can
/// store a uniform `Arc<dyn Fn>` per derivation regardless of type.
pub(crate) type RecomputeFn = Arc<dyn Fn(&mut World, Address) + Send + Sync>;

pub(crate) struct Derivation {
    pub(crate) deps: Vec<TypeId>,
    pub(crate) recompute: RecomputeFn,
}

impl Derivation {
    pub(crate) fn new<D: Derived>() -> Self {
        Self {
            deps: D::dependencies(),
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

/// Topologically sort registered derivations so a derivation appears in
/// the returned order *after* any other derivation it depends on.
///
/// Base components (those without an entry in `derivations`) don't
/// participate in the ordering — only derivation-to-derivation edges
/// contribute. Panics if a cycle is detected.
pub(crate) fn topo_sort(derivations: &HashMap<TypeId, Derivation>) -> Vec<TypeId> {
    let mut in_degree: HashMap<TypeId, usize> =
        derivations.keys().map(|k| (*k, 0)).collect();
    let mut adj: HashMap<TypeId, Vec<TypeId>> =
        derivations.keys().map(|k| (*k, Vec::new())).collect();

    for (derived, d) in derivations {
        for dep in &d.deps {
            if derivations.contains_key(dep) {
                adj.get_mut(dep)
                    .expect("derivations key present by construction")
                    .push(*derived);
                *in_degree
                    .get_mut(derived)
                    .expect("derivations key present by construction") += 1;
            }
        }
    }

    let mut queue: VecDeque<TypeId> = in_degree
        .iter()
        .filter_map(|(k, deg)| (*deg == 0).then_some(*k))
        .collect();
    let mut order: Vec<TypeId> = Vec::with_capacity(derivations.len());

    while let Some(node) = queue.pop_front() {
        order.push(node);
        let nexts = adj
            .get(&node)
            .expect("derivations key present by construction")
            .clone();
        for next in nexts {
            let d = in_degree
                .get_mut(&next)
                .expect("derivations key present by construction");
            *d -= 1;
            if *d == 0 {
                queue.push_back(next);
            }
        }
    }

    assert_eq!(
        order.len(),
        derivations.len(),
        "cycle detected in derivation graph"
    );
    order
}
