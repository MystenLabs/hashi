// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Built-in components and indexes.
//!
//! These cover the ownership and type-tag views every Sui-state-tracking
//! project will want. The [`install`] function registers all of them
//! along with the driver wiring that keeps them in sync with `Object`
//! and `NestedUids` writes.

mod nesting;
mod object;
mod ownership;
mod traversal;
mod typed;

pub use nesting::{NestedUids, UidToContainer};
pub use ownership::{OwnedByAddress, OwnedByObject};
pub use traversal::RootedTraversal;
pub use typed::ByType;

use sui_sdk_types::{Address, Object, ObjectType, Owner, StructTag};

use crate::world::World;

/// Register every built-in component and index on `world`, including the
/// driver wiring.
///
/// Idempotent: it's safe to call this on a world that already has some
/// (or all) of the built-ins registered, though duplicate driver
/// registrations would double-fire so don't call it twice in sequence.
pub fn install(world: &mut World) {
    world.register::<Object>();
    world.register::<NestedUids>();

    install_owned_by_address(world);
    install_owned_by_object(world);
    install_by_type(world);
    install_uid_to_container(world);
}

fn install_owned_by_address(world: &mut World) {
    world
        .register_index::<OwnedByAddress>()
        .driven_by::<Object>()
        .on_insert(|idx, id, obj| {
            if let Some(addr) = owning_address(obj.owner()) {
                idx.add(addr, id);
            }
        })
        .on_remove(|idx, id, obj| {
            if let Some(addr) = owning_address(obj.owner()) {
                idx.remove(&addr, &id);
            }
        })
        .register();
}

fn install_owned_by_object(world: &mut World) {
    world
        .register_index::<OwnedByObject>()
        .driven_by::<Object>()
        .on_insert(|idx, id, obj| {
            if let Owner::Object(parent) = obj.owner() {
                idx.add(*parent, id);
            }
        })
        .on_remove(|idx, id, obj| {
            if let Owner::Object(parent) = obj.owner() {
                idx.remove(parent, &id);
            }
        })
        .register();
}

fn install_by_type(world: &mut World) {
    world
        .register_index::<ByType>()
        .driven_by::<Object>()
        .on_insert(|idx, id, obj| {
            if let Some(tag) = struct_tag(obj) {
                idx.add(tag, id);
            }
        })
        .on_remove(|idx, id, obj| {
            if let Some(tag) = struct_tag(obj) {
                idx.remove(&tag, &id);
            }
        })
        .register();
}

fn install_uid_to_container(world: &mut World) {
    // Stable per-entity: the set of embedded UIDs is fixed for an
    // object's lifetime, so this driver only ever sees the create / delete
    // transitions — no update hook needed.
    world
        .register_index::<UidToContainer>()
        .driven_by::<NestedUids>()
        .on_insert(|idx, container, nested| {
            for uid in nested.0.iter() {
                idx.insert(*uid, container);
            }
        })
        .on_remove(|idx, _container, nested| {
            for uid in nested.0.iter() {
                idx.remove(uid);
            }
        })
        .register();
}

/// Project an `Owner` down to the owning address, if any. Folds in the
/// consensus-address variant; returns `None` for shared, immutable, and
/// object-owned cases (which are handled by other indexes).
fn owning_address(owner: &Owner) -> Option<Address> {
    // `Owner` is `#[non_exhaustive]` so the wildcard arm is required
    // even though we cover every variant defined today.
    match owner {
        Owner::Address(a) | Owner::ConsensusAddress { owner: a, .. } => Some(*a),
        Owner::Object(_) | Owner::Shared(_) | Owner::Immutable => None,
        _ => None,
    }
}

fn struct_tag(obj: &Object) -> Option<StructTag> {
    match obj.object_type() {
        ObjectType::Struct(tag) => Some(tag),
        ObjectType::Package => None,
    }
}
