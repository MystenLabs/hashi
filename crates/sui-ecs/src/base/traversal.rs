// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Root-rooted traversal helpers.
//!
//! Built on the [`OwnedByObject`](super::OwnedByObject) and
//! [`NestedUids`](super::NestedUids) indexes/components — i.e. these
//! methods only work on a `World` that has [`base::install`](super::install)
//! applied (or the equivalent registrations).
//!
//! A Sui container can own children in two ways:
//!
//! 1. Directly — the child's `Owner::Object(parent_id)` is the
//!    container's top-level object id.
//! 2. Via a nested `UID` — the child is owned by a `UID` embedded inside
//!    the container (typical of dynamic fields / dynamic object fields,
//!    `Bag`, `Table`, etc.).
//!
//! Both kinds are unified here: `children_of` returns every direct child
//! regardless of whether it hangs off the container's id or one of its
//! nested UIDs. `descendants_of` then walks transitively.

use std::collections::HashSet;

use sui_sdk_types::Address;

use crate::world::World;

use super::{NestedUids, OwnedByObject};

/// Extension trait providing root-rooted traversal helpers over a
/// `World` with the built-in components and indexes installed.
pub trait RootedTraversal {
    /// Every object directly owned by `parent`, including objects owned
    /// by any UID nested inside `parent` (e.g. dynamic fields). Does
    /// *not* include `parent` itself.
    fn children_of(&self, parent: Address) -> Vec<Address>;

    /// `parent` plus every object reachable from it through repeated
    /// application of [`children_of`]. Detects cycles via a visited set
    /// so it's safe to call on graphs that contain back-edges.
    fn descendants_of(&self, parent: Address) -> Vec<Address>;
}

impl RootedTraversal for World {
    fn children_of(&self, parent: Address) -> Vec<Address> {
        let Some(owned) = self.index::<OwnedByObject>() else {
            return Vec::new();
        };

        let mut out: Vec<Address> = owned.get(&parent).copied().collect();
        if let Some(nested) = self.get::<NestedUids>(parent) {
            for uid in nested.0.iter() {
                out.extend(owned.get(uid).copied());
            }
        }
        out
    }

    fn descendants_of(&self, parent: Address) -> Vec<Address> {
        let mut visited = HashSet::new();
        let mut stack = vec![parent];
        let mut out = Vec::new();
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            out.push(id);
            // Push in reverse so that a typical DFS visit order matches
            // the iteration order of `children_of`.
            for child in self.children_of(id).into_iter().rev() {
                stack.push(child);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sui_sdk_types::{Digest, Identifier, MoveStruct, Object, ObjectData, Owner, StructTag};

    use crate::base;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    /// Build a minimal `Object` whose owner is `Owner::Object(parent)`.
    /// The struct contents are just the object's own id, which is the
    /// minimum BCS payload `MoveStruct` will accept.
    fn child_object(id: Address, parent: Address) -> Object {
        let tag = StructTag::new(
            Address::TWO,
            Identifier::new("test").unwrap(),
            Identifier::new("Child").unwrap(),
            Vec::new(),
        );
        let move_struct = MoveStruct::new(tag, true, 1, id.as_bytes().to_vec()).unwrap();
        Object::new(
            ObjectData::Struct(move_struct),
            Owner::Object(parent),
            Digest::ZERO,
            0,
        )
    }

    /// Same as above but owner is an address (so it shouldn't appear as
    /// anyone's child via `OwnedByObject`).
    fn address_owned(id: Address) -> Object {
        let tag = StructTag::new(
            Address::TWO,
            Identifier::new("test").unwrap(),
            Identifier::new("Loose").unwrap(),
            Vec::new(),
        );
        let move_struct = MoveStruct::new(tag, true, 1, id.as_bytes().to_vec()).unwrap();
        Object::new(
            ObjectData::Struct(move_struct),
            Owner::Address(addr(0xFF)),
            Digest::ZERO,
            0,
        )
    }

    fn world_with_base() -> World {
        let mut w = World::new();
        base::install(&mut w);
        w
    }

    #[test]
    fn children_of_includes_direct_object_owners() {
        let mut world = world_with_base();
        let root = addr(0x10);
        let kid_a = addr(0x11);
        let kid_b = addr(0x12);
        let unrelated = addr(0x13);

        world.insert::<Object>(kid_a, child_object(kid_a, root));
        world.insert::<Object>(kid_b, child_object(kid_b, root));
        world.insert::<Object>(unrelated, address_owned(unrelated));

        let kids: HashSet<Address> = world.children_of(root).into_iter().collect();
        assert_eq!(kids, [kid_a, kid_b].into_iter().collect());
    }

    #[test]
    fn children_of_follows_nested_uids_for_dynamic_fields() {
        // Layout:
        //   root (top-level object) embeds a UID `inner_uid`.
        //   A "dynamic field" object df is owned by `inner_uid`, not by
        //   the root's id. children_of(root) should still surface df.
        let mut world = world_with_base();
        let root = addr(0x20);
        let inner_uid = addr(0x21);
        let df = addr(0x22);

        // Register the nested UID for root.
        world.insert::<NestedUids>(root, NestedUids(Box::new([inner_uid])));
        // Insert the df owned by inner_uid.
        world.insert::<Object>(df, child_object(df, inner_uid));

        let kids: HashSet<Address> = world.children_of(root).into_iter().collect();
        assert!(kids.contains(&df), "df owned by nested UID should appear");
    }

    #[test]
    fn descendants_of_walks_transitively_and_includes_root() {
        let mut world = world_with_base();
        let root = addr(0x30);
        let mid = addr(0x31);
        let leaf = addr(0x32);

        world.insert::<Object>(mid, child_object(mid, root));
        world.insert::<Object>(leaf, child_object(leaf, mid));

        let all: HashSet<Address> = world.descendants_of(root).into_iter().collect();
        assert_eq!(all, [root, mid, leaf].into_iter().collect());
    }

    #[test]
    fn descendants_of_handles_cycles() {
        // Construct A owns B and B owns A — pathological but the visited
        // set should still terminate the traversal.
        let mut world = world_with_base();
        let a = addr(0x40);
        let b = addr(0x41);

        world.insert::<Object>(a, child_object(a, b));
        world.insert::<Object>(b, child_object(b, a));

        let from_a: HashSet<Address> = world.descendants_of(a).into_iter().collect();
        assert_eq!(from_a, [a, b].into_iter().collect());
    }

    #[test]
    fn children_of_without_base_install_is_empty() {
        // A bare World (no base::install) lacks the OwnedByObject index,
        // so children_of should yield empty rather than panic.
        let world = World::new();
        assert!(world.children_of(addr(1)).is_empty());
    }
}
