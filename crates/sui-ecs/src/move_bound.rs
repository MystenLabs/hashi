// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `MoveBound` — Rust types that mirror Move structs on Sui.
//!
//! Sui's [`MoveStruct`](sui_sdk_types::MoveStruct) only carries a struct
//! tag and the BCS bytes of the encoded value. To work with that value
//! field-by-field in Rust, you implement [`MoveBound`] on a struct that
//! mirrors the on-chain layout. Every such type is then automatically a
//! [`Derived`] component: register it once with
//! [`World::register_derived`](crate::World::register_derived) and the
//! scheduler keeps a parsed copy in sync with the underlying `Object`.
//!
//! There is no dynamic, [`StructTag`]-keyed component family — each
//! Move type the project cares about is one Rust type, one Component,
//! one derivation. The framework doesn't need to know about Move types
//! that no one has bound; it only spends work parsing the bytes for
//! types that have been explicitly registered.
//!
//! # Example
//!
//! ```ignore
//! use sui_sdk_types::{Address, Identifier, StructTag};
//! use sui_ecs::{Component, MoveBound, World};
//!
//! #[derive(serde::Deserialize)]
//! struct MyCoin {
//!     id: Address,   // every Sui object's first field is its UID
//!     value: u64,
//! }
//!
//! impl Component for MyCoin {}
//!
//! impl MoveBound for MyCoin {
//!     fn struct_tag() -> StructTag {
//!         StructTag::new(
//!             Address::TWO,
//!             Identifier::new("my_coin").unwrap(),
//!             Identifier::new("MyCoin").unwrap(),
//!             vec![],
//!         )
//!     }
//!     fn parse(bytes: &[u8]) -> Option<Self> {
//!         bcs::from_bytes(bytes).ok()
//!     }
//! }
//!
//! let mut world = World::new();
//! world.register::<sui_sdk_types::Object>();
//! world.register_derived::<MyCoin>();
//! ```

use std::any::TypeId;

use sui_sdk_types::{Address, ObjectType, StructTag};

use crate::component::Component;
use crate::scheduler::Derived;
use crate::world::World;

/// A Rust type that mirrors a specific Move struct.
///
/// Implementors must also implement [`Component`] (so the framework can
/// store parsed values) and must return the same `struct_tag()` on every
/// call (so the scheduler's type-match check is stable).
pub trait MoveBound: Component {
    /// The Move struct tag this type mirrors.
    fn struct_tag() -> StructTag;

    /// Parse a value of this type from the BCS bytes of a Sui object's
    /// Move struct contents. Returning `None` signals a parse failure;
    /// the framework will drop any prior parsed value for the entity.
    ///
    /// The first 32 bytes of `bytes` are the object's id (the embedded
    /// `UID`'s address). Implementations that mirror Sui Move structs
    /// usually include a leading `id: Address` (or `UID`) field so that
    /// `bcs::from_bytes` deserializes against the full buffer.
    fn parse(bytes: &[u8]) -> Option<Self>;
}

/// Blanket Derived impl: every `MoveBound` is automatically a derived
/// component depending on `sui_sdk_types::Object`. Registering the type
/// with `World::register_derived` is enough to wire it up.
impl<M: MoveBound> Derived for M {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<sui_sdk_types::Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let object = world.get::<sui_sdk_types::Object>(entity)?;
        let move_struct = object.as_struct()?;
        // Cheap pre-check before we burn cycles on a BCS round-trip.
        let object_type = object.object_type();
        let ObjectType::Struct(tag) = &object_type else {
            return None;
        };
        if tag != &M::struct_tag() {
            return None;
        }
        M::parse(move_struct.contents())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_derive::{Deserialize, Serialize};
    use sui_sdk_types::{
        Digest, Identifier, MoveStruct, Object, ObjectData, Owner,
    };

    /// Rust mirror of a hypothetical Move struct:
    ///
    /// ```move
    /// module 0x2::test_coin {
    ///     struct TestCoin has key { id: UID, value: u64 }
    /// }
    /// ```
    ///
    /// In BCS, `UID { id: ID { bytes: address } }` flattens to the 32
    /// address bytes, so the struct serializes as 32-byte id followed by
    /// 8-byte little-endian value.
    #[derive(Debug, Serialize, Deserialize)]
    struct TestCoin {
        id: Address,
        value: u64,
    }

    impl Component for TestCoin {}

    impl MoveBound for TestCoin {
        fn struct_tag() -> StructTag {
            StructTag::new(
                Address::TWO,
                Identifier::new("test_coin").unwrap(),
                Identifier::new("TestCoin").unwrap(),
                Vec::new(),
            )
        }

        fn parse(bytes: &[u8]) -> Option<Self> {
            bcs::from_bytes(bytes).ok()
        }
    }

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    fn make_object(id: Address, value: u64) -> Object {
        let coin = TestCoin { id, value };
        let contents = bcs::to_bytes(&coin).expect("bcs encode");
        let move_struct = MoveStruct::new(
            TestCoin::struct_tag(),
            true,
            1,
            contents,
        )
        .expect("contents include valid object id");
        Object::new(
            ObjectData::Struct(move_struct),
            Owner::Address(addr(0xAA)),
            Digest::ZERO,
            0,
        )
    }

    #[test]
    fn move_bound_derives_from_object() {
        let mut world = World::new();
        world.register::<Object>();
        world.register_derived::<TestCoin>();

        let id = addr(0x11);
        world.insert::<Object>(id, make_object(id, 100));

        let parsed = world.get::<TestCoin>(id).expect("TestCoin derived");
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.value, 100);
    }

    #[test]
    fn move_bound_updates_when_object_changes() {
        let mut world = World::new();
        world.register::<Object>();
        world.register_derived::<TestCoin>();

        let id = addr(0x22);
        world.insert::<Object>(id, make_object(id, 100));
        assert_eq!(world.get::<TestCoin>(id).map(|c| c.value), Some(100));

        world.insert::<Object>(id, make_object(id, 200));
        assert_eq!(world.get::<TestCoin>(id).map(|c| c.value), Some(200));
    }

    #[test]
    fn move_bound_skips_objects_of_other_types() {
        let mut world = World::new();
        world.register::<Object>();
        world.register_derived::<TestCoin>();

        // Build an object whose StructTag is *different* from TestCoin.
        let id = addr(0x33);
        let other_tag = StructTag::new(
            Address::TWO,
            Identifier::new("other").unwrap(),
            Identifier::new("Other").unwrap(),
            Vec::new(),
        );
        let other_struct = MoveStruct::new(
            other_tag,
            true,
            1,
            id.as_bytes().to_vec(),
        )
        .unwrap();
        let other_obj = Object::new(
            ObjectData::Struct(other_struct),
            Owner::Address(addr(0xAA)),
            Digest::ZERO,
            0,
        );

        world.insert::<Object>(id, other_obj);

        assert!(
            world.get::<TestCoin>(id).is_none(),
            "TestCoin should not derive from a different Move type"
        );
    }

    #[test]
    fn move_bound_removed_when_object_removed() {
        let mut world = World::new();
        world.register::<Object>();
        world.register_derived::<TestCoin>();

        let id = addr(0x44);
        world.insert::<Object>(id, make_object(id, 100));
        assert!(world.contains::<TestCoin>(id));

        world.remove::<Object>(id);
        assert!(!world.contains::<TestCoin>(id));
    }
}
