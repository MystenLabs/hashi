// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Nested-UID tracking.
//!
//! A Sui Move struct can embed additional `UID`s inside its fields
//! (think `Bag`, `Table`, or any user-defined struct containing a `UID`).
//! Those embedded UIDs can themselves "own" other objects via the
//! `Owner::Object(uid)` ownership relation that Sui uses for dynamic
//! fields. To trace any owned object back to a user-visible parent, we
//! maintain a lookup from each nested UID to the top-level container's
//! object id.
//!
//! The set of nested UIDs inside a given object is determined by the
//! object's Move type and is stable for the object's lifetime, so we
//! only see (create, delete) transitions — no in-place mutations of the
//! set. The framework exploits this: the `UidToContainer` driver has no
//! update hook, just insert and remove.

use sui_sdk_types::Address;

use crate::component::Component;
use crate::index::{Index, OneToOne};

/// The set of UIDs embedded inside an object's Move struct contents.
///
/// Populated by the ingestion / parsing layer (not the framework itself,
/// since extracting nested UIDs requires the package registry to walk
/// the Move struct schema). Once populated for an entity, the set is
/// stable until the entity is deleted.
#[derive(Debug, Clone)]
pub struct NestedUids(pub Box<[Address]>);

impl Component for NestedUids {}

/// Reverse index: nested UID → top-level container object id.
///
/// Look up any UID you find in an `Owner::Object(uid)` field; if it's a
/// nested UID (i.e. embedded inside some other object rather than the
/// id of a top-level object itself), this resolves to the user-visible
/// parent.
pub struct UidToContainer;

impl Index for UidToContainer {
    type Storage = OneToOne<Address, Address>;
}
