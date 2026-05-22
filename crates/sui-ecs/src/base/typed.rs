// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Type-tag index — "all objects of this Move type".

use sui_sdk_types::{Address, StructTag};

use crate::index::{Index, OneToMany};

/// Reverse index: Move struct type → set of objects with that type.
///
/// Drops packages (which have no struct tag); only struct-typed objects
/// appear here.
pub struct ByType;

impl Index for ByType {
    type Storage = OneToMany<StructTag, Address>;
}
