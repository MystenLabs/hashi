// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ownership indexes.
//!
//! Sui's `Owner` enum mixes several distinct kinds of ownership (by
//! address, by parent object, shared, immutable, consensus-sequenced).
//! Rather than expose a single index keyed by the whole enum — which
//! makes queries awkward and groups together cases callers usually want
//! to handle separately — we split it into two purpose-built indexes:
//!
//! - [`OwnedByAddress`]: which objects does an address own? Folds in
//!   both `Owner::Address` and `Owner::ConsensusAddress { owner, .. }`,
//!   since from the caller's point of view both are "owned by this
//!   account".
//! - [`OwnedByObject`]: which objects does some parent (top-level
//!   object *or* nested UID) directly own? When the key is a nested UID
//!   you can chase it up to the top-level container via
//!   [`UidToContainer`](super::nesting::UidToContainer).
//!
//! Shared and immutable objects don't appear in either — they have no
//! single owning address or parent. If you need "all shared objects",
//! that's a separate index worth adding later.

use sui_sdk_types::Address;

use crate::index::{Index, OneToMany};

pub struct OwnedByAddress;

impl Index for OwnedByAddress {
    type Storage = OneToMany<Address, Address>;
}

pub struct OwnedByObject;

impl Index for OwnedByObject {
    type Storage = OneToMany<Address, Address>;
}
