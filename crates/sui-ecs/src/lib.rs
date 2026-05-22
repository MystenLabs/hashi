// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local view of Sui onchain state, organized as an ECS-style component
//! store keyed by `sui_sdk_types::Address` (object id).
//!
//! The crate exposes three layers:
//!
//! - [`component`] — the [`Component`] trait and per-type sparse storage.
//! - [`index`] — derived, framework-maintained views over component data.
//! - [`world`] — the [`World`] container and [`MutationBatch`] writer.
//!
//! [`base`] then provides the built-in components and indexes every Sui
//! project will want (the object itself, nested-UID tracking, ownership
//! reverse indexes, type-tag index) along with an `install` helper that
//! wires them onto a fresh `World`.
//!
//! # Example
//!
//! ```ignore
//! use sui_ecs::{World, base};
//!
//! let mut world = World::new();
//! base::install(&mut world);
//!
//! // Apply one transaction's effects.
//! let mut batch = world.batch();
//! batch.insert(object_id, object);
//! batch.insert(object_id, sui_ecs::base::NestedUids(nested.into()));
//! batch.commit();
//!
//! // Query.
//! let owned = world.index::<base::OwnedByAddress>().unwrap();
//! for child in owned.get(&owner_addr) { /* ... */ }
//! ```

pub mod base;
pub mod component;
pub mod index;
pub mod world;

pub use component::Component;
pub use index::{Index, IndexStorage, OneToMany, OneToOne};
pub use world::{MutationBatch, World};
