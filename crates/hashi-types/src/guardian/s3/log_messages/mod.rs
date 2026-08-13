// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian log message families and their per-message S3 object-key rules.
//!
//! Every message type exposes `object_key_pattern()`.
//! Types with deterministic keys also expose `object_key()`, which returns the
//! complete bucket-relative key. Types supporting batch reads may additionally
//! expose `object_key_dir()`, a slash-terminated S3 key prefix.

mod ceremony;
mod committee_update;
mod genesis;
mod heartbeat;
mod init;
mod kp_share;
mod withdrawal;

pub use ceremony::*;
pub use committee_update::*;
pub use genesis::*;
pub use heartbeat::*;
pub use init::*;
pub use kp_share::*;
pub use withdrawal::*;
