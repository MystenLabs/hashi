// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian S3 log protocol.
//!
//! This facade keeps the public log types together while the implementation is
//! split into explicit `log_*` files beside the rest of the S3 types.
//! `log_messages` holds the message families the enclave emits; `log_record`
//! holds the `LogRecord` wrapper written to S3 and its keying/signing;
//! [`crate::guardian::CeremonyState`] combines the ceremony and KP-share
//! messages for readers. The S3 layout and object-lock configuration live in
//! `log_layout` and `config`, respectively. See
//! `crates/hashi-guardian/README.md` for the canonical key layout.
//!
//! Writers call `LogRecord::new()`, which finalizes the key pattern exactly
//! once, stores the resulting key, and uses it for signing and upload. Readers
//! either fetch a deterministic record using `object_key()` or list records in
//! `object_key_dir()`. In both paths, the S3 client rejects a record unless its
//! signed key matches the actual key returned by S3.

pub use super::log_layout::*;
pub use super::log_messages::*;
pub use super::log_record::*;
pub use super::log_schema::*;
