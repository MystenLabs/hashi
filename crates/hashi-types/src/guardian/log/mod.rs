// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian S3 logs. `messages` holds the message families the enclave emits;
//! `record` holds the `LogRecord` wrapper written to S3 and its keying/signing;
//! `ceremony_state` combines the ceremony and KP-share messages for readers.
//! The S3 layout constants live here, while object-lock durations live in
//! `retention`. See `crates/hashi-guardian/README.md` for the canonical key
//! layout.
//!
//! Writers call `LogRecord::new()`, which finalizes the pattern exactly once,
//! stores the resulting key, and uses it for signing and upload.
//! Readers either fetch a deterministic record using `object_key()` or list
//! records in `object_key_dir()`. In both read paths, the S3 client rejects a
//! record unless its signed key matches the actual key returned by S3.

pub mod ceremony_state;
pub mod messages;
pub mod record;
pub mod retention;
pub mod schema;

pub use ceremony_state::*;
pub use messages::*;
pub use record::*;
pub use retention::*;
pub use schema::*;

pub enum ObjectKeyPattern {
    Fixed(String),
    /// Complete key prefix before the random suffix; finalize() appends the suffix.
    RandomSuffix(String),
}

pub(super) enum LogType {
    Heartbeat,
    Init,
    Withdrawal,
    Ceremony,
    KpShareState,
    CommitteeUpdate,
    Genesis,
}

impl ObjectKeyPattern {
    /// Finalizes the pattern into the complete S3 object key.
    pub fn finalize(self) -> String {
        match self {
            Self::Fixed(key) => key,
            Self::RandomSuffix(prefix) => {
                format!("{prefix}{:08x}.json", rand::random::<u32>())
            }
        }
    }
}

/// S3 sub-prefixes used for guardian log streams.
/// See `crates/hashi-guardian/README.md` for canonical key layout.
pub const S3_DIR_INIT: &str = "init";
pub const S3_DIR_WITHDRAW: &str = "withdraw";
pub const S3_DIR_HEARTBEAT: &str = "heartbeat";
pub const S3_DIR_CEREMONY: &str = "ceremony";
pub const S3_DIR_KP_SHARES: &str = "kp-shares";
pub const S3_DIR_COMMITTEE_UPDATE: &str = "committee-update";
pub const S3_DIR_GENESIS: &str = "genesis";
