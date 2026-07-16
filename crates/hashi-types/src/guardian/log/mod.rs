// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian S3 logs. `message` holds the `LogMessage` family the enclave emits;
//! `envelope` holds the `LogRecord` wrapper written to S3 and its keying/signing;
//! `ceremony_state` combines the ceremony and KP-share messages for readers.
//! The S3 layout constants (stream prefixes + object-lock durations) live here so
//! the whole key/lock scheme reads from one place. See
//! `crates/hashi-guardian/README.md` for the canonical key layout.

pub mod ceremony_state;
pub mod envelope;
pub mod message;

pub use ceremony_state::*;
pub use envelope::*;
pub use message::*;

use std::time::Duration;

/// Object lock durations used for S3 log objects.
///
/// These are public so that external verifiers/monitors can apply the same expectations.
///
/// TODO: Uniform 7 days is a coarse placeholder. Revisit per-log-type
/// against the SLO we actually want to defend — heartbeats could be shorter,
/// ceremony/withdraws likely want years.
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const ONE_WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const S3_OBJECT_LOCK_DURATION_INIT: Duration = ONE_WEEK;
pub const S3_OBJECT_LOCK_DURATION_WITHDRAW: Duration = ONE_WEEK;
pub const S3_OBJECT_LOCK_DURATION_HEARTBEAT: Duration = ONE_WEEK;
pub const S3_OBJECT_LOCK_DURATION_CEREMONY: Duration = ONE_WEEK;
pub const S3_OBJECT_LOCK_DURATION_COMMITTEE_UPDATE: Duration = ONE_WEEK;
pub const S3_OBJECT_LOCK_DURATION_GENESIS: Duration = ONE_WEEK;
/// Shares carry their own enclave signature, so the lock isn't for integrity —
/// it only guarantees a window in which the operator can't purge them before KPs
/// fetch. Short on purpose; they stay readable after expiry until deleted.
pub const S3_OBJECT_LOCK_DURATION_KP_SHARES: Duration = ONE_DAY;

/// S3 sub-prefixes used for guardian log streams.
/// See `crates/hashi-guardian/README.md` for canonical key layout.
pub const S3_DIR_INIT: &str = "init";
pub const S3_DIR_WITHDRAW: &str = "withdraw";
pub const S3_DIR_HEARTBEAT: &str = "heartbeat";
pub const S3_DIR_CEREMONY: &str = "ceremony";
pub const S3_DIR_KP_SHARES: &str = "kp-shares";
pub const S3_DIR_COMMITTEE_UPDATE: &str = "committee-update";
pub const S3_DIR_GENESIS: &str = "genesis";
