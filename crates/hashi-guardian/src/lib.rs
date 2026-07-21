// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

/// Interval between successful heartbeat writes.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(1);
/// Maximum write failure interval before the enclave aborts.
pub const MAX_S3_WRITE_FAILURE_INTERVAL: Duration = Duration::from_mins(5);
/// The live session's latest heartbeat must be at most 3 minutes old.
pub const LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE: Duration = Duration::from_mins(3);
/// Silence required before another session is considered inactive.
pub const OTHER_SESSION_QUIET_PERIOD: Duration = Duration::from_mins(10);

// An enclave that cannot write its next heartbeat must abort before another
// session is allowed to treat it as quiet.
const _: () = assert!(
    HEARTBEAT_INTERVAL.as_secs() + MAX_S3_WRITE_FAILURE_INTERVAL.as_secs()
        < OTHER_SESSION_QUIET_PERIOD.as_secs()
);

pub mod attestation;
pub mod ceremony_mode;
pub mod enclave;
pub mod info;
pub mod operator_activate;
pub mod operator_init;
pub mod rpc;
pub mod s3_client; // used by the monitor
pub mod s3_reader; // verified read layer; used by the monitor + init tooling
pub mod withdraw_mode;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use enclave::Enclave;
pub use s3_client::GuardianS3Client;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::activate_enclave_for_testing;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::create_fully_initialized_enclave;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::create_operator_initialized_enclave;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::mock_logger;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::mock_logger_capturing;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::mock_logger_with_layout;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::FullyInitializedArgs;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::OperatorInitTestArgs;
