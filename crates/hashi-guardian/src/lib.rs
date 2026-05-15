// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

// TODO: Leave as consts or make them configurable?
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(1);
pub const HEARTBEAT_RETRY_INTERVAL: Duration = Duration::from_secs(10);
pub const MAX_HEARTBEAT_FAILURES_INTERVAL: Duration = Duration::from_mins(5);

pub mod enclave;
pub mod getters;
pub mod heartbeat;
pub mod init;
pub mod rpc;
pub mod s3_logger; // used by the monitor
pub mod setup;
pub mod withdraw;

#[cfg(feature = "non-enclave-dev")]
pub mod dev_bootstrap;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use enclave::Enclave;
pub use s3_logger::S3Logger;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::create_fully_initialized_enclave;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::create_operator_initialized_enclave;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::mock_logger;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::FullyInitializedArgs;
#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::OperatorInitTestArgs;
