// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The events the monitor follows, their ids, and the cursors of its sources.
pub mod domain;

/// The bridge keys and the addresses they derive.
pub mod keys;

/// Timestamps and durations as the monitor prints and parses them.
pub mod time;

/// The withdrawal and deposit state machines.
pub mod state_machine;

/// The auditor core and the continuous auditor.
pub mod audit;

/// The Sui, guardian S3 and Bitcoin pollers.
pub mod rpc;

/// The YAML config file: the identity of one deployment.
pub mod config;

/// Timing bounds of the withdrawal and deposit flows.
pub mod timing;

/// The findings the monitor reports.
pub mod findings;

/// Prometheus metrics for continuous audits.
pub mod metrics;

/// The snapshot a continuous audit resumes from after a restart.
pub mod store;

/// Fixtures shared by the test modules.
#[cfg(test)]
pub(crate) mod test_utils;
