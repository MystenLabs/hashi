// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Normalized event types and findings.
pub mod domain;

/// Withdrawal state machine.
pub mod state_machine;

/// Auditor implementations.
pub mod audit;

/// RPC and S3 utilities.
pub mod rpc;

/// CLI config types.
pub mod config;

/// Timing bounds of the withdrawal and deposit flows.
pub mod timing;

/// Domain findings emitted by the monitor.
pub mod findings;

/// Prometheus metrics for continuous audits.
pub mod metrics;

pub use hashi_types::bitcoin::ExternalOutputUTXOWire as OutputUTXO;
