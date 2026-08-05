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

/// Domain findings emitted by the monitor.
pub mod findings;

pub use hashi_types::bitcoin::ExternalOutputUTXOWire as OutputUTXO;
