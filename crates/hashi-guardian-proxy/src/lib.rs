// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Out-of-enclave gRPC proxy for the hashi guardian. It fronts the enclave with
//! a stable, hardenable surface:
//!
//! - [`forward`] forwards the node-facing `GuardianService` RPCs to the
//!   enclave (rejecting operator/ceremony RPCs), and [`cache`] wraps it so
//!   `StandardWithdrawal` responses are idempotent by `wid` — an in-process LRU
//!   in front of the guardian's own S3 withdrawal log ([`widlog`]) as the
//!   durable, read-only tier.
//! - [`relay`] serves `GuardianRelayService`: key provisioners submit one share
//!   each and the relay batches a threshold-many into the guardian's
//!   `ProvisionerInit`.
//! - [`info`] serves a read-only HTTP `/info` + `/health` JSON surface (a
//!   curated limiter/identity view, with CORS) so browser / `fetch` clients can
//!   read limiter status that the gRPC surface only exposes to nodes.
//!
//! The proxy is liveness-only in the trust model: it can stall but never forge a
//! withdrawal or read a KP share (shares are end-to-end encrypted to the enclave).

pub mod cache;
pub mod config;
pub mod forward;
pub mod info;
pub mod metrics;
pub mod relay;
pub mod widlog;

pub use cache::CachingGuardianGrpc;
pub use config::Config;
pub use forward::Forwarding;
pub use relay::Relay;
