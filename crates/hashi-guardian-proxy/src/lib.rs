// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Out-of-enclave gRPC proxy for the hashi guardian. It fronts the enclave with
//! a stable, hardenable surface. [`forward`] forwards the `GuardianService` RPCs
//! to the enclave, rejecting operator/ceremony RPCs, and [`guardian_info`]
//! caches ordinary `GetGuardianInfo` for every caller. `GetAttestedGuardianInfo`
//! always forwards to the enclave without caching. The rest is grouped by who calls it:
//!
//! - [`node`]: [`node::cache`] makes `StandardWithdrawal` responses idempotent
//!   by `wid` — an in-process LRU in front of the guardian's own S3 withdrawal
//!   log ([`node::widlog`]) as the durable, read-only tier.
//! - [`kp`]: [`kp::relay`] serves `GuardianRelayService`: key provisioners
//!   submit one share each — authenticated against the ceremony's committed
//!   roster read from the S3 share log ([`kp::roster`]) — and the relay batches
//!   a threshold-many into the guardian's `ProvisionerInit`.
//! - [`public`]: [`public::info`] serves a read-only HTTP `/info` + `/health`
//!   JSON surface (a curated limiter/identity view, with CORS) so browser /
//!   `fetch` clients can read limiter status the gRPC surface only exposes to
//!   nodes — on the same port as gRPC, so the guardian exposes one interface.
//!
//! The proxy is liveness-only in the trust model: it can stall but never forge a
//! withdrawal or read a KP share (shares are end-to-end encrypted to the enclave).

pub mod config;
pub mod forward;
pub mod guardian_info;
pub mod kp;
pub mod log_store;
pub mod metrics;
pub mod node;
pub mod public;
pub mod remote_write;

pub use config::Config;
pub use forward::Forwarding;
pub use kp::relay::Relay;
pub use node::cache::CachingGuardianGrpc;
