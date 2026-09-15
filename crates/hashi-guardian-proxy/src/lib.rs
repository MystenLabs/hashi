// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Out-of-enclave gRPC proxy for the hashi guardian. It fronts the enclave with
//! a stable, hardenable surface:
//!
//! - [`forward`] forwards the node-facing `GuardianService` RPCs to the
//!   enclave, rejecting operator/ceremony RPCs. `StandardWithdrawal` passes
//!   through unchanged: the enclave itself replays a retried withdrawal.
//! - [`relay`] serves `GuardianRelayService`: key provisioners submit one share
//!   each — authenticated against the ceremony's committed roster read from the
//!   S3 share log ([`roster`], over [`log_store`]) — and the relay batches a
//!   threshold-many into the guardian's `ProvisionerInit`.
//! - [`info`] serves a read-only HTTP `/info` + `/health` JSON surface (a
//!   curated limiter/identity view, with CORS) so browser / `fetch` clients can
//!   read limiter status the gRPC surface only exposes to nodes — on the same
//!   port as gRPC, so the guardian exposes one interface.
//!
//! The proxy is liveness-only in the trust model: it can stall but never forge a
//! withdrawal or read a KP share (shares are end-to-end encrypted to the enclave).

pub mod config;
pub mod forward;
pub mod info;
pub mod log_store;
pub mod relay;
pub mod roster;

pub use config::Config;
pub use forward::Forwarding;
pub use relay::Relay;
