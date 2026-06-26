// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Out-of-enclave gRPC proxy for the hashi guardian. Forwards every
//! `GuardianService` RPC to the enclave and caches `StandardWithdrawal`
//! responses by `wid` for idempotency. See [`cache`] and [`forward`].

pub mod cache;
pub mod config;
pub mod forward;

pub use cache::CachingGuardianGrpc;
pub use config::Config;
pub use forward::Forwarding;
