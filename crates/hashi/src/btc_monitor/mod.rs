// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin monitoring library for the Hashi system.
//!
//! This crate provides functionality for monitoring the Bitcoin network
//! and verifying specific transactions.

pub mod config;
pub mod monitor;

pub use kyoto::TrustedPeer;
