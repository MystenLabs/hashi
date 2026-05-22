// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Treat `sui_sdk_types::Object` itself as the base metadata component.
//!
//! Everything in `Object` — version, digest, owner, type, contents,
//! previous transaction, storage rebate — is reached by accessor methods,
//! and the canonical SDK type is the single source of truth. We do *not*
//! split this into a separate `ObjectMeta` + `ObjectBytes` pair: the SDK
//! already has the right shape, and a wrapper would only get in the way
//! of indexes and derived components that want to read these fields
//! directly.

use crate::component::Component;

impl Component for sui_sdk_types::Object {}
