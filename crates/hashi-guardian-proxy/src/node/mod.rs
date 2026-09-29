// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What hashi nodes call. `StandardWithdrawal` is answered idempotently by wid
//! ([`cache`], over the guardian's withdrawal log in [`widlog`]).

pub mod cache;
pub mod widlog;
