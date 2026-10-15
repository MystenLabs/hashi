// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One function per operator step. Each reads what it acts on fresh, checks it, asks before changing anything, acts,
//! and checks the result.

pub mod inspect;
