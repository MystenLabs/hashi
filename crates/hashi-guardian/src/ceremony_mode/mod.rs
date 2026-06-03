// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ceremony-mode flows (enabled when CEREMONY_MODE=true): one-time key setup
//! (`setup_new_key`) and rotation (`rotate_kps`). The shared `operator_init`
//! and `get_guardian_info` live at the crate root.

pub mod rotate;
pub mod setup;
