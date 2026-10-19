// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One function per operator step. Each reads what it acts on fresh, checks it, asks before changing anything, acts,
//! and checks the result.

use anyhow::Result;

use crate::Ctx;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::stack::Stack;

pub mod inspect;

/// Loads the stack and the slot a step names, or the stack's only one.
fn slot(ctx: &Ctx, arg: Option<Slot>) -> Result<(Stack, SlotView)> {
    let stack = Stack::load(ctx)?;
    let slot = stack.select(arg)?;
    let view = stack.slot(ctx, slot)?;
    Ok((stack, view))
}
