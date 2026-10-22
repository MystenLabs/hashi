// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod btc;
pub mod guardian;
pub mod sui;

use hashi_types::guardian::time::UnixSeconds;

/// Report time progress separately from the next source position.
pub trait PollCursor {
    type Position;

    /// All monitored items before this timestamp have been read.
    fn read_until(&self) -> UnixSeconds;

    /// The position where the next poll starts.
    fn next_item_to_poll(&self) -> Self::Position;
}
