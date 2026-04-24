// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use hashi_types::committee::Committee;

pub trait CommitteeSetView {
    fn epoch(&self) -> u64;
    fn pending_epoch_change(&self) -> Option<u64>;
    fn committees(&self) -> &BTreeMap<u64, Committee>;
}
