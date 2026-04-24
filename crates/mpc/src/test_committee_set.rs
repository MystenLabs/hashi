// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use hashi_types::committee::Committee;

use crate::committee_view::CommitteeSetView;

#[derive(Default)]
pub struct TestCommitteeSet {
    pub epoch: u64,
    pub pending_epoch_change: Option<u64>,
    pub committees: BTreeMap<u64, Committee>,
}

impl TestCommitteeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    pub fn set_pending_epoch_change(&mut self, pending: Option<u64>) -> &mut Self {
        self.pending_epoch_change = pending;
        self
    }

    pub fn set_committees(&mut self, committees: BTreeMap<u64, Committee>) -> &mut Self {
        self.committees = committees;
        self
    }

    pub fn current_committee(&self) -> Option<&Committee> {
        self.committees.get(&self.epoch)
    }

    pub fn previous_committee(&self) -> Option<&Committee> {
        self.epoch
            .checked_sub(1)
            .and_then(|prev| self.committees.get(&prev))
    }
}

impl CommitteeSetView for TestCommitteeSet {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn pending_epoch_change(&self) -> Option<u64> {
        self.pending_epoch_change
    }

    fn committees(&self) -> &BTreeMap<u64, Committee> {
        &self.committees
    }
}
