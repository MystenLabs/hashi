// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Mutex;

use sui_sdk_types::Address;

use crate::mpc::types::ComplaintRefusal;
use crate::mpc::types::ProtocolTypeIndicator;

#[derive(Default)]
pub(crate) struct IdentifiedBadNodes(Mutex<BTreeMap<u64, BTreeSet<Address>>>);

impl IdentifiedBadNodes {
    pub(crate) fn complaint_refusal(
        &self,
        protocol: ProtocolTypeIndicator,
        epoch: u64,
        caller: &Address,
        dealer: &Address,
    ) -> Option<ComplaintRefusal> {
        if protocol != ProtocolTypeIndicator::NonceGeneration {
            return None;
        }
        if caller == dealer {
            return Some(ComplaintRefusal::OwnDealing);
        }
        self.contains(epoch, caller)
            .then_some(ComplaintRefusal::Flagged)
    }

    pub(crate) fn contains(&self, epoch: u64, caller: &Address) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(&epoch)
            .is_some_and(|flagged| flagged.contains(caller))
    }

    pub(crate) fn insert(&self, epoch: u64, caller: Address) {
        let mut flagged = self.0.lock().unwrap();
        flagged.retain(|&flagged_epoch, _| flagged_epoch >= epoch);
        flagged.entry(epoch).or_default().insert(caller);
    }
}
