// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::count_check::AvidShape;
use crate::mpc::count_check::AvssShape;
use crate::mpc::count_check::PartyWeights;
use crate::mpc::types::EncryptionGroupElement;
use crate::mpc::types::ProtocolType;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::types::ShareIndex;
use hashi_types::committee::RuntimeCommittee;
use sui_sdk_types::Address;

#[derive(Clone)]
pub struct CommitteeShape {
    committee: RuntimeCommittee,
    nodes: Nodes<EncryptionGroupElement>,
    weights: Vec<u16>,
    threshold: u16,
    own_party: Option<PartyId>,
}

impl CommitteeShape {
    pub(crate) fn new(
        committee: &RuntimeCommittee,
        nodes: &Nodes<EncryptionGroupElement>,
        threshold: u16,
        own_address: &Address,
    ) -> Self {
        Self {
            committee: committee.clone(),
            nodes: nodes.clone(),
            weights: nodes.iter().map(|node| node.weight).collect(),
            threshold,
            own_party: committee
                .index_of(own_address)
                .map(|index| index as PartyId),
        }
    }

    pub(crate) fn threshold(&self) -> u16 {
        self.threshold
    }

    pub(crate) fn own_party(&self) -> Option<PartyId> {
        self.own_party
    }

    pub(crate) fn party_of(&self, address: &Address) -> Option<PartyId> {
        self.committee
            .index_of(address)
            .map(|index| index as PartyId)
    }

    pub(crate) fn weight_of(&self, party: PartyId) -> u16 {
        self.weights.get(usize::from(party)).copied().unwrap_or(0)
    }

    pub(crate) fn share_ids_of(&self, address: &Address) -> Option<Vec<ShareIndex>> {
        self.party_of(address)
            .and_then(|party| self.nodes.share_ids_of(party).ok())
    }

    pub(crate) fn weights(&self) -> PartyWeights<'_> {
        PartyWeights(&self.weights)
    }

    pub(crate) fn avss_shape(&self) -> AvssShape {
        AvssShape {
            threshold: self.threshold,
            num_nodes: self.weights.len() as u16,
        }
    }

    pub(crate) fn rotation_messages_bcs(&self) -> bool {
        self.committee.config().mpc_rotation_messages_bcs()
    }
}

pub struct ShapeParams {
    epoch: u64,
    previous_epoch: u64,
    protocol_type: ProtocolType,
    batch_size_per_weight: u16,
    min_batch_presigs: u64,
    current: CommitteeShape,
    previous: Option<CommitteeShape>,
    previous_input: Option<CommitteeShape>,
}

impl ShapeParams {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        epoch: u64,
        previous_epoch: u64,
        protocol_type: ProtocolType,
        batch_size_per_weight: u16,
        min_batch_presigs: u64,
        current: CommitteeShape,
        previous: Option<CommitteeShape>,
        previous_input: Option<CommitteeShape>,
    ) -> Self {
        Self {
            epoch,
            previous_epoch,
            protocol_type,
            batch_size_per_weight,
            min_batch_presigs,
            current,
            previous,
            previous_input,
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }

    pub(crate) fn protocol_type(&self) -> &ProtocolType {
        &self.protocol_type
    }

    pub(crate) fn current(&self) -> &CommitteeShape {
        &self.current
    }

    pub(crate) fn min_batch_presigs(&self) -> u64 {
        self.min_batch_presigs
    }

    pub(crate) fn avid_shape(&self) -> AvidShape<'_> {
        AvidShape {
            threshold: self.current.threshold,
            weights: self.current.weights(),
            batch_size_per_weight: self.batch_size_per_weight,
        }
    }

    pub(crate) fn committee_for_epoch(&self, epoch: u64) -> Option<&CommitteeShape> {
        if epoch == self.epoch {
            Some(&self.current)
        } else if epoch == self.previous_epoch {
            self.previous.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn dealing_committee_for_epoch(&self, epoch: u64) -> Option<&CommitteeShape> {
        if epoch == self.epoch && epoch != self.previous_epoch {
            self.previous.as_ref()
        } else if epoch == self.previous_epoch {
            self.previous_input.as_ref()
        } else {
            None
        }
    }
}
