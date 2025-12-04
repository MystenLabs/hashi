// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal_events;

use sui::event;

public struct VoteCastEvent has copy, drop {
    proposal_id: ID,
    voter: address,
}

public struct VoteRemovedEvent has copy, drop {
    proposal_id: ID,
    voter: address,
}

public struct ProposalDeletedEvent has copy, drop {
    proposal_id: ID,
}

public struct ProposalExecutedEvent has copy, drop {
    proposal_id: ID,
}

public struct QuorumReachedEvent has copy, drop {
    proposal_id: ID,
}

public(package) fun emit_vote_cast_event(proposal_id: ID, voter: address) {
    event::emit(VoteCastEvent {
        proposal_id,
        voter,
    });
}

public(package) fun emit_vote_removed_event(proposal_id: ID, voter: address) {
    event::emit(VoteRemovedEvent {
        proposal_id,
        voter,
    });
}

public(package) fun emit_quorum_reached_event(proposal_id: ID) {
    event::emit(QuorumReachedEvent {
        proposal_id,
    });
}

public(package) fun emit_proposal_deleted_event(proposal_id: ID) {
    event::emit(ProposalDeletedEvent {
        proposal_id,
    });
}

// TODO: add any relevant proposal data to the event
public(package) fun emit_proposal_executed_event(proposal_id: ID) {
    event::emit(ProposalExecutedEvent {
        proposal_id,
    });
}

#[test_only]
public fun proposal_id(quorum_reached_event: &QuorumReachedEvent): ID {
    quorum_reached_event.proposal_id
}
