// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal_events;

use sui::event;

public struct ProposalCreatedEvent<phantom T> has copy, drop {
    proposal_id: ID,
    timestamp_ms: u64,
}

public struct VoteCastEvent<phantom T> has copy, drop {
    proposal_id: ID,
    voter: address,
}

public struct VoteRemovedEvent<phantom T> has copy, drop {
    proposal_id: ID,
    voter: address,
}

public struct ProposalDeletedEvent<phantom T> has copy, drop {
    proposal_id: ID,
}

public struct ProposalExecutedEvent<phantom T> has copy, drop {
    proposal_id: ID,
}

public struct QuorumReachedEvent<phantom T> has copy, drop {
    proposal_id: ID,
}

public struct PackageUpgradedEvent has copy, drop {
    package: ID,
    version: u64,
}

public(package) fun emit_proposal_created_event<T>(proposal_id: ID, timestamp_ms: u64) {
    event::emit(ProposalCreatedEvent<T> {
        proposal_id,
        timestamp_ms,
    });
}

public(package) fun emit_vote_cast_event<T>(proposal_id: ID, voter: address) {
    event::emit(VoteCastEvent<T> {
        proposal_id,
        voter,
    });
}

public(package) fun emit_vote_removed_event<T>(proposal_id: ID, voter: address) {
    event::emit(VoteRemovedEvent<T> {
        proposal_id,
        voter,
    });
}

public(package) fun emit_quorum_reached_event<T>(proposal_id: ID) {
    event::emit(QuorumReachedEvent<T> {
        proposal_id,
    });
}

public(package) fun emit_proposal_deleted_event<T>(proposal_id: ID) {
    event::emit(ProposalDeletedEvent<T> {
        proposal_id,
    });
}

public(package) fun emit_proposal_executed_event<T>(proposal_id: ID) {
    event::emit(ProposalExecutedEvent<T> {
        proposal_id,
    });
}

#[test_only]
public fun proposal_id<T>(quorum_reached_event: &QuorumReachedEvent<T>): ID {
    quorum_reached_event.proposal_id
}

public(package) fun emit_package_upgraded_event(package: ID, version: u64) {
    event::emit(PackageUpgradedEvent { package, version });
}
