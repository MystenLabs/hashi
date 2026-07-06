// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal;

use hashi::{hashi::Hashi, threshold};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const MAX_PROPOSAL_DURATION_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days

// ~~~~~~~ Structs ~~~~~~~

public struct Proposal<T> has key, store {
    id: UID,
    creator: address,
    votes: vector<address>,
    quorum_threshold_bps: u64,
    created_timestamp_ms: u64,
    /// Clock timestamp at execution. `None` until the proposal executes.
    executed_timestamp_ms: Option<u64>,
    metadata: VecMap<String, String>,
    data: T,
}

// ~~~~~~~ Errors ~~~~~~~
#[error(code = 0)]
const EUnauthorizedCaller: vector<u8> = b"Caller must be a voting member";
#[error(code = 1)]
const EVoteAlreadyCounted: vector<u8> = b"Vote already counted";
#[error(code = 2)]
const EQuorumNotReached: vector<u8> = b"Quorum not reached";
#[error(code = 3)]
const ENoVoteFound: vector<u8> = b"Vote doesn't exist";
#[error(code = 4)]
const EProposalNotExpired: vector<u8> = b"Proposal not expired";
#[error(code = 5)]
const EProposalExpired: vector<u8> = b"Proposal expired";
#[error(code = 6)]
const EProposalAlreadyExecuted: vector<u8> = b"Proposal already executed";

// ~~~~~~~ Public Functions ~~~~~~~

public(package) fun create<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    data: T,
    quorum_threshold_bps: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    // The caller must be the committee member `validator_address`, or the
    // operator key it has delegated to. The vote is recorded under
    // `validator_address` so quorum weight is computed correctly.
    assert!(hashi.committee_set().member_authorized(validator_address, ctx), EUnauthorizedCaller);

    let votes = vector[validator_address];
    let created_timestamp_ms = clock.timestamp_ms();

    let proposal = Proposal {
        id: object::new(ctx),
        creator: validator_address,
        votes,
        quorum_threshold_bps,
        created_timestamp_ms,
        executed_timestamp_ms: option::none(),
        metadata,
        data,
    };

    let proposal_id = object::id(&proposal);
    hashi.proposals_mut().active_mut().add(proposal_id, proposal);
    sui::event::emit(ProposalCreatedEvent<T> { proposal_id, timestamp_ms: created_timestamp_ms });
    proposal_id
}

public(package) fun execute<T: copy + drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
): T {
    hashi.versioning().assert_version_enabled();

    // Bag membership is the re-execution gate: an already-executed
    // proposal lives only in the executed bag. Check that explicitly so
    // the failure surface is `EProposalAlreadyExecuted` rather than the
    // ObjectBag's generic missing-key abort.
    assert!(
        !hashi.proposals().executed().contains(proposal_id.to_address()),
        EProposalAlreadyExecuted,
    );
    let mut proposal: Proposal<T> = hashi.proposals_mut().active_mut().remove(proposal_id);

    assert!(!proposal.is_expired(clock), EProposalExpired);
    assert!(proposal.quorum_reached(hashi), EQuorumNotReached);

    proposal.executed_timestamp_ms = option::some(clock.timestamp_ms());

    let data = proposal.data;
    let id = proposal.id.to_inner();

    hashi.proposals_mut().executed_mut().add(id.to_address(), proposal);

    sui::event::emit(ProposalExecutedEvent<T> { proposal_id: id, data });
    data
}

entry fun vote<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    hashi.versioning().assert_version_enabled();
    assert!(hashi.committee_set().member_authorized(validator_address, ctx), EUnauthorizedCaller);

    let proposal: &mut Proposal<T> = hashi.proposals_mut().active_mut().borrow_mut(proposal_id);

    assert!(!proposal.votes.contains(&validator_address), EVoteAlreadyCounted);
    assert!(!proposal.is_expired(clock), EProposalExpired);

    proposal.votes.push_back(validator_address);

    sui::event::emit(VoteCastEvent<T> { proposal_id, voter: validator_address });
    if (proposal.quorum_reached(hashi)) {
        sui::event::emit(QuorumReachedEvent<T> { proposal_id });
    }
}

entry fun remove_vote<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    hashi.versioning().assert_version_enabled();
    assert!(hashi.committee_set().member_authorized(validator_address, ctx), EUnauthorizedCaller);

    let proposal: &mut Proposal<T> = hashi.proposals_mut().active_mut().borrow_mut(proposal_id);
    let index = proposal
        .votes
        .find_index!(|v| v == &validator_address)
        .destroy_or!(abort ENoVoteFound);

    proposal.votes.remove(index);
    sui::event::emit(VoteRemovedEvent<T> {
        proposal_id: proposal.id.to_inner(),
        voter: validator_address,
    });
}

public(package) fun quorum_reached<T>(proposal: &Proposal<T>, hashi: &Hashi): bool {
    let valid_voting_power = proposal.votes.fold!(0, |acc, voter| {
        acc + hashi.current_committee().get_member_weight(&voter)
    });

    let total_weight = hashi.current_committee().total_weight();
    let required = threshold::weight_threshold(total_weight, proposal.quorum_threshold_bps);

    valid_voting_power >= required
}

public(package) fun is_expired<T>(proposal: &Proposal<T>, clock: &Clock): bool {
    clock.timestamp_ms() > proposal.created_timestamp_ms + MAX_PROPOSAL_DURATION_MS
}

public fun delete_expired<T: store>(hashi: &mut Hashi, proposal_id: ID, clock: &Clock): T {
    hashi.versioning().assert_version_enabled();
    // Executed proposals are archived in the executed bag and must
    // never be deletable, even after they expire. Refuse explicitly so
    // the caller gets `EProposalAlreadyExecuted` instead of the bag's
    // missing-key abort.
    assert!(
        !hashi.proposals().executed().contains(proposal_id.to_address()),
        EProposalAlreadyExecuted,
    );
    let proposal: Proposal<T> = hashi.proposals_mut().active_mut().remove(proposal_id);

    assert!(proposal.is_expired(clock), EProposalNotExpired);
    proposal.delete()
}

public(package) fun delete<T>(proposal: Proposal<T>): T {
    let Proposal<T> {
        id,
        data,
        ..,
    } = proposal;
    id.delete();
    data
}

// ~~~~~~~ Getters ~~~~~~~

public(package) fun votes<T>(proposal: &Proposal<T>): &vector<address> {
    &proposal.votes
}

#[test_only]
public fun data<T>(proposal: &Proposal<T>): &T {
    &proposal.data
}

// ~~~~~~~ Events ~~~~~~~

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

public struct ProposalExecutedEvent<T> has copy, drop {
    proposal_id: ID,
    data: T,
}

public struct QuorumReachedEvent<phantom T> has copy, drop {
    proposal_id: ID,
}
