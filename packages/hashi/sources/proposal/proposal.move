// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal;

use hashi::{hashi::Hashi, proposal_events};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

const MAX_PROPOSAL_DURATION_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days

// ~~~~~~~ Structs ~~~~~~~

public struct Proposal<T> has key, store {
    id: UID,
    creator: address,
    votes: vector<address>,
    quorum_threshold_bps: u64,
    timestamp_ms: u64,
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

// ~~~~~~~ Public Functions ~~~~~~~

public(package) fun create<T: store>(
    hashi: &mut Hashi,
    data: T,
    quorum_threshold_bps: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    // only voters can create proposal
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);

    let votes = vector[ctx.sender()];
    let timestamp_ms = clock.timestamp_ms();

    let proposal = Proposal {
        id: object::new(ctx),
        creator: ctx.sender(),
        votes,
        quorum_threshold_bps,
        timestamp_ms,
        metadata,
        data,
    };

    let proposal_id = object::id(&proposal);
    hashi.proposals_mut().add(proposal_id, proposal);
    proposal_events::emit_proposal_created_event<T>(proposal_id, timestamp_ms);
    proposal_id
}

public(package) fun execute<T: store>(hashi: &mut Hashi, proposal_id: ID, clock: &Clock): T {
    let proposal: Proposal<T> = hashi.proposals_mut().remove(proposal_id);

    assert!(proposal.quorum_reached(hashi), EQuorumNotReached);
    assert!(!proposal.is_expired(clock), EProposalExpired);

    hashi.config().assert_version_enabled();

    proposal_events::emit_proposal_executed_event<T>(proposal.id.to_inner());
    proposal.delete()
}

public fun vote<T: store>(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &mut TxContext) {
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);

    let proposal: &mut Proposal<T> = hashi.proposals_mut().borrow_mut(proposal_id);

    assert!(!proposal.votes.contains(&ctx.sender()), EVoteAlreadyCounted);
    assert!(!proposal.is_expired(clock), EProposalExpired);

    proposal.votes.push_back(ctx.sender());

    proposal_events::emit_vote_cast_event<T>(proposal_id, ctx.sender());
    if (proposal.quorum_reached(hashi)) {
        proposal_events::emit_quorum_reached_event<T>(proposal_id);
    }
}

public fun remove_vote<T: store>(hashi: &mut Hashi, proposal_id: ID, ctx: &mut TxContext) {
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);

    let proposal: &mut Proposal<T> = hashi.proposals_mut().borrow_mut(proposal_id);
    let index = proposal.votes.find_index!(|v| v == &ctx.sender()).destroy_or!(abort ENoVoteFound);

    proposal.votes.remove(index);
    proposal_events::emit_vote_removed_event<T>(
        proposal.id.to_inner(),
        ctx.sender(),
    );
}

public fun quorum_reached<T>(proposal: &Proposal<T>, hashi: &Hashi): bool {
    let valid_voting_power = proposal.votes.fold!(0, |acc, voter| {
        acc + hashi.current_committee().get_member_weight(&voter)
    });

    let total_weight = hashi.current_committee().total_weight();

    (valid_voting_power * 10000 / total_weight) as u64 >= proposal.quorum_threshold_bps
}

public fun is_expired<T>(proposal: &Proposal<T>, clock: &Clock): bool {
    clock.timestamp_ms() > proposal.timestamp_ms + MAX_PROPOSAL_DURATION_MS
}

public fun delete_expired<T: store>(hashi: &mut Hashi, proposal_id: ID, clock: &Clock): T {
    let proposal: Proposal<T> = hashi.proposals_mut().remove(proposal_id);

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

public fun votes<T>(proposal: &Proposal<T>): &vector<address> {
    &proposal.votes
}

#[test_only]
public fun data<T>(proposal: &Proposal<T>): &T {
    &proposal.data
}
