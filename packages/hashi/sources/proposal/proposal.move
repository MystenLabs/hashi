// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal;

use hashi::{hashi::Hashi, proposal_events};
use std::string::String;
use sui::vec_map::VecMap;

// ~~~~~~~ Structs ~~~~~~~

public struct Proposal<T> has key, store {
    id: UID,
    creator: address,
    votes: vector<address>,
    quorum_threshold_bps: u64,
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

// ~~~~~~~ Public Functions ~~~~~~~

public(package) fun create<T: store>(
    hashi: &mut Hashi,
    data: T,
    quorum_threshold_bps: u64,
    metadata: VecMap<String, String>,
    ctx: &mut TxContext,
) {
    // only voters can create proposal
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);

    let votes = vector[ctx.sender()];

    let proposal = Proposal {
        id: object::new(ctx),
        creator: ctx.sender(),
        votes,
        quorum_threshold_bps,
        metadata,
        data,
    };

    hashi.proposals_mut().add(proposal);
}

public(package) fun execute<T>(proposal: Proposal<T>, hashi: &Hashi): T {
    assert!(proposal.quorum_reached(hashi), EQuorumNotReached);

    // TODO: add version to proposal and check that it is a whitelisted version

    proposal_events::emit_proposal_executed_event(proposal.id.to_inner());
    proposal.delete()
}

public fun vote<T>(proposal: &mut Proposal<T>, hashi: &Hashi, ctx: &mut TxContext) {
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);
    assert!(!proposal.votes.contains(&ctx.sender()), EVoteAlreadyCounted);

    proposal.votes.push_back(ctx.sender());
    proposal_events::emit_vote_cast_event(proposal.id.to_inner(), ctx.sender());

    if (proposal.quorum_reached(hashi)) {
        // assign sequence number
        proposal_events::emit_quorum_reached_event(proposal.id.to_inner());
    }
}

public fun remove_vote<T>(proposal: &mut Proposal<T>, hashi: &mut Hashi, ctx: &mut TxContext) {
    assert!(hashi.committee_set().has_member(ctx.sender()), EUnauthorizedCaller);

    let index = proposal.votes.find_index!(|v| v == &ctx.sender()).destroy_or!(abort ENoVoteFound);

    proposal.votes.remove(index);
    proposal_events::emit_vote_removed_event(
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

public(package) fun delete<T>(proposal: Proposal<T>): T {
    let Proposal<T> {
        id,
        data,
        ..,
    } = proposal;
    id.delete();
    data
}

// ~~~~~~~ Getters ~~~~~~~                                                                                                                                                                                                                                                                                                                                                              ~~~~~~~

public fun votes<T>(proposal: &Proposal<T>): &vector<address> {
    &proposal.votes
}

#[test_only]
public fun data<T>(proposal: &Proposal<T>): &T {
    &proposal.data
}
