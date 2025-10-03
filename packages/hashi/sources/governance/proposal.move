// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal;
use hashi::governance_events;
use hashi::hashi::Hashi;
use std::string::String;
use std::type_name;
use sui::vec_map::VecMap;

// ~~~~~~~ Structs ~~~~~~~

public struct Proposal<T> has key, store {
    id: UID,
    creator: address,
    hashi: ID,
    votes: vector<address>,
    metadata: VecMap<String, String>,
    data: T,
}

// ~~~~~~~ Errors ~~~~~~~
#[error]
const EUnauthorizedCaller: vector<u8> = b"Caller must be a quorum voter";
#[error]
const EVoteAlreadyCounted: vector<u8> = b"Vote already counted";
#[error]
const ECallerNotCreator: vector<u8> = b"Caller must be the proposal creator";
#[error]
const EQuorumNotReached: vector<u8> = b"Quorum not reached";
#[error]
const EProposalCommitteeMismatch: vector<u8> = b"Proposal quorum mismatch";
#[error]
const ENoVoteFound: vector<u8> = b"Vote doesn't exist";

// ~~~~~~~ Public Functions ~~~~~~~

public fun new<T: store>(
    hashi: &mut Hashi,
    data: T,
    metadata: VecMap<String, String>,
    ctx: &mut TxContext,
) {
    // only voters can create proposal
    assert!(
        hashi.committee_ref().member_in_committee(&ctx.sender()),
        EUnauthorizedCaller,
    );
    let votes = vector[ctx.sender()];

    let proposal = Proposal {
        id: object::new(ctx),
        creator: ctx.sender(),
        hashi: object::id(hashi),
        votes,
        metadata,
        data,
    };
    transfer::share_object(proposal);
}

public(package) fun execute<T>(proposal: Proposal<T>, hashi: &Hashi): T {
    assert!(proposal.quorum_reached(hashi), EQuorumNotReached);
    assert!(
        proposal.hashi == object::id(hashi),
        EProposalCommitteeMismatch,
    );
    governance_events::emit_proposal_executed_event(proposal.id.to_inner());
    proposal.delete()
}

public fun vote<T>(
    proposal: &mut Proposal<T>,
    hashi: &Hashi,
    ctx: &mut TxContext,
) {
    validate_proposal!<T>(hashi, proposal, ctx.sender());
    assert!(!proposal.votes.contains(&ctx.sender()), EVoteAlreadyCounted);

    proposal.votes.push_back(ctx.sender());
    governance_events::emit_vote_cast_event(
        proposal.id.to_inner(),
        ctx.sender(),
    );
    if (proposal.quorum_reached(hashi)) {
        governance_events::emit_quorum_reached_event(proposal.id.to_inner());
    }
}

public fun remove_vote<T>(
    proposal: &mut Proposal<T>,
    hashi: &mut Hashi,
    ctx: &mut TxContext,
) {
    validate_proposal!<T>(hashi, proposal, ctx.sender());

    let (vote_exists, index) = proposal.votes.index_of(&ctx.sender());
    assert!(vote_exists, ENoVoteFound);

    proposal.votes.remove(index);
    governance_events::emit_vote_removed_event(
        proposal.id.to_inner(),
        ctx.sender(),
    );
}

public fun quorum_reached<T>(proposal: &Proposal<T>, hashi: &Hashi): bool {
    let valid_voting_power = proposal
        .votes
        .fold!(
            0,
            |acc, voter| {
                acc + hashi.committee_ref().member_voting_power(&voter)
            },
        );

    let proposal_threshold = hashi
        .config_ref()
        .proposal_threshold(&type_name::with_defining_ids<T>());
    let total_voting_power = hashi.committee_ref().total_voting_power();

    valid_voting_power * 10000 / total_voting_power >= proposal_threshold
}

public fun delete_by_creator<T: drop>(
    proposal: Proposal<T>,
    ctx: &mut TxContext,
) {
    assert!(proposal.creator == ctx.sender(), ECallerNotCreator);
    governance_events::emit_proposal_deleted_event(proposal.id.to_inner());
    proposal.delete();
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

macro fun validate_proposal<$T>(
    $hashi: &Hashi,
    $proposal: &Proposal<$T>,
    $sender: address,
) {
    let hashi = $hashi;
    let proposal = $proposal;
    let sender = $sender;
    assert!(
        hashi.committee_ref().member_in_committee(&sender),
        EUnauthorizedCaller,
    );
    assert!(
        proposal.hashi == object::id(hashi),
        EProposalCommitteeMismatch,
    );
}

// public fun voter_is_validator(
//     voter: &address,
//     sui_system: &SuiSystemState,
// ): bool {
//     sui_system.active_validator_addresses_ref().contains(voter)
// }

// public fun validator_voting_power(
//     voter: &address,
//     sui_system: &SuiSystemState,
// ): u64 {
//     sui_system.active_validator_voting_powers()[voter]
// }

// public fun total_active_validator_voting_power(
//     committee: &Committee,
//     sui_system: &SuiSystemState,
// ): u64 {
//     let (validators, powers) = sui_system
//         .active_validator_voting_powers()
//         .into_keys_values();
//     let mut total_power = 0;
//     validators.zip_do!(
//         powers,
//         |validator, power| {
//             if (committee.member_in_committee(&validator)) {
//                 total_power = total_power + power;
//             }
//         },
//     );
//     total_power
// }

// ~~~~~~~ Getters ~~~~~~~                                                                                                                                                                                                                                                                                                                                                              ~~~~~~~

public fun votes<T>(proposal: &Proposal<T>): &vector<address> {
    &proposal.votes
}

#[test_only]
public fun data<T>(proposal: &Proposal<T>): &T {
    &proposal.data
}
