/// @module Mutual Exclusion of Bags
/// @contract hashi::proposal
/// @contract hashi::proposals
///
/// @property PROPOSALS-MUTUAL-EXCLUSION A proposal is never in both the active and the
///   executed bag at the same time
module proposal::proposal_mutual_exclusion;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;
use std::string::String;
use sui::clock::Clock;
use sui::vec_map::VecMap;

public fun cvlm_manifest() {
    target(@hashi, b"proposal", b"vote");
    target(@hashi, b"proposal", b"remove_vote");
    target(@hashi, b"proposal", b"delete_expired");
    target(@hashi, b"proposal", b"execute");

    invoker(b"invoke");
    rule(b"proposal_mutual_exclusion");

    rule(b"create_does_not_duplicate_proposal");
}

native fun invoke(target: Function, hashi: &mut Hashi, proposal_id: ID);

/// @title A proposal is never both active and executed
/// @description For each of vote, remove_vote, delete_expired and execute, after a
///   successful call the proposal_id is in at most one of the active and executed bags.
/// @link_property PROPOSALS-MUTUAL-EXCLUSION
/// @assumption The active and executed bags are distinct objects
/// @assumption The checked proposal_id is in at most one of the active and executed
///   bags before the call
/// @status VERIFIED
/// @report proposals_mutual_exclusion.conf https://prover.certora.com/output/497546/030ae1b07f264a7ea862d5003261c842?anonymousKey=fbf121238803a6bc1b3c7f71448c31ffd6393d19
public fun proposal_mutual_exclusion(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let proposals = hashi.proposals();
    cvlm_assume_msg(
        object::id(proposals.active()) != object::id(proposals.executed()),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let active_pre = proposals.contains_active(proposal_id);
    let executed_pre = proposals.contains_executed(proposal_id);
    cvlm_assume_msg(
        !(active_pre && executed_pre),
        b"proposal_id starts in at most one of {active, executed}",
    );

    invoke(target, hashi, proposal_id);

    let proposals = hashi.proposals();
    let active_post = proposals.contains_active(proposal_id);
    let executed_post = proposals.contains_executed(proposal_id);
    cvlm_assert(!(active_post && executed_post));
}

/// @title create never puts a proposal in both bags
/// @description After a successful create, a proposal_id is not in both the active and
///   executed bags.
/// @link_property PROPOSALS-MUTUAL-EXCLUSION
/// @assumption The active and executed bags are distinct objects
/// @assumption The checked proposal_id is in neither the active nor the executed bag
///   before the call
/// @status VERIFIED
/// @report proposals_mutual_exclusion.conf https://prover.certora.com/output/497546/030ae1b07f264a7ea862d5003261c842?anonymousKey=fbf121238803a6bc1b3c7f71448c31ffd6393d19
public fun create_does_not_duplicate_proposal<T: store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    validator_address: address,
    data: T,
    quorum_threshold_bps: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let proposals = hashi.proposals();
    cvlm_assume_msg(
        object::id(proposals.active()) != object::id(proposals.executed()),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let active_pre = proposals.contains_active(proposal_id);
    let executed_pre = proposals.contains_executed(proposal_id);
    cvlm_assume_msg(
        !active_pre && !executed_pre,
        b"proposal_id starts absent from both active and executed",
    );

    hashi::proposal::create<T>(
        hashi,
        validator_address,
        data,
        quorum_threshold_bps,
        metadata,
        clock,
        ctx,
    );

    let proposals = hashi.proposals();
    let active_post = proposals.contains_active(proposal_id);
    let executed_post = proposals.contains_executed(proposal_id);
    cvlm_assert(!(active_post && executed_post));
}
