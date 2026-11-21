/// @module Proposal Governance State Machine
/// @contract hashi::proposal
/// @contract hashi::proposals
/// @impact A proposal could be created, voted on, executed or deleted from the wrong
///   state, or executed without quorum, letting governance actions run that the
///   committee never approved.
///
/// @global_assumption A proposal's key in the active or executed bag matches the
///   proposal's own id
/// @global_assumption A proposal's valid voting power is summarized as one opaque value,
///   not tied to its votes or the committee's weights, so whether quorum is reached is
///   unconstrained
/// @global_assumption Removing a validator's vote from a proposal is summarized: the
///   vote list is replaced by an arbitrary list that is one entry shorter (or the same
///   length if the validator had not voted) and no longer contains that validator
///
/// @property PROPOSALS-STATE-MACHINE Each governance entry point moves a proposal only
///   along its intended edge: create puts it in the active bag with the creator's vote,
///   vote and remove_vote keep it active, execute moves it from active to executed only
///   once quorum is met, and delete_expired removes it from both bags
module proposal::proposal_state_machine;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::ghost::ghost_destroy;
use cvlm::manifest::rule;
use hashi::hashi::Hashi;
use std::string::String;
use sui::clock::Clock;
use sui::vec_map::VecMap;

public fun cvlm_manifest() {
    rule(b"create_enters_active");
    rule(b"vote_preserves_membership");
    rule(b"remove_vote_preserves_membership");
    rule(b"execute_moves_active_to_executed");
    rule(b"delete_expired_exits_both_bags");

    rule(b"execute_requires_quorum");
}

fun bags_are_distinct(hashi: &Hashi): bool {
    let proposals = hashi.proposals();
    object::id(proposals.active()) != object::id(proposals.executed())
}

/// @title create puts a new proposal in the active bag
/// @description A successful create puts the returned proposal in the active bag under
///   its own id, with the named validator as creator and sole voter, the requested
///   quorum bar, and the current clock as its creation time.
/// @link_property PROPOSALS-STATE-MACHINE
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun create_enters_active<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    data: T,
    quorum_threshold_bps: u64,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let new_id = hashi::proposal::create<T>(
        hashi,
        validator_address,
        data,
        quorum_threshold_bps,
        metadata,
        clock,
        ctx,
    );

    cvlm_assert(hashi.proposals().contains_active(new_id));

    let created = hashi::proposal::borrow_active<T>(hashi, new_id);
    cvlm_assert(created.proposal_id() == new_id);
    cvlm_assert(created.proposal_creator() == validator_address);
    cvlm_assert(created.proposal_vote_count() == 1);
    cvlm_assert(created.proposal_vote_at(0) == validator_address);
    cvlm_assert(created.proposal_quorum_threshold_bps() == quorum_threshold_bps);
    cvlm_assert(created.proposal_created_timestamp_ms() == clock.timestamp_ms());
}

/// @title vote keeps the proposal active
/// @description A successful vote requires the proposal to be active and not executed,
///   and leaves it active and not executed.
/// @link_property PROPOSALS-STATE-MACHINE
/// @assumption The active and executed bags are distinct objects
/// @assumption The checked proposal is in at most one of the active and executed bags before the call
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun vote_preserves_membership<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    cvlm_assume_msg(
        bags_are_distinct(hashi),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let proposals = hashi.proposals();
    let active_pre = proposals.contains_active(proposal_id);
    let executed_pre = proposals.contains_executed(proposal_id);
    cvlm_assume_msg(!(active_pre && executed_pre), b"G1: never in both bags");

    hashi::proposal::vote<T>(hashi, validator_address, proposal_id, clock, ctx);

    let proposals = hashi.proposals();
    cvlm_assert(active_pre);
    cvlm_assert(proposals.contains_active(proposal_id));
    cvlm_assert(!executed_pre);
    cvlm_assert(!proposals.contains_executed(proposal_id));
}

/// @title remove_vote keeps the proposal active
/// @description A successful remove_vote requires the proposal to be active and not
///   executed, and leaves it active and not executed.
/// @link_property PROPOSALS-STATE-MACHINE
/// @assumption The active and executed bags are distinct objects
/// @assumption The checked proposal is in at most one of the active and executed bags before the call
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun remove_vote_preserves_membership<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    cvlm_assume_msg(
        bags_are_distinct(hashi),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let proposals = hashi.proposals();
    let active_pre = proposals.contains_active(proposal_id);
    let executed_pre = proposals.contains_executed(proposal_id);
    cvlm_assume_msg(!(active_pre && executed_pre), b"G1: never in both bags");

    hashi::proposal::remove_vote<T>(hashi, validator_address, proposal_id, ctx);

    let proposals = hashi.proposals();
    cvlm_assert(active_pre);
    cvlm_assert(proposals.contains_active(proposal_id));
    cvlm_assert(!executed_pre);
    cvlm_assert(!proposals.contains_executed(proposal_id));
}

/// @title execute moves the proposal from active to executed
/// @description A successful execute requires the proposal to be active, and afterwards
///   it is in the executed bag and no longer active.
/// @link_property PROPOSALS-STATE-MACHINE
/// @assumption The active and executed bags are distinct objects
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun execute_moves_active_to_executed<T: copy + drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    cvlm_assume_msg(
        bags_are_distinct(hashi),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let active_pre = hashi.proposals().contains_active(proposal_id);
    cvlm_assume_msg(
        !active_pre
            || hashi::proposal::borrow_active<T>(hashi, proposal_id).proposal_id() == proposal_id,
        b"active stores the proposal under its own object id",
    );

    let _data = hashi::proposal::execute<T>(hashi, proposal_id, clock);

    let proposals = hashi.proposals();
    cvlm_assert(active_pre);
    cvlm_assert(!proposals.contains_active(proposal_id));
    cvlm_assert(proposals.contains_executed(proposal_id));
}

/// @title execute requires quorum under the current committee
/// @description A successful execute implies the proposal's voting weight meets the
///   threshold computed from the current committee's total weight and the proposal's own
///   quorum bar.
/// @link_property PROPOSALS-STATE-MACHINE
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun execute_requires_quorum<T: copy + drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    let proposal = hashi::proposal::borrow_active<T>(hashi, proposal_id);
    let bps = proposal.proposal_quorum_threshold_bps();
    let weight = proposal.proposal_voting_weight(hashi);
    let total = hashi.current_committee().total_weight();

    let _data = hashi::proposal::execute<T>(hashi, proposal_id, clock);

    cvlm_assert(weight >= hashi::threshold::weight_threshold(total, bps));
}

/// @title delete_expired removes the proposal from both bags
/// @description A successful delete_expired requires the proposal to be active, and
///   afterwards it is in neither the active nor the executed bag.
/// @link_property PROPOSALS-STATE-MACHINE
/// @assumption The active and executed bags are distinct objects
/// @status VERIFIED
/// @report proposals_state_machine.conf https://prover.certora.com/output/497546/3adca2a2a7f6447d83bd4e9eeee712c1?anonymousKey=c3d78b33d4fb235b44d1e25c128da4689d194686
public fun delete_expired_exits_both_bags<T: drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    cvlm_assume_msg(
        bags_are_distinct(hashi),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    let active_pre = hashi.proposals().contains_active(proposal_id);

    let payload = hashi::proposal::delete_expired<T>(hashi, proposal_id, clock);
    ghost_destroy(payload);

    let proposals = hashi.proposals();
    cvlm_assert(active_pre);
    cvlm_assert(!proposals.contains_active(proposal_id));
    cvlm_assert(!proposals.contains_executed(proposal_id));
}
