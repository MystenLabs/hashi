/// @module Proposal Governance Integrity Properties
/// @contract hashi::proposal
/// @contract hashi::proposals
/// @contract hashi::emergency_pause
/// @contract hashi::update_config
/// @contract hashi::upgrade
/// @contract hashi::config
/// @impact A proposal's rules could be bent: its quorum bar or deadline moved while it
///   is in flight, an expired or already executed proposal acted on, votes miscounted,
///   or Hashi unpaused with less committee weight than the unpause bar requires.
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
/// @property PROPOSALS-INTEGRITY Governance proposals follow their rules: the quorum
///   bar and deadline are fixed at creation, votes are recorded and withdrawn one at a
///   time, nothing acts on an expired or executed proposal, executed proposals are
///   frozen, and unpausing needs at least the unpause bar in force when it was proposed
module proposal::proposals_integrity;

use cvlm::asserts::cvlm_assert;
use cvlm::ghost::ghost_destroy;
use cvlm::manifest::rule;
use hashi::emergency_pause::EmergencyPause;
use hashi::hashi::Hashi;
use hashi::update_config::UpdateConfig;
use hashi::upgrade::Upgrade;
use hashi::config_value::Value;
use std::string::String;
use sui::clock::Clock;
use sui::vec_map::VecMap;

public fun cvlm_manifest() {
    rule(b"pause_proposal_threshold_matches_config");
    rule(b"unpause_requires_pinned_threshold");
    rule(b"propose_then_execute_unpause_meets_unpause_bar");
    rule(b"update_config_proposal_threshold_is_supermajority");
    rule(b"update_config_preserves_guardian_btc_public_key");
    rule(b"upgrade_proposal_threshold_is_supermajority");

    rule(b"delete_expired_requires_not_executed");
    rule(b"delete_expired_requires_expiry");

    rule(b"vote_records_validator");
    rule(b"remove_vote_removes_validator");
}

/// @title Emergency pause proposals pin the configured bar
/// @description emergency_pause::propose creates a proposal whose quorum bar is the
///   configured pause bar when pausing and the configured unpause bar when unpausing,
///   with the requested flag as payload.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun pause_proposal_threshold_matches_config(
    hashi: &mut Hashi,
    validator_address: address,
    pause: bool,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let expected = if (pause) {
        hashi.config().emergency_pause_threshold_bps()
    } else {
        hashi.config().emergency_unpause_threshold_bps()
    };

    let id = hashi::emergency_pause::propose(hashi, validator_address, pause, metadata, clock, ctx);

    let p = hashi::proposal::borrow_active<EmergencyPause>(hashi, id);
    cvlm_assert(p.proposal_quorum_threshold_bps() == expected);
    cvlm_assert(p.data().emergency_pause_flag() == pause);
}

/// @title Unpausing requires the proposal's pinned bar
/// @description A successful emergency_pause::execute sets paused to the proposal's flag,
///   and if it clears a pause, the flag was false and the proposal's voting weight met
///   the bar pinned on that proposal.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun unpause_requires_pinned_threshold(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    let was_paused = hashi.config().paused();
    let p = hashi::proposal::borrow_active<EmergencyPause>(hashi, proposal_id);
    let flag = p.data().emergency_pause_flag();
    let bps = p.proposal_quorum_threshold_bps();
    let weight = p.proposal_voting_weight(hashi);
    let total = hashi.current_committee().total_weight();

    hashi::emergency_pause::execute(hashi, proposal_id, clock);

    let paused_after = hashi.config().paused();
    cvlm_assert(paused_after == flag);
    if (was_paused && !paused_after) {
        cvlm_assert(!flag);
        cvlm_assert(weight >= hashi::threshold::weight_threshold(total, bps));
    };
}

/// @title Propose-then-execute unpause meets the unpause bar
/// @description Proposing an unpause and then executing it leaves Hashi unpaused only if
///   the voting weight meets the configured unpause bar as it was at proposal time.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun propose_then_execute_unpause_meets_unpause_bar(
    hashi: &mut Hashi,
    validator_address: address,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let unpause_bps = hashi.config().emergency_unpause_threshold_bps();

    let id = hashi::emergency_pause::propose(hashi, validator_address, false, metadata, clock, ctx);
    let weight = hashi::proposal::borrow_active<EmergencyPause>(hashi, id)
        .proposal_voting_weight(hashi);
    let total = hashi.current_committee().total_weight();

    hashi::emergency_pause::execute(hashi, id, clock);

    cvlm_assert(!hashi.config().paused());
    cvlm_assert(weight >= hashi::threshold::weight_threshold(total, unpause_bps));
}

/// @title update_config proposals need a 6667 bps supermajority
/// @description update_config::propose creates a proposal with a quorum bar of 6667 bps.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun update_config_proposal_threshold_is_supermajority(
    hashi: &mut Hashi,
    validator_address: address,
    entries: VecMap<String, Value>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let id = hashi::update_config::propose(hashi, validator_address, entries, metadata, clock, ctx);

    let p = hashi::proposal::borrow_active<UpdateConfig>(hashi, id);
    cvlm_assert(p.proposal_quorum_threshold_bps() == 6667);
}

/// @title update_config never changes the guardian BTC public key
/// @description After a successful update_config::execute, the guardian BTC public key is
///   set if and only if it was set before, and holds the same bytes.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun update_config_preserves_guardian_btc_public_key(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    let before = hashi.config().guardian_btc_public_key();

    hashi::update_config::execute(hashi, proposal_id, clock);

    let after = hashi.config().guardian_btc_public_key();
    cvlm_assert(before.is_some() == after.is_some());
    if (before.is_some()) {
        cvlm_assert(*before.borrow() == *after.borrow());
    };
}

/// @title upgrade proposals need a 6667 bps supermajority
/// @description upgrade::propose creates a proposal with a quorum bar of 6667 bps.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun upgrade_proposal_threshold_is_supermajority(
    hashi: &mut Hashi,
    validator_address: address,
    digest: vector<u8>,
    exclusive: bool,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let id = hashi::upgrade::propose(hashi, validator_address, digest, exclusive, metadata, clock, ctx);

    let p = hashi::proposal::borrow_active<Upgrade>(hashi, id);
    cvlm_assert(p.proposal_quorum_threshold_bps() == 6667);
}

/// @title delete_expired never deletes an executed proposal
/// @description A successful delete_expired implies the proposal was not in the executed bag.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun delete_expired_requires_not_executed<T: drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    let was_executed = hashi.proposals().contains_executed(proposal_id);

    let payload = hashi::proposal::delete_expired<T>(hashi, proposal_id, clock);
    ghost_destroy(payload);

    cvlm_assert(!was_executed);
}

/// @title delete_expired only deletes expired proposals
/// @description A successful delete_expired implies the clock is strictly past the
///   proposal's creation time plus the maximum proposal duration.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun delete_expired_requires_expiry<T: drop + store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
) {
    let created = hashi::proposal::borrow_active<T>(hashi, proposal_id)
        .proposal_created_timestamp_ms();

    let payload = hashi::proposal::delete_expired<T>(hashi, proposal_id, clock);
    ghost_destroy(payload);

    cvlm_assert(clock.timestamp_ms() > created + hashi::proposal::max_proposal_duration_ms());
}

/// @title vote appends exactly one new vote
/// @description A successful vote appends the validator at the end of the proposal's
///   votes, increases the count by exactly one, and the validator had not voted
///   before.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun vote_records_validator<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let before = hashi::proposal::borrow_active<T>(hashi, proposal_id);
    let had_vote_before = before.proposal_has_vote(validator_address);
    let count_before = before.proposal_vote_count();

    hashi::proposal::vote<T>(hashi, validator_address, proposal_id, clock, ctx);

    let after = hashi::proposal::borrow_active<T>(hashi, proposal_id);
    cvlm_assert(after.proposal_vote_count() == count_before + 1);
    cvlm_assert(after.proposal_vote_at(count_before) == validator_address);
    cvlm_assert(!had_vote_before);
}

/// @title remove_vote drops the validator's vote
/// @description After a successful remove_vote the validator no longer has a vote, and
///   the vote count dropped by one if it had voted and is unchanged otherwise.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun remove_vote_removes_validator<T: store>(
    hashi: &mut Hashi,
    validator_address: address,
    proposal_id: ID,
    ctx: &mut TxContext,
) {
    let before = hashi::proposal::borrow_active<T>(hashi, proposal_id);
    let count_before = before.proposal_vote_count();
    let contained_before = before.proposal_has_vote(validator_address);

    hashi::proposal::remove_vote<T>(hashi, validator_address, proposal_id, ctx);

    let after = hashi::proposal::borrow_active<T>(hashi, proposal_id);
    if (contained_before) {
        cvlm_assert(after.proposal_vote_count() + 1 == count_before);
    } else {
        cvlm_assert(after.proposal_vote_count() == count_before);
    };
    cvlm_assert(!after.proposal_has_vote(validator_address));
}
