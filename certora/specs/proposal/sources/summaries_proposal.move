module proposal::summaries_proposal;

use cvlm::asserts::cvlm_assume_msg;
use cvlm::manifest::{ghost, summary};
use cvlm::nondet::nondet;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use sui::vec_map::VecMap;

public fun cvlm_manifest() {
    summary(b"sum_valid_voting_power_summary", @hashi, b"proposal", b"sum_valid_voting_power");

    ghost(b"sum_of_valid_voting_power");

    summary(b"remove_vote_from_summary", @hashi, b"proposal", b"remove_vote_from");

    summary(b"vec_map_length_summary", @sui, b"vec_map", b"length");
}

/// Forwards `vec_map::length` to the summarized `size`, which it is identical to.
public fun vec_map_length_summary<K: copy, V>(self: &VecMap<K, V>): u64 {
    self.size()
}

/// Replaces the voting-weight fold with the ghost sum_of_valid_voting_power, so
/// whether quorum is reached is unconstrained.
public fun sum_valid_voting_power_summary(_votes: &vector<address>, _hashi: &Hashi): u64 {
    sum_of_valid_voting_power()
}

/// Ghost: a proposal's valid voting power, one value per rule and not tied to its votes.
public native fun sum_of_valid_voting_power(): u64;

/// Replaces the vote list with an arbitrary one without the validator, one entry shorter
/// if it had voted and the same length otherwise.
public fun remove_vote_from_summary<T>(proposal: &mut Proposal<T>, validator_address: address) {
    let had_vote = proposal.proposal_has_vote(validator_address);
    let count_before = proposal.proposal_vote_count();

    *proposal.proposal_votes_mut() = nondet();

    if (had_vote) {
        // A recorded vote means the list was non-empty.
        cvlm_assume_msg(count_before > 0, b"a recorded vote means votes was non-empty");
        cvlm_assume_msg(
            proposal.proposal_vote_count() + 1 == count_before,
            b"removing a recorded vote drops exactly one entry",
        );
    } else {
        cvlm_assume_msg(
            proposal.proposal_vote_count() == count_before,
            b"removing a vote that was never recorded leaves the length alone",
        );
    };

    cvlm_assume_msg(
        !proposal.proposal_has_vote(validator_address),
        b"the withdrawn validator no longer has a vote",
    );
}
