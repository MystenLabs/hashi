/// @module Proposal Governance Integrity Properties
/// @contract hashi::proposal
module proposal::proposal_expiry;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;
use sui::clock::Clock;

public fun cvlm_manifest() {
    target(@hashi, b"proposal", b"vote");
    target(@hashi, b"proposal", b"execute");

    invoker(b"invoke");
    rule(b"no_action_after_expiry");
}

native fun invoke(target: Function, hashi: &mut Hashi, proposal_id: ID, clock: &Clock);

/// @title No vote or execution after expiry
/// @description A successful vote or execute implies the clock is at most the proposal's
///   creation time plus the maximum proposal duration.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun no_action_after_expiry<T: store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
    target: Function,
) {
    let created = hashi::proposal::borrow_active<T>(hashi, proposal_id)
        .proposal_created_timestamp_ms();

    invoke(target, hashi, proposal_id, clock);

    cvlm_assert(clock.timestamp_ms() <= created + hashi::proposal::max_proposal_duration_ms());
}
