/// @module Proposal Governance Integrity Properties
/// @contract hashi::proposal
/// @contract hashi::proposals
module proposal::proposals_integrity2;

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
    rule(b"expiry_deadline_is_immutable");
    rule(b"threshold_bps_is_immutable");
    rule(b"executed_proposal_is_frozen");
    rule(b"executed_flag_matches_bag");

    rule(b"create_establishes_executed_flag");
}

native fun invoke(target: Function, hashi: &mut Hashi, proposal_id: ID);

fun key_matches_object<T: store>(hashi: &Hashi, proposal_id: ID): bool {
    if (hashi.proposals().contains_active(proposal_id)) {
        hashi::proposal::borrow_active<T>(hashi, proposal_id).proposal_id() == proposal_id
    } else {
        true
    }
}

/// @title An active proposal's creation time never changes
/// @description For each of vote, remove_vote, delete_expired and execute, if the
///   proposal is still active after a successful call, its creation timestamp, and so
///   its expiry deadline, is unchanged.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun expiry_deadline_is_immutable<T: store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    target: Function,
) {
    cvlm_assume_msg(
        key_matches_object<T>(hashi, proposal_id),
        b"active stores the proposal under its own object id",
    );
    let created_before = hashi::proposal::borrow_active<T>(hashi, proposal_id)
        .proposal_created_timestamp_ms();

    invoke(target, hashi, proposal_id);

    if (hashi.proposals().contains_active(proposal_id)) {
        let created_after = hashi::proposal::borrow_active<T>(hashi, proposal_id)
            .proposal_created_timestamp_ms();
        cvlm_assert(created_after == created_before);
    };
}

/// @title An active proposal's quorum bar never changes
/// @description For each of vote, remove_vote, delete_expired and execute, if the
///   proposal is still active after a successful call, its quorum bar is unchanged.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun threshold_bps_is_immutable<T: store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    target: Function,
) {
    cvlm_assume_msg(
        key_matches_object<T>(hashi, proposal_id),
        b"active stores the proposal under its own object id",
    );
    let bps_before = hashi::proposal::borrow_active<T>(hashi, proposal_id)
        .proposal_quorum_threshold_bps();

    invoke(target, hashi, proposal_id);

    if (hashi.proposals().contains_active(proposal_id)) {
        let bps_after = hashi::proposal::borrow_active<T>(hashi, proposal_id)
            .proposal_quorum_threshold_bps();
        cvlm_assert(bps_after == bps_before);
    };
}

fun key_matches_executed_object<T: store>(hashi: &Hashi, archived_id: ID): bool {
    if (hashi.proposals().contains_executed(archived_id)) {
        hashi::proposal::borrow_executed<T>(hashi, archived_id).proposal_id() == archived_id
    } else {
        true
    }
}

/// @title Executed proposals are frozen
/// @description For each of vote, remove_vote, delete_expired and execute, acting on any
///   proposal, an executed proposal stays in the executed bag with its creator,
///   creation time, quorum bar and execution time unchanged.
/// @link_property PROPOSALS-INTEGRITY
/// @assumption The watched proposal is in the executed bag before the call
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun executed_proposal_is_frozen<T: copy + drop + store>(
    hashi: &mut Hashi,
    archived_id: ID,
    acted_id: ID,
    target: Function,
) {
    cvlm_assume_msg(
        key_matches_executed_object<T>(hashi, archived_id),
        b"executed stores the archived proposal under its own object id",
    );
    cvlm_assume_msg(
        hashi.proposals().contains_executed(archived_id),
        b"archived_id has already executed",
    );

    let archived = hashi::proposal::borrow_executed<T>(hashi, archived_id);
    let creator_before = archived.proposal_creator();
    let created_before = archived.proposal_created_timestamp_ms();
    let bps_before = archived.proposal_quorum_threshold_bps();
    let exec_ts_before = archived.proposal_executed_timestamp_ms();
    let had_exec_ts_before = exec_ts_before.is_some();
    let exec_ts_value_before = if (had_exec_ts_before) { *exec_ts_before.borrow() } else { 0 };

    invoke(target, hashi, acted_id);

    cvlm_assert(hashi.proposals().contains_executed(archived_id));

    let archived = hashi::proposal::borrow_executed<T>(hashi, archived_id);
    cvlm_assert(archived.proposal_creator() == creator_before);
    cvlm_assert(archived.proposal_created_timestamp_ms() == created_before);
    cvlm_assert(archived.proposal_quorum_threshold_bps() == bps_before);

    let exec_ts_after = archived.proposal_executed_timestamp_ms();
    cvlm_assert(exec_ts_after.is_some() == had_exec_ts_before);
    if (had_exec_ts_before) {
        cvlm_assert(*exec_ts_after.borrow() == exec_ts_value_before);
    };
}

fun executed_flag_coherent<T: store>(hashi: &Hashi, proposal_id: ID): bool {
    let proposals = hashi.proposals();
    (
        !proposals.contains_active(proposal_id)
            || hashi::proposal::borrow_active<T>(hashi, proposal_id)
                .proposal_executed_timestamp_ms()
                .is_none(),
    ) && (
            !proposals.contains_executed(proposal_id)
                || hashi::proposal::borrow_executed<T>(hashi, proposal_id)
                    .proposal_executed_timestamp_ms()
                    .is_some(),
        )
}

/// @title The executed timestamp matches bag membership
/// @description For each of vote, remove_vote, delete_expired and execute, after a
///   successful call a proposal in the active bag has no executed timestamp and one in
///   the executed bag has one.
/// @link_property PROPOSALS-INTEGRITY
/// @assumption The checked proposal's executed timestamp agrees with the bag it is in before the call
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun executed_flag_matches_bag<T: store>(
    hashi: &mut Hashi,
    proposal_id: ID,
    target: Function,
) {
    cvlm_assume_msg(
        executed_flag_coherent<T>(hashi, proposal_id),
        b"flag agrees with bag membership pre-call",
    );

    invoke(target, hashi, proposal_id);

    cvlm_assert(executed_flag_coherent<T>(hashi, proposal_id));
}

/// @title create makes an active proposal with no executed timestamp
/// @description A successful create puts the returned proposal in the active bag with no
///   executed timestamp.
/// @link_property PROPOSALS-INTEGRITY
/// @status VERIFIED
/// @report proposals_integrity.conf https://prover.certora.com/output/497546/7ca0df3fe9d14206894ea6e0ffa32e3a?anonymousKey=aaa143938dd54acca6a4bd2f529d8240813f2fce
public fun create_establishes_executed_flag<T: store>(
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
    cvlm_assert(
        hashi::proposal::borrow_active<T>(hashi, new_id)
            .proposal_executed_timestamp_ms()
            .is_none(),
    );
}
