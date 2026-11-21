/// @module Mutual Exclusion of Bags
/// @contract hashi::deposit
/// @contract hashi::deposit_queue
/// @impact A deposit request, withdrawal transaction or proposal could sit in both its
///   active and its terminal bag at once, letting it be processed or executed twice.
///
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
/// @global_assumption A deposit request's key in the requests or processed bag matches
///   the request's own id
/// @global_assumption Withdrawal commit_requests is summarized: the real per-request
///   commit runs only for one arbitrary tracked request, and only when vector::contains
///   reports it in the transaction's request list; every other request is left untouched
/// @global_assumption Pool BTC, the total amount of UTXOs with spent_by == none, is
///   tracked by the ghost total_active_amount, updated by summaries of insert_active,
///   insert_pending, lock and their batched withdraw-side callers
/// @global_assumption The loops in the withdrawal flow are summarized by opaque
///   per-call amounts: the input UTXO total (locked from the pool and used for fee
///   accounting), the change UTXO total (returned to the pool), the per-request output
///   total, the committed requests' balance total, and the request and output counts.
///   None of these is tied to the actual UTXOs or requests
/// @global_assumption The only relationship assumed between those amounts is that the
///   per-request output total plus request count times the per-user miner fee equals
///   the committed requests' balance total. Dust and destination-address checks on
///   withdrawal outputs are not modeled
/// @global_assumption A proposal's valid voting power is summarized as one opaque value,
///   not tied to its votes or the committee's weights, so whether quorum is reached is
///   unconstrained
/// @global_assumption Removing a validator's vote from a proposal is summarized: the
///   vote list is replaced by an arbitrary list that is one entry shorter (or the same
///   length if the validator had not voted) and no longer contains that validator
///
/// @property DEPOSIT-QUEUE-MUTUAL-EXCLUSION A deposit request is never in both the
///   active requests bag and the processed bag at the same time
module deposit::deposit_mutual_exclusion;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;
use hashi::utxo::Utxo;
use sui::clock::Clock;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");

    invoker(b"invoke");
    rule(b"deposit_request_mutual_exclusion");

    rule(b"deposit_does_not_create_duplicate_request");
}

native fun invoke(target: Function, hashi: &mut Hashi, request_id: address);

/// @title A request is never both active and processed
/// @description For each of approve_deposit, confirm_deposit and
///   delete_expired_deposit, after a successful call the request_id is in at most one
///   of the requests and processed bags.
/// @link_property DEPOSIT-QUEUE-MUTUAL-EXCLUSION
/// @assumption The checked request_id is in at most one of the requests and processed
///   bags before the call
/// @status VERIFIED
/// @report deposit_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/0747924493c444d5b01ee5ef97815679?anonymousKey=6daaa592293eb743cdffe56369b915123370f642
public fun deposit_request_mutual_exclusion(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().deposit_queue();
    let already_active_pre = queue.contains(request_id);
    let already_processed_pre = queue.contains_processed(request_id);
    cvlm_assume_msg(
        !(already_active_pre && already_processed_pre),
        b"request_id starts in at most one of {requests, processed}",
    );

    invoke(target, hashi, request_id);

    let queue = hashi.bitcoin().deposit_queue();
    let already_active_post = queue.contains(request_id);
    let already_processed_post = queue.contains_processed(request_id);
    cvlm_assert(!(already_active_post && already_processed_post));
}

/// @title deposit never puts a request in both bags
/// @description After a successful deposit, a request_id is not in both the requests
///   and processed bags.
/// @link_property DEPOSIT-QUEUE-MUTUAL-EXCLUSION
/// @assumption The checked request_id is in neither the requests nor the processed bag
///   before the call
/// @assumption The requests and processed bags are distinct objects
/// @status VERIFIED
/// @report deposit_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/0747924493c444d5b01ee5ef97815679?anonymousKey=6daaa592293eb743cdffe56369b915123370f642
public fun deposit_does_not_create_duplicate_request(
    hashi: &mut Hashi,
    request_id: address,
    utxo: Utxo,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    let already_active_pre = queue.contains(request_id);
    let already_processed_pre = queue.contains_processed(request_id);
    cvlm_assume_msg(
        !already_active_pre && !already_processed_pre,
        b"request_id starts absent from both requests and processed",
    );
    cvlm_assume_msg(
        object::id(queue.requests_ref()) != object::id(queue.processed_ref()),
        b"requests and processed are distinct ObjectBags, as in any reachable state",
    );

    hashi::deposit::deposit(hashi, utxo, clock, ctx);

    let queue = hashi.bitcoin().deposit_queue();
    let already_active_post = queue.contains(request_id);
    let already_processed_post = queue.contains_processed(request_id);
    cvlm_assert(!(already_active_post && already_processed_post));
}
