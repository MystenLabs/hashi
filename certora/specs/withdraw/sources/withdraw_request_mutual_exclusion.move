/// @module Mutual Exclusion of Bags
/// @contract hashi::withdraw
/// @contract hashi::withdrawal_queue
module withdraw::withdraw_request_mutual_exclusion;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::btc::BTC;
use hashi::hashi::Hashi;
use hashi::withdrawal_queue::WithdrawalRequestQueue;
use sui::balance::Balance;
use sui::clock::Clock;
use withdraw::withdraw_queue_helpers::queue_bags_distinct;

public fun cvlm_manifest() {
    target(@hashi, b"withdraw", b"cancel_withdrawal");
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_withdrawal_tx");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"confirm_withdrawal");
    target(@hashi, b"withdraw", b"archive_confirmed_withdrawals");
    target(@hashi, b"withdraw", b"archive_withdrawal_requests");
    target(@hashi, b"withdraw", b"finish_archive_withdrawal_txns");
    target(@hashi, b"withdraw", b"reallocate_presigs");
    target(@hashi, b"withdraw", b"cleanup_spent_utxos");

    invoker(b"invoke");
    rule(b"withdrawal_request_mutual_exclusion");

    rule(b"request_withdrawal_does_not_create_duplicate_request");
}

native fun invoke(target: Function, hashi: &mut Hashi);

fun in_both(queue: &WithdrawalRequestQueue, request_id: address): bool {
    queue.contains_request(request_id) && queue.contains_processed(request_id)
}

/// @title A withdrawal request is never both live and archived
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, a request_id is in at most one of the requests and processed
///   bags.
/// @link_property WITHDRAW-QUEUE-MUTUAL-EXCLUSION
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request_id is in at most one of the requests and processed
///   bags before the call
/// @status VERIFIED
/// @report withdraw_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/051cf84b7c61458e9e93d1b76f4bdd17?anonymousKey=204692d6b56438e2251e453a2eea7b8b583eb557
public fun withdrawal_request_mutual_exclusion(
    hashi: &mut Hashi,
    request_id: address,
    target: Function,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(
        !in_both(queue, request_id),
        b"request_id starts in at most one of {requests, processed}",
    );

    invoke(target, hashi);

    cvlm_assert(!in_both(hashi.bitcoin().withdrawal_queue(), request_id));
}

/// @title request_withdrawal never puts a request in both bags
/// @description After a successful request_withdrawal, a request_id is not in both the
///   requests and processed bags.
/// @link_property WITHDRAW-QUEUE-MUTUAL-EXCLUSION
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request_id is in neither the requests nor the processed bag
///   before the call
/// @status VERIFIED
/// @report withdraw_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/051cf84b7c61458e9e93d1b76f4bdd17?anonymousKey=204692d6b56438e2251e453a2eea7b8b583eb557
public fun request_withdrawal_does_not_create_duplicate_request(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(
        !queue.contains_request(request_id) && !queue.contains_processed(request_id),
        b"request_id starts absent from both requests and processed",
    );

    hashi::withdraw::request_withdrawal(hashi, clock, btc, bitcoin_address, ctx);

    cvlm_assert(!in_both(hashi.bitcoin().withdrawal_queue(), request_id));
}
