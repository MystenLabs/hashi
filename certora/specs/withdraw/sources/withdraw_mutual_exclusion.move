/// @module Mutual Exclusion of Bags
/// @contract hashi::withdraw
/// @contract hashi::withdrawal_queue
///
/// @property WITHDRAW-QUEUE-MUTUAL-EXCLUSION A withdrawal request is never in both the
///   requests and the processed bag, and a withdrawal transaction is never in both the
///   in-flight and the confirmed bag, at the same time
module withdraw::withdraw_mutual_exclusion;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use hashi::utxo::UtxoId;
use hashi::withdrawal_queue::OutputUtxo;
use sui::clock::Clock;
use sui::random::Random;
use withdraw::withdraw_queue_helpers::queue_bags_distinct;

public fun cvlm_manifest() {
    target(@hashi, b"withdraw", b"request_withdrawal");
    target(@hashi, b"withdraw", b"cancel_withdrawal");
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"confirm_withdrawal");
    target(@hashi, b"withdraw", b"archive_confirmed_withdrawals");
    target(@hashi, b"withdraw", b"archive_withdrawal_requests");
    target(@hashi, b"withdraw", b"finish_archive_withdrawal_txns");
    target(@hashi, b"withdraw", b"reallocate_presigs");
    target(@hashi, b"withdraw", b"cleanup_spent_utxos");

    invoker(b"invoke");
    rule(b"withdrawal_txn_mutual_exclusion");

    rule(b"commit_withdrawal_tx_does_not_create_duplicate_txn");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title A withdrawal transaction is never both in flight and confirmed
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a withdrawal_id is in at most one of the withdrawal_txns and
///   confirmed_txns bags.
/// @link_property WITHDRAW-QUEUE-MUTUAL-EXCLUSION
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked withdrawal_id is in at most one of the withdrawal_txns and
///   confirmed_txns bags before the call
/// @status VERIFIED
/// @report withdraw_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/051cf84b7c61458e9e93d1b76f4bdd17?anonymousKey=204692d6b56438e2251e453a2eea7b8b583eb557
public fun withdrawal_txn_mutual_exclusion(
    hashi: &mut Hashi,
    withdrawal_id: address,
    target: Function,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    let in_flight_pre = queue.contains_withdrawal_txn(withdrawal_id);
    let confirmed_pre = queue.contains_confirmed_txn(withdrawal_id);
    cvlm_assume_msg(
        !(in_flight_pre && confirmed_pre),
        b"withdrawal_id starts in at most one of {withdrawal_txns, confirmed_txns}",
    );

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    let in_flight_post = queue.contains_withdrawal_txn(withdrawal_id);
    let confirmed_post = queue.contains_confirmed_txn(withdrawal_id);
    cvlm_assert(!(in_flight_post && confirmed_post));
}

/// @title commit_withdrawal_tx never puts a transaction in both bags
/// @description After a successful commit_withdrawal_tx, a withdrawal_id is not in both
///   the withdrawal_txns and confirmed_txns bags.
/// @link_property WITHDRAW-QUEUE-MUTUAL-EXCLUSION
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked withdrawal_id is in neither the withdrawal_txns nor the
///   confirmed_txns bag before the call
/// @status VERIFIED
/// @report withdraw_queue_mutual_exclusion.conf https://prover.certora.com/output/497546/051cf84b7c61458e9e93d1b76f4bdd17?anonymousKey=204692d6b56438e2251e453a2eea7b8b583eb557
public fun commit_withdrawal_tx_does_not_create_duplicate_txn(
    hashi: &mut Hashi,
    withdrawal_id: address,
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
    cert: CommitteeSignature,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    let in_flight_pre = queue.contains_withdrawal_txn(withdrawal_id);
    let confirmed_pre = queue.contains_confirmed_txn(withdrawal_id);
    cvlm_assume_msg(
        !in_flight_pre && !confirmed_pre,
        b"withdrawal_id starts absent from both withdrawal_txns and confirmed_txns",
    );

    hashi::withdraw::commit_withdrawal_tx(
        hashi,
        request_ids,
        selected_utxos,
        outputs,
        txid,
        cert,
        clock,
        r,
        ctx,
    );

    let queue = hashi.bitcoin().withdrawal_queue();
    let in_flight_post = queue.contains_withdrawal_txn(withdrawal_id);
    let confirmed_post = queue.contains_confirmed_txn(withdrawal_id);
    cvlm_assert(!(in_flight_post && confirmed_post));
}
