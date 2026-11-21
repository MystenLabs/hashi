/// @module Withdraw State Machine
/// @contract hashi::withdraw
/// @contract hashi::withdrawal_queue
/// @impact A withdrawal request or transaction could skip or repeat a lifecycle step:
///   a request committed without approval, committed twice, cancelled after its BTC
///   was burned, or archived under the wrong transaction, or a transaction confirmed
///   twice or without being signed, letting BTC leave the pool more than once.
///
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
/// @global_assumption commit_requests is summarized: the real per-request commit runs
///   only for the one request a rule checks, and only when vector::contains reports it
///   in the transaction's request list. That membership answer is not tied to the
///   list's actual contents, and every other request in the list is left untouched
/// @global_assumption The other loops in the withdrawal flow are summarized by opaque
///   per-call amounts: the input UTXO total (locked from the pool and used for fee
///   accounting), the change UTXO total (returned to the pool), the per-request output
///   total, the committed requests' balance total, and the request and output counts.
///   None of these is tied to the actual UTXOs or requests
///
/// @property WITHDRAW-STATE-MACHINE A withdrawal request moves only forward: created
///   unapproved and uncommitted, then approved, then committed to one withdrawal
///   transaction, then archived once that transaction is confirmed, and it can be
///   cancelled only before it is committed. Its approval fields are set together and
///   never cleared, and its link to the transaction never changes. A withdrawal
///   transaction also moves only forward: created unsigned and unconfirmed, then fully
///   signed, then confirmed at most once, then archived
module withdraw::withdraw_request_lifecycle;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::btc::BTC;
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use hashi::utxo::UtxoId;
use hashi::withdrawal_queue::{OutputUtxo, WithdrawalRequest, WithdrawalRequestQueue};
use sui::balance::Balance;
use sui::clock::Clock;
use sui::random::Random;
use withdraw::summaries_utxo_pool::tracked_request;
use withdraw::withdraw_queue_helpers::{queue_bags_distinct, request_in_one_bag};

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
    rule(b"approval_fields_paired");
    rule(b"approval_never_reset");
    rule(b"committed_implies_approved");
    rule(b"commit_link_never_changes");
    rule(b"archived_implies_committed");

    rule(b"request_withdrawal_creates_fresh_request");
    rule(b"approve_request_sets_approval_fields");
    rule(b"reapproval_requires_later_epoch");
    rule(b"commit_links_approved_request");
    rule(b"cancel_destroys_uncommitted_request");
    rule(b"archive_moves_only_linked_request");
}

native fun invoke(target: Function, hashi: &mut Hashi);

public fun exists_request(queue: &WithdrawalRequestQueue, id: address): bool {
    queue.contains_request(id) || queue.contains_processed(id)
}

public fun borrow_either(queue: &WithdrawalRequestQueue, id: address): &WithdrawalRequest {
    if (queue.contains_request(id)) queue.borrow_request(id) else queue.borrow_processed(id)
}

fun approval_paired(req: &WithdrawalRequest): bool {
    req.request_approval_cert().is_some() == req.request_approved_timestamp_ms().is_some()
}

fun link_of(req: &WithdrawalRequest): address {
    let link = req.request_withdrawal_txn_id();
    *link.borrow()
}

/// @title Approval fields are always set together
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, a request's approval_cert and approved_timestamp_ms are both
///   set or both unset.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request is in at most one of the requests and processed
///   bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked request's approval fields are both set or both unset before
///   the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun approval_fields_paired(hashi: &mut Hashi, request_id: address, target: Function) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(request_in_one_bag(queue, request_id), b"request is in at most one bag");
    if (exists_request(queue, request_id)) {
        cvlm_assume_msg(
            approval_paired(borrow_either(queue, request_id)),
            b"approval fields start paired",
        );
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (exists_request(queue, request_id)) {
        cvlm_assert(approval_paired(borrow_either(queue, request_id)));
    };
}

/// @title Approval is never reset
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, an approved request is still approved, unless the call
///   removed it entirely.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request is in at most one of the requests and processed
///   bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked request exists and is approved before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun approval_never_reset(hashi: &mut Hashi, request_id: address, target: Function) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(request_in_one_bag(queue, request_id), b"request is in at most one bag");
    cvlm_assume_msg(
        exists_request(queue, request_id) && borrow_either(queue, request_id).is_approved(),
        b"request exists and is approved",
    );

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (exists_request(queue, request_id)) {
        cvlm_assert(borrow_either(queue, request_id).is_approved());
    };
}

/// @title A committed request is always approved
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, a committed request is approved.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request is in at most one of the requests and processed
///   bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked request, if committed, is approved before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun committed_implies_approved(hashi: &mut Hashi, request_id: address, target: Function) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(request_in_one_bag(queue, request_id), b"request is in at most one bag");
    if (exists_request(queue, request_id)) {
        let req = borrow_either(queue, request_id);
        cvlm_assume_msg(!req.is_committed() || req.is_approved(), b"committed implies approved");
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (exists_request(queue, request_id)) {
        let req = borrow_either(queue, request_id);
        cvlm_assert(!req.is_committed() || req.is_approved());
    };
}

/// @title A committed request keeps its transaction link and is never destroyed
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, a committed request still exists and is still committed to the
///   same withdrawal transaction.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request is in at most one of the requests and processed
///   bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked request exists and is committed before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun commit_link_never_changes(hashi: &mut Hashi, request_id: address, target: Function) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(request_in_one_bag(queue, request_id), b"request is in at most one bag");
    cvlm_assume_msg(
        exists_request(queue, request_id) && borrow_either(queue, request_id).is_committed(),
        b"request exists and is committed",
    );
    let withdrawal_id = link_of(borrow_either(queue, request_id));

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(exists_request(queue, request_id));
    let req = borrow_either(queue, request_id);
    cvlm_assert(req.is_committed());
    cvlm_assert(link_of(req) == withdrawal_id);
}

/// @title An archived request is always committed
/// @description After a successful call to any withdraw entry point other than
///   request_withdrawal, a request in the processed bag is committed.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request, if in the processed bag, is committed before the
///   call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun archived_implies_committed(hashi: &mut Hashi, request_id: address, target: Function) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    if (queue.contains_processed(request_id)) {
        cvlm_assume_msg(
            queue.borrow_processed(request_id).is_committed(),
            b"archived request starts committed",
        );
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (queue.contains_processed(request_id)) {
        cvlm_assert(queue.borrow_processed(request_id).is_committed());
    };
}

/// @title request_withdrawal creates an unapproved, uncommitted request
/// @description A successful request_withdrawal creates a live request with
///   approval_cert, approved_timestamp_ms and withdrawal_txn_id all unset.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request_id is in neither the requests nor the processed bag
///   before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun request_withdrawal_creates_fresh_request(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(!exists_request(queue, request_id), b"candidate request_id starts absent");

    hashi::withdraw::request_withdrawal(hashi, clock, btc, bitcoin_address, ctx);

    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(!queue.contains_processed(request_id));
    if (queue.contains_request(request_id)) {
        let req = queue.borrow_request(request_id);
        cvlm_assert(req.request_approval_cert().is_none());
        cvlm_assert(req.request_approved_timestamp_ms().is_none());
        cvlm_assert(req.request_withdrawal_txn_id().is_none());
    };
}

/// @title approve_request sets both approval fields on an uncommitted request
/// @description A successful approve_request was called on an uncommitted request,
///   and leaves it live and uncommitted with approval_cert and approved_timestamp_ms
///   both set.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The request is in the requests bag before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun approve_request_sets_approval_fields(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_request(request_id), b"request is live before the call");
    let was_committed = queue.borrow_request(request_id).is_committed();

    hashi::withdraw::approve_request(hashi, request_id, cert, clock);

    cvlm_assert(!was_committed);
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(queue.contains_request(request_id));
    let req = queue.borrow_request(request_id);
    cvlm_assert(!req.is_committed());
    cvlm_assert(req.request_approval_cert().is_some());
    cvlm_assert(req.request_approved_timestamp_ms().is_some());
}

/// @title Re-approval needs a certificate from a later epoch
/// @description A successful approve_request on an already-approved request uses a
///   certificate whose epoch is strictly later than the stored certificate's.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The request is in the requests bag and approved before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun reapproval_requires_later_epoch(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_request(request_id), b"request is live before the call");
    let old_cert = queue.borrow_request(request_id).request_approval_cert();
    cvlm_assume_msg(old_cert.is_some(), b"request is already approved");
    let old_epoch = old_cert.borrow().signature_epoch();
    let new_epoch = cert.signature_epoch();

    hashi::withdraw::approve_request(hashi, request_id, cert, clock);

    cvlm_assert(old_epoch < new_epoch);
}

/// @title commit_withdrawal_tx commits only approved, uncommitted requests
/// @description A successful commit_withdrawal_tx that includes a request was called
///   when that request was approved and uncommitted, and leaves it live, approved and
///   linked to a withdrawal transaction in the withdrawal_txns bag.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The request is in the requests bag before the call
/// @assumption The request is in the request_ids passed to commit_withdrawal_tx
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun commit_links_approved_request(
    hashi: &mut Hashi,
    request_id: address,
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
    cert: CommitteeSignature,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    cvlm_assume_msg(tracked_request() == request_id, b"commit summary tracks this request");
    cvlm_assume_msg(request_ids.contains(&request_id), b"request is in the transaction");
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_request(request_id), b"request is live before the call");
    let was_approved = queue.borrow_request(request_id).is_approved();
    let was_committed = queue.borrow_request(request_id).is_committed();

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

    cvlm_assert(was_approved);
    cvlm_assert(!was_committed);
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(queue.contains_request(request_id));
    let req = queue.borrow_request(request_id);
    cvlm_assert(req.is_approved());
    cvlm_assert(req.is_committed());
    cvlm_assert(queue.contains_withdrawal_txn(link_of(req)));
}

/// @title cancel_withdrawal destroys only uncommitted requests
/// @description A successful cancel_withdrawal was called on an uncommitted request,
///   and leaves it in neither the requests nor the processed bag.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked request is in at most one of the requests and processed
///   bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The request is in the requests bag before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun cancel_destroys_uncommitted_request(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(request_in_one_bag(queue, request_id), b"request is in at most one bag");
    cvlm_assume_msg(queue.contains_request(request_id), b"request is live before the call");
    let was_committed = queue.borrow_request(request_id).is_committed();

    let refund = hashi::withdraw::cancel_withdrawal(hashi, request_id, clock, ctx);
    sui::balance::destroy_for_testing(refund);

    cvlm_assert(!was_committed);
    cvlm_assert(!exists_request(hashi.bitcoin().withdrawal_queue(), request_id));
}

/// @title Archival moves only requests linked to a confirmed transaction
/// @description A successful archive_withdrawal_requests for a withdrawal_id and a
///   live request moves that request to the processed bag, and only when the request
///   is committed to that withdrawal_id and the transaction is confirmed.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The withdrawal transaction is in the withdrawal_txns bag before the call
/// @assumption The request is in the requests bag and not in the processed bag before
///   the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun archive_moves_only_linked_request(
    hashi: &mut Hashi,
    withdrawal_id: address,
    request_id: address,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"transaction is in flight");
    cvlm_assume_msg(
        queue.contains_request(request_id) && !queue.contains_processed(request_id),
        b"request is live and not archived",
    );
    let req = queue.borrow_request(request_id);
    let was_linked = req.is_committed() && link_of(req) == withdrawal_id;
    let txn_confirmed = queue
        .borrow_withdrawal_txn(withdrawal_id)
        .withdrawal_txn_confirmed_timestamp_ms()
        .is_some();

    hashi::withdraw::archive_withdrawal_requests(hashi, withdrawal_id, vector[request_id]);

    cvlm_assert(was_linked);
    cvlm_assert(txn_confirmed);
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(!queue.contains_request(request_id));
    cvlm_assert(queue.contains_processed(request_id));
    cvlm_assert(link_of(queue.borrow_processed(request_id)) == withdrawal_id);
}
