/// @module Deposit State Machine
/// @contract hashi::deposit
/// @contract hashi::deposit_queue
/// @impact An unauthorised or replayed deposit could mint hBTC without backing BTC.
///
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
/// @global_assumption A deposit request's key in the requests or processed bag matches
///   the request's own id
/// @global_assumption Pool BTC, the total amount of UTXOs with spent_by == none, is
///   tracked by the ghost total_active_amount, updated by summaries of insert_active,
///   insert_pending, lock and their batched withdraw-side callers
///
/// @property DEPOSIT-STATE-MACHINE A deposit request moves only forward through its
///   state machine: created unapproved and unconfirmed, then approved, then confirmed,
///   with the approval fields always set together and never cleared
module deposit::deposit_field_consistency;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::deposit_queue::{DepositRequest, DepositRequestQueue};
use hashi::hashi::Hashi;
use hashi::utxo::Utxo;
use sui::clock::Clock;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");

    invoker(b"invoke");
    rule(b"approval_fields_paired");
    rule(b"approval_fields_never_reset");
    rule(b"confirmed_implies_approved");

    rule(b"deposit_creates_unapproved_unconfirmed_request");
    rule(b"approve_deposit_sets_approval_fields");
    rule(b"confirm_deposit_sets_confirmed_field");
}

native fun invoke(target: Function, hashi: &mut Hashi, request_id: address);

fun exists_request(queue: &DepositRequestQueue, id: address): bool {
    queue.contains(id) || queue.contains_processed(id)
}

fun borrow_either(queue: &DepositRequestQueue, id: address): &DepositRequest {
    if (queue.contains(id)) queue.borrow_request(id) else queue.borrow_processed(id)
}

fun key_matches_object(queue: &DepositRequestQueue, id: address): bool {
    if (queue.contains(id)) {
        queue.borrow_request(id).request_id().to_address() == id
    } else if (queue.contains_processed(id)) {
        queue.borrow_processed(id).request_id().to_address() == id
    } else {
        true
    }
}

/// @title Approval fields are always set together
/// @description For each of approve_deposit, confirm_deposit and
///   delete_expired_deposit, if a request's approval_cert and approved_timestamp_ms
///   are both set or both unset before a successful call, the same holds after it.
/// @link_property DEPOSIT-STATE-MACHINE
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun approval_fields_paired(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");
    if (exists_request(queue, request_id)) {
        let req = borrow_either(queue, request_id);
        cvlm_assume_msg(
            req.approval_cert().is_some() == req.approved_timestamp_ms().is_some(),
            b"approval fields start paired",
        );
    };

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().deposit_queue();
    if (exists_request(queue2, request_id)) {
        let req2 = borrow_either(queue2, request_id);
        cvlm_assert(req2.approval_cert().is_some() == req2.approved_timestamp_ms().is_some());
    };
}

/// @title Approval is never reset
/// @description For each of approve_deposit, confirm_deposit and
///   delete_expired_deposit, if a request is approved before a successful call, it is
///   still approved after it, unless the call removed the request entirely.
/// @link_property DEPOSIT-STATE-MACHINE
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun approval_fields_never_reset(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");
    cvlm_assume_msg(
        exists_request(queue, request_id) && borrow_either(queue, request_id).approval_cert().is_some(),
        b"request exists and is already approved",
    );

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().deposit_queue();
    if (exists_request(queue2, request_id)) {
        let req2 = borrow_either(queue2, request_id);
        cvlm_assert(req2.approval_cert().is_some());
    };
}

/// @title A confirmed request is always approved
/// @description For each of approve_deposit, confirm_deposit and
///   delete_expired_deposit, if every confirmed request has both approval fields set
///   before a successful call, the same holds after it.
/// @link_property DEPOSIT-STATE-MACHINE
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun confirmed_implies_approved(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");
    if (exists_request(queue, request_id)) {
        let req = borrow_either(queue, request_id);
        cvlm_assume_msg(
            !req.confirmed_timestamp_ms().is_some() ||
            (req.approval_cert().is_some() && req.approved_timestamp_ms().is_some()),
            b"confirmed-implies-approved starts holding",
        );
    };

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().deposit_queue();
    if (exists_request(queue2, request_id)) {
        let req2 = borrow_either(queue2, request_id);
        cvlm_assert(
            !req2.confirmed_timestamp_ms().is_some() ||
            (req2.approval_cert().is_some() && req2.approved_timestamp_ms().is_some()),
        );
    };
}

/// @title deposit creates an unapproved, unconfirmed request
/// @description A successful deposit creates an active request with
///   approval_cert, approved_timestamp_ms and confirmed_timestamp_ms all unset.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The checked request_id is in neither the requests nor the processed bag
///   before the call
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun deposit_creates_unapproved_unconfirmed_request(
    hashi: &mut Hashi,
    request_id: address,
    utxo: Utxo,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(!exists_request(queue, request_id), b"candidate request_id starts absent");

    hashi::deposit::deposit(hashi, utxo, clock, ctx);

    let queue2 = hashi.bitcoin().deposit_queue();
    if (queue2.contains(request_id)) {
        let req = queue2.borrow_request(request_id);
        cvlm_assert(req.approval_cert().is_none());
        cvlm_assert(req.approved_timestamp_ms().is_none());
        cvlm_assert(req.confirmed_timestamp_ms().is_none());
    };
}

/// @title approve_deposit sets both approval fields
/// @description A successful approve_deposit on an active request leaves it
///   active, with approval_cert and approved_timestamp_ms both set.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The request is in the requests bag (active) before the call
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun approve_deposit_sets_approval_fields(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(queue.contains(request_id), b"request is active before the call");
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");

    hashi::deposit::approve_deposit(hashi, request_id, cert, clock, ctx);

    let queue2 = hashi.bitcoin().deposit_queue();
    cvlm_assert(queue2.contains(request_id));
    let req = queue2.borrow_request(request_id);
    cvlm_assert(req.approval_cert().is_some());
    cvlm_assert(req.approved_timestamp_ms().is_some());
}

/// @title confirm_deposit moves the request to processed and confirms it
/// @description A successful confirm_deposit on an active request moves it to
///   the processed set, with confirmed_timestamp_ms set.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The request is in the requests bag (active) before the call
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun confirm_deposit_sets_confirmed_field(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(queue.contains(request_id), b"request is active before the call");
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");

    hashi::deposit::confirm_deposit(hashi, request_id, clock, ctx);

    let queue2 = hashi.bitcoin().deposit_queue();
    cvlm_assert(queue2.contains_processed(request_id));
    let req = queue2.borrow_processed(request_id);
    cvlm_assert(req.confirmed_timestamp_ms().is_some());
}
