/// @module Withdraw State Machine
/// @contract hashi::withdraw
/// @contract hashi::withdrawal_queue
module withdraw::withdraw_txn_lifecycle;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use hashi::utxo::UtxoId;
use hashi::withdrawal_queue::{OutputUtxo, WithdrawalRequestQueue, WithdrawalTransaction};
use sui::clock::Clock;
use sui::random::Random;
use withdraw::withdraw_queue_helpers::{queue_bags_distinct, txn_in_one_bag};

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
    rule(b"signed_fields_paired");
    rule(b"signed_never_reset");
    rule(b"confirmed_implies_signed");
    rule(b"confirmed_never_reset");
    rule(b"archived_txn_is_confirmed");

    rule(b"commit_creates_unsigned_txn");
    rule(b"finalize_sets_signed_fields");
    rule(b"confirm_sets_confirmed_field");
    rule(b"confirm_withdrawal_at_most_once");
}

native fun invoke(target: Function, hashi: &mut Hashi);

public fun exists_txn(queue: &WithdrawalRequestQueue, id: address): bool {
    queue.contains_withdrawal_txn(id) || queue.contains_confirmed_txn(id)
}

public fun borrow_txn_either(queue: &WithdrawalRequestQueue, id: address): &WithdrawalTransaction {
    if (queue.contains_withdrawal_txn(id)) queue.borrow_withdrawal_txn(id)
    else queue.borrow_confirmed_txn(id)
}

fun is_signed(txn: &WithdrawalTransaction): bool {
    txn.withdrawal_txn_signed_timestamp_ms().is_some()
}

fun is_confirmed(txn: &WithdrawalTransaction): bool {
    txn.withdrawal_txn_confirmed_timestamp_ms().is_some()
}

fun signed_paired(txn: &WithdrawalTransaction): bool {
    txn.withdrawal_txn_has_guardian_signatures() == is_signed(txn)
}

/// @title Signing fields are always set together
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a withdrawal transaction's guardian_signatures and
///   signed_timestamp_ms are both set or both unset.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked transaction is in at most one of the withdrawal_txns and
///   confirmed_txns bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked transaction's signing fields are both set or both unset
///   before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun signed_fields_paired(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(txn_in_one_bag(queue, withdrawal_id), b"transaction is in at most one bag");
    if (exists_txn(queue, withdrawal_id)) {
        cvlm_assume_msg(
            signed_paired(borrow_txn_either(queue, withdrawal_id)),
            b"signing fields start paired",
        );
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (exists_txn(queue, withdrawal_id)) {
        cvlm_assert(signed_paired(borrow_txn_either(queue, withdrawal_id)));
    };
}

/// @title Signing is never reset
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a signed withdrawal transaction still exists and is still
///   signed.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked transaction is in at most one of the withdrawal_txns and
///   confirmed_txns bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked transaction exists and is signed before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun signed_never_reset(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(txn_in_one_bag(queue, withdrawal_id), b"transaction is in at most one bag");
    cvlm_assume_msg(
        exists_txn(queue, withdrawal_id) && is_signed(borrow_txn_either(queue, withdrawal_id)),
        b"transaction exists and is signed",
    );

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(exists_txn(queue, withdrawal_id));
    cvlm_assert(is_signed(borrow_txn_either(queue, withdrawal_id)));
}

/// @title A confirmed transaction is always signed
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a confirmed withdrawal transaction has its guardian
///   signatures and signed_timestamp_ms set.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked transaction is in at most one of the withdrawal_txns and
///   confirmed_txns bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked transaction, if confirmed, is signed before the call
/// @assumption The checked transaction's signing fields are both set or both unset
///   before the call, as signed_fields_paired proves
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun confirmed_implies_signed(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(txn_in_one_bag(queue, withdrawal_id), b"transaction is in at most one bag");
    if (exists_txn(queue, withdrawal_id)) {
        let txn = borrow_txn_either(queue, withdrawal_id);
        cvlm_assume_msg(signed_paired(txn), b"signing fields start paired");
        cvlm_assume_msg(
            !is_confirmed(txn) || (txn.withdrawal_txn_has_guardian_signatures() && is_signed(txn)),
            b"confirmed implies signed",
        );
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (exists_txn(queue, withdrawal_id)) {
        let txn = borrow_txn_either(queue, withdrawal_id);
        cvlm_assert(
            !is_confirmed(txn) || (txn.withdrawal_txn_has_guardian_signatures() && is_signed(txn)),
        );
    };
}

/// @title Confirmation is never reset
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a confirmed withdrawal transaction still exists and is still
///   confirmed.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked transaction is in at most one of the withdrawal_txns and
///   confirmed_txns bags before the call, as WITHDRAW-QUEUE-MUTUAL-EXCLUSION proves
/// @assumption The checked transaction exists and is confirmed before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun confirmed_never_reset(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(txn_in_one_bag(queue, withdrawal_id), b"transaction is in at most one bag");
    cvlm_assume_msg(
        exists_txn(queue, withdrawal_id) && is_confirmed(borrow_txn_either(queue, withdrawal_id)),
        b"transaction exists and is confirmed",
    );

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(exists_txn(queue, withdrawal_id));
    cvlm_assert(is_confirmed(borrow_txn_either(queue, withdrawal_id)));
}

/// @title Only confirmed transactions are archived
/// @description After a successful call to any withdraw entry point other than
///   commit_withdrawal_tx, a withdrawal transaction in the confirmed_txns bag is
///   confirmed.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked transaction, if in the confirmed_txns bag, is confirmed
///   before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun archived_txn_is_confirmed(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    if (queue.contains_confirmed_txn(withdrawal_id)) {
        cvlm_assume_msg(
            is_confirmed(queue.borrow_confirmed_txn(withdrawal_id)),
            b"archived transaction starts confirmed",
        );
    };

    invoke(target, hashi);

    let queue = hashi.bitcoin().withdrawal_queue();
    if (queue.contains_confirmed_txn(withdrawal_id)) {
        cvlm_assert(is_confirmed(queue.borrow_confirmed_txn(withdrawal_id)));
    };
}

/// @title commit_withdrawal_tx creates an unsigned, unconfirmed transaction
/// @description A successful commit_withdrawal_tx creates an in-flight withdrawal
///   transaction with guardian_signatures, signed_timestamp_ms and
///   confirmed_timestamp_ms all unset.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The checked withdrawal_id is in neither the withdrawal_txns nor the
///   confirmed_txns bag before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun commit_creates_unsigned_txn(
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
    cvlm_assume_msg(!exists_txn(queue, withdrawal_id), b"candidate withdrawal_id starts absent");

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
    cvlm_assert(!queue.contains_confirmed_txn(withdrawal_id));
    if (queue.contains_withdrawal_txn(withdrawal_id)) {
        let txn = queue.borrow_withdrawal_txn(withdrawal_id);
        cvlm_assert(!txn.withdrawal_txn_has_guardian_signatures());
        cvlm_assert(!is_signed(txn));
        cvlm_assert(!is_confirmed(txn));
    };
}

/// @title finalize_withdrawal sets both signing fields
/// @description A successful finalize_withdrawal leaves the withdrawal transaction in
///   flight with guardian_signatures and signed_timestamp_ms both set.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The transaction is in the withdrawal_txns bag before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun finalize_sets_signed_fields(
    hashi: &mut Hashi,
    withdrawal_id: address,
    guardian_signatures: vector<vector<u8>>,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"transaction is in flight");

    hashi::withdraw::finalize_withdrawal(hashi, withdrawal_id, guardian_signatures, cert, clock);

    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(queue.contains_withdrawal_txn(withdrawal_id));
    let txn = queue.borrow_withdrawal_txn(withdrawal_id);
    cvlm_assert(txn.withdrawal_txn_has_guardian_signatures());
    cvlm_assert(is_signed(txn));
}

/// @title confirm_withdrawal confirms a fully signed transaction in place
/// @description A successful confirm_withdrawal was called on an unconfirmed
///   transaction with its guardian signatures set, and leaves it in flight with
///   confirmed_timestamp_ms set.
/// @link_property WITHDRAW-STATE-MACHINE
/// @assumption The queue's four bags are distinct objects
/// @assumption The transaction is in the withdrawal_txns bag before the call
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun confirm_sets_confirmed_field(
    hashi: &mut Hashi,
    withdrawal_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue_bags_distinct(queue), b"the four queue bags are distinct");
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"transaction is in flight");
    let txn = queue.borrow_withdrawal_txn(withdrawal_id);
    let had_guardian = txn.withdrawal_txn_has_guardian_signatures();
    let was_confirmed = is_confirmed(txn);

    hashi::withdraw::confirm_withdrawal(hashi, withdrawal_id, cert, clock);

    cvlm_assert(had_guardian);
    cvlm_assert(!was_confirmed);
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assert(queue.contains_withdrawal_txn(withdrawal_id));
    cvlm_assert(is_confirmed(queue.borrow_withdrawal_txn(withdrawal_id)));
}

/// @title confirm_withdrawal succeeds at most once per transaction
/// @description No execution has two successful confirm_withdrawal calls for the same
///   withdrawal_id.
/// @link_property WITHDRAW-STATE-MACHINE
/// @status VERIFIED
/// @report withdraw_state_machine.conf https://prover.certora.com/output/497546/56d7c05f797142c1a0148cf4061e8d07?anonymousKey=3020710a73efb67ac58d0c61391628220498f659
public fun confirm_withdrawal_at_most_once(
    hashi: &mut Hashi,
    withdrawal_id: address,
    cert1: CommitteeSignature,
    cert2: CommitteeSignature,
    clock: &Clock,
) {
    hashi::withdraw::confirm_withdrawal(hashi, withdrawal_id, cert1, clock);
    hashi::withdraw::confirm_withdrawal(hashi, withdrawal_id, cert2, clock);

    cvlm_assert(false);
}
