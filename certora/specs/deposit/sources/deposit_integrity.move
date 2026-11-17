/// @module Deposit State Machine
/// @contract hashi::deposit
/// @contract hashi::deposit_queue
/// @contract hashi::utxo_pool
module deposit::deposit_integrity;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg, cvlm_satisfy_msg};
use cvlm::manifest::rule;
use hashi::btc::BTC;
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use hashi::utxo::Utxo;
use hashi::utxo_pool::UtxoPool;
use sui::clock::Clock;

public fun cvlm_manifest() {
    rule(b"confirm_requires_prior_approval");

    rule(b"confirm_deposit_at_most_once");

    rule(b"no_same_epoch_reapproval");

    rule(b"insert_active_rejects_duplicate");

    rule(b"insert_pending_rejects_spent");

    rule(b"confirm_deposit_mint_matches_condition");
}

/// @title confirm_deposit requires a prior approval
/// @description A successful confirm_deposit on an active request implies the
///   request already had approval_cert and approved_timestamp_ms set before the call.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The request is in the requests bag (active) before the call
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun confirm_requires_prior_approval(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(queue.contains(request_id), b"request_id is active before the call");
    let req = queue.borrow_request(request_id);
    let had_cert = req.approval_cert().is_some();
    let had_ts = req.approved_timestamp_ms().is_some();

    hashi::deposit::confirm_deposit(hashi, request_id, clock, ctx);

    cvlm_assert(had_cert);
    cvlm_assert(had_ts);
}

/// @title confirm_deposit succeeds at most once per request
/// @description No execution has two successful confirm_deposit calls for the same
///   request_id.
/// @link_property DEPOSIT-STATE-MACHINE
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun confirm_deposit_at_most_once(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    hashi::deposit::confirm_deposit(hashi, request_id, clock, ctx);
    hashi::deposit::confirm_deposit(hashi, request_id, clock, ctx);

    cvlm_assert(false);
}

/// @title No re-approval within the same committee epoch
/// @description No execution has two successful approve_deposit calls for the same
///   request_id without a committee epoch change in between.
/// @link_property DEPOSIT-STATE-MACHINE
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun no_same_epoch_reapproval(
    hashi: &mut Hashi,
    request_id: address,
    cert1: CommitteeSignature,
    cert2: CommitteeSignature,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    hashi::deposit::approve_deposit(hashi, request_id, cert1, clock, ctx);
    hashi::deposit::approve_deposit(hashi, request_id, cert2, clock, ctx);

    cvlm_assert(false);
}

/// @title The active pool rejects a duplicate UTXO
/// @description No execution inserts two UTXOs with the same UtxoId into the
///   active pool.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The two inserted UTXOs share the same UtxoId
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun insert_active_rejects_duplicate(
    pool: &mut UtxoPool,
    utxo1: Utxo,
    dup: Utxo,
) {
    cvlm_assume_msg(dup.id() == utxo1.id(), b"dup shares utxo1's UtxoId");

    pool.insert_active(utxo1);
    pool.insert_active(dup);

    cvlm_assert(false);
}

/// @title The pending pool rejects an already-spent UTXO
/// @description No execution inserts a UTXO through insert_pending when its UtxoId
///   is already recorded in spent_utxos.
/// @link_property DEPOSIT-STATE-MACHINE
/// @assumption The UTXO's UtxoId is in spent_utxos before the call
/// @status VERIFIED
/// @report deposit_state_machine.conf https://prover.certora.com/output/497546/7b1f99f8331149eea81e1896ba636475?anonymousKey=088eeaac22557f9108dc77501dee95f6b19f6436
public fun insert_pending_rejects_spent(
    pool: &mut UtxoPool,
    utxo: Utxo,
    withdrawal_id: address,
) {
    cvlm_assume_msg(pool.has_spent_record(utxo.id()), b"utxo is already spent");

    pool.insert_pending(utxo, withdrawal_id);

    cvlm_assert(false);
}

/// @ignore
public fun confirm_deposit_mint_matches_condition(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume_msg(queue.contains(request_id), b"request_id is active before the call");
    let utxo = queue.borrow_request(request_id).utxo();
    let derivation = utxo.derivation_path();
    cvlm_assume_msg(
        !hashi.bitcoin().utxo_pool().has_active_record(utxo.id()),
        b"utxo not already active before the call",
    );

    let supply_before = sui::coin::total_supply(hashi.treasury().treasury_cap_ref<BTC>());

    hashi::deposit::confirm_deposit(hashi, request_id, clock, ctx);

    cvlm_assert(hashi.bitcoin().utxo_pool().has_active_record(utxo.id()));

    let supply_after = sui::coin::total_supply(hashi.treasury().treasury_cap_ref<BTC>());
    if (derivation.is_some()) {
        cvlm_assert(supply_after == supply_before + utxo.amount());
    } else {
        cvlm_assert(supply_after == supply_before);
    };
}