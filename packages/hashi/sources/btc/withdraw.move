// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: withdraw
module hashi::withdraw;

use hashi::{
    btc::BTC,
    committee::CommitteeSignature,
    hashi::Hashi,
    utxo::UtxoId,
    withdrawal_queue::{OutputUtxo, withdrawal_request}
};
use sui::{clock::Clock, coin::{Self, Coin}, random::Random};

#[error]
const EUnauthorizedCancellation: vector<u8> = b"Only the original requester can cancel";
#[error]
const ECooldownNotElapsed: vector<u8> = b"Cancellation cooldown has not elapsed";
#[error]
const ERequestAlreadyApproved: vector<u8> = b"Request has already been approved";

// MESSAGE STEP 1
public struct RequestApprovalMessage has copy, drop, store {
    request_id: address,
}

// MESSAGE STEP 2
public struct WithdrawalCommitmentMessage has copy, drop, store {
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
}

// MESSAGE STEP 3
public struct WithdrawalSignedMessage has copy, drop, store {
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
}

// MESSAGE STEP 4
public struct WithdrawalConfirmationMessage has copy, drop, store {
    withdrawal_id: address,
}

// ======== Message Constructors ========

public(package) fun new_request_approval_message(request_id: address): RequestApprovalMessage {
    RequestApprovalMessage { request_id }
}

public(package) fun new_withdrawal_commitment_message(
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
): WithdrawalCommitmentMessage {
    WithdrawalCommitmentMessage { request_ids, selected_utxos, outputs, txid }
}

public(package) fun new_withdrawal_signed_message(
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
): WithdrawalSignedMessage {
    WithdrawalSignedMessage { withdrawal_id, request_ids, signatures }
}

public(package) fun new_withdrawal_confirmation_message(
    withdrawal_id: address,
): WithdrawalConfirmationMessage {
    WithdrawalConfirmationMessage { withdrawal_id }
}

/// Request a withdrawal of BTC from the bridge.
///
/// The protocol fee (`withdrawal_fee_btc`) is deducted upfront from the
/// provided BTC coin and sent to Hashi's address balance. The remaining
/// amount (net of fee) is stored in the withdrawal request and determines
/// the user's Bitcoin output at commitment time.
///
/// The user must provide at least `withdrawal_minimum()` sats, which
/// guarantees the net amount covers worst-case miner fees plus dust.
public fun request_withdrawal(
    hashi: &mut Hashi,
    clock: &Clock,
    mut btc: Coin<BTC>,
    bitcoin_address: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();

    assert!(btc.value() >= hashi::btc_config::withdrawal_minimum(hashi.config()));

    // Only P2WPKH (20 bytes) and P2TR (32 bytes) witness programs are supported.
    let addr_len = bitcoin_address.length();
    assert!(addr_len == 20 || addr_len == 32);

    // Deduct protocol fee upfront and send to Hashi's address balance.
    let fee_coin = btc.split(hashi::btc_config::withdrawal_fee_btc(hashi.config()), ctx);
    sui::coin::send_funds(fee_coin, hashi.id().to_address());

    // Store remaining BTC (net of protocol fee) in the withdrawal request.
    let request = withdrawal_request(btc.into_balance(), bitcoin_address, clock, ctx);
    request.emit_withdrawal_requested();
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_request(request);
}

entry fun approve_request(hashi: &mut Hashi, request_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();
    hashi.verify(RequestApprovalMessage { request_id }, cert);

    hashi.bitcoin_mut().withdrawal_queue_mut().approve_request(request_id);
    hashi::withdrawal_queue::emit_withdrawal_approved(request_id);
}

// NOTE: request_ids and outputs must come presorted, so that request_ids[i] matches outputs[i].
// If there is a change output, it must be the last one in outputs.
entry fun commit_withdrawal_tx(
    hashi: &mut Hashi,
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
    cert: CommitteeSignature,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow scheduling of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let epoch = hashi.committee_set().epoch();

    // Copy the full UTXO data from the pool before locking — used for fee
    // accounting and event emission inside new_pending_withdrawal.
    let inputs = selected_utxos.map!(|utxo_id| hashi.bitcoin().utxo_pool().get_utxo(utxo_id));

    let presig_start_index = hashi.bitcoin().withdrawal_queue().num_consumed_presigs();
    hashi.bitcoin_mut().withdrawal_queue_mut().increment_num_consumed_presigs(inputs.length());

    let approval = WithdrawalCommitmentMessage {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    };

    hashi.verify(approval, cert);

    let WithdrawalCommitmentMessage {
        outputs,
        txid,
        ..,
    } = approval;

    let requests = request_ids.map!(|request_id| {
        let request = hashi.bitcoin_mut().withdrawal_queue_mut().remove_approved_request(request_id);
        let (request, btc) = hashi::withdrawal_queue::request_into_parts(request);

        // burn BTC
        hashi.treasury_mut().burn(btc);

        request
    });

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(32);

    let pending_withdrawal = hashi::withdrawal_queue::new_pending_withdrawal(
        requests,
        inputs,
        outputs,
        txid,
        presig_start_index,
        epoch,
        hashi.config(),
        clock,
        randomness,
        ctx,
    );

    // Lock inputs and insert the pending change UTXO using the withdrawal's
    // freshly-assigned ID. UTXOs remain in the pool until confirm_withdrawal()
    // finalizes them as spent.
    let withdrawal_id = pending_withdrawal.pending_withdrawal_id();
    inputs.do_ref!(|utxo| hashi.bitcoin_mut().utxo_pool_mut().lock(utxo.id(), withdrawal_id));

    // Insert the pending change UTXO into the pool immediately so it can be
    // selected by subsequent transactions before this one confirms on Bitcoin.
    let change_utxo_opt = hashi::withdrawal_queue::build_change_utxo(&pending_withdrawal);
    if (change_utxo_opt.is_some()) {
        hashi.bitcoin_mut().utxo_pool_mut().insert_pending(change_utxo_opt.destroy_some(), withdrawal_id);
    } else {
        change_utxo_opt.destroy_none();
    };

    pending_withdrawal.emit_withdrawal_picked_for_processing();
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_pending_withdrawal(pending_withdrawal);
}

entry fun allocate_presigs_for_pending_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    let epoch = hashi.committee_set().epoch();
    hashi.bitcoin_mut().withdrawal_queue_mut().allocate_presigs_for_pending_withdrawal(withdrawal_id, epoch);
}

entry fun sign_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
    cert: CommitteeSignature,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow signing of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let approval = WithdrawalSignedMessage {
        withdrawal_id,
        request_ids,
        signatures,
    };

    hashi.verify(approval, cert);

    let WithdrawalSignedMessage { withdrawal_id, signatures, .. } = approval;

    hashi.bitcoin_mut().withdrawal_queue_mut().sign_pending_withdrawal(withdrawal_id, signatures);
}

entry fun confirm_withdrawal(hashi: &mut Hashi, withdrawal_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.verify(WithdrawalConfirmationMessage { withdrawal_id }, cert);

    let withdrawal = hashi.bitcoin_mut().withdrawal_queue_mut().remove_pending_withdrawal(withdrawal_id);
    withdrawal.emit_withdrawal_confirmed();

    let (input_utxos, change_id) = withdrawal.destroy_pending_withdrawal();
    let epoch = hashi.committee_set().epoch();

    // Move each locked input to the spent set now that the Bitcoin transaction
    // has been confirmed on-chain.
    input_utxos.do!(|utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().confirm_spent(utxo.id(), epoch);
    });

    // Promote the change UTXO from unconfirmed to confirmed. If the change was
    // already locked by a subsequent withdrawal, only `produced_by` is cleared.
    if (change_id.is_some()) {
        hashi.bitcoin_mut().utxo_pool_mut().confirm_pending(change_id.destroy_some());
    } else {
        change_id.destroy_none();
    };
}

/// Cancel a pending withdrawal request and return the stored BTC to the requester.
///
/// NOTE: The protocol fee (`withdrawal_fee_btc`) was deducted at request time and
/// is non-refundable. The returned amount is the net BTC stored in the
/// request (original amount minus protocol fee).
public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<BTC> {
    hashi.config().assert_version_enabled();

    assert!(!hashi.bitcoin().withdrawal_queue().is_request_approved(request_id), ERequestAlreadyApproved);

    let request = hashi.bitcoin_mut().withdrawal_queue_mut().remove_request(request_id);

    // Only the original requester can cancel
    assert!(request.requester_address() == ctx.sender(), EUnauthorizedCancellation);

    // Enforce cooldown
    let cooldown = hashi::btc_config::withdrawal_cancellation_cooldown_ms(hashi.config());
    assert!(clock.timestamp_ms() >= request.timestamp_ms() + cooldown, ECooldownNotElapsed);

    request.emit_withdrawal_cancelled();

    // Return BTC to the requester
    let (_, btc) = hashi::withdrawal_queue::request_into_parts(request);
    coin::from_balance(btc, ctx)
}

public fun delete_expired_spent_utxo(hashi: &mut Hashi, utxo_id: UtxoId) {
    hashi.config().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    hashi.bitcoin_mut().utxo_pool_mut().delete_expired_spent_utxo(utxo_id, current_epoch);
}
