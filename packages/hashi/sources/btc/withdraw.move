// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: withdraw
module hashi::withdraw;

use hashi::{
    btc::BTC,
    committee::CommitteeSignature,
    hashi::Hashi,
    utxo::UtxoId,
    withdrawal_queue::OutputUtxo
};
use sui::{clock::Clock, coin::{Self, Coin}, random::Random};

#[error]
const EUnauthorizedCancellation: vector<u8> = b"Only the original requester can cancel";
#[error]
const ECooldownNotElapsed: vector<u8> = b"Cancellation cooldown has not elapsed";
#[error]
const ECannotCancelAfterApproval: vector<u8> = b"Cannot cancel a withdrawal that has been approved";

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
/// amount (net of fee) is stored in the withdrawal balance and determines
/// the user's Bitcoin output at commitment time.
///
/// A soul-bound `WithdrawalReceipt` is sent to the sender's wallet,
/// allowing for clients to discover all withdrawals via `getOwnedObjects`.
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

    // Create the withdrawal request and balance.
    let (balance, request, request_id) = hashi::withdrawal_queue::create_withdrawal(
        btc.into_balance(),
        bitcoin_address,
        clock,
        ctx,
    );

    hashi::withdrawal_queue::emit_withdrawal_requested(request_id, &request);

    // Send a soul-bound receipt to the sender's wallet.
    hashi::hashi::send_withdrawal_receipt(request_id, ctx);

    // Insert both the persistent request and operational balance.
    hashi
        .borrow_bitcoin_state_mut()
        .withdrawal_queue_mut()
        .insert_withdrawal(request_id, balance, request);
}

entry fun approve_request(hashi: &mut Hashi, request_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();
    hashi.verify(RequestApprovalMessage { request_id }, cert);

    hashi.borrow_bitcoin_state_mut().withdrawal_queue_mut().approve_withdrawal(request_id);
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

    // Generate the pending withdrawal ID upfront so we can reference it in request statuses.
    let pending_id = ctx.fresh_object_address();

    // Borrow BitcoinState: spend UTXOs, consume approved balances
    let btc = hashi.borrow_bitcoin_state_mut();
    let inputs = selected_utxos.map!(|utxo_id| btc.utxo_pool_mut().spend(utxo_id, epoch));
    let (request_infos, balances_to_burn) = btc
        .withdrawal_queue_mut()
        .consume_approved_balances(&request_ids, pending_id);
    // btc borrow released

    // Allocate presigs from core counter (must happen after btc borrow is released)
    let presig_start_index = hashi.allocate_presigs(inputs.length());

    // Burn BTC balances
    balances_to_burn.do!(|bal| hashi.treasury_mut().burn(bal));

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(32);

    let pending_withdrawal = hashi::withdrawal_queue::new_pending_withdrawal(
        pending_id,
        request_ids,
        &request_infos,
        inputs,
        outputs,
        txid,
        presig_start_index,
        epoch,
        hashi.config(),
        clock,
        randomness,
    );

    pending_withdrawal.emit_withdrawal_picked_for_processing();

    // Re-borrow BitcoinState to insert pending withdrawal
    hashi
        .borrow_bitcoin_state_mut()
        .withdrawal_queue_mut()
        .insert_pending_withdrawal(pending_withdrawal);
}

entry fun allocate_presigs_for_pending_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    let epoch = hashi.committee_set().epoch();
    let num_inputs = hashi
        .borrow_bitcoin_state()
        .withdrawal_queue()
        .pending_withdrawal_num_inputs(withdrawal_id);
    let presig_start_index = hashi.allocate_presigs(num_inputs);
    hashi
        .borrow_bitcoin_state_mut()
        .withdrawal_queue_mut()
        .reassign_presigs_for_pending_withdrawal(
            withdrawal_id,
            presig_start_index,
            epoch,
        );
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

    let queue = hashi.borrow_bitcoin_state_mut().withdrawal_queue_mut();
    queue.sign_pending_withdrawal(withdrawal_id, signatures);
    queue.update_requests_signed(&request_ids, withdrawal_id);
}

entry fun confirm_withdrawal(hashi: &mut Hashi, withdrawal_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.verify(WithdrawalConfirmationMessage { withdrawal_id }, cert);

    let btc = hashi.borrow_bitcoin_state_mut();
    let withdrawal = btc.withdrawal_queue_mut().remove_pending_withdrawal(withdrawal_id);

    withdrawal.emit_withdrawal_confirmed();
    let (request_ids, txid, change_utxo) = withdrawal.destroy_pending_withdrawal();

    // Update all request statuses to Confirmed with the bitcoin txid
    btc.withdrawal_queue_mut().update_requests_confirmed(&request_ids, txid);

    // Insert the change UTXO back into the active pool
    if (change_utxo.is_some()) {
        btc.utxo_pool_mut().insert_active(change_utxo.destroy_some());
    } else {
        change_utxo.destroy_none();
    };
}

/// Cancel a pending withdrawal request and return the stored BTC to the requester.
///
/// NOTE: The protocol fee (`withdrawal_fee_btc`) was deducted at request time and
/// is non-refundable. The returned amount is the net BTC stored in the
/// balance (original amount minus protocol fee).
public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<BTC> {
    hashi.config().assert_version_enabled();

    // Read the persistent request for sender/timestamp checks (it has copy)
    let request = *hashi.borrow_bitcoin_state().withdrawal_queue().borrow_request(request_id);

    // Can only cancel before approval
    assert!(
        !hashi.borrow_bitcoin_state().withdrawal_queue().is_balance_approved(request_id),
        ECannotCancelAfterApproval,
    );

    // Only the original requester can cancel
    assert!(request.request_sender() == ctx.sender(), EUnauthorizedCancellation);

    // Enforce cooldown
    let cooldown = hashi::btc_config::withdrawal_cancellation_cooldown_ms(hashi.config());
    assert!(clock.timestamp_ms() >= request.request_timestamp_ms() + cooldown, ECooldownNotElapsed);

    hashi::withdrawal_queue::emit_withdrawal_cancelled(request_id, &request);

    // Remove balance and update status to Cancelled
    let btc = hashi.borrow_bitcoin_state_mut().withdrawal_queue_mut().cancel_withdrawal(request_id);
    coin::from_balance(btc, ctx)
}

public fun delete_expired_spent_utxo(hashi: &mut Hashi, utxo_id: UtxoId) {
    hashi.config().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    hashi
        .borrow_bitcoin_state_mut()
        .utxo_pool_mut()
        .delete_expired_spent_utxo(utxo_id, current_epoch);
}
