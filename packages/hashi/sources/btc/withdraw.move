// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: withdraw
module hashi::withdraw;

use hashi::{
    btc::BTC,
    btc_config,
    committee::CommitteeSignature,
    config::Config,
    hashi::Hashi,
    utxo::UtxoId,
    withdrawal_queue::OutputUtxo
};
use sui::{balance::Balance, clock::Clock, random::Random};

use fun btc_config::bitcoin_withdrawal_minimum as Config.bitcoin_withdrawal_minimum;
use fun btc_config::withdrawal_cancellation_cooldown_ms as
    Config.withdrawal_cancellation_cooldown_ms;

#[error]
const EBelowMinimumWithdrawal: vector<u8> = b"Withdrawal amount is below the minimum";
#[error]
const EInvalidBitcoinAddress: vector<u8> =
    b"Bitcoin address must be 20 bytes (P2WPKH) or 32 bytes (P2TR)";
#[error]
const EUnauthorizedCancellation: vector<u8> = b"Only the original requester can cancel";
#[error]
const ECooldownNotElapsed: vector<u8> = b"Cancellation cooldown has not elapsed";
#[error]
const ECannotCancelProcessingWithdrawal: vector<u8> =
    b"Cannot cancel a withdrawal that is already being processed";

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
/// The full BTC amount is stored in the withdrawal request. The miner
/// fee is deducted later at commitment time.
///
/// The user must provide at least `bitcoin_withdrawal_minimum()` sats,
/// which guarantees the amount covers worst-case miner fees plus dust.
public fun request_withdrawal(
    hashi: &mut Hashi,
    clock: &Clock,
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();

    assert!(btc.value() >= hashi.config().bitcoin_withdrawal_minimum(), EBelowMinimumWithdrawal);

    // Only P2WPKH (20 bytes) and P2TR (32 bytes) witness programs are supported.
    let addr_len = bitcoin_address.length();
    assert!(addr_len == 20 || addr_len == 32, EInvalidBitcoinAddress);

    // Create the withdrawal request.
    let request = hashi::withdrawal_queue::create_withdrawal(
        btc,
        bitcoin_address,
        clock,
        ctx,
    );
    let request_id = request.request_id().to_address();
    hashi::withdrawal_queue::emit_withdrawal_requested(&request);

    // Insert into the active requests bag.
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal(request);

    // Index by sender for client discovery.
    hashi.bitcoin_mut().index_user_request(ctx.sender(), request_id, ctx);
}

entry fun approve_request(hashi: &mut Hashi, request_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();
    hashi.verify(RequestApprovalMessage { request_id }, cert);

    hashi.bitcoin_mut().withdrawal_queue_mut().approve_withdrawal(request_id);
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

    let WithdrawalCommitmentMessage { outputs, txid, .. } = approval;

    // Copy the full UTXO data from the pool before locking — used for fee
    // accounting and event emission inside new_withdrawal_txn.
    let inputs = selected_utxos.map!(|utxo_id| hashi.bitcoin().utxo_pool().get_utxo(utxo_id));

    // Extract request data for fee validation (read-only, before the object exists).
    let request_infos = hashi.bitcoin().withdrawal_queue().extract_request_infos(&request_ids);

    // Allocate presigs from core counter
    let presig_start_index = hashi.allocate_presigs(inputs.length());

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(32);

    // Create the WithdrawalTransaction object
    let withdrawal_txn = hashi::withdrawal_queue::new_withdrawal_txn(
        ctx,
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

    // Now that the object exists, use its ID for UTXO locks and request commits.
    let withdrawal_txn_id = withdrawal_txn.withdrawal_txn_id();

    // Lock input UTXOs to this withdrawal transaction.
    withdrawal_txn.withdrawal_txn_inputs().do_ref!(|utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().lock(utxo.id(), withdrawal_txn_id);
    });

    // Commit requests: drain BTC, set status + withdrawal_txn_id, move to processed.
    let btc_to_burn = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&withdrawal_txn);

    // Burn BTC balance
    hashi.treasury_mut().burn(btc_to_burn);

    // Insert the pending change UTXO into the pool immediately so it can be
    // selected by subsequent transactions before this one confirms on Bitcoin.
    let change_utxo_opt = hashi::withdrawal_queue::build_change_utxo(&withdrawal_txn);
    if (change_utxo_opt.is_some()) {
        hashi
            .bitcoin_mut()
            .utxo_pool_mut()
            .insert_pending(change_utxo_opt.destroy_some(), withdrawal_txn_id);
    } else {
        change_utxo_opt.destroy_none();
    };

    withdrawal_txn.emit_withdrawal_picked_for_processing();

    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal_txn(withdrawal_txn);
}

entry fun allocate_presigs_for_withdrawal_txn(
    hashi: &mut Hashi,
    withdrawal_id: address,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    let epoch = hashi.committee_set().epoch();
    let num_inputs = hashi.bitcoin().withdrawal_queue().withdrawal_txn_num_inputs(withdrawal_id);
    let presig_start_index = hashi.allocate_presigs(num_inputs);
    hashi
        .bitcoin_mut()
        .withdrawal_queue_mut()
        .reassign_presigs_for_withdrawal_txn(withdrawal_id, presig_start_index, epoch);
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

    let approval = WithdrawalSignedMessage { withdrawal_id, request_ids, signatures };

    hashi.verify(approval, cert);

    let WithdrawalSignedMessage { withdrawal_id, signatures, .. } = approval;

    let queue = hashi.bitcoin_mut().withdrawal_queue_mut();
    queue.sign_withdrawal_txn(withdrawal_id, signatures);
    queue.update_requests_signed(&request_ids);
}

entry fun confirm_withdrawal(hashi: &mut Hashi, withdrawal_id: address, cert: CommitteeSignature) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.verify(WithdrawalConfirmationMessage { withdrawal_id }, cert);

    // Remove the in-flight withdrawal txn from the hot bag so we can do
    // all the bookkeeping with a direct handle, then re-insert it into the
    // confirmed bag at the end.
    let txn = hashi.bitcoin_mut().withdrawal_queue_mut().remove_withdrawal_txn(withdrawal_id);
    txn.emit_withdrawal_confirmed();

    // Update request statuses to Confirmed.
    hashi
        .bitcoin_mut()
        .withdrawal_queue_mut()
        .update_requests_confirmed(txn.withdrawal_txn_request_ids());

    let epoch = hashi.committee_set().epoch();

    // Mark each input UTXO as spent and emit spent events. The actual record
    // removal from utxo_records is deferred to `cleanup_spent_utxos` so this
    // transaction stays well under Sui's 1000-object runtime cache limit.
    txn.withdrawal_txn_inputs().do_ref!(|utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo.id(), epoch);
    });

    // Promote the change UTXO from unconfirmed to confirmed. If the change was
    // already locked by a subsequent withdrawal, only `produced_by` is cleared.
    let change_id = txn.change_utxo_id();
    if (change_id.is_some()) {
        hashi.bitcoin_mut().utxo_pool_mut().confirm_pending(change_id.destroy_some());
    } else {
        change_id.destroy_none();
    };

    // Move the txn to the cold (historical) bag.
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_confirmed_txn(txn);
}

/// Finalize the on-chain bookkeeping for spent UTXOs. Moves each UTXO's
/// record from `utxo_records` to `spent_utxos`, reading the spent epoch
/// from the record's `spent_epoch` field (set by `mark_spent` during
/// `confirm_withdrawal`). Callers pass the individual UTXO IDs to clean up.
entry fun cleanup_spent_utxos(hashi: &mut Hashi, utxo_ids: vector<UtxoId>) {
    hashi.config().assert_version_enabled();
    utxo_ids.do!(|utxo_id| {
        hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);
    });
}

/// Cancel a pending withdrawal request and return the stored BTC to the requester.
///
/// Cancellation is allowed while the request is in the `Requested` or `Approved`
/// state (i.e. still in the active requests bag). Once the committee commits the
/// request to a `WithdrawalTransaction` it moves to `Processing` in the processed
/// bag and its BTC is burned — cancellation is no longer possible.
public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Balance<BTC> {
    hashi.config().assert_version_enabled();

    assert!(
        !hashi.bitcoin().withdrawal_queue().is_request_processing(request_id),
        ECannotCancelProcessingWithdrawal,
    );

    let request = hashi.bitcoin().withdrawal_queue().borrow_request(request_id);

    // Only the original requester can cancel.
    assert!(request.request_sender() == ctx.sender(), EUnauthorizedCancellation);

    // Enforce cooldown.
    let cooldown = hashi.config().withdrawal_cancellation_cooldown_ms();
    assert!(clock.timestamp_ms() >= request.request_timestamp_ms() + cooldown, ECooldownNotElapsed);

    hashi::withdrawal_queue::emit_withdrawal_cancelled(request);

    // Return BTC to the requester.
    let btc = hashi.bitcoin_mut().withdrawal_queue_mut().cancel_withdrawal(request_id);

    // Clean up the user index.
    hashi.bitcoin_mut().unindex_user_request(ctx.sender(), request_id);

    btc
}
