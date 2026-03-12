/// Module: withdraw
module hashi::withdraw;

use hashi::{
    btc::BTC,
    committee,
    hashi::Hashi,
    threshold,
    utxo::UtxoId,
    withdrawal_queue::{OutputUtxo, withdrawal_request}
};
use sui::{clock::Clock, coin::{Self, Coin}, random::Random, sui::SUI};

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

// User entry-point for requesting a withdrawal
//
// In order to successfully enqueue a request:
// - The system needs to not be paused
// - The fee needs to be sufficient
// - The requested BTC amount to withdrawal needs to be above a certain minimum
public fun request_withdrawal(
    hashi: &mut Hashi,
    clock: &Clock,
    btc: Coin<BTC>,
    bitcoin_address: vector<u8>,
    fee: Coin<SUI>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();

    // Check that the fee is sufficient
    assert!(hashi.config().withdrawal_fee_sui() == fee.value());
    sui::coin::send_funds(fee, hashi.id().to_address());

    // check that the withdrawal amount is a minimum of X
    assert!(btc.value() >= hashi.config().withdrawal_minimum());

    // Only P2WPKH (20 bytes) and P2TR (32 bytes) witness programs are supported.
    let addr_len = bitcoin_address.length();
    assert!(addr_len == 20 || addr_len == 32);

    let request = withdrawal_request(btc.into_balance(), bitcoin_address, clock, ctx);
    request.emit_withdrawal_requested();
    hashi.withdrawal_queue_mut().insert_request(request);
}

entry fun approve_request(
    hashi: &mut Hashi,
    request_id: address,
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();

    let cert = committee::new_committee_signature(epoch, signature, signers_bitmap);

    let approval = RequestApprovalMessage { request_id };

    let threshold =
        threshold::certificate_threshold(hashi.current_committee().total_weight() as u16) as u64;
    hashi.current_committee().verify_certificate(approval, cert, threshold).into_message();

    hashi.withdrawal_queue_mut().approve_request(request_id);
    hashi::withdrawal_queue::emit_withdrawal_approved(request_id);
}

// NOTE: request_ids and outputs must come presorted, so that request_ids[i] matches outputs[i].
// If there is a change output, it must be the last one in outputs.
entry fun commit_withdrawal_tx(
    hashi: &mut Hashi,
    request_ids: vector<address>,
    selected_utxos: vector<vector<u8>>,
    outputs: vector<vector<u8>>,
    txid: address,
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow scheduling of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let cert = committee::new_committee_signature(epoch, signature, signers_bitmap);

    // Selected UTXOs
    let epoch = hashi.committee_set().epoch();
    let selected_utxos = selected_utxos.map!(|raw| hashi::utxo::utxo_id_from_bcs(raw));
    let inputs = selected_utxos.map!(|utxo_id| hashi.utxo_pool_mut().spend(utxo_id, epoch));

    hashi.withdrawal_queue_mut().increment_num_consumed_presigs(inputs.length());

    // outputs
    let outputs = outputs.map!(|raw| hashi::withdrawal_queue::output_utxo_from_bcs(raw));

    let approval = WithdrawalCommitmentMessage {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    };

    let threshold =
        threshold::certificate_threshold(hashi.current_committee().total_weight() as u16) as u64;
    hashi.current_committee().verify_certificate(approval, cert, threshold).into_message();

    let WithdrawalCommitmentMessage {
        outputs,
        txid,
        ..,
    } = approval;

    let requests = request_ids.map!(|request_id| {
        let request = hashi.withdrawal_queue_mut().remove_approved_request(request_id);
        let (request, btc) = hashi::withdrawal_queue::request_into_parts(request);

        // burn BTC
        hashi.treasury_mut().burn(btc);

        request
    });

    let withdrawal_fee_btc = hashi.config().withdrawal_fee_btc();

    let pending_withdrawal = hashi::withdrawal_queue::new_pending_withdrawal(
        requests,
        inputs,
        outputs,
        txid,
        withdrawal_fee_btc,
        clock,
        r,
        ctx,
    );

    pending_withdrawal.emit_withdrawal_picked_for_processing();
    hashi.withdrawal_queue_mut().insert_pending_withdrawal(pending_withdrawal);
}

entry fun sign_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow scheduling of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let cert = committee::new_committee_signature(epoch, signature, signers_bitmap);

    let approval = WithdrawalSignedMessage {
        withdrawal_id,
        request_ids,
        signatures,
    };

    let threshold =
        threshold::certificate_threshold(hashi.current_committee().total_weight() as u16) as u64;
    hashi.current_committee().verify_certificate(approval, cert, threshold).into_message();

    let WithdrawalSignedMessage { withdrawal_id, signatures, .. } = approval;

    hashi.withdrawal_queue_mut().sign_pending_withdrawal(withdrawal_id, signatures);
}

entry fun confirm_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();

    let cert = committee::new_committee_signature(epoch, signature, signers_bitmap);

    let threshold =
        threshold::certificate_threshold(hashi.current_committee().total_weight() as u16) as u64;
    let confirmation = WithdrawalConfirmationMessage { withdrawal_id };
    let _ = hashi
        .current_committee()
        .verify_certificate(confirmation, cert, threshold)
        .into_message();

    let withdrawal = hashi.withdrawal_queue_mut().remove_pending_withdrawal(withdrawal_id);

    withdrawal.emit_withdrawal_confirmed();
    let change_utxo = withdrawal.destroy_pending_withdrawal();

    // Insert the change UTXO back into the active pool
    if (change_utxo.is_some()) {
        hashi.utxo_pool_mut().insert_active(change_utxo.destroy_some());
    } else {
        change_utxo.destroy_none();
    };
}

public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<BTC> {
    hashi.config().assert_version_enabled();

    assert!(!hashi.withdrawal_queue().is_request_approved(request_id), ERequestAlreadyApproved);

    let request = hashi.withdrawal_queue_mut().remove_request(request_id);

    // Only the original requester can cancel
    assert!(request.requester_address() == ctx.sender(), EUnauthorizedCancellation);

    // Enforce cooldown
    let cooldown = hashi.config().withdrawal_cancellation_cooldown_ms();
    assert!(clock.timestamp_ms() >= request.timestamp_ms() + cooldown, ECooldownNotElapsed);

    request.emit_withdrawal_cancelled();

    // Return BTC to the requester
    let (_, btc) = hashi::withdrawal_queue::request_into_parts(request);
    coin::from_balance(btc, ctx)
}

public fun delete_expired_spent_utxo(hashi: &mut Hashi, txid: address, vout: u32) {
    hashi.config().assert_version_enabled();
    let utxo_id = hashi::utxo::utxo_id(txid, vout);
    let current_epoch = hashi.committee_set().epoch();
    hashi.utxo_pool_mut().delete_expired_spent_utxo(utxo_id, current_epoch);
}
