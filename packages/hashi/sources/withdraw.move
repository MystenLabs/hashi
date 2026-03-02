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

public struct WithdrawalApproval has copy, drop, store {
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
}

public struct WithdrawalConfirmation has copy, drop, store {
    withdrawal_id: address,
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
    assert!(hashi.config().withdrawal_fee() == fee.value());
    hashi.treasury_mut().deposit_fee(fee);

    // check that the withdrawal amount is a minimum of X
    assert!(btc.value() >= hashi.config().withdrawal_minimum());

    let request = withdrawal_request(btc.into_balance(), bitcoin_address, clock, ctx);
    request.emit_withdrawal_requested();
    hashi.withdrawal_queue_mut().insert_request(request);
}

// Leader picks request to process
// - Do sanctions checks
// - Do rate limit checks
// - Coin selection and craft txn (outputs would be to withdrawal address and change goes to hashi pubkey)
// - Broadcast txn to committee for agreement (maybe get preauth from guardian?)
// - Send txn onchain to commit to the txn
// - commit to utxos to use in input
entry fun pick_withdrawal_for_processing(
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

    let requests = request_ids.map!(|request_id| {
        let request = hashi.withdrawal_queue_mut().remove_request(request_id);
        let (request, btc) = hashi::withdrawal_queue::request_into_parts(request);

        // burn BTC
        hashi.treasury_mut().burn(btc);

        request
    });

    // Selected UTXOs
    let epoch = hashi.committee_set().epoch();
    let selected_utxos = selected_utxos.map!(|raw| hashi::utxo::utxo_id_from_bcs(raw));
    let inputs = selected_utxos.map!(|utxo_id| hashi.utxo_pool_mut().spend(utxo_id, epoch));

    // outputs
    let outputs = outputs.map!(|raw| hashi::withdrawal_queue::output_utxo_from_bcs(raw));

    let approval = WithdrawalApproval {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    };

    let threshold =
        threshold::certificate_threshold(hashi.current_committee().total_weight() as u16) as u64;
    let approval = hashi
        .current_committee()
        .verify_certificate(approval, cert, threshold)
        .into_message();

    let WithdrawalApproval {
        outputs,
        txid,
        ..,
    } = approval;

    let pending = hashi::withdrawal_queue::new_pending_withdrawal(
        requests,
        inputs,
        outputs,
        txid,
        clock,
        r,
        ctx,
    );
    pending.emit_withdrawal_picked_for_processing();
    hashi.withdrawal_queue_mut().insert_pending_withdrawal(pending);
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
    let confirmation = WithdrawalConfirmation { withdrawal_id };
    let _ = hashi
        .current_committee()
        .verify_certificate(confirmation, cert, threshold)
        .into_message();

    let withdrawal = hashi.withdrawal_queue_mut().remove_pending_withdrawal(withdrawal_id);

    // TODO create and insert new UTXO for change if it hasn't already been
    // inserted

    withdrawal.emit_withdrawal_confirmed();
    withdrawal.destroy_pending_withdrawal();
}

public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<BTC> {
    hashi.config().assert_version_enabled();

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
