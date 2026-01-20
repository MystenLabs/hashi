/// Module: deposit
module hashi::deposit;

use hashi::{btc::BTC, committee::CommitteeSignature, hashi::Hashi, utxo::UtxoId};
use sui::{coin::Coin, sui::SUI};

public fun deposit(
    hashi: &mut Hashi,
    request: hashi::deposit_queue::DepositRequest,
    fee: Coin<SUI>,
) {
    hashi.config().assert_version_enabled();
    // Check that the system isn't paused, but still allow users to request
    // deposits even when the system is reconfiguring
    hashi.assert_unpaused();

    // Check that the fee is sufficient
    assert!(hashi.config().deposit_fee() == fee.value());
    hashi.treasury_mut().deposit_fee(fee);

    // Check that the provided UTXO doesn't already exist in the system
    assert!(!hashi.utxo_pool().contains(request.utxo().id()));

    let deposit_requested_event = DepositRequestedEvent {
        request_id: request.id(),
        utxo_id: request.utxo().id(),
        amount: request.utxo().amount(),
        derivation_path: request.utxo().derivation_path(),
        timestamp_ms: request.timestamp_ms(),
    };

    hashi.deposit_queue_mut().insert(request);
    sui::event::emit(deposit_requested_event);
}

public fun confirm_deposit(
    hashi: &mut Hashi,
    request_id: address,
    // Committe signature over the deposit request
    signature: CommitteeSignature,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow confirmation of deposits during a reconfiguration, this
    // delays the confirmation to be done by the next epoch's committee.
    hashi.assert_not_reconfiguring();

    let request = hashi.deposit_queue_mut().remove(request_id);

    let deposit_confirmed_event = DepositConfirmedEvent {
        request_id: request.id(),
        utxo_id: request.utxo().id(),
        amount: request.utxo().amount(),
        derivation_path: request.utxo().derivation_path(),
        // signature,
    };

    // verify the Certificate over the request
    let request = hashi
        .current_committee()
        .verify_certificate(request, signature, 6667 /* TODO fill in real value */)
        .into_message();

    let utxo = request.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        // XXX Do we want to check an inflow limit here?
        let btc = hashi.treasury_mut().mint<BTC>(amount, ctx);
        sui::transfer::public_transfer(btc, recipient);
    };

    hashi.utxo_pool_mut().insert(utxo);
    sui::event::emit(deposit_confirmed_event);
}

public struct DepositRequestedEvent has copy, drop {
    request_id: address,
    utxo_id: UtxoId,
    amount: u64,
    derivation_path: Option<address>,
    timestamp_ms: u64,
}

public struct DepositConfirmedEvent has copy, drop {
    request_id: address,
    utxo_id: UtxoId,
    amount: u64,
    derivation_path: Option<address>,
    // signature: CommitteeSignature,
}
