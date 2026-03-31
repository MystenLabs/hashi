// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit;

use hashi::{btc::BTC, committee::CommitteeSignature, hashi::Hashi, utxo::UtxoId};
use sui::{coin::{Self, Coin}, sui::SUI};

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
    assert!(hashi::btc_config::deposit_fee(hashi.config()) == fee.value());
    sui::coin::send_funds(fee, hashi.id().to_address());

    // Check that the deposit amount meets the dust minimum
    assert!(request.utxo().amount() >= hashi::btc_config::deposit_minimum(hashi.config()));

    // Check that the UTXO isn't already active or previously spent (replay protection)
    assert!(!hashi.bitcoin().utxo_pool().is_spent_or_active(request.utxo().id()));

    let deposit_requested_event = DepositRequestedEvent {
        request_id: request.id(),
        utxo_id: request.utxo().id(),
        amount: request.utxo().amount(),
        derivation_path: request.utxo().derivation_path(),
        timestamp_ms: request.timestamp_ms(),
        requester_address: request.requester_address(),
        sui_tx_digest: request.sui_tx_digest(),
    };

    hashi.bitcoin_mut().deposit_queue_mut().insert(request);
    sui::event::emit(deposit_requested_event);
}

public fun confirm_deposit(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow confirmation of deposits during a reconfiguration, this
    // delays the confirmation to be done by the next epoch's committee.
    hashi.assert_not_reconfiguring();

    let request = hashi.bitcoin_mut().deposit_queue_mut().remove(request_id);

    let deposit_confirmed_event = DepositConfirmedEvent {
        request_id: request.id(),
        utxo_id: request.utxo().id(),
        amount: request.utxo().amount(),
        derivation_path: request.utxo().derivation_path(),
    };

    // Verify the certificate over the request.
    let request = hashi.verify(request, cert).into_message();

    let utxo = request.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        // XXX Do we want to check an inflow limit here?
        let btc = hashi.treasury_mut().mint_balance<BTC>(amount);
        transfer::public_transfer(coin::from_balance(btc, ctx), recipient);
    };

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);
    sui::event::emit(deposit_confirmed_event);
}

public fun delete_expired_deposit(
    hashi: &mut Hashi,
    request_id: address,
    clock: &sui::clock::Clock,
) {
    hashi.config().assert_version_enabled();
    hashi.bitcoin_mut().deposit_queue_mut().delete_expired(request_id, clock);

    let expired_deposit_deleted_event = ExpiredDepositDeletedEvent {
        request_id,
    };
    sui::event::emit(expired_deposit_deleted_event);
}

public struct DepositRequestedEvent has copy, drop {
    request_id: address,
    utxo_id: UtxoId,
    amount: u64,
    derivation_path: Option<address>,
    timestamp_ms: u64,
    requester_address: address,
    sui_tx_digest: vector<u8>,
}

public struct DepositConfirmedEvent has copy, drop {
    request_id: address,
    utxo_id: UtxoId,
    amount: u64,
    derivation_path: Option<address>,
    // signature: CommitteeSignature,
}

public struct ExpiredDepositDeletedEvent has copy, drop {
    request_id: address,
}
