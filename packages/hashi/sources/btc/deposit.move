// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit;

use hashi::{btc::BTC, committee::CommitteeSignature, deposit_queue, hashi::Hashi, utxo::UtxoId};
use sui::{coin::{Self, Coin}, sui::SUI};

public fun deposit(
    hashi: &mut Hashi,
    utxo: hashi::utxo::Utxo,
    fee: Coin<SUI>,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    // Check that the system isn't paused, but still allow users to request
    // deposits even when the system is reconfiguring
    hashi.assert_unpaused();

    // Check that the fee is sufficient
    assert!(hashi::btc_config::deposit_fee(hashi.config()) == fee.value());
    sui::coin::send_funds(fee, hashi.id().to_address());

    // Check that the deposit amount meets the dust minimum
    assert!(utxo.amount() >= hashi::btc_config::deposit_minimum(hashi.config()));

    // Check that the UTXO isn't already active or previously spent (replay protection)
    assert!(!hashi.borrow_bitcoin_state().utxo_pool().is_spent_or_active(utxo.id()));

    // Create the persistent request and operational pending structs.
    let (pending, request, request_id) = deposit_queue::create_deposit(utxo, clock, ctx);

    sui::event::emit(DepositRequestedEvent {
        request_id,
        utxo_id: pending.pending_utxo().id(),
        amount: pending.pending_utxo().amount(),
        derivation_path: pending.pending_utxo().derivation_path(),
        timestamp_ms: pending.pending_timestamp_ms(),
        requester_address: pending.pending_requester_address(),
        sui_tx_digest: pending.pending_sui_tx_digest(),
    });

    // Send a soul-bound receipt to the sender's wallet.
    hashi::hashi::send_deposit_receipt(request_id, ctx);

    // Insert both the persistent request and operational pending.
    hashi
        .borrow_bitcoin_state_mut()
        .deposit_queue_mut()
        .insert_deposit(request_id, pending, request);
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

    let pending = hashi.borrow_bitcoin_state_mut().deposit_queue_mut().remove_pending(request_id);

    let deposit_confirmed_event = DepositConfirmedEvent {
        request_id: pending.pending_id(),
        utxo_id: pending.pending_utxo().id(),
        amount: pending.pending_utxo().amount(),
        derivation_path: pending.pending_utxo().derivation_path(),
    };

    // Verify the certificate over the pending deposit.
    let pending = hashi.verify(pending, cert).into_message();

    let utxo = pending.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        let btc = hashi.treasury_mut().mint_balance<BTC>(amount);
        transfer::public_transfer(coin::from_balance(btc, ctx), recipient);
    };

    hashi.borrow_bitcoin_state_mut().utxo_pool_mut().insert_active(utxo);

    // Update the persistent request status to Confirmed.
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().confirm_request(request_id);

    sui::event::emit(deposit_confirmed_event);
}

public fun delete_expired_deposit(
    hashi: &mut Hashi,
    request_id: address,
    clock: &sui::clock::Clock,
) {
    hashi.config().assert_version_enabled();
    hashi.borrow_bitcoin_state_mut().deposit_queue_mut().delete_expired(request_id, clock);

    sui::event::emit(ExpiredDepositDeletedEvent { request_id });
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
}

public struct ExpiredDepositDeletedEvent has copy, drop {
    request_id: address,
}
