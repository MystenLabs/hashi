// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit;

use hashi::{
    btc::BTC,
    btc_config,
    committee::CommitteeSignature,
    config::Config,
    deposit_queue,
    hashi::Hashi,
    utxo::{Utxo, UtxoId}
};
use sui::{coin::{Self, Coin}, sui::SUI};

use fun btc_config::deposit_fee as Config.deposit_fee;
use fun btc_config::deposit_minimum as Config.deposit_minimum;

#[error]
const EIncorrectFee: vector<u8> = b"Deposit fee does not match the required protocol fee";
#[error]
const EBelowMinimumDeposit: vector<u8> = b"Deposit amount is below the minimum (dust threshold)";
#[error]
const EUtxoAlreadyUsed: vector<u8> = b"UTXO has already been deposited or is currently active";

/// Message signed by the committee to confirm a deposit.
public struct DepositConfirmationMessage has copy, drop, store {
    request_id: address,
    utxo: Utxo,
}

#[test_only]
public fun new_deposit_confirmation_message(
    request_id: address,
    utxo: Utxo,
): DepositConfirmationMessage {
    DepositConfirmationMessage { request_id, utxo }
}

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
    assert!(hashi.config().deposit_fee() == fee.value(), EIncorrectFee);
    sui::coin::send_funds(fee, hashi.id().to_address());

    // Check that the deposit amount meets the dust minimum
    assert!(utxo.amount() >= hashi.config().deposit_minimum(), EBelowMinimumDeposit);

    // Check that the UTXO isn't already active or previously spent (replay protection)
    assert!(!hashi.bitcoin().utxo_pool().is_spent_or_active(utxo.id()), EUtxoAlreadyUsed);

    let request = deposit_queue::create_deposit(utxo, clock, ctx);
    let request_id = request.request_id().to_address();

    let utxo_ref = request.request_utxo();
    sui::event::emit(DepositRequestedEvent {
        request_id,
        utxo_id: utxo_ref.id(),
        amount: utxo_ref.amount(),
        derivation_path: utxo_ref.derivation_path(),
        timestamp_ms: request.request_timestamp_ms(),
        requester_address: request.request_sender(),
        sui_tx_digest: request.request_sui_tx_digest(),
    });

    // Insert into the active requests bag.
    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);
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

    // Remove from active requests and copy the UTXO
    let request = hashi.bitcoin_mut().deposit_queue_mut().remove_request(request_id);
    let utxo = request.utxo();

    // Verify the committee certificate over the request ID + UTXO
    hashi.verify(DepositConfirmationMessage { request_id, utxo }, cert);

    sui::event::emit(DepositConfirmedEvent {
        request_id,
        utxo_id: utxo.id(),
        amount: utxo.amount(),
        derivation_path: utxo.derivation_path(),
    });

    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        let btc = hashi.treasury_mut().mint_balance<BTC>(amount);
        transfer::public_transfer(coin::from_balance(btc, ctx), recipient);
    };

    // Insert UTXO into active pool
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    // Move request to processed bag and index by recipient
    hashi.bitcoin_mut().deposit_queue_mut().insert_processed(request, ctx);
}

public fun delete_expired_deposit(
    hashi: &mut Hashi,
    request_id: address,
    clock: &sui::clock::Clock,
) {
    hashi.config().assert_version_enabled();
    hashi.bitcoin_mut().deposit_queue_mut().delete_expired(request_id, clock);

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
