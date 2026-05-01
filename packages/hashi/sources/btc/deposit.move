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

use fun btc_config::bitcoin_deposit_minimum as Config.deposit_minimum;
use fun btc_config::bitcoin_deposit_time_delay_ms as Config.deposit_time_delay_ms;

#[error]
const EBelowMinimumDeposit: vector<u8> = b"Deposit amount is below the minimum";
#[error]
const EUtxoAlreadyUsed: vector<u8> = b"UTXO has already been deposited or is currently active";
#[error]
const EDepositTimeDelayNotPassed: vector<u8> = b"Deposit time-delay has not passed";
#[error]
const EAlreadyApprovedThisEpoch: vector<u8> =
    b"Deposit has already been approved by the current committee";

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
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    // Check that the system isn't paused, but still allow users to request
    // deposits even when the system is reconfiguring.
    hashi.assert_unpaused();

    // Check that the deposit amount meets the minimum.
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

/// First phase of deposit confirmation. Records a committee certificate
/// over `(request_id, utxo)` on the request, alongside the approval
/// timestamp, and re-inserts the request into the queue.
///
/// The approval is not yet final — `confirm_deposit` must be called after
/// the configured `bitcoin_deposit_time_delay_ms` has elapsed. The delay
/// gives operators a window to detect a faulty or fraudulent committee
/// signature and pause the service before funds are minted; while paused,
/// `confirm_deposit` is rejected, leaving the approval parked. If the
/// committee rotates during the window, the deposit will also need to be
/// re-approved by the new epoch's committee.
entry fun approve_deposit(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    clock: &sui::clock::Clock,
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow approval of deposits during a reconfiguration, this
    // delays the approval to be done by the next epoch's committee.
    hashi.assert_not_reconfiguring();

    // Remove from active requests and copy the UTXO.
    let mut request = hashi.bitcoin_mut().deposit_queue_mut().remove_request(request_id);
    let utxo = request.utxo();

    // If the request already carries an approval from the current
    // committee, refuse to re-approve. Re-approving by the same
    // committee would just bump the approval timestamp, pushing the
    // confirmation window further out for no reason. Re-approval is
    // only meaningful after the committee has rotated.
    let current_epoch = hashi.current_committee().epoch();
    let existing = request.approval_cert();
    assert!(
        existing.is_none() || existing.borrow().signature_epoch() != current_epoch,
        EAlreadyApprovedThisEpoch,
    );

    // Verify the committee certificate over the request ID + UTXO.
    hashi.verify(DepositConfirmationMessage { request_id, utxo }, cert);

    // Record the cert and the approval timestamp for the time-delay check
    // in `confirm_deposit`.
    request.approve(cert, clock);

    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);

    sui::event::emit(DepositApprovedEvent {
        request_id,
        utxo,
        cert,
        approval_timestamp_ms: clock.timestamp_ms(),
    });
}

/// Second phase of deposit confirmation. Re-verifies the stored committee
/// certificate against the current committee, enforces the time-delay
/// since approval, then mints BTC to the recipient (if any) and moves
/// the UTXO into the active pool.
///
/// Re-verifying against the current committee means an approval from a
/// rotated-out committee will not confirm — it must be re-approved by
/// the current committee. Aborts if the request was never approved
/// (no stored cert), the cert no longer verifies (committee rotated),
/// or the time-delay window has not yet elapsed.
entry fun confirm_deposit(
    hashi: &mut Hashi,
    request_id: address,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow confirmation of deposits during a reconfiguration, this
    // delays the confirmation to be done by the next epoch's committee.
    hashi.assert_not_reconfiguring();

    // Remove from active requests and copy the UTXO. Aborts if the request
    // was never approved (no stored cert or timestamp).
    let request = hashi.bitcoin_mut().deposit_queue_mut().remove_request(request_id);
    let utxo = request.utxo();
    let cert = request.approval_cert().destroy_some();
    let approval_timestamp_ms = request.approval_timestamp_ms().destroy_some();

    // Verify the certificate over the request ID + UTXO against the current committee.
    // If a deposit is approved by an older committee, it will need to be
    // re-approved by the current committee.
    hashi.verify(DepositConfirmationMessage { request_id, utxo }, cert);

    // Check that the deposit was approved long enough ago.
    assert!(
        approval_timestamp_ms + hashi.config().deposit_time_delay_ms() <= clock.timestamp_ms(),
        EDepositTimeDelayNotPassed,
    );

    sui::event::emit(DepositConfirmedEvent {
        request_id,
        utxo,
    });

    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        let btc = hashi.treasury_mut().mint_balance<BTC>(amount);
        sui::balance::send_funds(btc, recipient);
    };

    // Insert UTXO into active pool
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    // Move request to processed bag.
    let (req_id, recipient_opt) = hashi.bitcoin_mut().deposit_queue_mut().insert_processed(request);

    // Index by recipient for client discovery.
    if (recipient_opt.is_some()) {
        hashi.bitcoin_mut().index_user_request(recipient_opt.destroy_some(), req_id, ctx);
    } else {
        recipient_opt.destroy_none();
    };
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

/// Emitted when a committee certificate has been recorded against a
/// deposit request. The deposit is not yet final — see `confirm_deposit`.
/// `approval_timestamp_ms` is the clock timestamp recorded on the
/// request, against which `confirm_deposit` enforces the time-delay
/// window.
public struct DepositApprovedEvent has copy, drop {
    request_id: address,
    utxo: Utxo,
    cert: CommitteeSignature,
    approval_timestamp_ms: u64,
}

/// Emitted when an approved deposit has cleared the time-delay window
/// and the corresponding BTC has been minted (when applicable) and the
/// UTXO moved into the active pool.
public struct DepositConfirmedEvent has copy, drop {
    request_id: address,
    utxo: Utxo,
}

public struct ExpiredDepositDeletedEvent has copy, drop {
    request_id: address,
}
