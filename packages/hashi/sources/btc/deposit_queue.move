// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit_queue;

use hashi::utxo::{Utxo, UtxoId};
use sui::{bag::Bag, clock::Clock};

const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days

#[error(code = 0)]
const EDepositRequestNotExpired: vector<u8> = b"Deposit request not expired";

// ======== Core Structs ========

/// Persistent status record for a deposit request.
/// Lives in the `requests` bag, keyed by request_id. Never deleted.
/// The client's single source of truth for deposit status.
public struct DepositRequest has copy, drop, store {
    sender: address,
    utxo_id: UtxoId,
    amount: u64,
    derivation_path: Option<address>,
    timestamp_ms: u64,
    confirmed: bool,
    sui_tx_digest: vector<u8>,
}

/// Operational deposit data held while awaiting confirmation.
/// Lives in the `pending` bag, keyed by request_id.
/// Deleted when the deposit is confirmed or expired.
public struct DepositPending has store {
    id: address,
    utxo: Utxo,
    timestamp_ms: u64,
    requester_address: address,
    sui_tx_digest: vector<u8>,
}

public struct DepositRequestQueue has store {
    /// Persistent status records (DepositRequest, never deleted)
    requests: Bag,
    /// Operational deposit data awaiting confirmation (DepositPending, deleted on confirm/expire)
    pending: Bag,
}

// ======== Constructors ========

public(package) fun create(ctx: &mut TxContext): DepositRequestQueue {
    DepositRequestQueue {
        requests: sui::bag::new(ctx),
        pending: sui::bag::new(ctx),
    }
}

/// Create both the persistent request and operational pending structs.
/// The caller (deposit.move) is responsible for inserting both.
public fun create_deposit(
    utxo: Utxo,
    clock: &Clock,
    ctx: &mut TxContext,
): (DepositPending, DepositRequest, address) {
    let request_id = ctx.fresh_object_address();

    let pending = DepositPending {
        id: request_id,
        utxo,
        timestamp_ms: clock.timestamp_ms(),
        requester_address: ctx.sender(),
        sui_tx_digest: *ctx.digest(),
    };

    let request = DepositRequest {
        sender: ctx.sender(),
        utxo_id: pending.utxo.id(),
        amount: pending.utxo.amount(),
        derivation_path: pending.utxo.derivation_path(),
        timestamp_ms: clock.timestamp_ms(),
        confirmed: false,
        sui_tx_digest: *ctx.digest(),
    };

    (pending, request, request_id)
}

// ======== Lifecycle Functions ========

/// Insert both the persistent request and operational pending.
public(package) fun insert_deposit(
    self: &mut DepositRequestQueue,
    request_id: address,
    pending: DepositPending,
    request: DepositRequest,
) {
    self.requests.add(request_id, request);
    self.pending.add(request_id, pending);
}

/// Check if a pending deposit exists.
public(package) fun contains(self: &DepositRequestQueue, id: address): bool {
    self.pending.contains(id)
}

/// Remove the operational pending deposit and return it.
/// Does NOT update the persistent request status — caller must do that.
public(package) fun remove_pending(self: &mut DepositRequestQueue, id: address): DepositPending {
    self.pending.remove(id)
}

/// Mark the persistent request as confirmed.
public(package) fun confirm_request(self: &mut DepositRequestQueue, request_id: address) {
    let request: &mut DepositRequest = self.requests.borrow_mut(request_id);
    request.confirmed = true;
}

/// Delete an expired pending deposit.
/// The persistent request stays with `confirmed: false` — clients can
/// check `timestamp_ms` to determine if the deposit expired.
public(package) fun delete_expired(
    self: &mut DepositRequestQueue,
    request_id: address,
    clock: &Clock,
) {
    let deposit_pending: DepositPending = self.pending.remove(request_id);
    assert!(is_expired(&deposit_pending, clock), EDepositRequestNotExpired);
    deposit_pending.delete();
}

/// Read a deposit request (persistent status record).
public(package) fun borrow_request(
    self: &DepositRequestQueue,
    request_id: address,
): &DepositRequest {
    self.requests.borrow(request_id)
}

// ======== Accessors ========

public(package) fun pending_id(self: &DepositPending): address {
    self.id
}

public(package) fun pending_utxo(self: &DepositPending): &Utxo {
    &self.utxo
}

public(package) fun pending_timestamp_ms(self: &DepositPending): u64 {
    self.timestamp_ms
}

public(package) fun pending_requester_address(self: &DepositPending): address {
    self.requester_address
}

public(package) fun pending_sui_tx_digest(self: &DepositPending): vector<u8> {
    self.sui_tx_digest
}

public(package) fun into_utxo(self: DepositPending): Utxo {
    let DepositPending { id: _, utxo, timestamp_ms: _, requester_address: _, sui_tx_digest: _ } =
        self;
    utxo
}

public(package) fun request_sender(self: &DepositRequest): address {
    self.sender
}

public(package) fun request_confirmed(self: &DepositRequest): bool {
    self.confirmed
}

public(package) fun request_amount(self: &DepositRequest): u64 {
    self.amount
}

// ======== Internal ========

fun is_expired(deposit_pending: &DepositPending, clock: &Clock): bool {
    clock.timestamp_ms() > deposit_pending.timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS
}

fun delete(deposit_pending: DepositPending) {
    let DepositPending {
        id: _,
        utxo,
        timestamp_ms: _,
        requester_address: _,
        sui_tx_digest: _,
    } = deposit_pending;
    utxo.delete();
}
