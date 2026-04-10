// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit_queue;

use hashi::utxo::Utxo;
use sui::{clock::Clock, object_bag::ObjectBag};

// const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days
const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24; // 1 days

#[error(code = 0)]
const EDepositRequestNotExpired: vector<u8> = b"Deposit request not expired";
#[error]
const EDepositAlreadyProcessed: vector<u8> = b"Deposit request has already been processed";

// ======== Core Structs ========

/// Deposit request object stored in the `requests` bag until confirmed or expired.
public struct DepositRequest has key, store {
    id: UID,
    sender: address,
    timestamp_ms: u64,
    sui_tx_digest: vector<u8>,
    utxo: Utxo,
}

public struct DepositRequestQueue has store {
    /// Active deposits awaiting confirmation.
    /// ObjectBag so DepositRequest UIDs are directly accessible via getObject.
    requests: ObjectBag,
    /// Completed deposits (confirmed or expired).
    processed: ObjectBag,
}

// ======== Constructors ========

public(package) fun create(ctx: &mut TxContext): DepositRequestQueue {
    DepositRequestQueue {
        requests: sui::object_bag::new(ctx),
        processed: sui::object_bag::new(ctx),
    }
}

/// Create a deposit request with the given UTXO.
public(package) fun create_deposit(utxo: Utxo, clock: &Clock, ctx: &mut TxContext): DepositRequest {
    DepositRequest {
        id: object::new(ctx),
        sender: ctx.sender(),
        timestamp_ms: clock.timestamp_ms(),
        sui_tx_digest: *ctx.digest(),
        utxo,
    }
}

// ======== Lifecycle Functions ========

/// Insert a new deposit request into the active requests bag.
public(package) fun insert_deposit(self: &mut DepositRequestQueue, request: DepositRequest) {
    let request_id = request.id.to_address();
    self.requests.add(request_id, request);
}

/// Check if an active deposit request exists.
public(package) fun contains(self: &DepositRequestQueue, id: address): bool {
    self.requests.contains(id)
}

/// Remove an active deposit request.
public(package) fun remove_request(
    self: &mut DepositRequestQueue,
    request_id: address,
): DepositRequest {
    self.requests.remove(request_id)
}

/// Copy the UTXO out of a deposit request (Utxo has copy).
public(package) fun utxo(request: &DepositRequest): Utxo {
    request.utxo
}

/// Insert a completed deposit into the processed bag.
/// Returns (request_id, recipient) so the caller can index by user.
public(package) fun insert_processed(
    self: &mut DepositRequestQueue,
    request: DepositRequest,
): (address, Option<address>) {
    let request_id = request.id.to_address();
    let recipient = request.utxo.derivation_path();
    self.processed.add(request_id, request);
    (request_id, recipient)
}

/// Delete an expired deposit request.
/// Expired requests are never confirmed, so they won't be in the user index.
public(package) fun delete_expired(
    self: &mut DepositRequestQueue,
    request_id: address,
    clock: &Clock,
) {
    assert!(!self.processed.contains(request_id), EDepositAlreadyProcessed);
    let request: DepositRequest = self.requests.remove(request_id);
    assert!(is_expired(&request, clock), EDepositRequestNotExpired);

    let DepositRequest { id, sender: _, timestamp_ms: _, sui_tx_digest: _, utxo } = request;
    id.delete();
    utxo.delete();
}

/// Borrow an active deposit request.
public(package) fun borrow_request(
    self: &DepositRequestQueue,
    request_id: address,
): &DepositRequest {
    self.requests.borrow(request_id)
}

// ======== Accessors ========

public(package) fun request_id(self: &DepositRequest): ID {
    self.id.to_inner()
}

public(package) fun request_sender(self: &DepositRequest): address {
    self.sender
}

public(package) fun request_timestamp_ms(self: &DepositRequest): u64 {
    self.timestamp_ms
}

public(package) fun request_sui_tx_digest(self: &DepositRequest): vector<u8> {
    self.sui_tx_digest
}

public(package) fun request_utxo(self: &DepositRequest): &Utxo {
    &self.utxo
}

// ======== Internal ========

fun is_expired(request: &DepositRequest, clock: &Clock): bool {
    clock.timestamp_ms() > request.timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS
}
