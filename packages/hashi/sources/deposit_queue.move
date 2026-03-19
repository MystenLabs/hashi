// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit_queue;

use hashi::utxo::Utxo;
use sui::{bag::Bag, clock::Clock};

const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days

#[error(code = 0)]
const EDepositRequestNotExpired: vector<u8> = b"Deposit request not expired";

public struct DepositRequestQueue has store {
    // XXX bag or table?
    requests: Bag,
}

public struct DepositRequest has store {
    id: address,
    utxo: Utxo,
    timestamp_ms: u64,
    requester_address: address,
    sui_tx_digest: vector<u8>,
}

public fun deposit_request(utxo: Utxo, clock: &Clock, ctx: &mut TxContext): DepositRequest {
    DepositRequest {
        // Create a unique id for this request in order to prevent griefing of
        // malicious users front-running deposit requests
        id: ctx.fresh_object_address(),
        utxo,
        timestamp_ms: clock.timestamp_ms(),
        requester_address: ctx.sender(),
        sui_tx_digest: *ctx.digest(),
    }
}

public(package) fun contains(self: &DepositRequestQueue, id: address): bool {
    self.requests.contains(id)
}

public(package) fun remove(self: &mut DepositRequestQueue, id: address): DepositRequest {
    self.requests.remove(id)
}

public(package) fun insert(self: &mut DepositRequestQueue, request: DepositRequest) {
    self.requests.add(request.id(), request)
}

public(package) fun into_utxo(self: DepositRequest): Utxo {
    let DepositRequest { id: _, utxo, timestamp_ms: _, requester_address: _, sui_tx_digest: _ } =
        self;
    utxo
}

public(package) fun utxo(self: &DepositRequest): &Utxo {
    &self.utxo
}

public(package) fun id(self: &DepositRequest): address {
    self.id
}

public(package) fun timestamp_ms(self: &DepositRequest): u64 {
    self.timestamp_ms
}

public(package) fun requester_address(self: &DepositRequest): address {
    self.requester_address
}

public(package) fun sui_tx_digest(self: &DepositRequest): vector<u8> {
    self.sui_tx_digest
}

public(package) fun create(ctx: &mut TxContext): DepositRequestQueue {
    DepositRequestQueue {
        requests: sui::bag::new(ctx),
    }
}

fun is_expired(deposit_request: &DepositRequest, clock: &Clock): bool {
    clock.timestamp_ms() > deposit_request.timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS
}

public(package) fun delete_expired(
    self: &mut DepositRequestQueue,
    request_id: address,
    clock: &Clock,
) {
    let deposit_request: DepositRequest = self.requests.remove(request_id);

    assert!(deposit_request.is_expired(clock), EDepositRequestNotExpired);
    deposit_request.delete();
}

public(package) fun delete(deposit_request: DepositRequest) {
    let DepositRequest {
        id: _,
        utxo,
        timestamp_ms: _,
        requester_address: _,
        sui_tx_digest: _,
    } = deposit_request;
    utxo.delete();
}
