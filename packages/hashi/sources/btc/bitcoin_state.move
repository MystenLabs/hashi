// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::bitcoin_state;

use hashi::{
    deposit_queue::DepositRequestQueue,
    utxo_pool::UtxoPool,
    withdrawal_queue::WithdrawalRequestQueue
};
use sui::{bag::Bag, table::Table};

public struct BitcoinStateKey has copy, drop, store {}

public struct BitcoinState has store {
    deposit_queue: DepositRequestQueue,
    withdrawal_queue: WithdrawalRequestQueue,
    utxo_pool: UtxoPool,
    /// Per-user index: user address -> Bag of request IDs (deposits and withdrawals).
    /// Allows clients to discover all requests for a given address.
    user_requests: Table<address, Bag>,
}

public(package) fun key(): BitcoinStateKey { BitcoinStateKey {} }

public(package) fun new(ctx: &mut TxContext): BitcoinState {
    BitcoinState {
        deposit_queue: hashi::deposit_queue::create(ctx),
        withdrawal_queue: hashi::withdrawal_queue::create(ctx),
        utxo_pool: hashi::utxo_pool::create(ctx),
        user_requests: sui::table::new(ctx),
    }
}

public(package) fun deposit_queue(self: &BitcoinState): &DepositRequestQueue {
    &self.deposit_queue
}

public(package) fun deposit_queue_mut(self: &mut BitcoinState): &mut DepositRequestQueue {
    &mut self.deposit_queue
}

public(package) fun withdrawal_queue(self: &BitcoinState): &WithdrawalRequestQueue {
    &self.withdrawal_queue
}

public(package) fun withdrawal_queue_mut(self: &mut BitcoinState): &mut WithdrawalRequestQueue {
    &mut self.withdrawal_queue
}

public(package) fun utxo_pool(self: &BitcoinState): &UtxoPool {
    &self.utxo_pool
}

public(package) fun utxo_pool_mut(self: &mut BitcoinState): &mut UtxoPool {
    &mut self.utxo_pool
}

// ======== User Request Index ========

/// Index a request ID under a user address.
public(package) fun index_user_request(
    self: &mut BitcoinState,
    user: address,
    request_id: address,
    ctx: &mut TxContext,
) {
    if (!self.user_requests.contains(user)) {
        self.user_requests.add(user, sui::bag::new(ctx));
    };
    self.user_requests[user].add(request_id, true);
}

/// Remove a request ID from a user's index.
public(package) fun unindex_user_request(
    self: &mut BitcoinState,
    user: address,
    request_id: address,
) {
    if (self.user_requests.contains(user)) {
        let user_bag: &mut Bag = &mut self.user_requests[user];
        if (user_bag.contains(request_id)) {
            let _: bool = user_bag.remove(request_id);
        };
        // Clean up the empty bag so we don't leak storage on the table.
        if (user_bag.is_empty()) {
            let empty_bag: Bag = self.user_requests.remove(user);
            empty_bag.destroy_empty();
        };
    };
}

/// Check if a user has any indexed requests.
public(package) fun has_user_requests(self: &BitcoinState, user: address): bool {
    self.user_requests.contains(user)
}

/// Check if a specific request ID is in a user's index.
public(package) fun user_has_request(
    self: &BitcoinState,
    user: address,
    request_id: address,
): bool {
    self.user_requests.contains(user) && self.user_requests[user].contains(request_id)
}
