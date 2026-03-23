// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::bitcoin_state;

use hashi::{
    deposit_queue::DepositRequestQueue,
    utxo_pool::UtxoPool,
    withdrawal_queue::WithdrawalRequestQueue
};

public struct BitcoinStateKey has copy, drop, store {}

public struct BitcoinState has store {
    deposit_queue: DepositRequestQueue,
    withdrawal_queue: WithdrawalRequestQueue,
    utxo_pool: UtxoPool,
}

public(package) fun key(): BitcoinStateKey { BitcoinStateKey {} }

public(package) fun new(ctx: &mut TxContext): BitcoinState {
    BitcoinState {
        deposit_queue: hashi::deposit_queue::create(ctx),
        withdrawal_queue: hashi::withdrawal_queue::create(ctx),
        utxo_pool: hashi::utxo_pool::create(ctx),
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
