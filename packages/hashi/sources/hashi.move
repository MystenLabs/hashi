#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::hashi;

use btc::btc::BTC;
use std::string::String;
use sui::{balance::Balance, object_bag::ObjectBag};

// For Move coding conventions, see
// https://docs.sui.io/concepts/sui-move-concepts/conventions

public struct Hashi has key {
    id: UID,
    /// Contract version of Hashi.
    /// Used to disallow usage with old contract versions.
    version: u32,
}

public struct Task<T> has key {
    id: UID,
    status: String,
    task: T,
}

public struct TaskBuffer has key {
    id: UID,
    buffer: ObjectBag,
}

public struct Withdraw {
    balance: Balance<BTC>,
    dst: BitcoinAddress,
}

public struct BitcoinAddress {
    address: String,
}

public struct Utxo {
    /// txid:vout
    id: UtxoId,
    amount: u64,
}

public struct UtxoId {
    /// txid:vout
    id: String,
}

public struct Settle {
    withdraws: vector<Task<Withdraw>>,
    transaction: String,
}
