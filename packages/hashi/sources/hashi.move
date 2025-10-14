// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::hashi;
use btc::btc::BTC;
use hashi::bls::BlsCommittee;
use hashi::committee::Committee;
use hashi::config::Config;
use hashi::treasury::Treasury;
use std::string::String;
use sui::balance::Balance;
use sui::object_bag::ObjectBag;

// For Move coding conventions, see
// https://docs.sui.io/concepts/sui-move-concepts/conventions

// TODO: versioning story for the hashi object and child objects
public struct Hashi has key {
    id: UID,
    /// Contract version of Hashi.
    /// Used to disallow usage with old contract versions.
    version: u32,
    committee: Committee,
    signing_committee: BlsCommittee,
    config: Config,
    treasury: Treasury,
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

public(package) fun increment_seq_num<T>(self: &mut Hashi) {
    self.config().increment_seq_num<T>();
}

public(package) fun id(self: &mut Hashi): &mut UID {
    &mut self.id
}

public(package) fun committee_ref(self: &Hashi): &Committee {
    &self.committee
}

public(package) fun config_ref(self: &Hashi): &Config {
    &self.config
}

public(package) fun config(self: &mut Hashi): &mut Config {
    &mut self.config
}

public(package) fun treasury(self: &mut Hashi): &mut Treasury {
    &mut self.treasury
}

public(package) fun seq_num(self: &Hashi): u64 {
    self.config_ref().seq_num()
}
