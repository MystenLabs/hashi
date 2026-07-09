// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Custody of the coin capabilities for bridge-issued assets. `Treasury`
/// holds the `TreasuryCap` and `MetadataCap` of each registered coin type in
/// an `ObjectBag` keyed by cap type, and exposes package-only mint/burn that
/// emit `Minted`/`Burned` events for off-chain watchers.
module hashi::treasury;

use sui::{
    balance::Balance,
    coin::{TreasuryCap, Coin},
    coin_registry::MetadataCap,
    object_bag::{Self, ObjectBag}
};

// ~~~~~~~ Structs ~~~~~~~

public struct Key<phantom T> has copy, drop, store {}

public struct Treasury has store {
    objects: ObjectBag,
}

// ~~~~~~~ Events ~~~~~~~

public struct Minted<phantom T> has copy, drop {
    amount: u64,
}

public struct Burned<phantom T> has copy, drop {
    amount: u64,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun create(ctx: &mut TxContext): Treasury {
    Treasury {
        objects: object_bag::new(ctx),
    }
}

public(package) fun register_treasury_cap<T>(self: &mut Treasury, treasury_cap: TreasuryCap<T>) {
    self.objects.add(Key<TreasuryCap<T>> {}, treasury_cap);
}

public(package) fun register_metadata_cap<T>(self: &mut Treasury, metadata_cap: MetadataCap<T>) {
    self.objects.add(Key<MetadataCap<T>> {}, metadata_cap);
}

public(package) fun mint<T>(self: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<T> {
    sui::event::emit(Minted<T> { amount });
    self.treasury_cap<T>().mint(amount, ctx)
}

public(package) fun mint_balance<T>(self: &mut Treasury, amount: u64): Balance<T> {
    sui::event::emit(Minted<T> { amount });
    self.treasury_cap<T>().mint_balance(amount)
}

public(package) fun burn<T>(self: &mut Treasury, balance: Balance<T>) {
    sui::event::emit(Burned<T> { amount: balance.value() });
    self.treasury_cap<T>().supply_mut().decrease_supply(balance);
}

// ~~~~~~~ Private Functions ~~~~~~~

fun treasury_cap<T>(self: &mut Treasury): &mut TreasuryCap<T> {
    &mut self.objects[Key<TreasuryCap<T>> {}]
}

#[allow(unused_function)]
fun metadata_cap<T>(self: &mut Treasury): &mut MetadataCap<T> {
    &mut self.objects[Key<MetadataCap<T>> {}]
}
