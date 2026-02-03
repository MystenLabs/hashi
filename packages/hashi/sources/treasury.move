// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::treasury;

use sui::{
    balance::Balance,
    coin::{TreasuryCap, Coin},
    coin_registry::MetadataCap,
    object_bag::{Self, ObjectBag}
};

//////////////////////////////////////////////////////
// Types
//

public struct Key<phantom T> has copy, drop, store {}

public struct Treasury has store {
    objects: ObjectBag,
}

//////////////////////////////////////////////////////
// Internal functions
//

fun treasury_cap<T>(self: &mut Treasury): &mut TreasuryCap<T> {
    &mut self.objects[Key<TreasuryCap<T>> {}]
}

#[allow(unused_function)]
fun metadata_cap<T>(self: &mut Treasury): &mut MetadataCap<T> {
    &mut self.objects[Key<MetadataCap<T>> {}]
}

fun balance<T>(self: &mut Treasury): &mut Coin<T> {
    &mut self.objects[Key<Coin<T>> {}]
}

public(package) fun burn<T>(self: &mut Treasury, balance: Balance<T>) {
    sui::event::emit(BurnEvent<T> { amount: balance.value() });
    self.treasury_cap<T>().supply_mut().decrease_supply(balance);
}

public(package) fun mint<T>(self: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<T> {
    sui::event::emit(MintEvent<T> { amount });
    self.treasury_cap<T>().mint(amount, ctx)
}

public(package) fun deposit_fee<T>(self: &mut Treasury, fee: Coin<T>) {
    let key = Key<Coin<T>> {};
    if (self.objects.contains(key)) {
        self.balance<T>().join(fee);
    } else {
        self.objects.add(key, fee);
    }
}

public(package) fun register_treasury_cap<T>(self: &mut Treasury, treasury_cap: TreasuryCap<T>) {
    self.objects.add(Key<TreasuryCap<T>> {}, treasury_cap);
}

public(package) fun register_metadata_cap<T>(self: &mut Treasury, metadata_cap: MetadataCap<T>) {
    self.objects.add(Key<MetadataCap<T>> {}, metadata_cap);
}

//
// Constructor
//

public(package) fun create(ctx: &mut TxContext): Treasury {
    Treasury {
        objects: object_bag::new(ctx),
    }
}

//
// Events
//

public struct MintEvent<phantom T> has copy, drop {
    amount: u64,
}

public struct BurnEvent<phantom T> has copy, drop {
    amount: u64,
}
