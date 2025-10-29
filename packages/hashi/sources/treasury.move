// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::treasury;

use sui::{coin::{TreasuryCap, Coin}, object_bag::{Self, ObjectBag}};

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

fun balance<T>(self: &mut Treasury): &mut Coin<T> {
    &mut self.objects[Key<Coin<T>> {}]
}

public(package) fun burn<T>(self: &mut Treasury, token: Coin<T>) {
    self.treasury_cap<T>().burn(token);
}

public(package) fun mint<T>(self: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<T> {
    self.treasury_cap<T>().mint(amount, ctx)
}

public(package) fun deposit_fee<T>(self: &mut Treasury, fee: Coin<T>) {
    self.balance<T>().join(fee);
}

//
// Constructor
//

public(package) fun create(ctx: &mut TxContext): Treasury {
    Treasury {
        objects: object_bag::new(ctx),
    }
}
