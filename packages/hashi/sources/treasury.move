// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::treasury;
use std::string::String;
use std::type_name::{Self, TypeName};
use sui::coin::{Self, Coin};
use sui::coin_registry::CoinRegistry;
use sui::object_bag::{Self, ObjectBag};
use sui::vec_set::{Self, VecSet};

//////////////////////////////////////////////////////
// Types
//

public struct HashiCoin<phantom T> has key {
    id: UID,
}

public struct Treasury has store {
    treasury_caps: ObjectBag,
    metadata_caps: ObjectBag,
    supported_tokens: VecSet<TypeName>,
}

//////////////////////////////////////////////////////
// Internal functions
//

public(package) fun register_new_token<T: key>(
    self: &mut Treasury,
    coin_registry: &mut CoinRegistry,
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
    ctx: &mut TxContext,
) {
    let (builder, treasury_cap) = coin_registry.new_currency<HashiCoin<T>>(
        decimals,
        symbol,
        name,
        description,
        icon_url,
        ctx,
    );
    let metadata_cap = builder.finalize<HashiCoin<T>>(ctx);
    let type_name = type_name::with_defining_ids<T>();
    self.treasury_caps.add(type_name, treasury_cap);
    self.metadata_caps.add(type_name, metadata_cap);
    self.supported_tokens.insert(type_name);
}

public(package) fun create(ctx: &mut TxContext): Treasury {
    Treasury {
        treasury_caps: object_bag::new(ctx),
        metadata_caps: object_bag::new(ctx),
        supported_tokens: vec_set::empty(),
    }
}

public(package) fun burn<T>(self: &mut Treasury, token: Coin<T>) {
    let treasury = &mut self.treasury_caps[type_name::with_defining_ids<T>()];
    coin::burn(treasury, token);
}

public(package) fun mint<T>(
    self: &mut Treasury,
    amount: u64,
    ctx: &mut TxContext,
): Coin<T> {
    let treasury = &mut self.treasury_caps[type_name::with_defining_ids<T>()];
    coin::mint(treasury, amount, ctx)
}
