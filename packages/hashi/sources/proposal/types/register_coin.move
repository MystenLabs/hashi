// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::register_coin;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use std::string::String;
use std::type_name::{Self, TypeName};
use sui::coin_registry::CoinRegistry;

#[error]
const ETypeNameMismatch: vector<u8> = b"Type name mismatch";

public struct RegisterCoin has store, drop {
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
    type_name: TypeName,
}

public fun new(
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
    type_name: TypeName,
): RegisterCoin {
    RegisterCoin {
        decimals,
        symbol,
        name,
        description,
        icon_url,
        type_name,
    }
}

public fun execute<T: key>(
    self: Proposal<RegisterCoin>,
    hashi: &mut Hashi,
    coin_registry: &mut CoinRegistry,
    ctx: &mut TxContext,
) {
    let RegisterCoin {
        decimals,
        symbol,
        name,
        description,
        icon_url,
        type_name,
    } = self.execute(hashi);
    assert!(type_name == type_name::with_defining_ids<T>(), ETypeNameMismatch);
    hashi
        .treasury()
        .register_new_token<T>(
            coin_registry,
            decimals,
            symbol,
            name,
            description,
            icon_url,
            ctx,
        );
}
