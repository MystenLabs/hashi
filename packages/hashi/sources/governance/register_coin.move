// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::register_coin;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use std::string::String;
use std::type_name;
use sui::coin_registry::CoinRegistry;

const THRESHOLD: u64 = 10000;

public struct RegisterCoin<phantom T> has store, drop {
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
}

public fun new<T>(
    decimals: u8,
    symbol: String,
    name: String,
    description: String,
    icon_url: String,
): RegisterCoin<T> {
    RegisterCoin<T> {
        decimals,
        symbol,
        name,
        description,
        icon_url,
    }
}

public fun execute<T: key>(
    self: Proposal<RegisterCoin<T>>,
    hashi: &mut Hashi,
    coin_registry: &mut CoinRegistry,
    ctx: &mut TxContext,
) {
    let RegisterCoin<T> {
        decimals,
        symbol,
        name,
        description,
        icon_url,
    } = self.execute(hashi);
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

// NOTE: This will need to be called for each coin type before the register proposal
// of that coin type can be executed
public fun register_proposal_type<T>(hashi: &mut Hashi) {
    hashi
        .config()
        .register_proposal_type(
            type_name::with_defining_ids<T>(),
            THRESHOLD,
            false,
        );
}
