// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The hBTC coin type — the Sui-side claim on BTC secured by the bridge.
/// `create` registers the currency (8 decimals, symbol hBTC) with the Sui
/// coin registry during system initialization and returns the treasury and
/// metadata caps, which `hashi::treasury` takes into custody so deposits can
/// mint and withdrawals can burn hBTC against Bitcoin UTXOs.
module hashi::btc;

use sui::{coin::TreasuryCap, coin_registry::{CoinRegistry, MetadataCap}};

// ~~~~~~~ Constants ~~~~~~~

const DECIMALS: u8 = 8;
const SYMBOL: vector<u8> = b"hBTC";
const NAME: vector<u8> = b"BTC";
const DESCRIPTION: vector<u8> = b"BTC secured by hashi.";
const ICON_URL: vector<u8> = b"";

// ~~~~~~~ Structs ~~~~~~~

/// Represents a claim on the BTC secured by hashi.
public struct BTC has key {
    id: sui::object::UID,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun create(
    registry: &mut CoinRegistry,
    ctx: &mut TxContext,
): (TreasuryCap<BTC>, MetadataCap<BTC>) {
    let (initializer, treasury_cap) = sui::coin_registry::new_currency<BTC>(
        registry,
        DECIMALS,
        SYMBOL.to_string(),
        NAME.to_string(),
        DESCRIPTION.to_string(),
        ICON_URL.to_string(),
        ctx,
    );

    let metadata_cap = sui::coin_registry::finalize(initializer, ctx);
    (treasury_cap, metadata_cap)
}
