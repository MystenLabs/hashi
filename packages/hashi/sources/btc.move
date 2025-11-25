/// Module: btc
module hashi::btc;

use sui::{coin::TreasuryCap, coin_registry::{CoinRegistry, MetadataCap}};

const DECIMALS: u8 = 8;
const SYMBOL: vector<u8> = b"BTC";
const NAME: vector<u8> = b"BTC";
const DESCRIPTION: vector<u8> = b"BTC secured by hashi.";
const ICON_URL: vector<u8> = b"";

/// Represents a claim on the BTC secured by hashi.
public struct BTC has key {
    id: sui::object::UID,
}

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
