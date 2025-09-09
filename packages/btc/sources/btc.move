/// Module: btc
module btc::btc;

use sui::{coin, url};

const DECIMALS: u8 = 8;
const SYMBOL: vector<u8> = b"BTC";
const NAME: vector<u8> = b"BTC";
const DESCRIPTION: vector<u8> = b"BTC secured by the hashi bridge.";
const ICON_URL: vector<u8> = b"";

/// The OTW for our token.
public struct BTC has drop {}

#[allow(unused_function, lint(share_owned))]
fun init(otw: BTC, ctx: &mut TxContext) {
    let (cap, metadata) = coin::create_currency(
        otw,
        DECIMALS,
        SYMBOL,
        NAME,
        DESCRIPTION,
        option::some(url::new_unsafe_from_bytes(ICON_URL)),
        ctx,
    );

    transfer::public_freeze_object(metadata);
    transfer::public_transfer(cap, tx_context::sender(ctx));
}
