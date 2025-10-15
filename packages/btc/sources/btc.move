/// Module: btc
module btc::btc;
use sui::coin;
use sui::url;

const DECIMALS: u8 = 8;
const SYMBOL: vector<u8> = b"#BTC";
const NAME: vector<u8> = b"#BTC";
const DESCRIPTION: vector<u8> = b"BTC secured by the Hashi protocol";
const ICON_URL: vector<u8> = b"";

/// The OTW for our token.
public struct BTC has key {}
