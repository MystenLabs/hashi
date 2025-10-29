#[allow(unused_function, unused_field)]
/// Module: hashi
module hashi::hashi;

use hashi::config::Config;
use hashi::treasury::Treasury;

public struct Hashi has key {
    id: UID,
    config: Config,
    treasury: Treasury,
}
