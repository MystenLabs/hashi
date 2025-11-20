#[allow(unused_function, unused_field, unused_use)]
/// Module: hashi
module hashi::hashi;

use btc::btc::BTC;
use hashi::{config::Config, treasury::Treasury};
use std::string::String;
use sui::{balance::Balance, coin::Coin, object_bag::ObjectBag, sui::SUI};

public struct Hashi has key {
    id: UID,
    config: Config,
    treasury: Treasury,
    deposit_queue: hashi::deposit_queue::DepositRequestQueue,
    utxo_pool: hashi::utxo_pool::UtxoPool,
}

public fun deposit(
    hashi: &mut Hashi,
    request: hashi::deposit_queue::DepositRequest,
    fee: Coin<SUI>,
) {
    hashi.config.assert_version();

    // Check if state is PAUSED
    assert!(!hashi.config.paused());

    // Check that the fee is sufficient
    assert!(hashi.config.deposit_fee() == fee.value());
    hashi.treasury.deposit_fee(fee);

    hashi.deposit_queue.insert(request);
}

public fun confirm_deposit(
    hashi: &mut Hashi,
    utxo_id: hashi::utxo::UtxoId,
    // cert: Cert
    ctx: &mut TxContext,
) {
    hashi.config.assert_version();

    // Check if state is PAUSED
    assert!(!hashi.config.paused());

    let request = hashi.deposit_queue.remove(utxo_id);

    // verify cert over the request
    // cert.verify(&request)

    let utxo = request.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        // XXX Do we want to check an inflow limit here?
        let btc = hashi.treasury.mint<BTC>(amount, ctx);
        sui::transfer::public_transfer(btc, recipient);
    };

    hashi.utxo_pool.insert(utxo);
}
