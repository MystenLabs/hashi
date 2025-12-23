/// Module: deposit
module hashi::deposit;

use hashi::{btc::BTC, hashi::Hashi};
use sui::{coin::Coin, sui::SUI};

public fun deposit(
    hashi: &mut Hashi,
    request: hashi::deposit_queue::DepositRequest,
    fee: Coin<SUI>,
) {
    hashi.config().assert_version_enabled();

    // Check if state is PAUSED
    assert!(!hashi.config().paused());

    // Check that the fee is sufficient
    assert!(hashi.config().deposit_fee() == fee.value());
    hashi.treasury_mut().deposit_fee(fee);

    hashi.deposit_queue_mut().insert(request);
}

public fun confirm_deposit(
    hashi: &mut Hashi,
    utxo_id: hashi::utxo::UtxoId,
    // cert: Cert
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();

    // Check if state is PAUSED
    assert!(!hashi.config().paused());

    let request = hashi.deposit_queue_mut().remove(utxo_id);

    // verify cert over the request
    // cert.verify(&request)

    let utxo = request.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        // XXX Do we want to check an inflow limit here?
        let btc = hashi.treasury_mut().mint<BTC>(amount, ctx);
        sui::transfer::public_transfer(btc, recipient);
    };

    hashi.utxo_pool_mut().insert(utxo);
}
