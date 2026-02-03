/// Module: withdraw
module hashi::withdraw;

use hashi::{btc::BTC, hashi::Hashi, withdrawal_queue::withdrawal_request};
use sui::{balance::Balance, clock::Clock, coin::Coin, random::Random, sui::SUI};

// User entry-point for requesting a withdrawal
//
// In order to successfully enqueue a request:
// - The system needs to not be paused
// - The fee needs to be sufficient
// - The requested BTC amount to withdrawal needs to be above a certain minimum
public fun request_withdrawal(
    hashi: &mut Hashi,
    clock: &Clock,
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    fee: Coin<SUI>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();

    // Check that the fee is sufficient
    assert!(hashi.config().withdrawal_fee() == fee.value());
    hashi.treasury_mut().deposit_fee(fee);

    // check that the withdrawal amount is a minimum of X
    assert!(btc.value() >= hashi.config().withdrawal_minimum());

    let request = withdrawal_request(btc, bitcoin_address, clock, ctx);

    hashi.withdrawal_queue_mut().insert_request(request);
}

// Leader picks request to process
// - Do sanctions checks
// - Do rate limit checks
// - Coin selection and craft txn (outputs would be to withdrawal address and change goes to hashi pubkey)
// - Broadcast txn to committee for agreement (maybe get preauth from guardian?)
// - Send txn onchain to commit to the txn
// - commit to utxos to use in input
entry fun pick_withdrawal_for_processing(
    hashi: &mut Hashi,
    requests: vector<address>,
    selected_utxos: vector<vector<u8>>,
    outputs: vector<vector<u8>>,
    txid: address,
    // BTC txn itself?
    // cert: Cert,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow scheduling of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let requests = requests.map!(|request_id| {
        let request = hashi.withdrawal_queue_mut().remove_request(request_id);
        let (request, btc) = hashi::withdrawal_queue::request_into_parts(request);

        // burn BTC
        hashi.treasury_mut().burn(btc);

        request
    });

    // Selected UTXOs
    let epoch = hashi.committee_set().epoch();
    let selected_utxos = selected_utxos.map!(|raw| hashi::utxo::utxo_id_from_bcs(raw));
    let inputs = selected_utxos.map!(|utxo_id| hashi.utxo_pool_mut().spend(utxo_id, epoch));

    // outputs
    let outputs = outputs.map!(|raw| hashi::withdrawal_queue::output_utxo_from_bcs(raw));

    // TODO Verify cert

    let pending = hashi::withdrawal_queue::new_pending_withdrawal(
        requests,
        inputs,
        outputs,
        txid,
        clock,
        r,
        ctx,
    );

    hashi.withdrawal_queue_mut().insert_pending_withdrawal(pending);
}

entry fun confirm_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    // BTC signatures?
    // cert: Cert
    _ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();

    let withdrawal = hashi.withdrawal_queue_mut().remove_pending_withdrawal(withdrawal_id);

    // TODO Verify cert

    // TODO create and insert new UTXO for change if it hasn't already been
    // inserted

    withdrawal.destroy_pending_withdrawal();
}
