#[test_only]
#[allow(implicit_const_copy)]
module hashi::deposit_tests;

use hashi::{deposit, deposit_queue, test_utils};
use sui::clock;

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const REQUESTER: address = @0x100;

#[test]
fun test_deposit_at_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 546, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let fee = sui::coin::zero(ctx);

    deposit::deposit(&mut hashi, request, fee);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_deposit_below_dust_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 545, option::none());
    let request = deposit_queue::deposit_request(utxo, &clock, ctx);
    let fee = sui::coin::zero(ctx);

    deposit::deposit(&mut hashi, request, fee);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}
