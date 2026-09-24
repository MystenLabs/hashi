// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::spend_data_bcs_tests;

use hashi::{deposit_queue, test_utils, utxo, utxo_pool, withdrawal_queue};
use sui::{bcs, clock};

const UTXO_RECORD_BCS: vector<u8> =
    x"0000000000000000000000000000000000000000000000000000000000000011020000000300000000000000010000000000000000000000000000000000000000000000000000000000000044035120aa0220bb02c0cc00000000000000000000000000000000000000000000000000000000000000dd0001000000000000000000000000000000000000000000000000000000000000005500010600000000000000";
const DEPOSIT_REQUEST_BCS: vector<u8> =
    x"a4137e2ed945e7f4e8c307001c32e97472fb3eebb8f7b4ab7534b447d22da89b000000000000000000000000000000000000000000000000000000000000010000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011020000000300000000000000010000000000000000000000000000000000000000000000000000000000000044010700000000000000000001035120aa0220bb02c0cc00000000000000000000000000000000000000000000000000000000000000dd0001000000000000000000";
const WITHDRAWAL_TRANSACTION_BCS: vector<u8> =
    x"a4137e2ed945e7f4e8c307001c32e97472fb3eebb8f7b4ab7534b447d22da89b0000000000000000000000000000000000000000000000000000000000000088000000000000000000000000000000000000000000000000000000000000009901000000000000000000000000000000000000000000000000000000000000006601000000000000000000000000000000000000000000000000000000000000001102000000030000000000000001000000000000000000000000000000000000000000000000000000000000004401010000000000000001770000000000000000000000040000000001000000000000000000000000000000000000";

fun spend(): utxo::SpendData {
    utxo::spend_data(x"5120aa", x"20bb", x"c0cc", @0xdd, 0)
}

fun input(): utxo::Utxo {
    utxo::utxo(utxo::utxo_id(@0x11, 2), 3, option::some(@0x44))
}

#[test]
fun utxo_record_bcs_is_pinned() {
    let record = utxo_pool::new_record_for_testing(
        input(),
        spend(),
        option::some(@0x55),
        option::none(),
        option::some(6),
    );
    assert!(bcs::to_bytes(&record) == UTXO_RECORD_BCS);
    std::unit_test::destroy(record);
}

#[test]
fun deposit_request_bcs_is_pinned() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let clock = clock::create_for_testing(ctx);
    let mut request = deposit_queue::create_deposit(input(), &clock, ctx);
    request.approve(
        hashi::committee::new_committee_signature(7, vector[], vector[]),
        spend(),
        &clock,
    );
    assert!(bcs::to_bytes(&request) == DEPOSIT_REQUEST_BCS);
    clock.destroy_for_testing();
    std::unit_test::destroy(request);
}

#[test]
fun withdrawal_transaction_bcs_is_pinned() {
    let ctx = &mut test_utils::new_tx_context(@0x100, 0);
    let clock = clock::create_for_testing(ctx);
    let mut txn = withdrawal_queue::new_withdrawal_txn_for_testing(
        vector[@0x66],
        vector[input()],
        vector[withdrawal_queue::output_utxo(1, x"77")],
        vector[],
        @0x88,
        &clock,
        ctx,
    );
    txn.set_sighash_digest_for_testing(@0x99);
    assert!(bcs::to_bytes(&txn) == WITHDRAWAL_TRANSACTION_BCS);
    clock.destroy_for_testing();
    std::unit_test::destroy(txn);
}
