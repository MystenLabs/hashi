// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::utxo_spent_tests;

use hashi::test_utils;

const REQUESTER: address = @0x100;
const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;

// ======== mark_spent marks but keeps record ========

/// mark_spent sets the spent_epoch flag and emits an event; the UTXO must
/// remain in utxo_records and must NOT appear in spent_utxos.
#[test]
fun test_mark_spent_marks_but_keeps_record() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 0);

    let pool = hashi.bitcoin().utxo_pool();
    assert!(pool.has_active_record(utxo_id));
    assert!(!pool.has_spent_record(utxo_id));

    std::unit_test::destroy(hashi);
}

// ======== cleanup_spent moves record ========

/// cleanup_spent removes the UTXO from utxo_records and adds it to
/// spent_utxos.
#[test]
fun test_cleanup_spent_moves_record() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);
    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 0);
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);

    let pool = hashi.bitcoin().utxo_pool();
    assert!(!pool.has_active_record(utxo_id));
    assert!(pool.has_spent_record(utxo_id));

    std::unit_test::destroy(hashi);
}

// ======== cleanup_spent is idempotent ========

/// A second cleanup_spent call for the same UTXO is a no-op (must not abort).
#[test]
fun test_cleanup_spent_idempotent() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    // Mark as spent, then cleanup -- moves to spent_utxos.
    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 0);
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);
    // Second cleanup -- should no-op, not abort.
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);

    let pool = hashi.bitcoin().utxo_pool();
    assert!(!pool.has_active_record(utxo_id));
    assert!(pool.has_spent_record(utxo_id));

    std::unit_test::destroy(hashi);
}
