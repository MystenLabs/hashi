// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::utxo_spent_tests;

use hashi::{test_utils, utxo_pool};

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

// ======== insert_active rejects duplicate active UTXO ========

#[test]
#[expected_failure(abort_code = utxo_pool::EUtxoAlreadyUsed)]
fun test_insert_active_rejects_existing_active_utxo() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo1 = hashi::utxo::utxo(utxo_id, 50_000, option::none());
    let utxo2 = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo1);
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo2);

    std::unit_test::destroy(hashi);
}

// ======== insert_active rejects spent UTXO ========

#[test]
#[expected_failure(abort_code = utxo_pool::EUtxoAlreadyUsed)]
fun test_insert_active_rejects_spent_utxo() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo1 = hashi::utxo::utxo(utxo_id, 50_000, option::none());
    let utxo2 = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo1);
    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 0);
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo2);

    std::unit_test::destroy(hashi);
}

// ======== cleanup_spent emits UtxoCleaned ========

/// A real cleanup emits exactly one UtxoCleaned event carrying the spent
/// epoch; node watchers prune their local mirror on it.
#[test]
fun test_cleanup_spent_emits_event() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);
    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 7);
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);

    let events = sui::event::events_by_type<utxo_pool::UtxoCleaned>();
    assert!(events.length() == 1);
    let (event_utxo_id, event_epoch) = utxo_pool::utxo_cleaned_fields(&events[0]);
    assert!(event_utxo_id == utxo_id);
    assert!(event_epoch == 7);

    std::unit_test::destroy(hashi);
}

/// A no-op cleanup (record already gone) must not emit UtxoCleaned.
#[test]
fun test_cleanup_spent_noop_emits_no_event() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 50_000, option::none());

    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);
    hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo_id, 0);
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);
    // Second cleanup is a no-op and must stay silent.
    hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);

    let events = sui::event::events_by_type<utxo_pool::UtxoCleaned>();
    assert!(events.length() == 1);

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
