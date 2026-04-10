// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(implicit_const_copy)]
module hashi::deposit_tests;

use hashi::{deposit, deposit_queue, test_utils};
use sui::{bcs, clock};

const VOTER1: address = @0x1;
const VOTER2: address = @0x2;
const VOTER3: address = @0x3;
const REQUESTER: address = @0x100;

/// Helper: build the signing message bytes for a certificate.
/// Format: BCS(epoch) || BCS(message)
fun build_cert_message<T: copy + drop + store>(epoch: u64, message: &T): vector<u8> {
    let mut bytes = bcs::to_bytes(&epoch);
    bytes.append(bcs::to_bytes(message));
    bytes
}

// ======== deposit() tests ========

#[test]
fun test_deposit_at_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    // Default bitcoin_deposit_minimum is 30,000 sats.
    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 30_000, option::none());

    deposit::deposit(&mut hashi, utxo, &clock, ctx);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_deposit_below_minimum() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 29_999, option::none());

    deposit::deposit(&mut hashi, utxo, &clock, ctx);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// A spent UTXO cannot be used for a new deposit request.
#[test]
#[expected_failure]
fun test_spent_utxo_cannot_be_redeposited() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 30_000, option::none());

    // Simulate: deposit confirmed (UTXO inserted into active pool)
    hashi.bitcoin_mut().utxo_pool_mut().insert_active(utxo);

    // Simulate: UTXO spent in a withdrawal (moved to spent_utxos)
    hashi.bitcoin_mut().utxo_pool_mut().confirm_spent(utxo_id, 0);

    // Attempt to deposit the same UTXO again — should abort because
    // is_spent_or_active() returns true.
    let utxo2 = hashi::utxo::utxo(utxo_id, 30_000, option::none());
    deposit::deposit(&mut hashi, utxo2, &clock, ctx);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// Multiple deposit requests for the same UTXO are allowed (anti-griefing).
#[test]
fun test_multiple_deposit_requests_same_utxo_allowed() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);

    // First deposit request succeeds.
    let utxo1 = hashi::utxo::utxo(utxo_id, 30_000, option::none());
    deposit::deposit(&mut hashi, utxo1, &clock, ctx);

    // Second deposit request with the same UTXO also succeeds (anti-griefing).
    let utxo2 = hashi::utxo::utxo(utxo_id, 30_000, option::none());
    deposit::deposit(&mut hashi, utxo2, &clock, ctx);

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

// ======== confirm_deposit() tests ========

#[test]
fun test_confirm_deposit_with_valid_certificate() {
    let epoch = 0;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    // Use derivation_path: None to skip BTC minting (no TreasuryCap in test setup)
    let utxo = hashi::utxo::utxo(utxo_id, 10_000, option::none());
    let request = deposit_queue::create_deposit(utxo, &clock, ctx);
    let request_id = request.request_id().to_address();
    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);

    let message = deposit::new_deposit_confirmation_message(request_id, utxo);
    let message_bytes = build_cert_message(epoch, &message);
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 3);

    deposit::confirm_deposit(&mut hashi, request_id, cert, ctx);

    assert!(hashi.bitcoin().utxo_pool().is_spent_or_active(utxo_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

/// Recipient is indexed at confirmation time via the unified user_requests on BitcoinState.
/// No indexing happens at request creation time.
#[test]
fun test_confirm_deposit_indexes_recipient() {
    let epoch = 0;
    let recipient: address = @0x200;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let mut hashi = test_utils::create_hashi_with_committee(voters, ctx);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 10_000, option::some(recipient));
    let request = deposit_queue::create_deposit(utxo, &clock, ctx);
    let request_id = request.request_id().to_address();
    hashi.bitcoin_mut().deposit_queue_mut().insert_deposit(request);

    // Neither sender nor recipient should be indexed at request time
    assert!(!hashi.bitcoin().user_has_request(REQUESTER, request_id));
    assert!(!hashi.bitcoin().user_has_request(recipient, request_id));

    // Simulate the indexing that confirm_deposit does
    hashi.bitcoin_mut().index_user_request(recipient, request_id, ctx);

    // Recipient should now be indexed
    assert!(hashi.bitcoin().user_has_request(recipient, request_id));
    // Sender should NOT be indexed (only recipient is indexed on confirm)
    assert!(!hashi.bitcoin().user_has_request(REQUESTER, request_id));

    clock.destroy_for_testing();
    std::unit_test::destroy(hashi);
}

#[test]
fun test_deposit_confirmation_certificate_verifies() {
    let epoch = 0;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo = hashi::utxo::utxo(hashi::utxo::utxo_id(@0xCAFE, 0), 1000, option::none());
    let message = deposit::new_deposit_confirmation_message(@0xBEEF, utxo);
    let message_bytes = build_cert_message(epoch, &message);
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 3);

    hashi.verify(message, cert);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_deposit_confirmation_certificate_wrong_message_fails() {
    let epoch = 0;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo = hashi::utxo::utxo(hashi::utxo::utxo_id(@0xCAFE, 0), 1000, option::none());
    let wrong_message = deposit::new_deposit_confirmation_message(@0xDEAD, utxo);
    let wrong_bytes = build_cert_message(epoch, &wrong_message);
    let bad_cert = test_utils::sign_certificate(epoch, &wrong_bytes, 3);

    let correct_message = deposit::new_deposit_confirmation_message(@0xBEEF, utxo);
    hashi.verify(correct_message, bad_cert);

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_deposit_confirmation_certificate_insufficient_signers() {
    let epoch = 0;
    let ctx = &mut test_utils::new_tx_context(REQUESTER, epoch);
    let voters = vector[VOTER1, VOTER2, VOTER3];
    let hashi = test_utils::create_hashi_with_committee(voters, ctx);

    let utxo = hashi::utxo::utxo(hashi::utxo::utxo_id(@0xCAFE, 0), 1000, option::none());
    let message = deposit::new_deposit_confirmation_message(@0xBEEF, utxo);
    let message_bytes = build_cert_message(epoch, &message);
    let cert = test_utils::sign_certificate(epoch, &message_bytes, 1);

    hashi.verify(message, cert);

    std::unit_test::destroy(hashi);
}

// ======== into_utxo() test ========

#[test]
fun test_into_utxo_returns_utxo() {
    let ctx = &mut test_utils::new_tx_context(REQUESTER, 0);
    let clock = clock::create_for_testing(ctx);

    let utxo_id = hashi::utxo::utxo_id(@0xCAFE, 0);
    let utxo = hashi::utxo::utxo(utxo_id, 10_000, option::some(REQUESTER));
    let request = deposit_queue::create_deposit(utxo, &clock, ctx);

    let recovered_utxo = request.utxo();
    assert!(recovered_utxo.id() == utxo_id);
    assert!(recovered_utxo.amount() == 10_000);

    clock.destroy_for_testing();
    std::unit_test::destroy(recovered_utxo);
    std::unit_test::destroy(request);
}
