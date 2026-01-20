// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Test utilities for creating Hashi instances and proposals in unit tests
#[test_only]
#[allow(unused_use, duplicate_alias, implicit_const_copy)]
module hashi::test_utils;

use hashi::{
    committee::{Self, CommitteeMember},
    deposit_queue,
    disable_version,
    enable_version,
    hashi::Hashi,
    update_deposit_fee,
    utxo_pool
};
use sui::{bag, bls12381, clock::Clock, vec_map};

// ======== Test Fixtures ========
// TODO: add proper signing and encryption fixtures for signature verification tests

/// BLS12-381 G1 generator point - valid public key for testing committee membership
const TEST_BLS_PUBKEY: vector<u8> =
    x"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

/// 32-byte dummy encryption key for testing
const TEST_ENCRYPTION_KEY: vector<u8> =
    x"0000000000000000000000000000000000000000000000000000000000000001";

// ======== Transaction Context Helpers ========

/// Creates a new TxContext with the specified sender address
public fun new_tx_context(sender: address, epoch: u64): TxContext {
    tx_context::new_from_hint(
        sender,
        0, // tx_hash hint
        epoch,
        0, // epoch_timestamp_ms
        0, // ids_created
    )
}

// ======== Hashi Creation ========

/// Creates a test Hashi instance with a committee containing the specified voters
/// Each voter has equal weight (weight = 1)
public fun create_hashi_with_committee(voters: vector<address>, ctx: &mut TxContext): Hashi {
    let weights = voters.map!(|_| 1u16);
    create_hashi_with_weighted_committee(voters, weights, ctx)
}

/// Creates a test Hashi instance with a committee containing voters with custom weights
public fun create_hashi_with_weighted_committee(
    voters: vector<address>,
    weights: vector<u16>,
    ctx: &mut TxContext,
): Hashi {
    assert!(voters.length() == weights.length());

    // Create committee members
    let mut members = vector[];
    let mut i = 0;
    while (i < voters.length()) {
        let member = create_test_committee_member(voters[i], weights[i]);
        members.push_back(member);
        i = i + 1;
    };

    // Create the committee
    let committee = committee::new_committee(ctx.epoch(), members);

    // Create committee set with the test committee
    let committee_set = hashi::committee_set::create_for_testing(
        committee,
        voters,
        TEST_BLS_PUBKEY,
        TEST_ENCRYPTION_KEY,
        ctx,
    );

    // Create config with version enabled
    let config = hashi::config::create();

    // Create treasury
    let treasury = hashi::treasury::create(ctx);

    // Create deposit queue
    let deposit_queue = deposit_queue::create(ctx);

    // Create utxo pool
    let utxo_pool = utxo_pool::create(ctx);

    // Create proposals bag
    let proposals = bag::new(ctx);

    // Create TOB bag
    let tob = bag::new(ctx);

    hashi::hashi::create_for_testing(
        committee_set,
        config,
        treasury,
        deposit_queue,
        utxo_pool,
        proposals,
        tob,
        ctx,
    )
}

fun create_test_committee_member(validator_address: address, weight: u16): CommitteeMember {
    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&TEST_BLS_PUBKEY),
    );

    committee::new_committee_member(
        validator_address,
        public_key,
        TEST_ENCRYPTION_KEY,
        weight,
    )
}

// ======== Proposal Creation Helpers ========

/// Creates a deposit fee update proposal and returns its ID
public fun create_deposit_fee_proposal(
    hashi: &mut Hashi,
    fee: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    update_deposit_fee::propose(hashi, fee, vec_map::empty(), clock, ctx)
}

/// Creates an enable version proposal and returns its ID
public fun create_enable_version_proposal(
    hashi: &mut Hashi,
    version: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    enable_version::propose(hashi, version, vec_map::empty(), clock, ctx)
}

/// Creates a disable version proposal and returns its ID
public fun create_disable_version_proposal(
    hashi: &mut Hashi,
    version: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    disable_version::propose(hashi, version, vec_map::empty(), clock, ctx)
}
