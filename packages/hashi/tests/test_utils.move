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

// === BLS Helpers ===

public fun bls_min_pk_sign(msg: &vector<u8>, sk: &vector<u8>): vector<u8> {
    let sk_element = bls12381::scalar_from_bytes(sk);
    let hashed_msg = bls12381::hash_to_g2(msg);
    let sig = bls12381::g2_mul(&sk_element, &hashed_msg);
    *sig.bytes()
}

public fun bls_min_pk_from_sk(sk: &vector<u8>): vector<u8> {
    let sk_element = bls12381::scalar_from_bytes(sk);
    let g1 = bls12381::g1_generator();
    let pk = bls12381::g1_mul(&sk_element, &g1);
    *pk.bytes()
}

// Prepends the key with zeros to get 32 bytes.
public fun pad_bls_sk(sk: &vector<u8>): vector<u8> {
    let mut sk = *sk;
    if (sk.length() < 32) {
        // Prepend with zeros to get 32 bytes.
        sk.reverse();
        (32 - sk.length()).do!(|_| sk.push_back(0));
        sk.reverse();
    };
    sk
}

/// Returns the secret key scalar 117.
public fun bls_sk_for_testing(): vector<u8> {
    pad_bls_sk(&x"75")
}

/// Returns 10 bls secret keys.
public fun bls_secret_keys_for_testing(): vector<vector<u8>> {
    let mut res = vector[];
    10u64.do!(|i| {
        let sk = bls12381::scalar_from_u64(1 + (i as u64));
        res.push_back(*sk.bytes());
    });
    res
}

/// Aggregates the given signatures into one signature.
public fun bls_aggregate_sigs(signatures: &vector<vector<u8>>): vector<u8> {
    let mut aggregate = bls12381::g2_identity();
    signatures.do_ref!(
        |sig| aggregate = bls12381::g2_add(&aggregate, &bls12381::g2_from_bytes(sig)),
    );
    *aggregate.bytes()
}

// ======== Hashi Creation ========

/// Creates a test Hashi instance with a committee containing the specified voters
/// Each voter has equal weight (weight = 1)
public fun create_hashi_with_committee(voters: vector<address>, ctx: &mut TxContext): Hashi {
    let weights = voters.map!(|_| 1u64);
    create_hashi_with_weighted_committee(voters, weights, ctx)
}

/// Creates a test Hashi instance with a committee containing voters with custom weights
public fun create_hashi_with_weighted_committee(
    voters: vector<address>,
    weights: vector<u64>,
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

    let sk = bls_sk_for_testing();
    let pub_key = bls12381::g1_from_bytes(&bls_min_pk_from_sk(&sk));

    // Create committee set with the test committee
    let committee_set = hashi::committee_set::create_for_testing(
        committee,
        voters,
        *pub_key.bytes(),
        sk,
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

fun create_test_committee_member(validator_address: address, weight: u64): CommitteeMember {
    let sk = bls_sk_for_testing();
    let pub_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&bls_min_pk_from_sk(&sk)),
    );

    committee::new_committee_member(
        validator_address,
        pub_key,
        sk,
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
