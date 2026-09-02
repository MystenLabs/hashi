// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the governance identity resolution in `cli::client`.

use fastcrypto::bls12381::min_pk::BLS12381KeyPair;
use fastcrypto::traits::KeyPair;
use sui_sdk_types::Address;

use super::resolve_governance_identity;
use crate::onchain::types::MemberInfo;

fn addr(byte: u8) -> Address {
    Address::new([byte; 32])
}

/// A registered member whose operator address is `operator`. The keys are
/// irrelevant to resolution; one throwaway BLS key satisfies the struct.
fn member(validator: Address, operator: Address) -> MemberInfo {
    let keypair = BLS12381KeyPair::generate(&mut rand::thread_rng());
    MemberInfo {
        validator_address: validator,
        operator_address: operator,
        next_epoch_public_key: keypair.public().clone(),
        endpoint_url: None,
        tls_public_key: None,
        next_epoch_encryption_public_key: None,
        ignored: false,
        resigned: false,
    }
}

#[test]
fn exact_validator_match_beats_an_earlier_operator_delegation() {
    // M sorts before V and has pointed its operator address at V's signing
    // address. V's key must still act as V, not as M.
    let m = addr(1);
    let v = addr(2);
    let members = [member(m, v), member(v, v)];

    assert_eq!(resolve_governance_identity(&members, v).unwrap(), v);
}

#[test]
fn exact_validator_match_wins_over_any_number_of_delegations() {
    let v = addr(5);
    let members = [member(addr(1), v), member(addr(2), v), member(v, addr(9))];

    assert_eq!(resolve_governance_identity(&members, v).unwrap(), v);
}

#[test]
fn single_operator_delegation_resolves_to_the_delegating_member() {
    let m = addr(3);
    let operator = addr(9);
    let members = [member(addr(1), addr(1)), member(m, operator)];

    assert_eq!(resolve_governance_identity(&members, operator).unwrap(), m);
}

#[test]
fn two_delegations_to_the_same_signer_are_an_error_naming_both() {
    let a = addr(1);
    let b = addr(2);
    let operator = addr(9);
    let members = [
        member(a, operator),
        member(b, operator),
        member(addr(3), addr(3)),
    ];

    let err = resolve_governance_identity(&members, operator)
        .unwrap_err()
        .to_string();
    assert!(err.contains(&operator.to_hex()), "{err}");
    assert!(err.contains(&a.to_hex()), "{err}");
    assert!(err.contains(&b.to_hex()), "{err}");
    assert!(err.contains("2 committee members"), "{err}");
}

#[test]
fn unknown_signer_is_rejected() {
    let members = [member(addr(1), addr(1)), member(addr(2), addr(8))];
    let stranger = addr(7);

    let err = resolve_governance_identity(&members, stranger)
        .unwrap_err()
        .to_string();
    assert!(err.contains(&stranger.to_hex()), "{err}");
    assert!(
        err.contains("not a committee member or delegated operator"),
        "{err}"
    );
}
