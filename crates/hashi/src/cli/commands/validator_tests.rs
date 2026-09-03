// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn v() -> sui_sdk_types::Address {
    sui_sdk_types::Address::new([5; 32])
}

#[test]
fn an_unregistered_validator_cannot_resign_or_withdraw() {
    for action in [ResignationAction::Resign, ResignationAction::Withdraw] {
        let err = refuse_resignation_state(v(), None, action)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not registered"), "{err}");
    }
}

#[test]
fn resigning_twice_is_refused_and_points_at_withdrawal() {
    refuse_resignation_state(v(), Some(false), ResignationAction::Resign).unwrap();
    let err = refuse_resignation_state(v(), Some(true), ResignationAction::Resign)
        .unwrap_err()
        .to_string();
    assert!(err.contains("has already resigned"), "{err}");
    assert!(err.contains("withdraw-resignation"), "{err}");
}

#[test]
fn withdrawing_without_a_pending_resignation_is_refused() {
    refuse_resignation_state(v(), Some(true), ResignationAction::Withdraw).unwrap();
    let err = refuse_resignation_state(v(), Some(false), ResignationAction::Withdraw)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no pending resignation"), "{err}");
}
