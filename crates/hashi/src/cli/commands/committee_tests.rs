// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn abort_is_refused_when_nothing_is_pending() {
    let err = refuse_unabortable_reconfig(None, 7)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no reconfiguration is in progress"), "{err}");
}

#[test]
fn abort_is_refused_while_the_pending_epoch_is_still_current() {
    let err = refuse_unabortable_reconfig(Some(7), 7)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Sui's current epoch (7)"), "{err}");
    assert!(err.contains("may still complete"), "{err}");
}

#[test]
fn abort_proceeds_once_sui_has_moved_past_the_pending_epoch() {
    assert_eq!(refuse_unabortable_reconfig(Some(7), 8).unwrap(), 7);
    // Several missed epochs are just as stale as one.
    assert_eq!(refuse_unabortable_reconfig(Some(7), 12).unwrap(), 7);
}

#[test]
fn start_is_refused_while_a_reconfiguration_is_pending() {
    let err = refuse_unstartable_reconfig(Some(7), 6, 8, true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("epoch 7 is already in progress"), "{err}");
    assert!(err.contains("abort-reconfig"), "{err}");
}

#[test]
fn start_is_refused_while_hashi_is_on_suis_epoch() {
    // The current committee is the epoch-7 committee, so both chain asserts
    // (a committee for Sui's epoch, equal epochs) would fire; the committee
    // check comes first, as on chain.
    let err = refuse_unstartable_reconfig(None, 7, 7, true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("committee already exists for Sui's current epoch (7)"),
        "{err}"
    );
    // Equal epochs alone (no committee mirrored for it) hit the epoch check.
    let err = refuse_unstartable_reconfig(None, 7, 7, false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("already on Sui's current epoch (7)"), "{err}");
}

#[test]
fn start_is_refused_when_the_fullnode_lags_hashi() {
    let err = refuse_unstartable_reconfig(None, 7, 6, false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("ahead of the fullnode's Sui epoch (6)"),
        "{err}"
    );
}

#[test]
fn start_proceeds_once_hashi_lags_sui_with_nothing_pending() {
    // The state an abort leaves behind: nothing pending, the aborted
    // committee removed, Hashi one or more epochs behind Sui.
    refuse_unstartable_reconfig(None, 6, 7, false).unwrap();
    refuse_unstartable_reconfig(None, 6, 12, false).unwrap();
}

#[test]
fn start_proceeds_at_genesis_with_equal_epochs() {
    // Pre-genesis Hashi sits at epoch 0 with no committee; the chain lets a
    // genesis start through even when Sui is also at epoch 0.
    refuse_unstartable_reconfig(None, 0, 0, false).unwrap();
    // An aborted genesis DKG at Sui epoch 3 leaves the same shape.
    refuse_unstartable_reconfig(None, 0, 3, false).unwrap();
}
