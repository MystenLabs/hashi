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
