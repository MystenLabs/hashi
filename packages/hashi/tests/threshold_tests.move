// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::threshold_tests;

use hashi::threshold;

#[test]
fun test_genesis_stake_satisfied_at_threshold() {
    // The forming committee must cover >=95% of total stake.
    // weight_threshold(1000, 9500) = ceil(950.0) = 950.
    assert!(threshold::genesis_stake_satisfied(950, 1000)); // exactly 95% -> ok
    assert!(threshold::genesis_stake_satisfied(1000, 1000)); // 100% -> ok
    assert!(!threshold::genesis_stake_satisfied(949, 1000)); // just under -> not satisfied
    assert!(!threshold::genesis_stake_satisfied(0, 1000)); // none registered -> not satisfied
}

#[test]
fun test_genesis_stake_threshold_is_95_percent() {
    // Pins the genesis stake threshold at 95%.
    // weight_threshold(10000, 9500) = 9500.
    assert!(threshold::genesis_stake_satisfied(9500, 10000));
    assert!(!threshold::genesis_stake_satisfied(9499, 10000));
}
