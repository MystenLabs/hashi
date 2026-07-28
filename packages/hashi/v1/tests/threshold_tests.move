// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::threshold_tests;

use hashi::threshold;

#[test]
fun test_certificate_threshold() {
    // 6667 bps of 3 -> ceil(3*6667/10000) = ceil(2.0001) = 3.
    assert!(threshold::certificate_threshold(3) == 3);
    // 6667 bps of 10 -> ceil(66670/10000) = 7.
    assert!(threshold::certificate_threshold(10) == 7);
    // 6667 bps of 6 -> ceil(40002/10000) = 5.
    assert!(threshold::certificate_threshold(6) == 5);
    // 6667 bps of 1 -> ceil(6667/10000) = 1.
    assert!(threshold::certificate_threshold(1) == 1);
    // 6667 bps of 0 = 0.
    assert!(threshold::certificate_threshold(0) == 0);
    // Matches Sui system: 6667 bps of 10000 = 6667.
    assert!(threshold::certificate_threshold(10000) == 6667);
}

#[test]
fun test_weight_threshold_basic() {
    // 66.67% of 3 -> 3*6667 = 20001 -> ceil(20001/10000) = 3.
    assert!(threshold::weight_threshold(3, 6667) == 3);
    // 66.67% of 6 -> 6*6667 = 40002 -> ceil(40002/10000) = 5.
    assert!(threshold::weight_threshold(6, 6667) == 5);
    // 66.67% of 10 -> 10*6667 = 66670 -> ceil(66670/10000) = 7.
    assert!(threshold::weight_threshold(10, 6667) == 7);
}

#[test]
fun test_weight_threshold_unanimity() {
    // 100% always requires all weight.
    assert!(threshold::weight_threshold(1, 10000) == 1);
    assert!(threshold::weight_threshold(3, 10000) == 3);
    assert!(threshold::weight_threshold(100, 10000) == 100);
}

#[test]
fun test_weight_threshold_zero() {
    // 0 bps requires no weight.
    assert!(threshold::weight_threshold(100, 0) == 0);
    // Any threshold of 0 total weight requires 0.
    assert!(threshold::weight_threshold(0, 6667) == 0);
}

#[test]
fun test_weight_threshold_exact_division() {
    // 50% of 10 = 5 (exact, no rounding needed).
    assert!(threshold::weight_threshold(10, 5000) == 5);
    // 25% of 100 = 25.
    assert!(threshold::weight_threshold(100, 2500) == 25);
}

#[test]
fun test_weight_threshold_rounds_up() {
    // 50% of 3 = 1.5 -> 2.
    assert!(threshold::weight_threshold(3, 5000) == 2);
    // 1 bps of 1 = 0.0001 -> 1.
    assert!(threshold::weight_threshold(1, 1) == 1);
    // 33.33% of 10 = 3.333 -> 4.
    assert!(threshold::weight_threshold(10, 3333) == 4);
}

#[test]
#[expected_failure(abort_code = threshold::EThresholdBpsTooHigh)]
fun test_weight_threshold_rejects_above_10000() {
    threshold::weight_threshold(100, 10001);
}
