// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::threshold;

const MAX_BPS: u64 = 10000;

/// Quorum threshold (2f + 1 out of 3f) in basis points.
const CERTIFICATE_THRESHOLD_BPS: u64 = 6667;

#[error]
const EThresholdBpsTooHigh: vector<u8> = b"Threshold basis points must be at most 10000";

/// Returns the minimum aggregate signer weight required for a valid
/// certificate (>2/3 of total weight, matching the Sui system's
/// quorum threshold of 6667 bps).
public(package) fun certificate_threshold(total_weight: u16): u16 {
    (weight_threshold(total_weight as u64, CERTIFICATE_THRESHOLD_BPS) as u16)
}

/// Returns the minimum weight required to meet a threshold expressed
/// in basis points (0..10000). Uses ceiling division so the required
/// weight is never less than the true fractional threshold.
public(package) fun weight_threshold(total_weight: u64, threshold_bps: u64): u64 {
    assert!(threshold_bps <= MAX_BPS, EThresholdBpsTooHigh);
    (total_weight * threshold_bps).divide_and_round_up(MAX_BPS)
}

// ======== Tests ========

#[test]
fun test_certificate_threshold() {
    // 6667 bps of 3 -> ceil(3*6667/10000) = ceil(2.0001) = 3.
    assert!(certificate_threshold(3) == 3);
    // 6667 bps of 10 -> ceil(66670/10000) = 7.
    assert!(certificate_threshold(10) == 7);
    // 6667 bps of 6 -> ceil(40002/10000) = 5.
    assert!(certificate_threshold(6) == 5);
    // 6667 bps of 1 -> ceil(6667/10000) = 1.
    assert!(certificate_threshold(1) == 1);
    // 6667 bps of 0 = 0.
    assert!(certificate_threshold(0) == 0);
    // Matches Sui system: 6667 bps of 10000 = 6667.
    assert!(certificate_threshold(10000) == 6667);
}

#[test]
fun test_weight_threshold_basic() {
    // 66.67% of 3 -> 3*6667 = 20001 -> ceil(20001/10000) = 3.
    assert!(weight_threshold(3, 6667) == 3);
    // 66.67% of 6 -> 6*6667 = 40002 -> ceil(40002/10000) = 5.
    assert!(weight_threshold(6, 6667) == 5);
    // 66.67% of 10 -> 10*6667 = 66670 -> ceil(66670/10000) = 7.
    assert!(weight_threshold(10, 6667) == 7);
}

#[test]
fun test_weight_threshold_unanimity() {
    // 100% always requires all weight.
    assert!(weight_threshold(1, 10000) == 1);
    assert!(weight_threshold(3, 10000) == 3);
    assert!(weight_threshold(100, 10000) == 100);
}

#[test]
fun test_weight_threshold_zero() {
    // 0 bps requires no weight.
    assert!(weight_threshold(100, 0) == 0);
    // Any threshold of 0 total weight requires 0.
    assert!(weight_threshold(0, 6667) == 0);
}

#[test]
fun test_weight_threshold_exact_division() {
    // 50% of 10 = 5 (exact, no rounding needed).
    assert!(weight_threshold(10, 5000) == 5);
    // 25% of 100 = 25.
    assert!(weight_threshold(100, 2500) == 25);
}

#[test]
fun test_weight_threshold_rounds_up() {
    // 50% of 3 = 1.5 -> 2.
    assert!(weight_threshold(3, 5000) == 2);
    // 1 bps of 1 = 0.0001 -> 1.
    assert!(weight_threshold(1, 1) == 1);
    // 33.33% of 10 = 3.333 -> 4.
    assert!(weight_threshold(10, 3333) == 4);
}

#[test]
#[expected_failure(abort_code = EThresholdBpsTooHigh)]
fun test_weight_threshold_rejects_above_10000() {
    weight_threshold(100, 10001);
}
