// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Committee weight-threshold arithmetic. Computes the minimum aggregate
/// signer weight for a valid certificate (>2/3 quorum, matching the Sui
/// system's 6667 bps threshold) and general basis-point thresholds using
/// ceiling division, so the required weight is never below the true
/// fractional threshold.
module hashi::threshold;

// ~~~~~~~ Constants ~~~~~~~

const MAX_BPS: u64 = 10000;

/// Quorum threshold (2f + 1 out of 3f) in basis points.
const CERTIFICATE_THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EThresholdBpsTooHigh: vector<u8> = b"Threshold basis points must be at most 10000";

// ~~~~~~~ Package Functions ~~~~~~~

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
