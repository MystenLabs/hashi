// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governed MPC protocol parameters — signing threshold, weight-reduction
/// allowed delta, max-faulty bound, nonce-generation protocol, and
/// presignature-derivation version — each stored under a permanent config key
/// with a compiled-in default. `pin` snapshots the full parameter set into a
/// deterministic, canonically-ordered store that is attached to a `Committee`
/// for its epoch, so mid-epoch governance changes never affect an active
/// committee.
module hashi::mpc_config;

use hashi::{config::{Self, Config}, config_value};

// ~~~~~~~ Constants ~~~~~~~

const DEFAULT_THRESHOLD_IN_BASIS_POINTS: u64 = 3334;

const DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA: u64 = 800;

const DEFAULT_MAX_FAULTY_IN_BASIS_POINTS: u64 = 3333;

const VANILLA_NONCE_GENERATION_PROTOCOL: u64 = 0;

/// fastcrypto's legacy `W - f` extraction.
const LEGACY_PRESIGNATURE_DERIVATION_VERSION: u64 = 0;
/// The `W - (t - 1)` privacy-threshold extraction.
const DEFAULT_PRESIGNATURE_DERIVATION_VERSION: u64 = 1;

const MAX_BPS: u64 = 10000;

const KEY_THRESHOLD_IN_BASIS_POINTS: vector<u8> = b"mpc_threshold_in_basis_points";
const KEY_MAX_FAULTY_IN_BASIS_POINTS: vector<u8> = b"mpc_max_faulty_in_basis_points";
const KEY_WEIGHT_REDUCTION_ALLOWED_DELTA: vector<u8> = b"mpc_weight_reduction_allowed_delta";
const KEY_NONCE_GENERATION_PROTOCOL: vector<u8> = b"mpc_nonce_generation_protocol";
const KEY_PRESIGNATURE_DERIVATION_VERSION: vector<u8> = b"mpc_presignature_derivation_version";

// ~~~~~~~ Package Functions ~~~~~~~

#[allow(implicit_const_copy)]
public(package) fun is_valid_value(key: &std::string::String, value: &config_value::Value): bool {
    let k = key.as_bytes();
    if (k == &KEY_THRESHOLD_IN_BASIS_POINTS) {
        value.is_u64() && (*value).as_u64() > 0 && (*value).as_u64() <= MAX_BPS
    } else if (k == &KEY_WEIGHT_REDUCTION_ALLOWED_DELTA) {
        value.is_u64() && (*value).as_u64() <= MAX_BPS
    } else if (k == &KEY_MAX_FAULTY_IN_BASIS_POINTS) {
        value.is_u64() && (*value).as_u64() <= MAX_BPS
    } else if (k == &KEY_NONCE_GENERATION_PROTOCOL) {
        value.is_u64() && (*value).as_u64() <= 1
    } else if (k == &KEY_PRESIGNATURE_DERIVATION_VERSION) {
        value.is_u64() && (*value).as_u64() <= 1
    } else {
        true
    }
}

public(package) fun threshold_in_basis_points(config: &Config): u64 {
    config
        .try_get(KEY_THRESHOLD_IN_BASIS_POINTS)
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_THRESHOLD_IN_BASIS_POINTS)
}

public(package) fun weight_reduction_allowed_delta(config: &Config): u64 {
    config
        .try_get(KEY_WEIGHT_REDUCTION_ALLOWED_DELTA)
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA)
}

public(package) fun max_faulty_in_basis_points(config: &Config): u64 {
    config
        .try_get(KEY_MAX_FAULTY_IN_BASIS_POINTS)
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_MAX_FAULTY_IN_BASIS_POINTS)
}

public(package) fun nonce_generation_protocol(config: &Config): u64 {
    config
        .try_get(KEY_NONCE_GENERATION_PROTOCOL)
        .map!(|v| v.as_u64())
        .destroy_or!(VANILLA_NONCE_GENERATION_PROTOCOL)
}

public(package) fun presignature_derivation_version(config: &Config): u64 {
    config
        .try_get(KEY_PRESIGNATURE_DERIVATION_VERSION)
        .map!(|v| v.as_u64())
        .destroy_or!(LEGACY_PRESIGNATURE_DERIVATION_VERSION)
}

public(package) fun init_defaults(config: &mut Config) {
    config.upsert(
        KEY_THRESHOLD_IN_BASIS_POINTS,
        config_value::new_u64(DEFAULT_THRESHOLD_IN_BASIS_POINTS),
    );
    config.upsert(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_value::new_u64(DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA),
    );
    config.upsert(
        KEY_MAX_FAULTY_IN_BASIS_POINTS,
        config_value::new_u64(DEFAULT_MAX_FAULTY_IN_BASIS_POINTS),
    );
    config.upsert(
        KEY_NONCE_GENERATION_PROTOCOL,
        config_value::new_u64(VANILLA_NONCE_GENERATION_PROTOCOL),
    );
    config.upsert(
        KEY_PRESIGNATURE_DERIVATION_VERSION,
        config_value::new_u64(DEFAULT_PRESIGNATURE_DERIVATION_VERSION),
    );
}

/// Snapshot the MPC parameters from `config` into a fresh store to pin onto a
/// `Committee` for the epoch. The full key set is always materialized (using
/// defaults for absent keys) and inserted in a fixed canonical order, so the
/// snapshot's BCS encoding is deterministic. The committee is signed, so the
/// Rust mirror (`move_types::Committee`'s `From`) must build this map in the
/// same order with the same keys.
public(package) fun pin(config: &Config): Config {
    let mut mpc = config::empty();
    mpc.upsert(
        KEY_THRESHOLD_IN_BASIS_POINTS,
        config_value::new_u64(threshold_in_basis_points(config)),
    );
    mpc.upsert(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_value::new_u64(weight_reduction_allowed_delta(config)),
    );
    mpc.upsert(
        KEY_MAX_FAULTY_IN_BASIS_POINTS,
        config_value::new_u64(max_faulty_in_basis_points(config)),
    );
    mpc.upsert(
        KEY_NONCE_GENERATION_PROTOCOL,
        config_value::new_u64(nonce_generation_protocol(config)),
    );
    mpc.upsert(
        KEY_PRESIGNATURE_DERIVATION_VERSION,
        config_value::new_u64(presignature_derivation_version(config)),
    );
    mpc
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
/// Build a pinned MPC parameter store directly from explicit values, in the
/// same canonical key order as `pin`. Used by tests that construct committees
/// without a full governed config.
public(package) fun new_for_testing(
    threshold_in_basis_points: u64,
    weight_reduction_allowed_delta: u64,
    max_faulty_in_basis_points: u64,
    nonce_generation_protocol: u64,
    presignature_derivation_version: u64,
): Config {
    let mut mpc = config::empty();
    mpc.upsert(KEY_THRESHOLD_IN_BASIS_POINTS, config_value::new_u64(threshold_in_basis_points));
    mpc.upsert(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_value::new_u64(weight_reduction_allowed_delta),
    );
    mpc.upsert(KEY_MAX_FAULTY_IN_BASIS_POINTS, config_value::new_u64(max_faulty_in_basis_points));
    mpc.upsert(KEY_NONCE_GENERATION_PROTOCOL, config_value::new_u64(nonce_generation_protocol));
    mpc.upsert(
        KEY_PRESIGNATURE_DERIVATION_VERSION,
        config_value::new_u64(presignature_derivation_version),
    );
    mpc
}
