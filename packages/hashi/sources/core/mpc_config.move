// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::mpc_config;

use hashi::{config::Config, config_value};

const DEFAULT_THRESHOLD_IN_BASIS_POINTS: u64 = 3334;

const DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA: u64 = 800;

const DEFAULT_MAX_FAULTY_IN_BASIS_POINTS: u64 = 3333;

const KEY_THRESHOLD_IN_BASIS_POINTS: vector<u8> = b"mpc_threshold_in_basis_points";
const KEY_MAX_FAULTY_IN_BASIS_POINTS: vector<u8> = b"mpc_max_faulty_in_basis_points";
const KEY_WEIGHT_REDUCTION_ALLOWED_DELTA: vector<u8> = b"mpc_weight_reduction_allowed_delta";

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

public(package) fun set_threshold_in_basis_points(config: &mut Config, value: u64) {
    config.upsert(KEY_THRESHOLD_IN_BASIS_POINTS, config_value::new_u64(value));
}

public(package) fun set_max_faulty_in_basis_points(config: &mut Config, value: u64) {
    config.upsert(KEY_MAX_FAULTY_IN_BASIS_POINTS, config_value::new_u64(value));
}

public(package) fun set_weight_reduction_allowed_delta(config: &mut Config, value: u64) {
    config.upsert(KEY_WEIGHT_REDUCTION_ALLOWED_DELTA, config_value::new_u64(value));
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
}
