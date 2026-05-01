// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::mpc_config;

use hashi::{config::Config, config_value};

const DEFAULT_THRESHOLD_IN_BASIS_POINTS: u64 = 3334;

const DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA: u64 = 800;

const DEFAULT_MAX_FAULTY_IN_BASIS_POINTS: u64 = 3333;

public(package) fun threshold_in_basis_points(config: &Config): u64 {
    config
        .try_get(b"mpc_threshold_in_basis_points")
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_THRESHOLD_IN_BASIS_POINTS)
}

public(package) fun weight_reduction_allowed_delta(config: &Config): u64 {
    config
        .try_get(b"mpc_weight_reduction_allowed_delta")
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA)
}

public(package) fun max_faulty_in_basis_points(config: &Config): u64 {
    config
        .try_get(b"mpc_max_faulty_in_basis_points")
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_MAX_FAULTY_IN_BASIS_POINTS)
}

public(package) fun init_defaults(config: &mut Config) {
    config.upsert(
        b"mpc_threshold_in_basis_points",
        config_value::new_u64(DEFAULT_THRESHOLD_IN_BASIS_POINTS),
    );
    config.upsert(
        b"mpc_weight_reduction_allowed_delta",
        config_value::new_u64(DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA),
    );
    config.upsert(
        b"mpc_max_faulty_in_basis_points",
        config_value::new_u64(DEFAULT_MAX_FAULTY_IN_BASIS_POINTS),
    );
}
