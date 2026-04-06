// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::mpc_config;

use hashi::{config::Config, config_value};

const DEFAULT_THRESHOLD_BASIS_POINTS: u64 = 3333;

const MAX_BPS: u64 = 10000;

/// Default allowed delta for weight reduction.
const DEFAULT_ALLOWED_DELTA: u64 = 800;

#[allow(implicit_const_copy)]
public(package) fun is_valid_config_entry(
    key: &std::string::String,
    value: &config_value::Value,
): bool {
    let k = key.as_bytes();
    if (k == &b"mpc_threshold_basis_points") {
        value.is_u64() && (*value).as_u64() > 0 && (*value).as_u64() <= MAX_BPS
    } else if (k == &b"mpc_allowed_delta") {
        value.is_u64() && (*value).as_u64() <= MAX_BPS
    } else {
        false
    }
}

public(package) fun init_defaults(config: &mut Config) {
    config.upsert(
        b"mpc_threshold_basis_points",
        config_value::new_u64(DEFAULT_THRESHOLD_BASIS_POINTS),
    );
    config.upsert(b"mpc_allowed_delta", config_value::new_u64(DEFAULT_ALLOWED_DELTA));
}
