// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::mpc_config;

use hashi::{config::{Self, Config}, config_value};

// ~~~~~~~ Constants ~~~~~~~

const DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA: u64 = 800;

const DEFAULT_MAX_FAULTY_IN_BASIS_POINTS: u64 = 3333;

const VANILLA_NONCE_GENERATION_PROTOCOL: u64 = 0;

/// How long nodes keep collecting nonce dealer certs past the `W − f` floor.
const DEFAULT_NONCE_ACCUMULATION_WINDOW_MS: u64 = 2000;

const MAX_NONCE_ACCUMULATION_WINDOW_MS: u64 = 10000;

const MAX_BPS: u64 = 10000;

const MAX_FAULTY_BPS: u64 = 3333;

const KEY_REMOVED_THRESHOLD_IN_BASIS_POINTS: vector<u8> = b"mpc_threshold_in_basis_points";
const KEY_MAX_FAULTY_IN_BASIS_POINTS: vector<u8> = b"mpc_max_faulty_in_basis_points";
const KEY_WEIGHT_REDUCTION_ALLOWED_DELTA: vector<u8> = b"mpc_weight_reduction_allowed_delta";
const KEY_NONCE_GENERATION_PROTOCOL: vector<u8> = b"mpc_nonce_generation_protocol";
const KEY_NONCE_ACCUMULATION_WINDOW_MS: vector<u8> = b"mpc_nonce_accumulation_window_ms";

// ~~~~~~~ Package Functions ~~~~~~~

#[allow(implicit_const_copy)]
public(package) fun is_valid_value(key: &std::string::String, value: &config_value::Value): bool {
    let k = key.as_bytes();
    if (k == &KEY_REMOVED_THRESHOLD_IN_BASIS_POINTS) {
        false
    } else if (k == &KEY_WEIGHT_REDUCTION_ALLOWED_DELTA) {
        value.is_u64() && (*value).as_u64() <= MAX_BPS
    } else if (k == &KEY_MAX_FAULTY_IN_BASIS_POINTS) {
        value.is_u64() && (*value).as_u64() > 0 && (*value).as_u64() <= MAX_FAULTY_BPS
    } else if (k == &KEY_NONCE_GENERATION_PROTOCOL) {
        value.is_u64() && (*value).as_u64() <= 1
    } else if (k == &KEY_NONCE_ACCUMULATION_WINDOW_MS) {
        value.is_u64() && (*value).as_u64() <= MAX_NONCE_ACCUMULATION_WINDOW_MS
    } else {
        true
    }
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

public(package) fun nonce_accumulation_window_ms(config: &Config): u64 {
    config
        .try_get(KEY_NONCE_ACCUMULATION_WINDOW_MS)
        .map!(|v| v.as_u64())
        .destroy_or!(DEFAULT_NONCE_ACCUMULATION_WINDOW_MS)
}

public(package) fun seed_absent_defaults(config: &mut Config) {
    seed_if_absent(
        config,
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA,
    );
    seed_if_absent(config, KEY_MAX_FAULTY_IN_BASIS_POINTS, DEFAULT_MAX_FAULTY_IN_BASIS_POINTS);
    seed_if_absent(config, KEY_NONCE_GENERATION_PROTOCOL, VANILLA_NONCE_GENERATION_PROTOCOL);
    seed_if_absent(
        config,
        KEY_NONCE_ACCUMULATION_WINDOW_MS,
        DEFAULT_NONCE_ACCUMULATION_WINDOW_MS,
    );
}

fun reset_if_out_of_range(config: &mut Config, key: vector<u8>, lo: u64, hi: u64, default: u64) {
    config.try_get(key).map!(|v| v.as_u64()).do!(|value| if (value < lo || value > hi) {
        config.upsert(key, config_value::new_u64(default));
    });
}

fun seed_if_absent(config: &mut Config, key: vector<u8>, default: u64) {
    if (!config.contains(key)) {
        config.upsert(key, config_value::new_u64(default));
    };
}

fun repair_out_of_range(config: &mut Config) {
    reset_if_out_of_range(
        config,
        KEY_MAX_FAULTY_IN_BASIS_POINTS,
        1,
        MAX_FAULTY_BPS,
        DEFAULT_MAX_FAULTY_IN_BASIS_POINTS,
    );
    let max_delta = max_faulty_in_basis_points(config) - 1;
    clamp_at_most(config, KEY_WEIGHT_REDUCTION_ALLOWED_DELTA, max_delta);
}

fun clamp_at_most(config: &mut Config, key: vector<u8>, hi: u64) {
    config.try_get(key).map!(|v| v.as_u64()).do!(|value| if (value > hi) {
        config.upsert(key, config_value::new_u64(hi));
    });
}

public(package) fun init_defaults(config: &mut Config) {
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
        KEY_NONCE_ACCUMULATION_WINDOW_MS,
        config_value::new_u64(DEFAULT_NONCE_ACCUMULATION_WINDOW_MS),
    );
}

public(package) fun pin(config: &mut Config): Config {
    repair_out_of_range(config);
    let mut mpc = config::empty();
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
        KEY_NONCE_ACCUMULATION_WINDOW_MS,
        config_value::new_u64(nonce_accumulation_window_ms(config)),
    );
    mpc
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun new_for_testing(
    weight_reduction_allowed_delta: u64,
    max_faulty_in_basis_points: u64,
    nonce_generation_protocol: u64,
    nonce_accumulation_window_ms: u64,
): Config {
    let mut mpc = config::empty();
    mpc.upsert(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_value::new_u64(weight_reduction_allowed_delta),
    );
    mpc.upsert(KEY_MAX_FAULTY_IN_BASIS_POINTS, config_value::new_u64(max_faulty_in_basis_points));
    mpc.upsert(KEY_NONCE_GENERATION_PROTOCOL, config_value::new_u64(nonce_generation_protocol));
    mpc.upsert(
        KEY_NONCE_ACCUMULATION_WINDOW_MS,
        config_value::new_u64(nonce_accumulation_window_ms),
    );
    mpc
}
