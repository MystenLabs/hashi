// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The MPC protocol parameters (`f`, weight-reduction delta, nonce protocol,
/// nonce accumulation window) and their validation. They live in the
/// package's EPOCH config: governance edits them through
/// `update_epoch_config`, and `pin` snapshots the whole epoch config onto the
/// committee formed at `start_reconfig`, so a committee's parameters never
/// change under it.
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

/// Range-checks a value bound for the epoch config. Keys this module does not
/// own pass unconditionally; the retired threshold key is rejected outright so
/// it can never reappear in a pinned config (nodes treat its presence as the
/// legacy threshold formula).
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

/// The one rule the per-entry range checks cannot see: the weight-reduction
/// delta must stay below max-faulty. The proposals that write the epoch
/// config check it on the store they leave behind, so a joint update of both
/// keys is judged on its result rather than on entry order, and
/// `start_reconfig` copies the store verbatim with nothing left to repair.
public(package) fun is_consistent(config: &Config): bool {
    weight_reduction_allowed_delta(config) < max_faulty_in_basis_points(config)
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
