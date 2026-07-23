// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governed MPC protocol parameters — signing threshold, weight-reduction
/// allowed delta, max-faulty bound, and nonce-generation protocol — each
/// stored under a permanent config key with a compiled-in default. Registered
/// as epoch-pinned, so `config::pin` snapshots them onto each epoch's
/// `Committee` and mid-epoch governance changes never affect an active
/// committee.
module hashi::mpc_config;

use hashi::{config::Config, config_registry::{Self, ConfigRegistry}, config_value};

#[test_only]
use hashi::config;

// ~~~~~~~ Constants ~~~~~~~

const DEFAULT_THRESHOLD_IN_BASIS_POINTS: u64 = 3334;

const DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA: u64 = 800;

const DEFAULT_MAX_FAULTY_IN_BASIS_POINTS: u64 = 3333;

const VANILLA_NONCE_GENERATION_PROTOCOL: u64 = 0;

const MAX_BPS: u64 = 10000;

const KEY_THRESHOLD_IN_BASIS_POINTS: vector<u8> = b"mpc_threshold_in_basis_points";
const KEY_MAX_FAULTY_IN_BASIS_POINTS: vector<u8> = b"mpc_max_faulty_in_basis_points";
const KEY_WEIGHT_REDUCTION_ALLOWED_DELTA: vector<u8> = b"mpc_weight_reduction_allowed_delta";
const KEY_NONCE_GENERATION_PROTOCOL: vector<u8> = b"mpc_nonce_generation_protocol";

// ~~~~~~~ Package Functions ~~~~~~~

/// Register the specs for the MPC parameter keys: epoch-pinned, range-checked,
/// non-removable (removal would silently revert nodes to the compiled defaults
/// at the next reconfig).
public(package) fun register_keys(registry: &mut ConfigRegistry) {
    registry.register(
        KEY_THRESHOLD_IN_BASIS_POINTS,
        config_registry::new_spec(
            true,
            true,
            false,
            option::some(1),
            option::some(MAX_BPS),
            option::none(),
        ),
    );
    registry.register(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_registry::new_spec(
            true,
            true,
            false,
            option::none(),
            option::some(MAX_BPS),
            option::none(),
        ),
    );
    registry.register(
        KEY_MAX_FAULTY_IN_BASIS_POINTS,
        config_registry::new_spec(
            true,
            true,
            false,
            option::none(),
            option::some(MAX_BPS),
            option::none(),
        ),
    );
    registry.register(
        KEY_NONCE_GENERATION_PROTOCOL,
        config_registry::new_spec(
            true,
            true,
            false,
            option::none(),
            option::some(1),
            option::none(),
        ),
    );
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
}

#[test_only]
/// Build a pinned MPC parameter store directly from explicit values, in the
/// canonical key order (matching `register_keys`). Used by tests that construct
/// committees without a full governed config.
public(package) fun new_for_testing(
    threshold_in_basis_points: u64,
    weight_reduction_allowed_delta: u64,
    max_faulty_in_basis_points: u64,
    nonce_generation_protocol: u64,
): Config {
    let mut mpc = config::empty();
    mpc.upsert(KEY_THRESHOLD_IN_BASIS_POINTS, config_value::new_u64(threshold_in_basis_points));
    mpc.upsert(
        KEY_WEIGHT_REDUCTION_ALLOWED_DELTA,
        config_value::new_u64(weight_reduction_allowed_delta),
    );
    mpc.upsert(KEY_MAX_FAULTY_IN_BASIS_POINTS, config_value::new_u64(max_faulty_in_basis_points));
    mpc.upsert(KEY_NONCE_GENERATION_PROTOCOL, config_value::new_u64(nonce_generation_protocol));
    mpc
}
