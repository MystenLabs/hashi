// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The capability-gated protocol version. Consensus-affecting node behavior
/// changes ride this single epoch-pinned value: binaries advertise the
/// versions they support via member capabilities, and `start_reconfig`
/// advances the version one step when enough weight verifiably supports it —
/// the fleet-coverage condition is enforced on-chain, never checked by hand.
///
/// The version is never set by proposal (`updatable: false`): governance
/// steers through the ceiling knob; the advance rule is the only writer.
module hashi::protocol_version;

use hashi::{config::Config, config_registry::{Self, ConfigRegistry}, config_value};

// ~~~~~~~ Constants ~~~~~~~

const KEY_PROTOCOL_VERSION: vector<u8> = b"hashi_protocol_version";
/// Governance brake on auto-advancement: the version never advances past the
/// ceiling. u64::MAX (the default) = advance whenever supported.
const KEY_CEILING: vector<u8> = b"hashi_protocol_version_ceiling";
/// Safety margin (bps of W) on top of the W - t support floor. Absorbs
/// advertisement staleness: a member that advertised support and then
/// restarted onto an older binary mid-epoch.
const KEY_BUFFER_BPS: vector<u8> = b"hashi_protocol_version_buffer_bps";

/// Reserved member-capability keys (stored in `MemberInfo.extra_fields`):
/// the inclusive range of protocol versions the member's binary supports.
const KEY_SUPPORTED_MIN: vector<u8> = b"supported_protocol_version_min";
const KEY_SUPPORTED_MAX: vector<u8> = b"supported_protocol_version_max";

const GENESIS_PROTOCOL_VERSION: u64 = 1;
// TODO(mainnet-genesis): confirm against the actual genesis weight
// distribution — sized to ~two top-weight members' advertisement staleness.
const DEFAULT_BUFFER_BPS: u64 = 500;
/// Keeps `W - t + buffer` attainable at sane thresholds.
const MAX_BUFFER_BPS: u64 = 2000;
const MAX_BPS: u64 = 10000;

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun init_defaults(config: &mut Config) {
    config.upsert(KEY_PROTOCOL_VERSION, config_value::new_u64(GENESIS_PROTOCOL_VERSION));
    config.upsert(KEY_CEILING, config_value::new_u64(std::u64::max_value!()));
    config.upsert(KEY_BUFFER_BPS, config_value::new_u64(DEFAULT_BUFFER_BPS));
}

/// Non-removable throughout: removing the version would drop nodes to binary
/// defaults (the coordination hazard this key exists to prevent); removing a
/// knob would silently flip advancement policy.
public(package) fun register_keys(registry: &mut ConfigRegistry) {
    registry.register(
        KEY_PROTOCOL_VERSION,
        config_registry::new_spec(true, false, false, option::none(), option::none(), option::none()),
    );
    registry.register(
        KEY_CEILING,
        config_registry::new_spec(false, true, false, option::none(), option::none(), option::none()),
    );
    registry.register(
        KEY_BUFFER_BPS,
        config_registry::new_spec(
            false,
            true,
            false,
            option::none(),
            option::some(MAX_BUFFER_BPS),
            option::none(),
        ),
    );
}

public(package) fun current(config: &Config): u64 {
    config.try_get(KEY_PROTOCOL_VERSION).map!(|v| v.as_u64()).destroy_or!(GENESIS_PROTOCOL_VERSION)
}

public(package) fun ceiling(config: &Config): u64 {
    config.try_get(KEY_CEILING).map!(|v| v.as_u64()).destroy_or!(std::u64::max_value!())
}

public(package) fun buffer_bps(config: &Config): u64 {
    config.try_get(KEY_BUFFER_BPS).map!(|v| v.as_u64()).destroy_or!(DEFAULT_BUFFER_BPS)
}

/// The advance rule is the only writer (the key's spec is non-updatable, so
/// governance proposals cannot reach it).
public(package) fun set(config: &mut Config, version: u64) {
    config.upsert(KEY_PROTOCOL_VERSION, config_value::new_u64(version));
}

/// Whether a member's advertised capability range covers `version`. Fail
/// closed: a missing or malformed advertisement supports nothing — an old
/// binary that never heard of capabilities must count as a holdout.
public(package) fun member_supports(capabilities: &Config, version: u64): bool {
    let max = capabilities.try_get(KEY_SUPPORTED_MAX);
    if (max.is_none()) return false;
    let max = max.destroy_some();
    if (!max.is_u64()) return false;
    if (max.as_u64() < version) return false;

    let min = capabilities.try_get(KEY_SUPPORTED_MIN);
    if (min.is_none()) return true;
    let min = min.destroy_some();
    if (!min.is_u64()) return false;
    min.as_u64() <= version
}

/// One-step, ceiling-capped advance: move to `current + 1` iff supporting
/// weight >= W - t + buffer. `W - t` is the safety floor — holdouts must stay
/// below `t` weight or they could keep signing under the old behavior next
/// epoch; the buffer absorbs advertisement staleness. If `buffer > t` the
/// required weight exceeds W and the rule simply never fires (safe).
public(package) fun next_version(
    current: u64,
    ceiling: u64,
    support_weight: u64,
    total_weight: u64,
    threshold_weight: u64,
    buffer_bps: u64,
): u64 {
    if (current == std::u64::max_value!()) return current;
    let candidate = current + 1;
    if (candidate > ceiling) return current;

    let buffer = (total_weight * buffer_bps).divide_and_round_up(MAX_BPS);
    let below_threshold = threshold_weight.min(total_weight);
    let required = total_weight - below_threshold + buffer;
    if (support_weight >= required) {
        candidate
    } else {
        current
    }
}
