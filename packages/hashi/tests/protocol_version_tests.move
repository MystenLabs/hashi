// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::protocol_version_tests;

use hashi::{config_value, protocol_version, test_utils};
use sui::vec_map;

const VOTER1: address = @0x1;
const OTHER: address = @0x2;
const FRESH: address = @0x9;

// W = 10000, t = 3334 (default bps on equal weights), buffer 500:
// required = 10000 - 3334 + 500 = 7166.
const W: u64 = 10000;
const T: u64 = 3334;
const BUFFER_BPS: u64 = 500;

#[test]
fun test_next_version_advances_exactly_at_required_weight() {
    let required = W - T + 500;
    assert!(
        protocol_version::next_version(1, std::u64::max_value!(), required, W, T, BUFFER_BPS) == 2,
    );
    assert!(
        protocol_version::next_version(
            1,
            std::u64::max_value!(),
            required - 1,
            W,
            T,
            BUFFER_BPS,
        ) == 1,
    );
}

#[test]
fun test_next_version_buffer_rounds_up() {
    // W = 999, buffer 500 bps => ceil(999 * 500 / 10000) = 50 (not 49).
    let w = 999;
    let t = 333;
    let required = w - t + 50;
    assert!(protocol_version::next_version(1, std::u64::max_value!(), required, w, t, 500) == 2);
    assert!(
        protocol_version::next_version(1, std::u64::max_value!(), required - 1, w, t, 500) == 1,
    );
}

#[test]
fun test_next_version_respects_ceiling() {
    assert!(protocol_version::next_version(1, 1, W, W, T, 0) == 1);
    assert!(protocol_version::next_version(1, 2, W, W, T, 0) == 2);
}

#[test]
fun test_next_version_never_fires_when_buffer_exceeds_threshold() {
    // t weight below the buffer: required > W, unreachable even at full support.
    assert!(protocol_version::next_version(1, std::u64::max_value!(), W, W, 100, 2000) == 1);
}

#[test]
fun test_next_version_guards_max_current() {
    let max = std::u64::max_value!();
    assert!(protocol_version::next_version(max, max, W, W, T, 0) == max);
}

#[test]
fun test_member_supports_fail_closed() {
    let mut capabilities = hashi::config::empty();
    // No advertisement at all: holdout.
    assert!(!protocol_version::member_supports(&capabilities, 2));

    // Malformed max (wrong type): holdout.
    capabilities.upsert(b"supported_protocol_version_max", config_value::new_bool(true));
    assert!(!protocol_version::member_supports(&capabilities, 2));

    // Well-formed max below the version: holdout.
    capabilities.upsert(b"supported_protocol_version_max", config_value::new_u64(1));
    assert!(!protocol_version::member_supports(&capabilities, 2));

    // Covering range: support (absent min counts from genesis).
    capabilities.upsert(b"supported_protocol_version_max", config_value::new_u64(3));
    assert!(protocol_version::member_supports(&capabilities, 2));

    // Min above the version: holdout.
    capabilities.upsert(b"supported_protocol_version_min", config_value::new_u64(3));
    assert!(!protocol_version::member_supports(&capabilities, 2));
    capabilities.upsert(b"supported_protocol_version_min", config_value::new_u64(2));
    assert!(protocol_version::member_supports(&capabilities, 2));
}

#[test]
fun test_update_capabilities_stores_advertisement() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.committee_set_mut().add_bare_member_for_testing(FRESH);

    let mut capabilities = vec_map::empty();
    capabilities.insert(
        b"supported_protocol_version_max".to_string(),
        config_value::new_u64(2),
    );
    let fresh_ctx = &mut test_utils::new_tx_context(FRESH, 0);
    hashi::validator::update_capabilities(&mut hashi, FRESH, capabilities, fresh_ctx);

    let stored = hashi.committee_set().member_capabilities_for_testing(FRESH);
    assert!(protocol_version::member_supports(stored, 2));
    assert!(!protocol_version::member_supports(stored, 3));

    std::unit_test::destroy(hashi);
}

#[test]
#[expected_failure]
fun test_update_capabilities_rejects_unauthorized_sender() {
    let ctx = &mut test_utils::new_tx_context(VOTER1, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[VOTER1], ctx);
    hashi.committee_set_mut().add_bare_member_for_testing(FRESH);

    let other_ctx = &mut test_utils::new_tx_context(OTHER, 0);
    hashi::validator::update_capabilities(&mut hashi, FRESH, vec_map::empty(), other_ctx);

    std::unit_test::destroy(hashi);
}
