// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module hashi::finish_publish_tests;

use hashi::{hashi::{Self, Hashi}, test_utils};
use sui::coin_registry;

const PUBLISHER: address = @0x1;

fun guardian_btc_public_key(): vector<u8> {
    vector::tabulate!(32, |i| (i as u8))
}

fun registry_for_testing(): coin_registry::CoinRegistry {
    // The registry constructor asserts a system-address sender.
    let ctx = &mut test_utils::new_tx_context(@0x0, 0);
    coin_registry::create_coin_data_registry_for_testing(ctx)
}

#[test]
fun test_finish_publish_stores_upgrade_cap() {
    let ctx = &mut test_utils::new_tx_context(PUBLISHER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[PUBLISHER], ctx);
    let mut registry = registry_for_testing();
    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    let cap = sui::package::test_publish(this_package_id, ctx);

    hashi.finish_publish_for_testing(
        cap,
        @0xb17c,
        b"http://guardian.example:3000".to_string(),
        guardian_btc_public_key(),
        &mut registry,
        ctx,
    );

    assert!(hashi.versioning().has_upgrade_cap());
    std::unit_test::destroy(hashi);
    std::unit_test::destroy(registry);
}

#[test]
/// The launch emits exactly one LaunchCompleted carrying the pinned
/// guardian config; node watchers refresh their config snapshot on it.
fun test_finish_publish_emits_launch_completed() {
    let ctx = &mut test_utils::new_tx_context(PUBLISHER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[PUBLISHER], ctx);
    let mut registry = registry_for_testing();
    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    let cap = sui::package::test_publish(this_package_id, ctx);

    hashi.finish_publish_for_testing(
        cap,
        @0xb17c,
        b"http://guardian.example:3000".to_string(),
        guardian_btc_public_key(),
        &mut registry,
        ctx,
    );

    let events = sui::event::events_by_type<hashi::LaunchCompleted>();
    assert!(events.length() == 1);
    let (url, btc_key) = hashi::launch_completed_fields(&events[0]);
    assert!(url == b"http://guardian.example:3000".to_string());
    assert!(btc_key == guardian_btc_public_key());

    std::unit_test::destroy(hashi);
    std::unit_test::destroy(registry);
}

#[test]
#[expected_failure(abort_code = hashi::EWrongUpgradeCap)]
fun test_finish_publish_rejects_wrong_cap() {
    let ctx = &mut test_utils::new_tx_context(PUBLISHER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[PUBLISHER], ctx);
    let mut registry = registry_for_testing();
    let cap = sui::package::test_publish(@0xdead.to_id(), ctx);

    hashi.finish_publish_for_testing(
        cap,
        @0xb17c,
        b"http://guardian.example:3000".to_string(),
        guardian_btc_public_key(),
        &mut registry,
        ctx,
    );

    std::unit_test::destroy(hashi);
    std::unit_test::destroy(registry);
}

#[test]
// The second call aborts inside `set_upgrade_cap` (option::fill on an
// already-filled slot), making the launch call-once.
#[expected_failure]
fun test_finish_publish_twice_aborts() {
    let ctx = &mut test_utils::new_tx_context(PUBLISHER, 0);
    let mut hashi = test_utils::create_hashi_with_committee(vector[PUBLISHER], ctx);
    let mut registry = registry_for_testing();
    let this_package_id = std::type_name::original_id<Hashi>().to_id();

    hashi.finish_publish_for_testing(
        sui::package::test_publish(this_package_id, ctx),
        @0xb17c,
        b"http://guardian.example:3000".to_string(),
        guardian_btc_public_key(),
        &mut registry,
        ctx,
    );
    hashi.finish_publish_for_testing(
        sui::package::test_publish(this_package_id, ctx),
        @0xb17c,
        b"http://guardian.example:3000".to_string(),
        guardian_btc_public_key(),
        &mut registry,
        ctx,
    );

    std::unit_test::destroy(hashi);
    std::unit_test::destroy(registry);
}
