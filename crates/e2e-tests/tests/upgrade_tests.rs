// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for the package upgrade lifecycle.
//!
//! Exercises real cascading effects of upgrading the hashi package:
//! - Rust watcher picks up the new package version via PackageUpgraded
//! - Validators auto-confirm deposits against the upgraded package
//! - Package ID routing updates correctly in OnchainState

use anyhow::Result;
use e2e_tests::TestNetworksBuilder;
use e2e_tests::test_helpers::create_deposit_and_wait;
use e2e_tests::test_helpers::get_hbtc_balance;
use e2e_tests::test_helpers::init_test_logging;
use e2e_tests::upgrade_flow;
use hashi::sui_tx_executor::SuiTxExecutor;
use std::collections::BTreeSet;
use std::time::Duration;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use tracing::info;

/// An exclusive upgrade binds the committee-approved policy to publication.
///
/// The builder first performs the unavoidable legacy v1 → v2 upgrade, with
/// `keep_v1_enabled` so BOTH versions stay enabled (the raw legacy-upgrade
/// outcome). This test then publishes v3 with
/// `exclusive = true` and verifies that the same transaction leaves only v3
/// enabled, retiring {1, 2} atomically. Because the test binary supports v1
/// and v2, it must halt autonomous writes afterward.
#[tokio::test]
async fn test_exclusive_upgrade_via_proposal() -> Result<()> {
    init_test_logging();
    let mut networks = TestNetworksBuilder::new()
        .with_nodes(4)
        .keep_v1_enabled()
        .build()
        .await?;

    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    let (current_version, current_package_id) = {
        let state = networks.hashi_network.nodes()[0]
            .hashi()
            .onchain_state()
            .state();
        let versions = state.package_versions();
        (
            versions
                .latest_version()
                .expect("default builder publishes package v2"),
            versions
                .latest_id()
                .expect("default builder publishes package v2"),
        )
    };
    assert_eq!(
        current_version, 2,
        "the upgraded-chain boot lands at package v2"
    );

    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks, true).await?;
    assert_ne!(new_package_id, current_package_id);
    upgrade_flow::wait_for_package_convergence(&networks, new_package_id, Duration::from_secs(30))
        .await?;

    let target_version = current_version + 1;
    for (i, node) in networks.hashi_network.nodes().iter().enumerate() {
        let onchain = node.hashi().onchain_state();
        let state = onchain.state();
        assert_eq!(
            state.package_versions().latest_version(),
            Some(target_version)
        );
        assert_eq!(state.package_versions().latest_id(), Some(new_package_id));
        assert_eq!(
            state.hashi().config.enabled_versions,
            BTreeSet::from([target_version]),
            "node {i}: exclusive publication must atomically retire every older version"
        );
        assert!(
            onchain.version_support().must_halt(),
            "node {i}: a v1+v2 binary must halt after exclusive v3 publication"
        );
    }

    info!("=== UPGRADE V2 EXCLUSIVE TEST PASSED ===");
    Ok(())
}

/// Explicit upgrade via governance proposal, exercising real cascading effects.
///
/// The builder's default boot already lands the chain at the current source
/// (fresh v1 auto-upgraded at build), so the upgrade driven *by this test*
/// goes one version further (vN -> vN+1) through the full proposal flow:
///
/// 1. Watcher picks up new package — PackageUpgraded updates OnchainState
/// 2. Validators confirm deposits post-upgrade — leader routes calls correctly
/// 3. Package ID routing — OnchainState.package_id() returns the new package
///
/// `keep_v1_enabled`: this test drives DisableVersion(1) itself after its
/// own vN -> vN+1 upgrade (a second disable would abort on-chain), and the
/// v1-rejection assertion needs v1 to still be enabled until that move.
#[tokio::test]
async fn test_upgrade_via_proposal() -> Result<()> {
    init_test_logging();
    let mut networks = TestNetworksBuilder::new()
        .with_nodes(4)
        .keep_v1_enabled()
        .build()
        .await?;

    let hashi_ids = networks.hashi_network.ids();
    info!("original package ID: {}", hashi_ids.package_id);

    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    // ── Pre-upgrade: deposit to establish state ─────────────────────────
    info!("depositing 100k sats before upgrade...");
    let hbtc_recipient = create_deposit_and_wait(&mut networks, 100_000).await?;
    let balance_before = get_hbtc_balance(
        &mut networks.sui_network.client,
        hashi_ids.package_id,
        hbtc_recipient,
    )
    .await?;
    assert_eq!(balance_before, 100_000);
    info!("pre-upgrade balance: {balance_before} sats");

    // ── Upgrade ─────────────────────────────────────────────────────────
    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks, false).await?;
    info!("upgraded to v2: {new_package_id}");
    assert_ne!(new_package_id, hashi_ids.package_id);

    // ── Cascading effect 1: Watcher picks up new package ────────────────
    upgrade_flow::wait_for_package_convergence(&networks, new_package_id, Duration::from_secs(30))
        .await?;

    // ── Cascading effect 2: Package ID routing ──────────────────────────
    //
    // Verify all nodes have the correct version map.
    for (i, node) in networks.hashi_network.nodes().iter().enumerate() {
        let versions = node
            .hashi()
            .onchain_state()
            .state()
            .package_versions()
            .versions()
            .clone();
        assert!(
            versions.len() >= 3,
            "node {i}: expected the auto-upgrade and this test's upgrade on \
             top of v1 (>= 3 package versions), got {}",
            versions.len()
        );
        info!("node {i}: package_versions = {versions:?}");
    }
    info!("all nodes correctly track the new package version");

    // ── Cascading effect 3: Validator deposit confirmation post-upgrade ──
    //
    // This is the real test: deposit BTC, submit a deposit request, and
    // wait for the validators to auto-confirm it. The leader must:
    // - Observe the DepositRequested
    // - Build a BLS certificate
    // - Call approve_deposit on the correct (upgraded) package
    // - After the time-delay window, call confirm_deposit
    //
    // If the watcher or leader has stale package routing, this will fail.
    info!("depositing 50k sats post-upgrade (full validator confirmation path)...");
    create_deposit_and_wait(&mut networks, 50_000).await?;
    let balance_after = get_hbtc_balance(
        &mut networks.sui_network.client,
        hashi_ids.package_id,
        hbtc_recipient,
    )
    .await?;
    assert_eq!(
        balance_after, 150_000,
        "post-upgrade deposit should be confirmed by validators"
    );
    info!("post-upgrade deposit confirmed by validators, balance: {balance_after}");

    // ── Bonus: v2-only canary module callable ───────────────────────────
    info!("calling v2-only upgrade_canary::version()...");
    let user_key = networks.sui_network.user_keys.first().unwrap();
    let hashi = networks.hashi_network.nodes()[0].hashi().clone();
    let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
        .with_signer(user_key.clone().into());

    let mut builder = TransactionBuilder::new();
    builder.move_call(
        Function::new(
            new_package_id,
            Identifier::from_static("upgrade_canary"),
            Identifier::from_static("version"),
        ),
        vec![],
    );
    let canary_resp = executor.execute(builder).await?;
    assert!(
        canary_resp.transaction().effects().status().success(),
        "v2-only canary module should be callable"
    );
    info!("v2 canary module call succeeded");

    // ── Disable v1, verify rejection ────────────────────────────────────
    let mut executors: Vec<SuiTxExecutor> = networks
        .hashi_network
        .nodes()
        .iter()
        .map(|node| SuiTxExecutor::from_config(&node.hashi().config, node.hashi().onchain_state()))
        .collect::<Result<_>>()?;

    let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
        &mut networks.sui_network.client.clone(),
        hashi_ids.hashi_object_id,
    )
    .await?;
    upgrade_flow::disable_version(&mut executors, hashi_ids, hashi_isv, 1, new_package_id).await?;
    info!("version 1 disabled");

    let mut builder = TransactionBuilder::new();
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let txid_arg = builder.pure(&Address::ZERO);
    let vout_arg = builder.pure(&0u32);
    let utxo_id = builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("utxo"),
            Identifier::from_static("utxo_id"),
        ),
        vec![txid_arg, vout_arg],
    );
    let amount_arg = builder.pure(&50_000u64);
    let derivation_arg = builder.pure(&Option::<Address>::None);
    let utxo = builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("utxo"),
            Identifier::from_static("utxo"),
        ),
        vec![utxo_id, amount_arg, derivation_arg],
    );
    let clock_arg = builder.object(
        ObjectInput::new(hashi::sui_tx_executor::SUI_CLOCK_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );
    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("deposit"),
            Identifier::from_static("deposit"),
        ),
        vec![hashi_arg, utxo, clock_arg],
    );

    let v1_result = executors[0].execute(builder).await;
    assert!(v1_result.is_err(), "v1 should be rejected after disable");
    let err_msg = v1_result.unwrap_err().to_string();
    // With v1 disabled the executor still submits (a later version is enabled,
    // published and supported, so it does not halt); the call targets the v1
    // package, whose `assert_version_enabled` aborts with EVersionDisabled. The
    // halt arm below covers a binary that supports no enabled version.
    assert!(
        err_msg.contains("EVersionDisabled")
            || err_msg.contains("assert_version_enabled")
            || err_msg.contains("supports no enabled on-chain package version"),
        "expected a version-disabled rejection, got: {err_msg}"
    );
    info!("v1 entry point correctly rejected");

    info!("=== UPGRADE TEST PASSED ===");
    Ok(())
}

/// The end-to-end governance upgrade test on a fresh chain.
///
/// Publishes the current source as v1 and runs the ordinary governance-gated
/// upgrade flow ([`upgrade_flow::execute_full_upgrade`]) to a const-patched
/// v2 of the same source. This proves — end to end, against a running Sui
/// net — that the published package can be upgraded through governance, a
/// strictly stronger claim than any static compatibility check.
///
/// Asserts:
/// - v1 publishes and forms a committee (DKG completes).
/// - a deposit confirms against v1, establishing real v1-initialized
///   on-chain state before the upgrade.
/// - the governance upgrade succeeds (effects success).
/// - the new package id differs from v1's.
/// - all nodes' watchers pick up the new package version.
/// - a post-upgrade deposit confirms through the full validator path, on top
///   of the state v1 initialized.
/// - a v2-only module (`upgrade_canary::version`) is callable post-upgrade.
#[tokio::test]
async fn fresh_v1_upgrades_via_governance() -> Result<()> {
    init_test_logging();

    // Default boot: fresh v1 from the current source, no auto-upgrade — the
    // pre-upgrade deposit runs against v1, and this test drives the upgrade.
    let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

    let hashi_ids = networks.hashi_network.ids();
    info!("fresh v1 package ID: {}", hashi_ids.package_id);

    // Committee must be formed (DKG done) before the upgrade proposal can be
    // voted through at the required 100% quorum.
    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    // ── Pre-upgrade: deposit against v1 ──────────────
    //
    // Establishes real on-chain state *initialized by v1* (UTXO pool entries, deposit records, hBTC supply), so the
    // post-upgrade assertions below exercise the upgraded package against
    // v1-created state — not a fresh object graph.
    info!("depositing 100k sats against v1...");
    let hbtc_recipient = create_deposit_and_wait(&mut networks, 100_000).await?;
    let balance_before = get_hbtc_balance(
        &mut networks.sui_network.client,
        hashi_ids.package_id,
        hbtc_recipient,
    )
    .await?;
    assert_eq!(balance_before, 100_000);
    info!("pre-upgrade balance: {balance_before} sats");

    // ── Upgrade the deployed bytecode to the current source ─────────────
    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks, false).await?;
    info!("upgraded fresh v1 -> patched source: new package {new_package_id}");
    assert_ne!(
        new_package_id, hashi_ids.package_id,
        "upgrade should mint a new package id"
    );

    // ── All nodes' watchers must pick up the new package version ─────────
    upgrade_flow::wait_for_package_convergence(&networks, new_package_id, Duration::from_secs(30))
        .await?;

    // ── Post-upgrade: deposit on top of v1-initialized state ────────────
    //
    // The full validator confirmation path (observe DepositRequested, build
    // the BLS certificate, approve, time-delay, confirm) must work against
    // the upgraded package operating on state v1 created.
    info!("depositing 50k sats post-upgrade (full validator confirmation path)...");
    create_deposit_and_wait(&mut networks, 50_000).await?;
    let balance_after = get_hbtc_balance(
        &mut networks.sui_network.client,
        hashi_ids.package_id,
        hbtc_recipient,
    )
    .await?;
    assert_eq!(
        balance_after, 150_000,
        "post-upgrade deposit should confirm on top of v1-initialized state"
    );
    info!("post-upgrade deposit confirmed, balance: {balance_after} sats");

    // ── v2-only canary module must be callable post-upgrade ─────────────
    //
    // `execute_full_upgrade` adds an `upgrade_canary` module to the patched
    // source; being callable proves the new code (not just a new object id)
    // is live on the upgraded package.
    info!("calling v2-only upgrade_canary::version()...");
    let user_key = networks.sui_network.user_keys.first().unwrap();
    let hashi = networks.hashi_network.nodes()[0].hashi().clone();
    let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
        .with_signer(user_key.clone().into());

    let mut builder = TransactionBuilder::new();
    builder.move_call(
        Function::new(
            new_package_id,
            Identifier::from_static("upgrade_canary"),
            Identifier::from_static("version"),
        ),
        vec![],
    );
    let canary_resp = executor.execute(builder).await?;
    assert!(
        canary_resp.transaction().effects().status().success(),
        "v2-only canary module should be callable after upgrading the deployed bytecode"
    );
    info!("v2 canary module call succeeded");

    info!("=== GOVERNANCE UPGRADE TEST PASSED ===");
    Ok(())
}
