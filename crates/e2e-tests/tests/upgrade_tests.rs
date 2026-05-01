// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for the package upgrade lifecycle.
//!
//! Exercises real cascading effects of upgrading the hashi package:
//! - Rust watcher picks up the new package version via PackageUpgradedEvent
//! - Validators auto-confirm deposits against the upgraded package
//! - Package ID routing updates correctly in OnchainState

use anyhow::Result;
use e2e_tests::TestNetworksBuilder;
use e2e_tests::test_helpers::create_deposit_and_wait;
use e2e_tests::test_helpers::get_hbtc_balance;
use e2e_tests::test_helpers::init_test_logging;
use e2e_tests::upgrade_flow;
use hashi::sui_tx_executor::SuiTxExecutor;
use std::time::Duration;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use tracing::info;

/// Test the full upgrade lifecycle, exercising real cascading effects.
///
/// 1. Watcher picks up new package — PackageUpgradedEvent updates OnchainState
/// 2. Validators confirm deposits post-upgrade — leader routes calls correctly
/// 3. Package ID routing — OnchainState.package_id() returns the new package
#[tokio::test]
async fn test_upgrade_v1_to_v2() -> Result<()> {
    init_test_logging();
    let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

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
    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks).await?;
    info!("upgraded to v2: {new_package_id}");
    assert_ne!(new_package_id, hashi_ids.package_id);

    // ── Cascading effect 1: Watcher picks up new package ────────────────
    //
    // The PackageUpgradedEvent handler in watcher.rs should update
    // OnchainState's package_versions map. Poll until all nodes see the
    // new package — this proves the watcher correctly processes the event.
    info!("waiting for all nodes to detect the new package version...");
    let wait_start = std::time::Instant::now();
    let max_wait = Duration::from_secs(30);
    loop {
        let all_updated = networks
            .hashi_network
            .nodes()
            .iter()
            .all(|node| node.hashi().onchain_state().package_id() == Some(new_package_id));
        if all_updated {
            break;
        }
        if wait_start.elapsed() > max_wait {
            // Print diagnostic info before failing
            for (i, node) in networks.hashi_network.nodes().iter().enumerate() {
                let latest = node.hashi().onchain_state().package_id();
                let versions = node
                    .hashi()
                    .onchain_state()
                    .state()
                    .package_versions()
                    .clone();
                info!("node {i}: package_id={latest:?}, versions={versions:?}");
            }
            anyhow::bail!("timeout: not all nodes detected the new package version");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Cascading effect 2: Package ID routing ──────────────────────────
    //
    // Verify all nodes have the correct version map.
    for (i, node) in networks.hashi_network.nodes().iter().enumerate() {
        let versions = node
            .hashi()
            .onchain_state()
            .state()
            .package_versions()
            .clone();
        assert!(
            versions.len() >= 2,
            "node {i}: should have at least 2 package versions, got {}",
            versions.len()
        );
        info!("node {i}: package_versions = {versions:?}");
    }
    info!("all nodes correctly track the new package version");

    // ── Cascading effect 3: Validator deposit confirmation post-upgrade ──
    //
    // This is the real test: deposit BTC, submit a deposit request, and
    // wait for the validators to auto-confirm it. The leader must:
    // - Observe the DepositRequestedEvent
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
        .with_signer(user_key.clone());

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

    upgrade_flow::disable_version(&mut executors, hashi_ids, 1, new_package_id).await?;
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
    assert!(
        err_msg.contains("EVersionDisabled") || err_msg.contains("assert_version_enabled"),
        "expected EVersionDisabled, got: {err_msg}"
    );
    info!("v1 entry point correctly rejected");

    info!("=== UPGRADE TEST PASSED ===");
    Ok(())
}
