// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for the package upgrade lifecycle.
//!
//! Exercises real cascading effects of upgrading the hashi package:
//! - Rust watcher picks up the new package version via PackageUpgraded
//! - Validators auto-confirm deposits against the upgraded package
//! - Package ID routing updates correctly in OnchainState

use anyhow::Result;
use anyhow::anyhow;
use e2e_tests::TestNetworksBuilder;
use e2e_tests::snapshot;
use e2e_tests::test_helpers::BackgroundMiner;
use e2e_tests::test_helpers::create_deposit_and_wait;
use e2e_tests::test_helpers::extract_witness_program;
use e2e_tests::test_helpers::get_hbtc_balance;
use e2e_tests::test_helpers::init_test_logging;
use e2e_tests::test_helpers::subscribe_withdrawal_confirmations;
use e2e_tests::upgrade_flow;
use hashi::sui_tx_executor::SuiTxExecutor;
use hashi_types::move_types::WithdrawalStatus;
use std::collections::BTreeSet;
use std::time::Duration;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use tracing::info;

/// The Sui framework package (`0x2`), for consuming the `Balance<BTC>` a
/// direct `cancel_withdrawal` call would return via `coin::from_balance`.
const SUI_FRAMEWORK_ADDRESS: Address = Address::from_static("0x2");

/// Upgrade v2 binds the committee-approved exclusivity policy to publication.
///
/// The default builder first performs the unavoidable legacy v1 → v2 upgrade.
/// This test then publishes v3 through `upgrade_v2` with `exclusive = true`
/// and verifies that the same transaction leaves only v3 enabled. Because the
/// test binary supports v1 and v2, it must halt autonomous writes afterward.
#[tokio::test]
async fn test_upgrade_v2_exclusive_via_proposal() -> Result<()> {
    init_test_logging();
    let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

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
    assert_eq!(current_version, 2, "upgrade_v2 is introduced in package v2");

    let new_package_id = upgrade_flow::execute_full_upgrade_v2(&mut networks, true).await?;
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
/// (snapshot v1 auto-upgraded at build), so the upgrade driven *by this test*
/// goes one version further (vN -> vN+1) through the full proposal flow:
///
/// 1. Watcher picks up new package — PackageUpgraded updates OnchainState
/// 2. Validators confirm deposits post-upgrade — leader routes calls correctly
/// 3. Package ID routing — OnchainState.package_id() returns the new package
#[tokio::test]
async fn test_upgrade_via_proposal() -> Result<()> {
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

/// The real "deployed bytecode → current source" upgrade test.
///
/// Bootstraps the local net by publishing the checked-in **bytecode snapshot**
/// of the deployed testnet package as v1 (via
/// [`TestNetworksBuilder::with_v1_from_snapshot`]), then runs the ordinary
/// governance-gated upgrade flow ([`upgrade_flow::execute_full_upgrade`]) to
/// upgrade it to the current `packages/hashi` source. This proves — end to
/// end, against a running Sui net — that the deployed bytecode can actually be
/// upgraded to what's in the tree today, a strictly stronger claim than the
/// static compatibility gate (which only normalizes-and-diffs the modules).
///
/// Asserts:
/// - v1 publishes from the snapshot and forms a committee (DKG completes).
/// - a deposit confirms against the snapshot bytecode, establishing real
///   v1-initialized on-chain state before the upgrade.
/// - the governance upgrade to current source succeeds (effects success).
/// - the new package id differs from v1's.
/// - all nodes' watchers pick up the new package version.
/// - a post-upgrade deposit confirms through the full validator path, on top
///   of the state the snapshot bytecode initialized.
/// - a v2-only module (`upgrade_canary::version`) is callable post-upgrade.
#[tokio::test]
async fn snapshot_v1_upgrades_to_current_source() -> Result<()> {
    init_test_logging();

    // v1 = the checked-in deployed bytecode snapshot, NOT a source build.
    // `without_upgrade` so the pre-upgrade deposit really runs against the
    // deployed bytecode; this test drives the upgrade itself.
    let mut networks = TestNetworksBuilder::new()
        .with_nodes(4)
        .with_v1_from_snapshot(snapshot::default_snapshot_dir()?)
        .without_upgrade()
        .build()
        .await?;

    let hashi_ids = networks.hashi_network.ids();
    info!("snapshot-published v1 package ID: {}", hashi_ids.package_id);

    // Committee must be formed (DKG done) before the upgrade proposal can be
    // voted through at the required 100% quorum.
    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    // ── Pre-upgrade: deposit against the snapshot bytecode ──────────────
    //
    // Establishes real on-chain state *initialized by the deployed v1
    // bytecode* (UTXO pool entries, deposit records, hBTC supply), so the
    // post-upgrade assertions below exercise the upgraded package against
    // v1-created state — not a fresh object graph.
    info!("depositing 100k sats against the snapshot bytecode...");
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
    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks).await?;
    info!("upgraded snapshot v1 -> current source: new package {new_package_id}");
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
    // the upgraded package operating on state the snapshot bytecode created.
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
        "post-upgrade deposit should confirm on top of snapshot-initialized state"
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

    info!("=== SNAPSHOT UPGRADE TEST PASSED ===");
    Ok(())
}

/// A withdrawal committed and fully signed under the deployed **v1 bytecode**
/// must complete after the governance upgrade to the current source:
/// confirmation runs through the v2 `confirm_withdrawal` (which defers
/// archival), and the leader's archival GC — armed by the confirm and
/// version-gated on active >= 2 — then drains it.
///
/// This is the mid-flight rollout window the deferred-archival change has to
/// survive: v1's commit moved the requests into the unmirrored `processed`
/// bag, so the upgraded package confirms and archives a transaction whose
/// requests never sat in the v2 hot-bag layout. The final assertion is that
/// nothing wedges — signing/confirm completes and both hot-bag mirrors drain
/// to empty on every node.
///
/// Parking the withdrawal fully-signed-but-unconfirmed needs no
/// block-withholding machinery: commit and signing are driven purely by Sui
/// checkpoints, while confirmation additionally requires the signed Bitcoin
/// transaction to be mined — so simply not mining regtest blocks holds the
/// flow at fully-signed under v1 (the same seam the signature-chunking tests
/// use to observe `WithdrawalSigned` before starting their miner).
#[tokio::test]
async fn test_withdrawal_committed_under_v1_completes_after_upgrade() -> Result<()> {
    init_test_logging();

    // v1 = the checked-in deployed bytecode snapshot; no auto-upgrade — this
    // test drives the upgrade itself, mid-withdrawal.
    let mut networks = TestNetworksBuilder::new()
        .with_nodes(4)
        .with_v1_from_snapshot(snapshot::default_snapshot_dir()?)
        .without_upgrade()
        .build()
        .await?;

    let hashi_ids = networks.hashi_network.ids();
    info!("snapshot-published v1 package ID: {}", hashi_ids.package_id);

    // Committee/DKG must complete before anything can be signed (and before
    // the upgrade proposal can pass at its 100% quorum).
    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    // ── Deposit under v1 ────────────────────────────────────────────────
    let deposit_sats = 100_000u64;
    let hbtc_recipient = create_deposit_and_wait(&mut networks, deposit_sats).await?;

    // ── Withdrawal: commit + full signing under v1, confirmation withheld ──
    let node0 = networks.hashi_network.nodes()[0].hashi().clone();
    let user_key = networks.sui_network.user_keys.first().unwrap().clone();
    let withdrawal_sats = 30_000u64;
    let btc_destination = networks.bitcoin_node.get_new_address()?;
    let destination_bytes = extract_witness_program(&btc_destination)?;

    let mut executor = SuiTxExecutor::from_config(&node0.config, node0.onchain_state())?
        .with_signer(user_key.into());
    let withdrawal_request_id = executor
        .execute_create_withdrawal_request(withdrawal_sats, destination_bytes)
        .await?;
    info!("withdrawal request created under v1: {withdrawal_request_id}");

    // With no regtest blocks being mined the flow parks at
    // fully-signed-but-unconfirmed: presig generation, MPC signing, and the
    // guardian finalize all complete (Sui-driven), the signed Bitcoin tx is
    // broadcast, but the leader cannot observe it mined and so cannot
    // confirm.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        if node0
            .onchain_state()
            .withdrawal_txns()
            .iter()
            .any(|txn| txn.is_fully_signed() && !txn.is_confirmed())
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for the withdrawal to fully sign under the v1 bytecode"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Still a single-version chain: commit + signing really ran under v1.
    assert_eq!(
        node0
            .onchain_state()
            .state()
            .package_versions()
            .versions()
            .len(),
        1,
        "the withdrawal must be committed and fully signed before any upgrade"
    );
    info!("withdrawal fully signed under v1 (unconfirmed; no regtest blocks mined)");

    // ── Governance upgrade to the current source, mid-withdrawal ────────
    let new_package_id = upgrade_flow::execute_full_upgrade(&mut networks).await?;
    assert_ne!(
        new_package_id, hashi_ids.package_id,
        "upgrade should mint a new package id"
    );
    upgrade_flow::wait_for_package_convergence(&networks, new_package_id, Duration::from_secs(30))
        .await?;
    info!("upgraded mid-withdrawal: new package {new_package_id}");

    // ── Complete the flow under v2: confirm, then archival GC ───────────
    //
    // Subscribe before the miner starts: the parked withdrawal cannot
    // confirm until its Bitcoin tx is mined, so the subscription provably
    // precedes the event.
    let confirmations =
        subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;
    let miner = BackgroundMiner::start(&networks.bitcoin_node);
    let confirmed = confirmations
        .wait_for(withdrawal_request_id, Duration::from_secs(300))
        .await?;
    drop(miner);
    info!(
        "v1-committed withdrawal confirmed via the v2 package: txid={}",
        confirmed.txid
    );

    // The hBTC actually burned — the withdrawal completed, not merely landed.
    assert_eq!(
        get_hbtc_balance(
            &mut networks.sui_network.client,
            hashi_ids.package_id,
            hbtc_recipient,
        )
        .await?,
        deposit_sats - withdrawal_sats,
        "withdrawal committed under v1 should burn hBTC once confirmed under v2"
    );

    // The v2 confirm left the txn in the hot bag with
    // `confirmed_timestamp_ms` set; the archival GC must now move it to
    // `confirmed_txns`. The v1-committed requests lived in the unmirrored
    // `processed` bag since commit time, and the archive bags are unmirrored
    // too — so completion is observable exactly as both hot-bag mirrors
    // draining to empty on every node, and nothing may wedge on the
    // cross-version state.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let laggard =
            networks
                .hashi_network
                .nodes()
                .iter()
                .enumerate()
                .find_map(|(index, node)| {
                    let state = node.hashi().onchain_state();
                    let txns = state.withdrawal_txns().len();
                    let requests = state.withdrawal_requests().len();
                    (txns > 0 || requests > 0).then_some((index, txns, requests))
                });
        let Some((index, txns, requests)) = laggard else {
            break;
        };
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "node {index}'s mirror still shows {txns} withdrawal txn(s) and {requests} \
                 request(s) after the post-upgrade archival window"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    info!("withdrawal_txns and withdrawal_requests empty on every node");

    info!("=== V1-COMMITTED WITHDRAWAL COMPLETES AFTER UPGRADE TEST PASSED ===");
    Ok(())
}

/// Assert that a direct v1 entry call failed at the v1 version gate — the
/// `EVersionDisabled` abort raised by `versioning::assert_version_enabled`,
/// located in the v1 package — and not merely that it failed. The gate is the
/// first statement of both v1 entries, so the abort provably fires before any
/// argument-semantic check could.
fn assert_version_gate_abort<T>(result: Result<T>, v1_package_id: Address, what: &str) {
    let err = match result {
        Ok(_) => panic!("{what} against a v2-committed request must abort at the version gate"),
        Err(err) => err,
    };
    let err_msg = err.to_string();
    info!("{what} rejected: {err_msg}");
    assert!(
        err_msg.contains("EVersionDisabled") || err_msg.contains("assert_version_enabled"),
        "{what}: expected the EVersionDisabled abort from versioning::assert_version_enabled, \
         got: {err_msg}"
    );
    let v1_hex = v1_package_id.to_string();
    let v1_hex = v1_hex.trim_start_matches("0x");
    assert!(
        err_msg.contains(v1_hex),
        "{what}: the abort must locate in the v1 package {v1_package_id}, got: {err_msg}"
    );
}

/// Direct v1 entries against a v2-committed request must abort at the gate.
///
/// The deferred-archival commit (v2) flips the request to `Processing` *in
/// place*: it stays in the hot `requests` bag with its balance drained. The
/// deployed v1 bytecode predates that layout — its `cancel_withdrawal` guard
/// (`is_request_processing`, per the bytecode snapshot) only consults the
/// `processed` bag v1 itself moved requests into at commit time. Aimed at a
/// v2-committed request the v1 guard passes, and with v1 still enabled the
/// entry would destroy the request and mint a refund out of a balance the
/// in-flight WithdrawalTransaction already drained; v1's `approve_request`
/// (replaying a cert) would similarly reset the committed request to
/// `Approved` for a second commit. `DisableVersion(1)` is what closes this
/// hazard: both entries assert the version gate as their first statement.
///
/// This test pins that closure by calling the deployed v1 bytecode directly
/// at its package id, against a live v2-committed withdrawal:
/// - v1 `withdraw::cancel_withdrawal` (as the requester, return consumed via
///   `coin::from_balance` at BTC's defining v1 address) aborts EVersionDisabled
/// - v1 `withdraw::approve_request` (garbage cert; the gate precedes cert
///   verification) aborts EVersionDisabled
/// - the request is untouched afterwards, and the normal v2 flow then
///   confirms and archives it on every node.
#[tokio::test]
async fn test_v1_entries_abort_against_v2_committed_request() -> Result<()> {
    init_test_logging();

    // Standard boot: the deployed-v1 snapshot auto-upgraded to the current
    // source. Both versions stay enabled — disabling v1 is this test's move.
    let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;
    let hashi_ids = networks.hashi_network.ids();

    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    let node0 = networks.hashi_network.nodes()[0].hashi().clone();
    let (v1_package_id, active_package_id) = {
        let state = node0.onchain_state().state();
        let versions = state.package_versions();
        assert_eq!(
            versions.latest_version(),
            Some(2),
            "default boot lands the chain at package v2"
        );
        assert!(
            state.hashi().config.enabled_versions.contains(&1),
            "the boot upgrade must leave v1 enabled; disabling it is this test's move"
        );
        (
            versions.get(1).expect("v1 must be in the version map"),
            versions.latest_id().expect("v2 must be in the version map"),
        )
    };
    assert_eq!(
        v1_package_id, hashi_ids.package_id,
        "v1 is the original package"
    );
    assert_ne!(v1_package_id, active_package_id);

    // ── Deposit, then drive a withdrawal to committed-under-v2 ──────────
    let deposit_sats = 100_000u64;
    let withdrawal_sats = 30_000u64;
    let hbtc_recipient = create_deposit_and_wait(&mut networks, deposit_sats).await?;

    let user_key = networks.sui_network.user_keys.first().unwrap().clone();
    let btc_destination = networks.bitcoin_node.get_new_address()?;
    let destination_bytes = extract_witness_program(&btc_destination)?;
    let mut user_executor = SuiTxExecutor::from_config(&node0.config, node0.onchain_state())?
        .with_signer(user_key.into());
    let requester = user_executor.sender();
    let withdrawal_request_id = user_executor
        .execute_create_withdrawal_request(withdrawal_sats, destination_bytes)
        .await?;
    info!("withdrawal request created: {withdrawal_request_id}");

    // Committed under v2 = the in-place status flip to Processing with the
    // balance drained, still in the hot `requests` bag — which is exactly
    // what the mirror covers (a v1-style commit would instead have moved the
    // request into the unmirrored `processed` bag).
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let committed = loop {
        if let Some(request) = node0
            .onchain_state()
            .withdrawal_request(&withdrawal_request_id)
            && request.status == WithdrawalStatus::Processing
        {
            break request;
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for the withdrawal to commit under v2"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(
        committed.btc, 0,
        "the v2 commit must drain the request's balance in place"
    );
    assert!(
        committed.withdrawal_txn_id.is_some(),
        "a committed request must reference its withdrawal transaction"
    );
    info!("withdrawal committed under v2 (Processing, balance drained, still in `requests`)");

    // ── DisableVersion(1) via governance ────────────────────────────────
    let mut executors: Vec<SuiTxExecutor> = networks
        .hashi_network
        .nodes()
        .iter()
        .map(|node| SuiTxExecutor::from_config(&node.hashi().config, node.hashi().onchain_state()))
        .collect::<Result<_>>()?;
    upgrade_flow::disable_version(&mut executors, hashi_ids, 1, active_package_id).await?;

    // Every watcher must converge on v1-disabled; the proposal execution is
    // checkpointed, so the fullnode state the direct v1 calls run against
    // already has it.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let converged = networks.hashi_network.nodes().iter().all(|node| {
            let state = node.hashi().onchain_state().state();
            !state.hashi().config.enabled_versions.contains(&1)
        });
        if converged {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for the watchers to reflect DisableVersion(1)"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    info!("version 1 disabled");

    // ── Direct v1 `withdraw::cancel_withdrawal` on the committed id ─────
    //
    // Deployed v1 signature (from the bytecode snapshot):
    //   public fun cancel_withdrawal(&mut Hashi, address, &Clock, &mut TxContext): Balance<BTC>
    // A `public fun` return must be consumed, so the PTB wraps it through
    // `coin::from_balance` and transfers the coin to the sender — with BTC
    // addressed at its DEFINING package, v1 (type identity survives
    // upgrades). The version gate aborts in command 0, before any of that.
    let mut builder = TransactionBuilder::new();
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let request_id_arg = builder.pure(&withdrawal_request_id);
    let clock_arg = builder.object(
        ObjectInput::new(hashi::sui_tx_executor::SUI_CLOCK_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );
    let refund = builder.move_call(
        Function::new(
            v1_package_id,
            Identifier::from_static("withdraw"),
            Identifier::from_static("cancel_withdrawal"),
        ),
        vec![hashi_arg, request_id_arg, clock_arg],
    );
    let btc_type = TypeTag::Struct(Box::new(StructTag::new(
        v1_package_id,
        Identifier::from_static("btc"),
        Identifier::from_static("BTC"),
        vec![],
    )));
    let refund_coin = builder.move_call(
        Function::new(
            SUI_FRAMEWORK_ADDRESS,
            Identifier::from_static("coin"),
            Identifier::from_static("from_balance"),
        )
        .with_type_args(vec![btc_type]),
        vec![refund],
    );
    let recipient_arg = builder.pure(&requester);
    builder.transfer_objects(vec![refund_coin], recipient_arg);

    let cancel_result = user_executor.execute(builder).await;
    assert_version_gate_abort(cancel_result, v1_package_id, "v1 cancel_withdrawal");

    // ── Direct v1 `withdraw::approve_request` with a garbage cert ───────
    //
    // Deployed v1 signature:
    //   entry fun approve_request(&mut Hashi, address, CommitteeSignature, &Clock)
    // The gate is asserted before certificate verification, and v1's
    // `committee::new_committee_signature` is a bare struct pack (verified in
    // the disassembly), so dummy contents construct fine and the abort can
    // only come from the gate.
    let mut builder = TransactionBuilder::new();
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let request_id_arg = builder.pure(&withdrawal_request_id);
    let epoch_arg = builder.pure(&0u64);
    let signature_arg = builder.pure(&vec![0u8; 96]);
    let bitmap_arg = builder.pure(&vec![0xffu8]);
    let cert_arg = builder.move_call(
        Function::new(
            v1_package_id,
            Identifier::from_static("committee"),
            Identifier::from_static("new_committee_signature"),
        ),
        vec![epoch_arg, signature_arg, bitmap_arg],
    );
    let clock_arg = builder.object(
        ObjectInput::new(hashi::sui_tx_executor::SUI_CLOCK_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );
    builder.move_call(
        Function::new(
            v1_package_id,
            Identifier::from_static("withdraw"),
            Identifier::from_static("approve_request"),
        ),
        vec![hashi_arg, request_id_arg, cert_arg, clock_arg],
    );

    let approve_result = user_executor.execute(builder).await;
    assert_version_gate_abort(approve_result, v1_package_id, "v1 approve_request");

    // ── The aborted v1 calls changed nothing ────────────────────────────
    //
    // Signing continues in the background, so the status may legitimately
    // have advanced Processing -> Signed; what the v1 entries would have
    // left behind — a vanished, refunded request (cancel) or a reset to
    // Approved (approve) — must not have happened.
    let after = node0
        .onchain_state()
        .withdrawal_request(&withdrawal_request_id)
        .expect("the v2-committed request must still sit in the `requests` bag");
    assert_eq!(
        after.btc, 0,
        "the drained balance must not have been refunded"
    );
    assert!(
        matches!(
            after.status,
            WithdrawalStatus::Processing | WithdrawalStatus::Signed
        ),
        "the request must still be committed, got {:?}",
        after.status
    );
    info!(
        "request intact after the aborted v1 calls (status {:?})",
        after.status
    );

    // ── And the normal v2 flow finishes on top of it ────────────────────
    //
    // Subscribe before the miner starts so the confirmation event cannot be
    // missed, then let confirm + the archival GC drain both hot-bag mirrors
    // on every node — proving the v1 attempts left nothing to wedge on.
    let confirmations =
        subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;
    let miner = BackgroundMiner::start(&networks.bitcoin_node);
    let confirmed = confirmations
        .wait_for(withdrawal_request_id, Duration::from_secs(300))
        .await?;
    drop(miner);
    info!("withdrawal confirmed under v2: txid={}", confirmed.txid);

    assert_eq!(
        get_hbtc_balance(
            &mut networks.sui_network.client,
            hashi_ids.package_id,
            hbtc_recipient,
        )
        .await?,
        deposit_sats - withdrawal_sats,
        "the confirmed withdrawal should burn exactly the withdrawn hBTC"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let laggard =
            networks
                .hashi_network
                .nodes()
                .iter()
                .enumerate()
                .find_map(|(index, node)| {
                    let state = node.hashi().onchain_state();
                    let txns = state.withdrawal_txns().len();
                    let requests = state.withdrawal_requests().len();
                    (txns > 0 || requests > 0).then_some((index, txns, requests))
                });
        let Some((index, txns, requests)) = laggard else {
            break;
        };
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "node {index}'s mirror still shows {txns} withdrawal txn(s) and {requests} \
                 request(s) after the archival window"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    info!("withdrawal_txns and withdrawal_requests empty on every node");

    info!("=== V1 ENTRIES ABORT AGAINST V2-COMMITTED REQUEST TEST PASSED ===");
    Ok(())
}
