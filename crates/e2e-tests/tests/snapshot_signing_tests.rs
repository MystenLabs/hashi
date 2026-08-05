// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Signing lifecycle against the deployed **v1 bytecode snapshot**.
//!
//! Boots a local net by publishing the checked-in deployed testnet package
//! bytecode as v1 (via [`TestNetworksBuilder::with_v1_from_snapshot`]) and then
//! drives a full deposit → withdrawal cycle. The withdrawal forces the
//! committee to generate presignatures and threshold-sign a Bitcoin
//! transaction end to end.
//!
//! Why this is distinct from the source-built withdrawal e2e (`e2e_flow`):
//! every other harness publishes the *current* `packages/hashi` source, so the
//! binary always runs against a package built from the same tree. This test
//! runs the current binary against the **actually-deployed** (older) Move
//! bytecode — the real rollout-window configuration, where the node binary is
//! rolled out before the on-chain package is upgraded. A full withdrawal here
//! proves that configuration can still sign.
//!
//! With the version-gated stamped nonce-cert path in place, a v1-only snapshot
//! chain is exactly the *bare* cert path (`supports_stamped_nonce_certs() ==
//! false`, timestamps synthesized to `0`) that no fresh-publish harness
//! exercises, and the assertion below pins this test to it.

use anyhow::Result;
use e2e_tests::TestNetworksBuilder;
use e2e_tests::snapshot;
use e2e_tests::test_helpers::create_deposit_and_wait;
use e2e_tests::test_helpers::create_withdrawal_and_wait;
use e2e_tests::test_helpers::get_hbtc_balance;
use e2e_tests::test_helpers::init_test_logging;
use std::time::Duration;
use tracing::info;

/// Deposit then withdraw on a chain published from the deployed v1 bytecode
/// snapshot, proving the committee generates presignatures and threshold-signs
/// a withdrawal end-to-end against the deployed (pre-upgrade) package.
///
/// Asserts:
/// - the snapshot chain is a single-version (v1) package — no upgrade has run,
///   so signing happens against the deployed bytecode;
/// - a deposit credits hBTC;
/// - a withdrawal reaches `WithdrawalConfirmed` and burns the hBTC — i.e. the
///   presig + signing path completed, not merely that a request was accepted.
#[tokio::test]
async fn snapshot_v1_signs_withdrawal_end_to_end() -> Result<()> {
    init_test_logging();

    // v1 = the checked-in deployed bytecode snapshot, not a source build.
    let mut networks = TestNetworksBuilder::new()
        .with_nodes(4)
        .with_v1_from_snapshot(snapshot::default_snapshot_dir()?)
        .build()
        .await?;

    let hashi_ids = networks.hashi_network.ids();
    info!("snapshot-published v1 package ID: {}", hashi_ids.package_id);

    // Committee/DKG must complete before anything can be signed.
    networks.hashi_network.nodes()[0]
        .wait_for_mpc_key(Duration::from_secs(120))
        .await?;

    // The snapshot chain is a single-version v1 package (no upgrade has run),
    // so the committee signs against the deployed bytecode.
    let node0 = networks.hashi_network.nodes()[0].hashi().clone();
    assert_eq!(
        node0
            .onchain_state()
            .state()
            .package_versions()
            .versions()
            .len(),
        1,
        "snapshot chain should be a single-version (v1) package before any upgrade"
    );
    assert!(
        !node0.onchain_state().supports_stamped_nonce_certs(),
        "a v1-only snapshot chain must not enable the stamped nonce-cert ABI"
    );

    // ── Deposit ─────────────────────────────────────────────────────────
    let deposit_sats = 100_000u64;
    let hbtc_recipient = create_deposit_and_wait(&mut networks, deposit_sats).await?;
    assert_eq!(
        get_hbtc_balance(
            &mut networks.sui_network.client,
            hashi_ids.package_id,
            hbtc_recipient,
        )
        .await?,
        deposit_sats,
        "pre-withdrawal deposit should have credited hBTC",
    );

    // ── Withdraw — forces presig generation + threshold signing ──────────
    let withdrawal_sats = 30_000u64;
    let confirmed = create_withdrawal_and_wait(&mut networks, withdrawal_sats).await?;
    info!(
        "withdrawal confirmed on Sui against deployed v1: txid={}",
        confirmed.txid
    );

    assert_eq!(
        get_hbtc_balance(
            &mut networks.sui_network.client,
            hashi_ids.package_id,
            hbtc_recipient,
        )
        .await?,
        deposit_sats - withdrawal_sats,
        "withdrawal did not complete (hBTC not burned) against the deployed v1 package",
    );

    info!("=== V1 SNAPSHOT SIGNING TEST PASSED ===");
    Ok(())
}
