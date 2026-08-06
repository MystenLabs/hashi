// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Upgrade test infrastructure.
//!
//! Provides helpers to exercise the full governance-gated upgrade lifecycle:
//! programmatically patch the package source, build an upgrade, propose/vote/
//! execute the upgrade, publish the new bytecode, and finalize.

use anyhow::Result;
use hashi::cli::client::CreateProposalParams;
use hashi::cli::client::build_create_proposal_transaction;
use hashi::cli::client::build_vote_transaction;
use hashi::cli::upgrade::build_execute_proposal_transaction;
use hashi::cli::upgrade::build_upgrade_execution_transaction;
use hashi::cli::upgrade::build_upgrade_package;
use hashi::cli::upgrade::extract_new_package_id_from_response;
use hashi::cli::upgrade::extract_proposal_id_from_response;
use hashi::config::HashiIds;
use hashi::sui_tx_executor::SuiTxExecutor;
use std::path::Path;
use std::path::PathBuf;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;

use crate::TestNetworks;
use crate::sui_network::sui_binary;

/// Poll until every node's watcher reports `package_id` as the active
/// package — the PackageUpgraded handler in watcher.rs must update
/// OnchainState's package_versions map on all nodes. Prints per-node
/// diagnostics before failing on timeout.
pub async fn wait_for_package_convergence(
    networks: &TestNetworks,
    package_id: Address,
    max_wait: std::time::Duration,
) -> Result<()> {
    tracing::info!("waiting for all nodes to detect the new package version...");
    let wait_start = std::time::Instant::now();
    loop {
        let all_updated = networks
            .hashi_network
            .nodes()
            .iter()
            .all(|node| node.hashi().onchain_state().package_id() == Some(package_id));
        if all_updated {
            return Ok(());
        }
        if wait_start.elapsed() > max_wait {
            for (i, node) in networks.hashi_network.nodes().iter().enumerate() {
                let latest = node.hashi().onchain_state().package_id();
                let versions = node
                    .hashi()
                    .onchain_state()
                    .state()
                    .package_versions()
                    .clone();
                tracing::info!("node {i}: package_id={latest:?}, versions={versions:?}");
            }
            anyhow::bail!("timeout: not all nodes detected the new package version");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Prepare an upgrade package by copying the current source and patching it.
///
/// 1. Copies `<test_dir>/packages/hashi` to `<test_dir>/packages/hashi-upgrade`
/// 2. Sets `PACKAGE_VERSION` in `versioning.move` to `target_version`
///    (whatever the source currently declares — a no-op rewrite when the tree
///    already carries the target, a real bump when the chain has moved past it)
/// 3. Sets `published-at` in `Move.toml` to `published_at` — the chain's
///    LATEST published package id, which the upgrade ticket checks against
///
/// Returns the path to the patched package directory.
pub fn prepare_upgrade_package(
    test_dir: &Path,
    published_at: Address,
    target_version: u64,
) -> Result<PathBuf> {
    let src = test_dir.join("packages/hashi");
    let dst = test_dir.join("packages/hashi-upgrade");

    anyhow::ensure!(
        src.exists(),
        "source package not found at {}",
        src.display()
    );

    // Copy the package; the builder's auto-upgrade may have left a previous
    // copy behind, and `cp -r` into an existing directory would nest.
    let _ = std::fs::remove_dir_all(&dst);
    let output = std::process::Command::new("cp")
        .args(["-r", &src.to_string_lossy(), &dst.to_string_lossy()])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "failed to copy package: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Patch versioning.move: set PACKAGE_VERSION to the target version.
    let versioning_path = dst.join("sources/core/versioning.move");
    let versioning_src = std::fs::read_to_string(&versioning_path)?;
    const CONST_PREFIX: &str = "const PACKAGE_VERSION: u64 = ";
    let mut replaced = false;
    let patched: String = versioning_src
        .lines()
        .map(|line| {
            if line.starts_with(CONST_PREFIX) {
                replaced = true;
                format!("{CONST_PREFIX}{target_version};\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    anyhow::ensure!(
        replaced,
        "PACKAGE_VERSION constant not found in versioning.move"
    );
    std::fs::write(&versioning_path, patched)?;

    // Patch Move.toml: add published-at
    let move_toml_path = dst.join("Move.toml");
    let move_toml = std::fs::read_to_string(&move_toml_path)?;
    let patched_toml = move_toml.replace(
        "[package]",
        &format!("[package]\npublished-at = \"{}\"", published_at),
    );
    std::fs::write(&move_toml_path, patched_toml)?;

    // Add a trivial new-in-this-version module to prove new code is callable
    // post-upgrade. Re-added on every prepare so successive upgrades stay
    // module-compatible.
    let test_module_path = dst.join("sources/upgrade_canary.move");
    std::fs::write(
        &test_module_path,
        format!(
            "module hashi::upgrade_canary;\n\npublic fun version(): u64 {{ {target_version} }}\n"
        ),
    )?;

    // Clean build artifacts from the copy
    let _ = std::fs::remove_dir_all(dst.join("build"));

    tracing::info!(
        "upgrade package prepared at {} (published-at = {})",
        dst.display(),
        published_at
    );

    Ok(dst)
}

/// Run the full upgrade lifecycle: prepare → build → propose → vote → execute+publish+finalize.
///
/// Returns the new package ID on success.
pub async fn execute_full_upgrade(networks: &mut TestNetworks) -> Result<Address> {
    let nodes = networks.hashi_network.nodes();
    let hashi_ids = networks.hashi_network.ids();

    let mut executors: Vec<SuiTxExecutor> = nodes
        .iter()
        .map(|node| {
            let hashi = node.hashi();
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
        })
        .collect::<Result<_>>()?;

    // 1. Prepare the upgrade package (copy + patch), targeting one past the
    // chain's latest published version. `published-at` must name the LATEST
    // published package (not the original): upgrading v2 -> v3 with a
    // v1 `published-at` fails the upgrade ticket's package-id check.
    let (current_version, current_package_id) = {
        let state = nodes[0].hashi().onchain_state().state();
        let versions = state.package_versions();
        match (versions.latest_version(), versions.latest_id()) {
            (Some(version), Some(id)) => (version, id),
            _ => anyhow::bail!("onchain state has no package versions yet"),
        }
    };
    let target_version = current_version + 1;
    let test_dir = networks.dir();
    let upgrade_path = prepare_upgrade_package(test_dir, current_package_id, target_version)?;

    let client_config_path = test_dir.join("sui/client.yaml");
    let client_config = client_config_path
        .exists()
        .then_some(client_config_path.as_path());

    // 2. Build the upgrade
    tracing::info!("building upgrade package from {}", upgrade_path.display());
    let (compiled, digest) =
        build_upgrade_package(sui_binary(), &upgrade_path, client_config, target_version)?;
    tracing::info!("upgrade package built, digest: {digest:?}");

    // 3. Propose the upgrade
    tracing::info!("proposing upgrade...");
    let creator = executors[0].sender();
    let create_tx = build_create_proposal_transaction(
        hashi_ids,
        creator,
        CreateProposalParams::Upgrade {
            digest: digest.clone(),
            metadata: vec![("reason".to_string(), "upgrade test".to_string())],
        },
    );
    let response = executors[0].execute(create_tx).await?;
    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "create Upgrade proposal failed"
    );

    let proposal_id = extract_proposal_id_from_response(&response)?;
    tracing::info!("upgrade proposal {proposal_id} created");

    // 4. All other nodes vote (upgrade requires 100% quorum)
    let upgrade_type_tag = TypeTag::Struct(Box::new(StructTag::new(
        hashi_ids.package_id,
        Identifier::from_static("upgrade"),
        Identifier::from_static("Upgrade"),
        vec![],
    )));

    for executor in &mut executors[1..] {
        let voter = executor.sender();
        let vote_tx =
            build_vote_transaction(hashi_ids, voter, proposal_id, upgrade_type_tag.clone());
        let vote_resp = executor.execute(vote_tx).await?;
        anyhow::ensure!(
            vote_resp.transaction().effects().status().success(),
            "vote on Upgrade proposal failed"
        );
    }
    tracing::info!("all nodes voted on upgrade proposal");

    // 5. Execute upgrade + publish + finalize in one PTB
    tracing::info!("executing upgrade (execute + publish + finalize in one PTB)...");
    let upgrade_tx =
        build_upgrade_execution_transaction(hashi_ids, current_package_id, proposal_id, compiled);
    let upgrade_resp = executors[0].execute(upgrade_tx).await?;
    anyhow::ensure!(
        upgrade_resp.transaction().effects().status().success(),
        "upgrade execute+publish+finalize failed: {:?}",
        upgrade_resp.transaction().effects().status()
    );

    let new_package_id = extract_new_package_id_from_response(&upgrade_resp)?;
    tracing::info!("upgrade complete! new package: {new_package_id}");
    Ok(new_package_id)
}

/// Propose + vote + execute a DisableVersion governance action.
///
/// `execute_package_id` is the package whose `disable_version::execute` is called.
/// When disabling an old version after upgrade, this must be the NEW package ID
/// (whose `PACKAGE_VERSION` differs from the version being disabled).
pub async fn disable_version(
    executors: &mut [SuiTxExecutor],
    hashi_ids: HashiIds,
    version: u64,
    execute_package_id: Address,
) -> Result<()> {
    let creator = executors[0].sender();
    let create_tx = build_create_proposal_transaction(
        hashi_ids,
        creator,
        CreateProposalParams::DisableVersion {
            version,
            metadata: vec![],
        },
    );
    let response = executors[0].execute(create_tx).await?;
    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "create DisableVersion proposal failed"
    );

    let proposal_id = extract_proposal_id_from_response(&response)?;

    let disable_version_type = TypeTag::Struct(Box::new(StructTag::new(
        hashi_ids.package_id,
        Identifier::from_static("disable_version"),
        Identifier::from_static("DisableVersion"),
        vec![],
    )));

    for executor in &mut executors[1..] {
        let voter = executor.sender();
        let vote_tx =
            build_vote_transaction(hashi_ids, voter, proposal_id, disable_version_type.clone());
        let vote_resp = executor.execute(vote_tx).await?;
        anyhow::ensure!(
            vote_resp.transaction().effects().status().success(),
            "vote on DisableVersion proposal failed"
        );
    }

    let execute_tx = build_execute_proposal_transaction(
        hashi_ids,
        proposal_id,
        execute_package_id,
        "disable_version",
    )?;
    let exec_resp = executors[0].execute(execute_tx).await?;
    anyhow::ensure!(
        exec_resp.transaction().effects().status().success(),
        "execute DisableVersion proposal failed"
    );

    tracing::info!("version {version} disabled");
    Ok(())
}
