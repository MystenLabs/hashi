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
use hashi::config::HashiIds;
use hashi::sui_tx_executor::SUI_CLOCK_OBJECT_ID;
use hashi::sui_tx_executor::SuiTxExecutor;
use std::path::Path;
use std::path::PathBuf;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

use crate::TestNetworks;
use crate::sui_network::sui_binary;

/// Prepare an upgrade package by copying the deployed source and patching it.
///
/// 1. Copies `<test_dir>/packages/hashi` to `<test_dir>/packages/hashi-upgrade`
/// 2. Bumps `PACKAGE_VERSION` from 1 to 2 in `config.move`
/// 3. Sets `published-at` in `Move.toml` to the original package ID
///
/// Returns the path to the patched package directory.
pub fn prepare_upgrade_package(test_dir: &Path, original_package_id: Address) -> Result<PathBuf> {
    let src = test_dir.join("packages/hashi");
    let dst = test_dir.join("packages/hashi-upgrade");

    anyhow::ensure!(
        src.exists(),
        "source package not found at {}",
        src.display()
    );

    // Copy the package
    let output = std::process::Command::new("cp")
        .args(["-r", &src.to_string_lossy(), &dst.to_string_lossy()])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "failed to copy package: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Patch config.move: bump PACKAGE_VERSION from 1 to 2
    let config_path = dst.join("sources/core/config/config.move");
    let config_src = std::fs::read_to_string(&config_path)?;
    let patched = config_src.replace(
        "const PACKAGE_VERSION: u64 = 1;",
        "const PACKAGE_VERSION: u64 = 2;",
    );
    anyhow::ensure!(
        patched != config_src,
        "PACKAGE_VERSION replacement failed — pattern not found in config.move"
    );
    std::fs::write(&config_path, patched)?;

    // Patch Move.toml: add published-at
    let move_toml_path = dst.join("Move.toml");
    let move_toml = std::fs::read_to_string(&move_toml_path)?;
    let patched_toml = move_toml.replace(
        "[package]",
        &format!("[package]\npublished-at = \"{}\"", original_package_id),
    );
    std::fs::write(&move_toml_path, patched_toml)?;

    // Add a trivial v2-only module to prove new code is callable post-upgrade
    let test_module_path = dst.join("sources/upgrade_canary.move");
    std::fs::write(
        &test_module_path,
        "module hashi::upgrade_canary;\n\npublic fun version(): u64 { 2 }\n",
    )?;

    // Clean build artifacts from the copy
    let _ = std::fs::remove_dir_all(dst.join("build"));

    tracing::info!(
        "upgrade package prepared at {} (published-at = {})",
        dst.display(),
        original_package_id
    );

    Ok(dst)
}

/// Build the upgraded package and return the compiled modules + digest.
pub fn build_upgrade_package(
    package_path: &Path,
    client_config: Option<&Path>,
) -> Result<(sui_sdk_types::Publish, Vec<u8>)> {
    let mut cmd = std::process::Command::new(sui_binary());
    cmd.arg("move");

    if let Some(config) = client_config {
        cmd.arg("--client.config").arg(config);
    }

    cmd.arg("-p")
        .arg(package_path)
        .arg("build")
        .arg("-e")
        .arg("testnet")
        .arg("--dump-bytecode-as-base64");

    let output = cmd.output()?;
    anyhow::ensure!(
        output.status.success(),
        "sui move build failed:\nstdout: {}\nstderr: {}",
        output.stdout.escape_ascii(),
        output.stderr.escape_ascii()
    );

    #[derive(serde::Deserialize)]
    struct MoveBuildOutput {
        modules: Vec<String>,
        dependencies: Vec<Address>,
        digest: Vec<u8>,
    }

    let build_output: MoveBuildOutput = serde_json::from_slice(&output.stdout)?;
    let digest = build_output.digest.clone();
    let modules = build_output
        .modules
        .into_iter()
        .map(|b64| <base64ct::Base64 as base64ct::Encoding>::decode_vec(&b64))
        .collect::<Result<Vec<_>, _>>()?;

    Ok((
        sui_sdk_types::Publish {
            modules,
            dependencies: build_output.dependencies,
        },
        digest,
    ))
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

    // 1. Prepare the upgrade package (copy + patch)
    let test_dir = networks.dir();
    let upgrade_path = prepare_upgrade_package(test_dir, hashi_ids.package_id)?;

    let client_config_path = test_dir.join("sui/client.yaml");
    let client_config = client_config_path
        .exists()
        .then_some(client_config_path.as_path());

    // 2. Build the upgrade
    tracing::info!("building upgrade package from {}", upgrade_path.display());
    let (compiled, digest) = build_upgrade_package(&upgrade_path, client_config)?;
    tracing::info!("upgrade package built, digest: {digest:?}");

    // 3. Propose the upgrade
    tracing::info!("proposing upgrade...");
    let create_tx = build_create_proposal_transaction(
        hashi_ids,
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

    let proposal_id = response
        .transaction()
        .events()
        .events()
        .iter()
        .find(|e| e.contents().name().contains("ProposalCreatedEvent"))
        .ok_or_else(|| anyhow::anyhow!("ProposalCreatedEvent not found"))
        .and_then(|e| {
            let (id, _ts): (Address, u64) = bcs::from_bytes(e.contents().value())?;
            Ok(id)
        })?;
    tracing::info!("upgrade proposal {proposal_id} created");

    // 4. All other nodes vote (upgrade requires 100% quorum)
    let upgrade_type_tag = TypeTag::Struct(Box::new(StructTag::new(
        hashi_ids.package_id,
        Identifier::from_static("upgrade"),
        Identifier::from_static("Upgrade"),
        vec![],
    )));

    for executor in &mut executors[1..] {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("vote"),
            )
            .with_type_args(vec![upgrade_type_tag.clone()]),
            vec![hashi_arg, proposal_id_arg, clock_arg],
        );
        let vote_resp = executor.execute(builder).await?;
        anyhow::ensure!(
            vote_resp.transaction().effects().status().success(),
            "vote on Upgrade proposal failed"
        );
    }
    tracing::info!("all nodes voted on upgrade proposal");

    // 5. Execute upgrade + publish + finalize in one PTB
    tracing::info!("executing upgrade (execute + publish + finalize in one PTB)...");
    let mut builder = TransactionBuilder::new();
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let proposal_id_arg = builder.pure(&proposal_id);
    let clock_arg = builder.object(
        ObjectInput::new(SUI_CLOCK_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );

    // Step A: upgrade::execute → UpgradeTicket
    let ticket = builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("upgrade"),
            Identifier::from_static("execute"),
        ),
        vec![hashi_arg, proposal_id_arg, clock_arg],
    );

    // Step B: publish upgrade → UpgradeReceipt
    let receipt = builder.upgrade(
        compiled.modules,
        compiled.dependencies,
        hashi_ids.package_id,
        ticket,
    );

    // Step C: finalize_upgrade
    let hashi_arg2 = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("upgrade"),
            Identifier::from_static("finalize_upgrade"),
        ),
        vec![hashi_arg2, receipt],
    );

    let upgrade_resp = executors[0].execute(builder).await?;
    anyhow::ensure!(
        upgrade_resp.transaction().effects().status().success(),
        "upgrade execute+publish+finalize failed: {:?}",
        upgrade_resp.transaction().effects().status()
    );

    let new_package_id = upgrade_resp
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == "package")
        .ok_or_else(|| anyhow::anyhow!("new package not found in upgrade effects"))?
        .object_id()
        .parse::<Address>()?;

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
    let create_tx = build_create_proposal_transaction(
        hashi_ids,
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

    let proposal_id = response
        .transaction()
        .events()
        .events()
        .iter()
        .find(|e| e.contents().name().contains("ProposalCreatedEvent"))
        .ok_or_else(|| anyhow::anyhow!("ProposalCreatedEvent not found"))
        .and_then(|e| {
            let (id, _ts): (Address, u64) = bcs::from_bytes(e.contents().value())?;
            Ok(id)
        })?;

    let disable_version_type = TypeTag::Struct(Box::new(StructTag::new(
        hashi_ids.package_id,
        Identifier::from_static("disable_version"),
        Identifier::from_static("DisableVersion"),
        vec![],
    )));

    for executor in &mut executors[1..] {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("vote"),
            )
            .with_type_args(vec![disable_version_type.clone()]),
            vec![hashi_arg, proposal_id_arg, clock_arg],
        );
        let vote_resp = executor.execute(builder).await?;
        anyhow::ensure!(
            vote_resp.transaction().effects().status().success(),
            "vote on DisableVersion proposal failed"
        );
    }

    let mut builder = TransactionBuilder::new();
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let proposal_id_arg = builder.pure(&proposal_id);
    let clock_arg = builder.object(
        ObjectInput::new(SUI_CLOCK_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );
    builder.move_call(
        Function::new(
            execute_package_id,
            Identifier::from_static("disable_version"),
            Identifier::from_static("execute"),
        ),
        vec![hashi_arg, proposal_id_arg, clock_arg],
    );
    let exec_resp = executors[0].execute(builder).await?;
    anyhow::ensure!(
        exec_resp.transaction().effects().status().success(),
        "execute DisableVersion proposal failed"
    );

    tracing::info!("version {version} disabled");
    Ok(())
}
