// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Reusable helpers for the package-upgrade governance flow.
//!
//! Covers the non-orchestrating pieces that both the CLI (`hashi proposal
//! create upgrade` + `proposal execute`) and the e2e test harness need:
//!
//! - Building an upgrade package via `sui move build`
//! - Constructing the `execute + publish + finalize` PTB
//! - Constructing the generic `execute` PTB for non-upgrade proposals
//! - Parsing the proposal ID out of a `ProposalCreatedEvent` in tx effects
//! - Finding the new package ID in the effects of an upgrade transaction
//!
//! Orchestration (collecting votes from committee members, driving the full
//! propose → vote → execute lifecycle end to end) still lives in the caller —
//! the e2e harness has all four validator keys so it can drive it
//! programmatically, while the CLI only has one operator key and drives it
//! one step at a time.

use crate::config::HashiIds;
use crate::sui_tx_executor::SUI_CLOCK_OBJECT_ID;
use anyhow::Result;
use anyhow::anyhow;
use std::path::Path;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::Publish;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

/// Relative path (from a package root) to the Move source file declaring the
/// `PACKAGE_VERSION` constant.
const PACKAGE_VERSION_SOURCE: &str = "sources/core/config/config.move";

/// Parse the `PACKAGE_VERSION` constant from `sources/core/config/config.move`
/// in a package source tree.
///
/// This is the version gate enforced by `config::assert_version_enabled`; it
/// must be bumped in every upgrade or the new package will reject all entry
/// points guarded by that check.
pub fn read_package_version(package_path: &Path) -> Result<u64> {
    let source_path = package_path.join(PACKAGE_VERSION_SOURCE);
    let source = std::fs::read_to_string(&source_path).map_err(|e| {
        anyhow!(
            "failed to read {} to parse PACKAGE_VERSION: {e}",
            source_path.display()
        )
    })?;

    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with("const PACKAGE_VERSION"))
        .ok_or_else(|| {
            anyhow!(
                "PACKAGE_VERSION declaration not found in {}",
                source_path.display()
            )
        })?;

    let rhs = line
        .split_once('=')
        .and_then(|(_, rhs)| rhs.split(';').next())
        .ok_or_else(|| anyhow!("malformed PACKAGE_VERSION line: {line:?}"))?
        .trim();

    rhs.parse::<u64>()
        .map_err(|e| anyhow!("PACKAGE_VERSION value {rhs:?} is not a u64: {e}"))
}

/// Build an upgrade package by invoking `sui move build --dump-bytecode-as-base64`
/// and parsing the resulting JSON.
///
/// `sui_binary` is the path (or PATH-resolvable name) of the `sui` executable
/// to shell out to. `package_path` is the directory containing `Move.toml`.
/// `client_config` is passed as `--client.config` when supplied, otherwise the
/// `sui` binary's default client config is used.
///
/// Runs a pre-flight check that the package declares `PACKAGE_VERSION ==
/// expected_version`, failing before shelling out if the constant wasn't
/// bumped. Callers typically pass `current_highest_version + 1`.
///
/// Returns the compiled `Publish` (modules + dependencies) plus the package
/// digest — the latter is what goes into the `Upgrade` proposal.
pub fn build_upgrade_package(
    sui_binary: &Path,
    package_path: &Path,
    client_config: Option<&Path>,
    expected_version: u64,
) -> Result<(Publish, Vec<u8>)> {
    let declared_version = read_package_version(package_path)?;
    anyhow::ensure!(
        declared_version == expected_version,
        "upgrade package declares PACKAGE_VERSION = {declared_version}, expected {expected_version} \
         (must be exactly +1 of the currently published version)"
    );

    let mut cmd = std::process::Command::new(sui_binary);
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
        Publish {
            modules,
            dependencies: build_output.dependencies,
        },
        digest,
    ))
}

/// Build the PTB that executes an `Upgrade` proposal in a single transaction:
/// `upgrade::execute` → `builder.upgrade(...)` → `upgrade::finalize_upgrade`.
///
/// The three steps must be in one PTB so the `UpgradeTicket` and
/// `UpgradeReceipt` hot potatoes can be consumed without leaving the
/// transaction.
pub fn build_upgrade_execution_transaction(
    hashi_ids: HashiIds,
    proposal_id: Address,
    compiled: Publish,
) -> TransactionBuilder {
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

    // Step C: finalize_upgrade — takes the receipt and swaps the package in-place.
    // Needs a second mutable reference to the hashi object since the first one
    // was consumed by `upgrade::execute`.
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

    builder
}

/// Build the PTB that executes a non-upgrade proposal (UpdateConfig,
/// EnableVersion, DisableVersion, EmergencyPause).
///
/// Calls `<execute_package_id>::<proposal_module>::execute(hashi, proposal_id, clock)`.
///
/// `execute_package_id` is almost always `hashi_ids.package_id`, but may
/// differ when disabling an old version after an upgrade: the `execute` call
/// has to go through the NEW package (whose `PACKAGE_VERSION` differs from
/// the version being disabled), not through the stored original
/// `hashi_ids.package_id`.
pub fn build_execute_proposal_transaction(
    hashi_ids: HashiIds,
    proposal_id: Address,
    execute_package_id: Address,
    proposal_module: &str,
) -> Result<TransactionBuilder> {
    let module = Identifier::new(proposal_module)
        .map_err(|e| anyhow!("invalid proposal module {proposal_module:?}: {e}"))?;

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
            module,
            Identifier::from_static("execute"),
        ),
        vec![hashi_arg, proposal_id_arg, clock_arg],
    );

    Ok(builder)
}

/// Extract the newly-created proposal's object ID from a transaction that
/// called `<module>::propose(...)`. Looks for a single `ProposalCreatedEvent`
/// in the transaction's emitted events.
///
/// The BCS payload of the event is `(proposal_id, timestamp_ms)`; we only
/// return the proposal ID here.
pub fn extract_proposal_id_from_response(response: &ExecuteTransactionResponse) -> Result<Address> {
    let event = response
        .transaction()
        .events()
        .events()
        .iter()
        .find(|e| e.contents().name().contains("ProposalCreatedEvent"))
        .ok_or_else(|| anyhow!("ProposalCreatedEvent not found in transaction effects"))?;

    let (id, _ts): (Address, u64) = bcs::from_bytes(event.contents().value())
        .map_err(|e| anyhow!("failed to deserialize ProposalCreatedEvent payload: {e}"))?;
    Ok(id)
}

pub fn extract_proposal_ids_from_response(
    response: &ExecuteTransactionResponse,
) -> Result<Vec<Address>> {
    let ids: Vec<Address> = response
        .transaction()
        .events()
        .events()
        .iter()
        .filter(|e| e.contents().name().contains("ProposalCreatedEvent"))
        .map(|e| {
            let (id, _ts): (Address, u64) = bcs::from_bytes(e.contents().value())
                .map_err(|e| anyhow!("failed to deserialize ProposalCreatedEvent payload: {e}"))?;
            Ok(id)
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        !ids.is_empty(),
        "ProposalCreatedEvent not found in transaction effects"
    );
    Ok(ids)
}

/// Extract the new package ID from the effects of a successful upgrade
/// transaction. The upgrade PTB creates exactly one `package` changed object.
pub fn extract_new_package_id_from_response(
    response: &ExecuteTransactionResponse,
) -> Result<Address> {
    response
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == "package")
        .ok_or_else(|| anyhow!("new package not found in upgrade effects"))?
        .object_id()
        .parse::<Address>()
        .map_err(|e| anyhow!("failed to parse new package ID: {e}"))
}
