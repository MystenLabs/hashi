// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Publish a checked-in Move *bytecode snapshot* into a local Sui network.
//!
//! Hashi keeps a checked-in bytecode snapshot of the deployed package
//! (`crates/hashi/tests/move_upgrade_snapshots/<network>/v<version>/`) so the
//! upgrade-compatibility CI gate can run hermetically. This module reuses that
//! same snapshot for a *stronger* test: publish the deployed v1 bytecode into a
//! fresh local net and then upgrade it to the current source, proving the real
//! "deployed bytecode → current source" upgrade end-to-end (not just the static
//! compatibility check).
//!
//! ## Mechanism
//!
//! 1. Read every `*.mv` in the snapshot directory.
//! 2. Rebase each module's self-address from the package's *runtime* id to
//!    `0x0`. This is the **inverse** of the compat test's
//!    `substitute_self_address`: the on-chain `module_map` (and thus the
//!    snapshot) stores modules self-addressed at the runtime id, while a fresh
//!    `publish` on Sui assigns a brand-new object id and expects the incoming
//!    modules to be self-addressed at `0x0` (what a source build of an
//!    upgradeable package emits).
//! 3. Re-serialize at each module's *original* binary version (via
//!    `serialize_with_version`, NOT `serialize()` — the latter forces
//!    `VERSION_MAX`, which could exceed what the local net accepts).
//! 4. Build a `Publish { modules, dependencies: [0x1, 0x2, 0x3] }` — the
//!    framework-only deps present on any local net, per the on-chain linkage
//!    table.
//! 5. Publish via the production `hashi::publish::publish_package` path, which
//!    also extracts the `Hashi` shared object + `UpgradeCap` — a strong signal
//!    the snapshot published as a real, init-run package.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use hashi::publish::PublishOutput;
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_sdk_types::Address;

/// Default snapshot directory, resolved relative to the `e2e-tests` crate:
/// `../hashi/tests/move_upgrade_snapshots/testnet/v1`. This is the same
/// snapshot the compat CI gate checks against.
pub fn default_snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("hashi")
        .join("tests")
        .join("move_upgrade_snapshots")
        .join("testnet")
        .join("v1")
}

/// The self-address a module declares in its bytecode.
fn module_self_address(module: &CompiledModule) -> Result<AccountAddress> {
    let idx = module.self_handle().address;
    module
        .address_identifiers
        .get(idx.0 as usize)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("module has an invalid self-address index"))
}

/// Rebase a module's self-address from `runtime` to `0x0`.
///
/// INVERSE of the compat test's `substitute_self_address` (which rebases
/// `0x0` → runtime for comparison). Here we go the other way because we are
/// *publishing* the snapshot as a brand-new package: the adapter assigns a
/// fresh object id and requires the incoming modules to be `0x0`-addressed.
fn rebase_runtime_to_zero(module: &mut CompiledModule, runtime: AccountAddress) -> Result<()> {
    let self_addr_idx = module.self_handle().address;
    let name = module.identifier_at(module.self_handle().name).to_string();

    let addr = module
        .address_identifiers
        .get_mut(self_addr_idx.0 as usize)
        .ok_or_else(|| anyhow::anyhow!("module `{name}` has an invalid self-address index"))?;

    anyhow::ensure!(
        *addr == runtime,
        "module `{name}` self-address is {addr}, expected snapshot runtime id {runtime}"
    );

    *addr = AccountAddress::ZERO;
    Ok(())
}

/// Read the snapshot's runtime package id.
///
/// Every snapshot module is self-addressed at the deployed package's
/// runtime/original id. We derive it from the first module's bytecode
/// (matching `MovePackage::original_package_id`) rather than trusting the
/// manifest, then assert every module agrees.
fn read_runtime_id(modules: &[CompiledModule]) -> Result<AccountAddress> {
    let runtime = module_self_address(
        modules
            .first()
            .ok_or_else(|| anyhow::anyhow!("snapshot has no modules"))?,
    )?;
    anyhow::ensure!(
        runtime != AccountAddress::ZERO,
        "snapshot modules unexpectedly carry a 0x0 self-address"
    );
    Ok(runtime)
}

/// Load every `*.mv` in `snapshot_dir`, rebase each module's self-address from
/// the runtime id to `0x0`, re-serialize at its original binary version, and
/// return a `Publish` payload with framework-only dependencies (`[0x1, 0x2,
/// 0x3]`) ready to hand to `hashi::publish::publish_package`.
pub fn load_snapshot_publish(snapshot_dir: &Path) -> Result<sui_sdk_types::Publish> {
    anyhow::ensure!(
        snapshot_dir.is_dir(),
        "snapshot dir missing: {}",
        snapshot_dir.display()
    );

    let mut mv_paths: Vec<PathBuf> = std::fs::read_dir(snapshot_dir)
        .with_context(|| format!("reading snapshot directory {}", snapshot_dir.display()))?
        .map(|e| e.map(|e| e.path()).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("mv"))
        .collect();
    mv_paths.sort();
    anyhow::ensure!(
        !mv_paths.is_empty(),
        "no .mv files in {}",
        snapshot_dir.display()
    );

    // Deserialize first so we can derive the runtime id from the bytecode.
    let mut modules: Vec<CompiledModule> = mv_paths
        .iter()
        .map(|path| {
            let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            CompiledModule::deserialize_with_defaults(&raw)
                .map_err(|e| anyhow::anyhow!("deserialize {}: {e:?}", path.display()))
        })
        .collect::<Result<_>>()?;

    let runtime = read_runtime_id(&modules)?;

    let mut serialized = Vec::with_capacity(modules.len());
    for module in &mut modules {
        rebase_runtime_to_zero(module, runtime)?;

        // Preserve the binary version the snapshot was serialized at (do NOT
        // bump to VERSION_MAX — that could exceed what the local net accepts).
        let version = module.version;
        let mut bytes = Vec::new();
        module
            .serialize_with_version(version, &mut bytes)
            .map_err(|e| anyhow::anyhow!("re-serialize module: {e:?}"))?;
        serialized.push(bytes);
    }

    // Dependencies = the sui framework, per the on-chain linkage table. These
    // three are present on any local net.
    let dependencies: Vec<Address> = vec![
        Address::from_static("0x1"),
        Address::from_static("0x2"),
        Address::from_static("0x3"),
    ];

    Ok(sui_sdk_types::Publish {
        modules: serialized,
        dependencies,
    })
}

/// Publish the bytecode snapshot at `snapshot_dir` as a fresh package, driven
/// by `private_key`. Mirrors [`crate::publish`] but sources the modules from a
/// checked-in bytecode snapshot instead of a source build.
///
/// Like the source-build path, the `UpgradeCap` is transferred to the sender
/// and left there until `hashi::finish_publish` (the launch switch) hands it
/// into on-chain custody — so the returned [`PublishOutput`] slots directly
/// into the normal genesis/launch sequencing.
pub async fn publish_snapshot(
    snapshot_dir: &Path,
    client: &mut Client,
    private_key: &Ed25519PrivateKey,
) -> Result<PublishOutput> {
    let publish = load_snapshot_publish(snapshot_dir)?;
    tracing::info!(
        modules = publish.modules.len(),
        dir = %snapshot_dir.display(),
        "publishing bytecode snapshot (runtime -> 0x0 rebased)"
    );
    hashi::publish::publish_package(client, &private_key.clone().into(), publish).await
}
