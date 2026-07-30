// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Move package upgrade-compatibility gate.
//!
//! Hashi's Move package is deployed & governed on-chain via an `UpgradeCap`
//! that is custodied inside a shared object. That means `sui client upgrade`'s
//! built-in compatibility check (which needs a wallet-held cap) is *not*
//! available to us. Instead this test reproduces the exact check the Sui
//! validator runs when it processes an `Upgrade` command with the default
//! (`Compatible`) upgrade policy: it normalizes the old and new modules and
//! runs `move_binary_format::compatibility::Compatibility::upgrade_check()`
//! per module. See
//! `sui-execution/latest/sui-adapter/.../execution.rs::check_compatibility`
//! (`UpgradePolicy::Compatible` arm) for the authoritative implementation this
//! mirrors.
//!
//! ## What runs where
//!
//! * [`synthetic_incompatible_change_is_rejected`] and
//!   [`synthetic_identical_module_is_compatible`] are pure, network-free unit
//!   tests. They prove the compat machinery actually *catches* a break (and
//!   passes an identical module) using synthetic `CompiledModule`s. These run
//!   in every `cargo test` invocation, locally and in CI.
//!
//! * [`current_source_is_compatible_upgrade_of_deployed`] is the real gate. It
//!   builds `packages/hashi` and fetches the live deployed package's bytecode
//!   from a Sui fullnode, then asserts the current source is a compatible
//!   upgrade. It needs (a) the `sui` binary on PATH / `SUI_BINARY`, and (b)
//!   network access to a fullnode. It self-skips (prints and returns `Ok`)
//!   when the build tool is missing so a purely offline `cargo test` doesn't
//!   spuriously fail; in CI both prerequisites are present so it runs for real.
//!
//! ## Configuration (env vars)
//!
//! * `HASHI_COMPAT_RPC_URL` — fullnode gRPC URL. Defaults to Sui testnet.
//! * `HASHI_COMPAT_PACKAGE_ID` — deployed package id to check against.
//!   Defaults to the live testnet package.
//! * `HASHI_COMPAT_ENV` — Move build environment (`-e`). Defaults to `testnet`
//!   so the build links the same framework dependency versions the deployed
//!   package was built against.
//! * `SUI_BINARY` — path to the `sui` CLI (default `sui`).
//!
//! ## Addressing
//!
//! A source build of an upgradeable package emits modules addressed at `0x0`,
//! while the on-chain `module_map` (what both the validator's compat check and
//! the RPC `GetPackage` see) is addressed at the package's runtime/original id.
//! We rebase the built modules onto the on-chain address before comparing —
//! exactly what the Sui adapter does via `substitute_package_id` right before
//! `check_compatibility`.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use move_binary_format::CompiledModule;
use move_binary_format::compatibility::Compatibility;
use move_binary_format::normalized;
use move_core_types::account_address::AccountAddress;

/// Live Hashi package on Sui **testnet** (v1).
const DEFAULT_TESTNET_PACKAGE_ID: &str =
    "0xfcea10cadbb553c4874201584abf68771592678952efd957b2e82c010c7f4360";

// TODO(mainnet): once Hashi is deployed to mainnet, add the mainnet package id
// here and default (or add a matrix entry) to check against it as well. Until
// then the gate only guards the testnet deployment.
//
// const DEFAULT_MAINNET_PACKAGE_ID: &str = "0x…";

/// Default fullnode gRPC endpoint. `fullnode.testnet.sui.io` has been observed
/// to have TLS issues from some local clients but works fine from CI runners;
/// override with `HASHI_COMPAT_RPC_URL` if needed.
const DEFAULT_RPC_URL: &str = "https://fullnode.testnet.sui.io:443";

/// Default Move build environment (selects the `[env]`/published-at address).
const DEFAULT_BUILD_ENV: &str = "testnet";

/// Normalize a `CompiledModule` into the representation the compatibility
/// checker consumes. `include_code = true` matches what the on-chain adapter
/// uses (`check_compatibility(..)` passes `include code = true`).
fn normalize(pool: &mut normalized::RcPool, module: &CompiledModule) -> normalized::Module<normalized::RcIdentifier> {
    normalized::Module::new(pool, module, /* include_code */ true)
}

/// The self-address a module declares in its bytecode.
fn module_self_address(module: &CompiledModule) -> AccountAddress {
    let idx = module.self_handle().address;
    module.address_identifiers[idx.0 as usize]
}

/// Rebase a freshly-built module's self-address (`0x0`) to `new_address`.
///
/// A source build of an upgradeable package produces modules addressed at
/// `0x0`. The on-chain `module_map` (what the validator's compat check reads,
/// and what the RPC `GetPackage` returns) stores modules addressed at the
/// package's *runtime* / original id. The Sui adapter reconciles the two by
/// calling `substitute_package_id(&mut modules, runtime_id)` on the incoming
/// modules *before* running `check_compatibility`. We reproduce that exactly so
/// the per-module `ModuleId` (address + name) lines up — otherwise every module
/// would be spuriously flagged as an id mismatch. See
/// `sui-execution/latest/sui-adapter/src/adapter.rs::substitute_package_id`.
fn substitute_self_address(module: &mut CompiledModule, new_address: AccountAddress) -> Result<()> {
    let self_addr_idx = module.self_handle().address;
    let name = module.identifier_at(module.self_handle().name).to_string();

    let addr = module
        .address_identifiers
        .get_mut(self_addr_idx.0 as usize)
        .ok_or_else(|| anyhow::anyhow!("module `{name}` has an invalid self-address index"))?;

    anyhow::ensure!(
        *addr == AccountAddress::ZERO,
        "module `{name}` was built with non-zero self-address {addr}; expected 0x0 from a source \
         build of an upgradeable package"
    );

    *addr = new_address;
    Ok(())
}

/// Run the authoritative per-module compatibility check for the default
/// (`Compatible`) upgrade policy — the policy of a stock `UpgradeCap`.
///
/// Mirrors `check_compatibility` in the Sui adapter: every module present in
/// the old package must be present in the new package and pass
/// `Compatibility::upgrade_check().check(old, new)`. Adding brand-new modules
/// is allowed under the `Compatible` policy. Returns a human-readable error
/// describing the first incompatibility found.
fn assert_compatible_upgrade(old_modules: &[CompiledModule], new_modules: &[CompiledModule]) -> Result<()> {
    let pool = &mut normalized::RcPool::new();

    let old_normalized: std::collections::BTreeMap<String, _> = old_modules
        .iter()
        .map(|m| {
            let n = normalize(pool, m);
            (n.name().to_string(), n)
        })
        .collect();

    let mut new_normalized: std::collections::BTreeMap<String, _> = new_modules
        .iter()
        .map(|m| {
            let n = normalize(pool, m);
            (n.name().to_string(), n)
        })
        .collect();

    let compat = Compatibility::upgrade_check();

    for (name, old_module) in &old_normalized {
        let new_module = new_normalized.remove(name).ok_or_else(|| {
            anyhow::anyhow!(
                "existing module `{name}` is missing from the new package — removing a module is \
                 not a compatible upgrade"
            )
        })?;

        compat.check(old_module, &new_module).map_err(|e| {
            anyhow::anyhow!(
                "module `{name}` is NOT a compatible upgrade of the deployed version: {e:?}. \
                 A compatible (default `UpgradeCap` policy) upgrade may not change public \
                 function signatures, struct/enum layouts or abilities, etc."
            )
        })?;
    }

    Ok(())
}

/// Build `packages/hashi` from source and return its compiled modules.
///
/// Reuses [`hashi::publish::build_package`], which shells out to
/// `sui move build --dump-bytecode-as-base64`. Returns `Ok(None)` if the `sui`
/// build tool is unavailable (so an offline `cargo test` can skip rather than
/// fail); any other build error is propagated.
fn build_current_source() -> Result<Option<Vec<CompiledModule>>> {
    let package_path = workspace_package_path();
    anyhow::ensure!(
        package_path.exists(),
        "Move package path does not exist: {}",
        package_path.display()
    );

    let sui_binary = std::env::var("SUI_BINARY").unwrap_or_else(|_| "sui".to_string());
    let build_env = std::env::var("HASHI_COMPAT_ENV").unwrap_or_else(|_| DEFAULT_BUILD_ENV.to_string());

    let params = hashi::publish::BuildParams {
        sui_binary: std::path::Path::new(&sui_binary),
        package_path: &package_path,
        client_config: None,
        environment: Some(&build_env),
    };

    let publish = match hashi::publish::build_package(&params) {
        Ok(p) => p,
        Err(e) => {
            // Distinguish "tool missing" (skip) from a genuine build failure (fail).
            if is_missing_tool(&e) {
                eprintln!(
                    "SKIP: `{sui_binary}` not found — cannot build the Move package. \
                     Install the sui CLI to run the on-chain compatibility gate. ({e})"
                );
                return Ok(None);
            }
            return Err(e).context("building packages/hashi failed");
        }
    };

    let modules = deserialize_modules(&publish.modules).context("deserializing freshly-built modules")?;
    Ok(Some(modules))
}

/// Fetch the deployed package's compiled modules from a Sui fullnode.
async fn fetch_deployed_modules() -> Result<Vec<CompiledModule>> {
    use sui_rpc::proto::sui::rpc::v2::GetPackageRequest;
    use sui_sdk_types::Address;

    let rpc_url = std::env::var("HASHI_COMPAT_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());
    let package_id_str =
        std::env::var("HASHI_COMPAT_PACKAGE_ID").unwrap_or_else(|_| DEFAULT_TESTNET_PACKAGE_ID.to_string());
    let package_id: Address = package_id_str
        .parse()
        .with_context(|| format!("parsing package id `{package_id_str}`"))?;

    let mut client = sui_rpc::Client::new(rpc_url.as_str())
        .with_context(|| format!("connecting to fullnode at `{rpc_url}`"))?;

    let response = client
        .package_client()
        .get_package(GetPackageRequest::new(&package_id))
        .await
        .with_context(|| format!("GetPackage RPC for `{package_id}` at `{rpc_url}` failed"))?
        .into_inner();

    let package = response
        .package
        .ok_or_else(|| anyhow::anyhow!("GetPackage response for `{package_id}` had no package"))?;

    anyhow::ensure!(
        !package.modules.is_empty(),
        "deployed package `{package_id}` returned zero modules"
    );

    let raw: Vec<Vec<u8>> = package
        .modules
        .into_iter()
        .map(|m| m.contents.map(|b| b.to_vec()).unwrap_or_default())
        .collect();

    deserialize_modules(&raw).context("deserializing on-chain modules")
}

/// Deserialize raw module bytecode into `CompiledModule`s.
fn deserialize_modules(raw: &[Vec<u8>]) -> Result<Vec<CompiledModule>> {
    raw.iter()
        .enumerate()
        .map(|(i, bytes)| {
            CompiledModule::deserialize_with_defaults(bytes)
                .map_err(|e| anyhow::anyhow!("failed to deserialize module #{i}: {e:?}"))
        })
        .collect()
}

/// Absolute path to `packages/hashi` relative to this crate.
fn workspace_package_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <workspace>/crates/hashi
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("packages")
        .join("hashi")
}

/// Best-effort detection of a "sui binary not found" error so the on-chain
/// test can self-skip when the build tool is absent (offline dev machine).
fn is_missing_tool(e: &anyhow::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("no such file or directory")
        || msg.contains("cannot find")
        || msg.contains("not found")
        || msg.contains("program not found")
}

// ───────────────────────────── the real gate ─────────────────────────────

/// Assert the current `packages/hashi` source is a compatible upgrade of the
/// live deployed package. This is the CI gate.
#[tokio::test]
async fn current_source_is_compatible_upgrade_of_deployed() -> Result<()> {
    let Some(mut new_modules) = build_current_source()? else {
        // sui build tool unavailable → skip (see module docs). CI has it.
        return Ok(());
    };

    let old_modules = fetch_deployed_modules().await?;

    // The on-chain modules are addressed at the package's runtime/original id.
    // Rebase the freshly-built (0x0-addressed) modules to that same address so
    // the per-module comparison lines up — mirroring what the validator does
    // before it runs the compat check. Deriving the target from the on-chain
    // bytecode itself (rather than trusting an optional RPC field) matches
    // `MovePackage::original_package_id`.
    let runtime_address = module_self_address(
        old_modules
            .first()
            .ok_or_else(|| anyhow::anyhow!("deployed package returned zero modules"))?,
    );
    anyhow::ensure!(
        runtime_address != AccountAddress::ZERO,
        "deployed modules unexpectedly carry a 0x0 self-address"
    );
    for module in &mut new_modules {
        substitute_self_address(module, runtime_address)?;
    }

    eprintln!(
        "checking compatibility against runtime address {runtime_address}: {} deployed module(s) vs \
         {} freshly-built module(s)",
        old_modules.len(),
        new_modules.len()
    );

    assert_compatible_upgrade(&old_modules, &new_modules)
        .context("current packages/hashi source is NOT a compatible upgrade of the deployed package")?;

    eprintln!("OK: current source is a compatible upgrade of the deployed package");
    Ok(())
}

// ─────────────────── network-free machinery self-tests ───────────────────

/// Proves the gate actually catches a break: mutate a module so a struct
/// field is removed (a layout-incompatible change) and assert the checker
/// reports it incompatible. Runs everywhere, no network / tools required.
#[test]
fn synthetic_incompatible_change_is_rejected() {
    use move_binary_format::file_format::StructFieldInformation;
    use move_binary_format::file_format::basic_test_module;

    // Old: module with `struct Bar { x: u64 }`.
    let old = basic_test_module();

    // New: same module but drop `Bar`'s field — a layout break.
    let mut new = basic_test_module();
    assert!(!new.struct_defs.is_empty(), "test module should declare a struct");
    match &mut new.struct_defs[0].field_information {
        StructFieldInformation::Declared(fields) => {
            assert!(!fields.is_empty(), "struct should have a field to remove");
            fields.clear();
        }
        StructFieldInformation::Native => panic!("expected a declared struct"),
    }

    let result = assert_compatible_upgrade(&[old], &[new]);
    assert!(
        result.is_err(),
        "removing a struct field MUST be flagged as an incompatible upgrade, but the checker \
         accepted it — the gate is not actually catching breaks"
    );
}

/// Sanity check the other direction: an identical module is a compatible
/// upgrade of itself.
#[test]
fn synthetic_identical_module_is_compatible() {
    use move_binary_format::file_format::basic_test_module;

    let old = basic_test_module();
    let new = basic_test_module();

    assert_compatible_upgrade(&[old], &[new])
        .expect("an identical module must be a compatible upgrade of itself");
}
