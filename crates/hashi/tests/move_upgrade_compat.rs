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
//! ## Hermetic: no network
//!
//! The "deployed package" side of the comparison is a **checked-in bytecode
//! snapshot** (`tests/move_upgrade_snapshots/<network>/v<version>/`), NOT a
//! live RPC fetch. CI must not depend on a network call, so the deployed
//! package's compiled modules are committed to the repo. Which snapshot(s) to
//! check is derived from `packages/hashi/Published.toml`: the gate checks the
//! current source against every published environment at its recorded
//! version, and cross-validates the snapshot's manifest and bytecode ids
//! against that entry. When a new version is deployed on chain (Published.toml
//! is bumped), capture a new snapshot — see
//! `tests/move_upgrade_snapshots/README.md`.
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
//!   builds `packages/hashi`, loads the checked-in snapshot of each deployment
//!   recorded in `Published.toml`, and asserts the current source is a
//!   compatible upgrade of every one. It requires only the `sui` binary (to
//!   build the current source) — no network. It does NOT skip: any missing
//!   tool / build failure / IO error fails the test — this is a required gate
//!   and must never green by skipping.
//!
//! ## Configuration (env vars)
//!
//! * `HASHI_COMPAT_SNAPSHOT_DIR` — dev escape hatch: check exactly this
//!   snapshot directory instead of the `Published.toml`-derived set (the
//!   `Published.toml` cross-validation is skipped for it).
//! * `SUI_BINARY` — path to the `sui` CLI (default `sui`).
//!
//! ## Addressing
//!
//! A source build of an upgradeable package emits modules addressed at `0x0`,
//! while the on-chain `module_map` (what both the validator's compat check and
//! the snapshot bytecode carry) is addressed at the package's runtime/original
//! id. We rebase the built modules onto the snapshot's address before
//! comparing — exactly what the Sui adapter does via `substitute_package_id`
//! right before `check_compatibility`.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use hashi::published::PublishedEntry;
use move_binary_format::CompiledModule;
use move_binary_format::compatibility::Compatibility;
use move_binary_format::normalized;
use move_core_types::account_address::AccountAddress;

/// Normalize a `CompiledModule` into the representation the compatibility
/// checker consumes. `include_code = true` matches what the on-chain adapter
/// uses (`check_compatibility(..)` passes `include code = true`).
fn normalize(
    pool: &mut normalized::RcPool,
    module: &CompiledModule,
) -> normalized::Module<normalized::RcIdentifier> {
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
/// and what the checked-in snapshot carries) stores modules addressed at the
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
/// is allowed under the `Compatible` policy — but, like the adapter, a new
/// module must not define an `init` function: the validator aborts such
/// upgrades with `FeatureNotYetSupported` ("`init` in new modules on upgrade
/// is not yet supported"). Returns a human-readable error describing the
/// first incompatibility found.
fn assert_compatible_upgrade(
    old_modules: &[CompiledModule],
    new_modules: &[CompiledModule],
) -> Result<()> {
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

    // Whatever is left in `new_normalized` was not in the old package, i.e. a
    // brand-new module. Adding modules is allowed, but the adapter separately
    // rejects new modules that define an `init` function (it cannot run `init`
    // on upgrade) — mirror that or the gate would green-light an upgrade the
    // validator aborts. Existing modules keeping their `init` are fine; it
    // simply never re-runs. See `execution.rs` (`check_for_init_during_upgrade`)
    // at the rev move-binary-format is pinned to.
    for module in new_modules {
        let name = module.identifier_at(module.self_handle().name).as_str();
        if !new_normalized.contains_key(name) {
            continue;
        }
        let has_init = module.function_defs.iter().any(|fdef| {
            let fhandle = module.function_handle_at(fdef.function);
            module.identifier_at(fhandle.name).as_str() == "init"
        });
        anyhow::ensure!(
            !has_init,
            "newly added module `{name}` defines an `init` function — the validator rejects such \
             upgrades (\"`init` in new modules on upgrade is not yet supported\"). Move the \
             initialization into an explicit function called after the upgrade."
        );
    }

    Ok(())
}

/// Build `packages/hashi` from source and return its compiled modules.
///
/// Reuses [`hashi::publish::build_package`], which shells out to
/// `sui move build --dump-bytecode-as-base64 --no-tree-shaking`. Any failure
/// (including a missing `sui` binary) is propagated — this is a required gate
/// and must not skip.
///
/// The build is **environment-agnostic**: `environment: None` is passed so
/// modules are emitted with `0x0` self-addresses (which
/// [`substitute_self_address`] later rebases onto the snapshot's address).
/// Passing `-e testnet` requires a sui client config to resolve the env; with
/// none present the CLI emits no JSON to stdout and the parse fails with
/// `expected value at line 1 column 1`. An env-agnostic build emits valid JSON
/// with `0x0`-addressed modules — exactly what this gate expects.
///
/// We DO pass a throwaway `--client.config`. Without a client config the CLI
/// can try to create one and print an interactive `create one [Y/n]?` prompt —
/// in non-interactive CI that prompt is written to *stdout*, so it would
/// prefix the `--dump-bytecode-as-base64` JSON and break the parse. A minimal
/// config (with a `testnet` env carrying its `chain_id`) skips the prompt and
/// needs no network for chain-id resolution; `--no-tree-shaking` already avoids
/// the other RPC call, so the build is offline apart from fetching the
/// git-pinned framework deps.
fn build_current_source() -> Result<Vec<CompiledModule>> {
    let package_path = workspace_package_path();
    anyhow::ensure!(
        package_path.exists(),
        "Move package path does not exist: {}",
        package_path.display()
    );

    let sui_binary = std::env::var("SUI_BINARY").unwrap_or_else(|_| "sui".to_string());

    // Throwaway client config so the CLI never prompts. `_config_dir` keeps the
    // temp dir alive for the duration of the build.
    let (_config_dir, client_config_path) =
        write_throwaway_client_config().context("preparing throwaway sui client config")?;

    // Build environment-agnostic: no `-e`, so modules come out at `0x0`. See the
    // doc comment above for why `-e testnet` breaks the JSON parse here.
    let params = hashi::publish::BuildParams {
        sui_binary: std::path::Path::new(&sui_binary),
        package_path: &package_path,
        client_config: Some(&client_config_path),
        environment: None,
    };

    let publish = hashi::publish::build_package(&params).with_context(|| {
        format!(
            "building packages/hashi with `{sui_binary}` failed (is the sui CLI installed and on \
             PATH / SUI_BINARY?)"
        )
    })?;

    deserialize_modules(&publish.modules).context("deserializing freshly-built modules")
}

/// Write a minimal, self-contained `sui` client config into a fresh temp dir
/// and return `(temp_dir_guard, client_yaml_path)`.
///
/// The config declares the `testnet`/`mainnet` envs (with their chain ids so no
/// network round-trip is needed to resolve them) and points at an empty
/// keystore. It exists purely to stop the CLI from prompting to create one;
/// nothing in it is used to sign or reach the network for the build.
fn write_throwaway_client_config() -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::tempdir().context("creating temp dir for sui client config")?;
    let keystore_path = dir.path().join("sui.keystore");
    std::fs::write(&keystore_path, "[]").context("writing empty keystore")?;

    let client_yaml = dir.path().join("client.yaml");
    let contents = format!(
        "---\n\
         keystore:\n\
         \x20 File: {keystore}\n\
         envs:\n\
         \x20 - alias: testnet\n\
         \x20   rpc: \"https://fullnode.testnet.sui.io:443\"\n\
         \x20   ws: ~\n\
         \x20   basic_auth: ~\n\
         \x20   chain_id: 4c78adac\n\
         \x20 - alias: mainnet\n\
         \x20   rpc: \"https://fullnode.mainnet.sui.io:443\"\n\
         \x20   ws: ~\n\
         \x20   basic_auth: ~\n\
         \x20   chain_id: 35834a8a\n\
         active_env: testnet\n\
         active_address: ~\n",
        keystore = keystore_path.display()
    );
    std::fs::write(&client_yaml, contents).context("writing client.yaml")?;

    Ok((dir, client_yaml))
}

/// Parse `packages/hashi/Published.toml` into its per-network entries. This
/// is the source of truth the gate derives its snapshot locations from, so
/// bumping the version there without capturing a matching snapshot fails the
/// gate instead of silently checking an obsolete package.
fn published_entries() -> Result<std::collections::BTreeMap<String, PublishedEntry>> {
    hashi::published::published_entries(&workspace_package_path().join("Published.toml"))
}

/// Root of the checked-in snapshots: `tests/move_upgrade_snapshots/`.
/// Per-deployment snapshots live at `<network>/v<version>/` beneath it, with
/// network and version taken from `Published.toml`.
fn snapshots_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("move_upgrade_snapshots")
}

/// Validate a loaded snapshot against its `Published.toml` entry: manifest
/// network/version must match the entry, manifest `package_id` must be the
/// entry's `published-at` (the storage id the capture was fetched from), and
/// the bytecode's self-address must be the entry's `original-id` (the runtime
/// id the validator's compat check runs against).
fn validate_snapshot_against_published(
    manifest: &SnapshotManifest,
    bytecode_self_address: AccountAddress,
    network: &str,
    entry: &PublishedEntry,
) -> Result<()> {
    anyhow::ensure!(
        manifest.network == network,
        "snapshot manifest network `{}` does not match Published.toml environment `{network}`",
        manifest.network
    );
    anyhow::ensure!(
        manifest.version == entry.version,
        "snapshot manifest version {} does not match Published.toml version {} — regenerate the \
         snapshot for the currently-deployed package",
        manifest.version,
        entry.version
    );
    let manifest_id = AccountAddress::from_hex_literal(&manifest.package_id)
        .context("parsing snapshot manifest package_id")?;
    let published_at = AccountAddress::from_hex_literal(&entry.published_at)
        .context("parsing Published.toml published-at")?;
    anyhow::ensure!(
        manifest_id == published_at,
        "snapshot manifest package_id {} does not match Published.toml published-at {} — the \
         snapshot must capture the currently-deployed package",
        manifest.package_id,
        entry.published_at
    );
    let original_id = AccountAddress::from_hex_literal(&entry.original_id)
        .context("parsing Published.toml original-id")?;
    anyhow::ensure!(
        bytecode_self_address == original_id,
        "snapshot bytecode self-address {bytecode_self_address} does not match Published.toml \
         original-id {} — the capture does not belong to this deployment",
        entry.original_id
    );
    Ok(())
}

/// The `manifest.json` checked in alongside a snapshot's `.mv` files.
#[derive(serde_derive::Deserialize)]
struct SnapshotManifest {
    network: String,
    version: u64,
    package_id: String,
    module_count: usize,
    modules: Vec<String>,
}

/// Load a snapshot directory: parse `manifest.json`, deserialize every `*.mv`
/// file, and cross-check the two.
///
/// The `.mv` files are the raw compiled modules of the deployed package,
/// addressed at the package's runtime/original id. This replaces the old
/// network fetch: the snapshot IS the deployed package.
///
/// A nonempty directory is not enough: a snapshot missing one `.mv` file would
/// make that module look *newly added* in the current source, silently
/// bypassing its compatibility check. So the manifest's module list must match
/// the files on disk — and each file's deserialized self-name — exactly, in
/// both directions.
fn load_snapshot(dir: &Path) -> Result<(SnapshotManifest, Vec<CompiledModule>)> {
    anyhow::ensure!(
        dir.is_dir(),
        "snapshot directory does not exist: {} (regenerate the snapshot — see \
         tests/move_upgrade_snapshots/README.md)",
        dir.display()
    );

    let manifest_path = dir.join("manifest.json");
    let manifest: SnapshotManifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading snapshot manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parsing snapshot manifest {}", manifest_path.display()))?;

    anyhow::ensure!(
        manifest.module_count == manifest.modules.len(),
        "snapshot manifest {} is inconsistent: module_count is {} but the modules list has {} \
         entries",
        manifest_path.display(),
        manifest.module_count,
        manifest.modules.len()
    );

    let mut mv_paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading snapshot directory {}", dir.display()))?
        .map(|entry| entry.map(|e| e.path()).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("mv"))
        .collect();
    mv_paths.sort();

    let file_names: BTreeSet<String> = mv_paths
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    let manifest_names: BTreeSet<String> = manifest.modules.iter().cloned().collect();
    anyhow::ensure!(
        manifest_names.len() == manifest.modules.len(),
        "snapshot manifest {} lists duplicate module names",
        manifest_path.display()
    );

    let missing: Vec<&String> = manifest_names.difference(&file_names).collect();
    anyhow::ensure!(
        missing.is_empty(),
        "snapshot {} is INCOMPLETE: manifest lists module(s) with no `.mv` file: {missing:?}. An \
         omitted module would be treated as newly added and skip compatibility checking entirely \
         (regenerate the snapshot — see tests/move_upgrade_snapshots/README.md)",
        dir.display()
    );
    let unlisted: Vec<&String> = file_names.difference(&manifest_names).collect();
    anyhow::ensure!(
        unlisted.is_empty(),
        "snapshot {} contains `.mv` file(s) not listed in its manifest: {unlisted:?} (regenerate \
         the snapshot — see tests/move_upgrade_snapshots/README.md)",
        dir.display()
    );

    let raw: Vec<Vec<u8>> = mv_paths
        .iter()
        .map(|p| {
            std::fs::read(p).with_context(|| format!("reading snapshot module {}", p.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let modules = deserialize_modules(&raw)
        .with_context(|| format!("deserializing snapshot modules from {}", dir.display()))?;

    for (path, module) in mv_paths.iter().zip(&modules) {
        let self_name = module.identifier_at(module.self_handle().name).as_str();
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        anyhow::ensure!(
            self_name == stem,
            "snapshot module file {} deserializes to a module named `{self_name}` — file name and \
             module self-name must agree",
            path.display()
        );
    }

    Ok((manifest, modules))
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

// ───────────────────────────── the real gate ─────────────────────────────

/// Assert the current `packages/hashi` source is a compatible upgrade of
/// every deployed package recorded in `Published.toml`, each captured as a
/// checked-in snapshot at `move_upgrade_snapshots/<network>/v<version>/`.
/// This is the CI gate. It never skips: a missing tool, build failure, IO
/// error, or a `Published.toml` entry without a matching snapshot fails the
/// test. Fully synchronous — there is no network call.
///
/// `HASHI_COMPAT_SNAPSHOT_DIR` is a dev escape hatch: when set, exactly that
/// directory is checked and the `Published.toml` cross-validation is skipped
/// (there is no entry to validate an arbitrary directory against).
#[test]
fn current_source_is_compatible_upgrade_of_deployed() -> Result<()> {
    let built = build_current_source()?;

    if let Ok(dir) = std::env::var("HASHI_COMPAT_SNAPSHOT_DIR") {
        eprintln!("HASHI_COMPAT_SNAPSHOT_DIR is set — checking only {dir}");
        return check_snapshot_compat(Path::new(&dir), &built, None);
    }

    for (network, entry) in published_entries()? {
        let dir = snapshots_root()
            .join(&network)
            .join(format!("v{}", entry.version));
        check_snapshot_compat(&dir, &built, Some((&network, &entry))).with_context(|| {
            format!(
                "current packages/hashi source failed the upgrade check against the `{network}` \
                 v{} deployment",
                entry.version
            )
        })?;
    }

    eprintln!("OK: current source is a compatible upgrade of every published deployment");
    Ok(())
}

/// Check the built modules against one snapshot directory. When `published`
/// carries the corresponding `Published.toml` entry, the snapshot's manifest
/// and bytecode are first validated against it: manifest network/version must
/// match the entry, manifest `package_id` must be the entry's `published-at`
/// (the storage id the capture was fetched from), and the bytecode's
/// self-address must be the entry's `original-id` (the runtime id the
/// validator's compat check runs against).
fn check_snapshot_compat(
    dir: &Path,
    built: &[CompiledModule],
    published: Option<(&str, &PublishedEntry)>,
) -> Result<()> {
    let (manifest, old_modules) = load_snapshot(dir)?;

    // The snapshot modules are addressed at the package's runtime/original id.
    // Rebase the freshly-built (0x0-addressed) modules to that same address so
    // the per-module comparison lines up — mirroring what the validator does
    // before it runs the compat check. Deriving the target from the snapshot
    // bytecode itself matches `MovePackage::original_package_id`.
    let runtime_address = module_self_address(
        old_modules
            .first()
            .ok_or_else(|| anyhow::anyhow!("snapshot returned zero modules"))?,
    );
    anyhow::ensure!(
        runtime_address != AccountAddress::ZERO,
        "snapshot modules unexpectedly carry a 0x0 self-address"
    );
    if let Some((network, entry)) = published {
        validate_snapshot_against_published(&manifest, runtime_address, network, entry)?;
    }

    let mut new_modules = built.to_vec();
    for module in &mut new_modules {
        substitute_self_address(module, runtime_address)?;
    }

    eprintln!(
        "checking compatibility against runtime address {runtime_address}: {} snapshot module(s) \
         vs {} freshly-built module(s)",
        old_modules.len(),
        new_modules.len()
    );

    assert_compatible_upgrade(&old_modules, &new_modules).context(
        "current packages/hashi source is NOT a compatible upgrade of the deployed package",
    )
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
    assert!(
        !new.struct_defs.is_empty(),
        "test module should declare a struct"
    );
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

/// Rewrite a module's self-name (the identifier its module handle points at).
fn rename_module(module: &mut CompiledModule, new_name: &str) {
    use move_core_types::identifier::Identifier;
    let idx = module.self_handle().name;
    module.identifiers[idx.0 as usize] = Identifier::new(new_name).unwrap();
}

/// Rewrite the name of the module's first function definition.
fn rename_first_function(module: &mut CompiledModule, new_name: &str) {
    use move_core_types::identifier::Identifier;
    let idx = module
        .function_handle_at(module.function_defs[0].function)
        .name;
    module.identifiers[idx.0 as usize] = Identifier::new(new_name).unwrap();
}

/// A newly added module that defines `init` must be rejected: the validator
/// aborts such upgrades with "`init` in new modules on upgrade is not yet
/// supported", so the gate has to as well.
#[test]
fn synthetic_new_module_with_init_is_rejected() {
    use move_binary_format::file_format::basic_test_module;

    let old = basic_test_module();
    let mut fresh = basic_test_module();
    rename_module(&mut fresh, "fresh");
    rename_first_function(&mut fresh, "init");

    let new = vec![old.clone(), fresh];
    let result = assert_compatible_upgrade(&[old], &new);
    let err = result.expect_err("a new module defining `init` MUST be rejected");
    assert!(
        format!("{err:#}").contains("init"),
        "error should mention `init`, got: {err:#}"
    );
}

/// The positive counterpart: adding a new module *without* `init` is a
/// compatible upgrade.
#[test]
fn synthetic_new_module_without_init_is_accepted() {
    use move_binary_format::file_format::basic_test_module;

    let old = basic_test_module();
    let mut fresh = basic_test_module();
    rename_module(&mut fresh, "fresh");

    let new = vec![old.clone(), fresh];
    assert_compatible_upgrade(&[old], &new)
        .expect("adding a new module without `init` must be a compatible upgrade");
}

/// `init` is only banned in *newly added* modules. An existing module keeping
/// its `init` (as every already-published module does) must still pass.
#[test]
fn synthetic_existing_module_keeping_init_is_accepted() {
    use move_binary_format::file_format::basic_test_module;

    let mut old = basic_test_module();
    rename_first_function(&mut old, "init");
    let new = old.clone();

    assert_compatible_upgrade(&[old], &[new])
        .expect("an existing module keeping its `init` must be a compatible upgrade");
}

/// The committed testnet/v1 snapshot location, ignoring the
/// `HASHI_COMPAT_SNAPSHOT_DIR` override — the manifest self-tests below must
/// always exercise the real committed snapshot.
fn checked_in_snapshot_dir() -> PathBuf {
    snapshots_root().join("testnet").join("v1")
}

/// Every deployment recorded in `Published.toml` must have a checked-in
/// snapshot whose manifest and bytecode agree with it. Network-free and does
/// not build the package, so it runs everywhere — this is what forces a
/// snapshot capture when `Published.toml` is bumped by an on-chain upgrade.
#[test]
fn every_published_deployment_has_a_valid_snapshot() -> Result<()> {
    for (network, entry) in published_entries()? {
        let dir = snapshots_root()
            .join(&network)
            .join(format!("v{}", entry.version));
        let (manifest, modules) = load_snapshot(&dir).with_context(|| {
            format!(
                "Published.toml records a `{network}` v{} deployment but its snapshot is missing \
                 or invalid — capture it per tests/move_upgrade_snapshots/README.md",
                entry.version
            )
        })?;
        let self_address = module_self_address(
            modules
                .first()
                .ok_or_else(|| anyhow::anyhow!("snapshot returned zero modules"))?,
        );
        validate_snapshot_against_published(&manifest, self_address, &network, &entry)?;
    }
    Ok(())
}

/// The committed snapshot must satisfy its own manifest — files, names and
/// counts all agree. Network-free; runs everywhere.
#[test]
fn checked_in_snapshot_passes_manifest_validation() -> Result<()> {
    let (manifest, modules) = load_snapshot(&checked_in_snapshot_dir())?;
    assert_eq!(manifest.module_count, modules.len());
    Ok(())
}

/// Proves the manifest cross-check catches an incomplete capture: copy the
/// real snapshot minus one `.mv` file (keeping the manifest) and assert
/// loading fails. Without this check the omitted module would silently be
/// treated as newly added and skip compatibility checking.
#[test]
fn snapshot_missing_module_file_is_detected() -> Result<()> {
    let src = checked_in_snapshot_dir();
    let tmp = tempfile::tempdir().context("creating temp snapshot dir")?;

    let mut dropped: Option<String> = None;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&src)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if dropped.is_none() && path.extension().and_then(|e| e.to_str()) == Some("mv") {
            dropped = Some(name.trim_end_matches(".mv").to_string());
            continue;
        }
        std::fs::copy(&path, tmp.path().join(name))?;
    }
    let dropped = dropped.expect("checked-in snapshot should contain at least one .mv file");

    let err = load_snapshot(tmp.path())
        .err()
        .expect("a snapshot missing a manifest-listed .mv file MUST fail to load");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("INCOMPLETE") && msg.contains(&dropped),
        "error should name the missing module `{dropped}`, got: {msg}"
    );
    Ok(())
}
