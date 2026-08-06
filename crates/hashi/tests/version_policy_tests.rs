// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pins the package-version bump policy in CI.
//!
//! The source tree always declares the *next* package version: exactly one
//! past the deployed testnet package recorded in `Published.toml`. The e2e
//! harness patches the constant when building upgrade artifacts, so no test
//! that runs the code would notice a missed or doubled bump — the first
//! thing that would is the real upgrade build on deploy day
//! (`build_upgrade_package`'s `declared == published + 1` check). This test
//! moves that failure to the PR that should have carried the bump:
//!
//! - after deploying an upgrade, bump `PACKAGE_VERSION` in the same change
//!   that records the deployment (Published.toml + snapshot capture);
//! - mid-cycle Move changes never touch it.

use std::path::PathBuf;

#[test]
fn source_declares_one_past_the_deployed_testnet_version() -> anyhow::Result<()> {
    let packages_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/hashi");

    let versioning = std::fs::read_to_string(packages_dir.join("sources/core/versioning.move"))?;
    const PREFIX: &str = "const PACKAGE_VERSION: u64 = ";
    let declared: u64 = versioning
        .lines()
        .find_map(|line| line.strip_prefix(PREFIX))
        .and_then(|rest| rest.strip_suffix(';'))
        .ok_or_else(|| anyhow::anyhow!("PACKAGE_VERSION constant not found in versioning.move"))?
        .parse()?;

    let entries = hashi::published::published_entries(&packages_dir.join("Published.toml"))?;
    let deployed = entries
        .get("testnet")
        .ok_or_else(|| anyhow::anyhow!("no `testnet` entry in Published.toml"))?
        .version;

    assert_eq!(
        declared,
        deployed + 1,
        "versioning.move declares PACKAGE_VERSION = {declared}, but the deployed testnet \
         package (Published.toml) is version {deployed}. The tree must declare exactly one \
         past the deployment: bump the constant in the change that records a new deployment, \
         and never in mid-cycle Move changes."
    );
    Ok(())
}
