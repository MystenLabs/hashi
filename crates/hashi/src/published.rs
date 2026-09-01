// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Parse `packages/hashi/Published.toml` — the Move tooling's record of
//! where (and at what version) the package is deployed per network.
//!
//! This file is the source of truth the upgrade-compatibility CI gate
//! (`crates/hashi/tests/move_upgrade_compat.rs`) derives its snapshot locations
//! from, so a version bump there without a matching snapshot capture fails
//! that check instead of silently exercising an obsolete package.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

/// One `[published.<network>]` entry of `Published.toml`.
#[derive(serde_derive::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublishedEntry {
    /// Storage id of the deployed package object (the id a snapshot capture
    /// is fetched from).
    pub published_at: String,
    /// Runtime/original id the deployed modules are self-addressed at.
    pub original_id: String,
    /// Deployed package version (`v<version>` names the snapshot directory).
    pub version: u64,
}

#[derive(serde_derive::Deserialize)]
struct PublishedFile {
    #[serde(default)]
    published: BTreeMap<String, PublishedEntry>,
}

/// Parse the `Published.toml` at `path` into its per-network entries.
/// Fails on a missing/unparsable file. An empty map is a legal result: a
/// fresh cycle (nothing deployed from this tree) declares no environments,
/// and the consumers treat it as "nothing to check".
pub fn published_entries(path: &Path) -> Result<BTreeMap<String, PublishedEntry>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: PublishedFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.published)
}
