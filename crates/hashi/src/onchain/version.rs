// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Package-version support resolution.
//!
//! The on-chain `hashi::versioning` module tracks which package versions are
//! *enabled* (governance) and, separately, which have been *published* (an
//! upgrade mints a new package id). This binary declares the versions whose
//! semantics it implements in [`crate::constants::SUPPORTED_PACKAGE_VERSIONS`].
//!
//! [`resolve_version_support`] combines the three to decide how this binary
//! should behave: operate at the highest mutually-live version, or — if the
//! chain has moved entirely beyond what this build understands — halt
//! autonomous mutations and signal for an upgrade rather than act on data it
//! cannot safely interpret. The on-chain `assert_version_enabled` gate is the
//! ultimate backstop (a stale binary's writes abort); this is the node-side
//! fail-safe that avoids acting on misreads and surfaces the condition loudly.

use std::collections::BTreeSet;

use hashi_types::move_types::PackageVersions;

/// How this binary's supported versions relate to the on-chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSupport {
    /// This binary supports the highest enabled+published on-chain version;
    /// operate at `.0`.
    Active(u64),
    /// No enabled+published version is one this binary supports — typically the
    /// chain has upgraded past this build. Halt autonomous mutations and signal
    /// for a binary upgrade. `supported_max`/`live_max` are for diagnostics.
    Unsupported { supported_max: u64, live_max: u64 },
    /// No version is both enabled and published yet (pre-genesis or an
    /// incomplete scrape). NOT a halt condition — normal genesis/startup gating
    /// applies.
    NotReady,
}

impl VersionSupport {
    /// The version to operate at, if this binary supports the chain.
    pub fn active_version(self) -> Option<u64> {
        match self {
            VersionSupport::Active(v) => Some(v),
            _ => None,
        }
    }

    /// Whether autonomous work must halt: only [`VersionSupport::Unsupported`].
    /// [`VersionSupport::NotReady`] deliberately does NOT halt, so startup /
    /// pre-genesis states aren't blocked spuriously.
    pub fn must_halt(self) -> bool {
        matches!(self, VersionSupport::Unsupported { .. })
    }
}

/// Resolve version support from the enabled set (governance), the published
/// version map (on-chain package history), and this binary's supported set.
///
/// The active version is `max(enabled ∩ published ∩ supported)`. A version that
/// is enabled but not yet published (governance can enable ahead of a deploy)
/// is excluded, so the ABI is never switched on before the package is live.
///
/// Pure over its inputs for exhaustive unit testing; [`super::OnchainState`]
/// wraps it against live state.
pub fn resolve_version_support(
    enabled: &BTreeSet<u64>,
    published: &PackageVersions,
    supported: &[u64],
) -> VersionSupport {
    // Versions that are both governance-enabled and actually published.
    let live: BTreeSet<u64> = enabled
        .iter()
        .copied()
        .filter(|v| published.get(*v).is_some())
        .collect();

    let Some(&live_max) = live.iter().next_back() else {
        // Nothing enabled+published visible yet.
        return VersionSupport::NotReady;
    };

    // Highest version that is live AND supported by this binary.
    match live.iter().rev().copied().find(|v| supported.contains(v)) {
        Some(active) => VersionSupport::Active(active),
        None => VersionSupport::Unsupported {
            supported_max: supported.iter().copied().max().unwrap_or(0),
            live_max,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use sui_sdk_types::Address;

    /// Build a `PackageVersions` from version numbers; the mapped ids are
    /// distinct but otherwise irrelevant to resolution (only presence matters).
    fn published(versions: &[u64]) -> PackageVersions {
        let map: BTreeMap<u64, Address> = versions
            .iter()
            .map(|v| (*v, Address::new([*v as u8; 32])))
            .collect();
        PackageVersions::new(map)
    }

    fn enabled(versions: &[u64]) -> BTreeSet<u64> {
        versions.iter().copied().collect()
    }

    #[test]
    fn v1_only_is_active() {
        assert_eq!(
            resolve_version_support(&enabled(&[1]), &published(&[1]), &[1]),
            VersionSupport::Active(1)
        );
    }

    #[test]
    fn both_enabled_picks_highest_supported() {
        // Post-upgrade steady state: chain has {1,2}, binary supports {1,2}.
        assert_eq!(
            resolve_version_support(&enabled(&[1, 2]), &published(&[1, 2]), &[1, 2]),
            VersionSupport::Active(2)
        );
    }

    #[test]
    fn old_binary_on_upgraded_chain_uses_highest_it_supports() {
        // Chain enabled {1,2}, both published, but this binary only supports v1:
        // it keeps operating at v1 (v1 is still live).
        assert_eq!(
            resolve_version_support(&enabled(&[1, 2]), &published(&[1, 2]), &[1]),
            VersionSupport::Active(1)
        );
    }

    #[test]
    fn chain_fully_ahead_is_unsupported() {
        // v1 retired: only v2 enabled+published, binary supports only v1.
        assert_eq!(
            resolve_version_support(&enabled(&[2]), &published(&[2]), &[1]),
            VersionSupport::Unsupported {
                supported_max: 1,
                live_max: 2
            }
        );
    }

    #[test]
    fn enabled_but_unpublished_version_is_ignored() {
        // Governance pre-enabled v2 before the package is published: v2 is not
        // live, so the ABI stays at v1 (guards against switching on too early).
        assert_eq!(
            resolve_version_support(&enabled(&[1, 2]), &published(&[1]), &[1, 2]),
            VersionSupport::Active(1)
        );
    }

    #[test]
    fn enabled_gap_ignores_unpublished_higher_version() {
        // {1,3} enabled but only 1 published; supports {1,2}. Live∩supported = {1}.
        assert_eq!(
            resolve_version_support(&enabled(&[1, 3]), &published(&[1]), &[1, 2]),
            VersionSupport::Active(1)
        );
    }

    #[test]
    fn nothing_live_is_not_ready() {
        // Enabled version not yet published, and nothing else live.
        assert_eq!(
            resolve_version_support(&enabled(&[2]), &published(&[]), &[1, 2]),
            VersionSupport::NotReady
        );
        // Empty everything.
        assert_eq!(
            resolve_version_support(&enabled(&[]), &published(&[]), &[1]),
            VersionSupport::NotReady
        );
    }

    #[test]
    fn only_live_version_unsupported_by_this_binary_halts() {
        // Misconfiguration: binary dropped v1 support (supports only {2}) while
        // the chain's sole live version is v1. No mutual version -> halt.
        assert_eq!(
            resolve_version_support(&enabled(&[1]), &published(&[1]), &[2]),
            VersionSupport::Unsupported {
                supported_max: 2,
                live_max: 1
            }
        );
    }

    #[test]
    fn must_halt_only_on_unsupported() {
        assert!(
            VersionSupport::Unsupported {
                supported_max: 1,
                live_max: 2
            }
            .must_halt()
        );
        assert!(!VersionSupport::Active(1).must_halt());
        assert!(!VersionSupport::NotReady.must_halt());
    }
}
