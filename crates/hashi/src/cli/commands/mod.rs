// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Command implementations for the Hashi CLI

pub mod backup;
pub mod balance;
pub mod committee;
pub mod config;
pub mod deposit;
pub mod proposal;
pub mod validator;
pub mod withdraw;

use anyhow::Context;

/// Resolve, from a one-shot governance read, the package id CLI-built Hashi
/// transactions must call: the active version's package. Resolution
/// failure is a hard
/// error with no fallback to the original package id, because every
/// v1-targeted entry aborts once v1 is disabled. Returns the reader state
/// alongside the id so batch paths can attach it to a
/// [`crate::sui_tx_executor::SuiTxExecutor`] for self-routing.
pub(crate) async fn resolve_active_call_package(
    config: &super::config::CliConfig,
    hashi_ids: crate::config::HashiIds,
) -> anyhow::Result<(crate::onchain::OnchainState, sui_sdk_types::Address)> {
    let state = crate::onchain::OnchainState::new_reader(
        &config.sui_rpc_url,
        hashi_ids,
        None,
        crate::onchain::ScrapeScope::GovernanceOnly,
    )
    .await
    .context("failed to read on-chain governance state to resolve the active package")?;
    let package = state.active_package().map(|(id, _version)| id).context(
        "no supported active on-chain package version resolved; refusing to fall back to the \
         original package",
    )?;
    Ok((state, package))
}

/// The package `hashi register` calls: the highest version that is both
/// governance-enabled and published on-chain, resolved from a one-shot
/// governance read and deliberately NOT intersected with this binary's
/// [`crate::constants::SUPPORTED_PACKAGE_VERSIONS`]. That list gates what a
/// node may decode and mutate autonomously; the registration transaction is a
/// fixed set of `validator::*` entry calls whose only version dependency is
/// the called package's `assert_version_enabled`, so the live package is the
/// correct target even for a CLI built before the chain's latest upgrade. A
/// chain with no enabled+published version is a hard error, never a fallback
/// to the original package id (`hashi_ids.package_id`), whose entries abort
/// once its version is retired.
pub async fn resolve_latest_enabled_package(
    sui_rpc_url: &str,
    hashi_ids: crate::config::HashiIds,
) -> anyhow::Result<sui_sdk_types::Address> {
    let state = crate::onchain::OnchainState::new_reader(
        sui_rpc_url,
        hashi_ids,
        None,
        crate::onchain::ScrapeScope::GovernanceOnly,
    )
    .await
    .context("failed to read on-chain governance state to resolve the enabled package")?;
    let state = state.state();
    let published: Vec<u64> = state
        .package_versions()
        .versions()
        .keys()
        .copied()
        .collect();
    let version = state
        .version_support(&published)
        .active_version()
        .context("no on-chain package version is both enabled and published")?;
    state
        .package_versions()
        .get(version)
        .with_context(|| format!("package id for enabled version {version} is not known"))
}
