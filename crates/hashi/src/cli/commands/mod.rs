// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Command implementations for the Hashi CLI

pub mod backup;
pub mod balance;
pub mod committee;
pub mod config;
pub mod deposit;
pub mod proposal;
pub mod withdraw;

use anyhow::Context;

/// Resolve, from a one-shot governance read, the package id CLI-built Hashi
/// transactions must call: the active version's package. Resolution failure
/// is a hard error with no fallback to the original package id, because v1
/// bytecode's guards do not match v2 on-chain state (a v1-targeted cancel
/// can destroy a request a live withdrawal txn still references) and every
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
