// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HashiOnchainConfig {
    /// Sui RPC URL used to fetch Hashi on-chain state.
    pub sui_rpc: String,
    #[serde(flatten)]
    pub hashi_ids: HashiIds,
}

impl HashiOnchainConfig {
    pub async fn onchain_state(&self) -> anyhow::Result<OnchainState> {
        let (state, _watcher) = OnchainState::new(&self.sui_rpc, self.hashi_ids, None, None, None)
            .await
            .with_context(|| format!("failed to connect to Sui RPC at {}", self.sui_rpc))?;
        Ok(state)
    }
}
