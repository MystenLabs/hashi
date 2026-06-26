// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use hashi_types::guardian::LimiterConfig;
use serde::Deserialize;

use crate::kp_roster::KpRosterConfig;

#[derive(Clone)]
pub struct HashiOnchainConfig {
    /// Sui RPC URL used to fetch Hashi on-chain state.
    pub sui_rpc: String,
    pub hashi_ids: HashiIds,
}

impl<'de> Deserialize<'de> for HashiOnchainConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct HashiOnchainConfigWire {
            sui_rpc: String,
            package_id: String,
            hashi_object_id: String,
        }

        let wire = HashiOnchainConfigWire::deserialize(deserializer)?;
        Ok(Self {
            sui_rpc: wire.sui_rpc,
            hashi_ids: HashiIds {
                package_id: wire.package_id.parse().map_err(serde::de::Error::custom)?,
                hashi_object_id: wire
                    .hashi_object_id
                    .parse()
                    .map_err(serde::de::Error::custom)?,
            },
        })
    }
}

impl HashiOnchainConfig {
    pub async fn onchain_state(&self) -> anyhow::Result<OnchainState> {
        let (state, _watcher) = OnchainState::new(&self.sui_rpc, self.hashi_ids, None, None, None)
            .await
            .with_context(|| format!("failed to connect to Sui RPC at {}", self.sui_rpc))?;
        Ok(state)
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub hashi: HashiOnchainConfig,
    pub kp_roster: KpRosterConfig,
    pub limiter_config: LimiterConfig,
    /// Relay endpoint the KP's encrypted share is submitted to.
    pub relay_endpoint: String,
    /// gRPC endpoint of the guardian.
    pub guardian_endpoint: String,
    /// Path to this KP's armored OpenPGP public cert. Required by
    /// key-provisioner commands.
    pub kp_pgp_cert_path: Option<PathBuf>,
}

impl Config {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path).with_context(|| {
            format!("failed to read guardian init config at {}", path.display())
        })?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse guardian init yaml at {}", path.display()))
    }

    pub fn require_kp_pgp_cert_path(&self, command: &str) -> anyhow::Result<&Path> {
        self.kp_pgp_cert_path.as_deref().ok_or_else(|| {
            anyhow::anyhow!("{command} requires kp_pgp_cert_path in guardian init config")
        })
    }
}
