// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use serde::Deserialize;

use crate::kp_roster::KpRosterConfig;

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

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub hashi: HashiOnchainConfig,
    pub kp_roster: KpRosterConfig,
    #[serde(deserialize_with = "deserialize_limiter_config")]
    pub limiter_config: LimiterConfig,
    /// Relay endpoint the KP's encrypted share is submitted to.
    pub relay_endpoint: String,
    /// gRPC endpoint of the guardian.
    pub guardian_endpoint: String,
    /// Path to this KP's armored OpenPGP public cert. Required by
    /// key-provisioner commands.
    pub kp_pgp_cert_path: Option<PathBuf>,
}

pub fn deserialize_s3_config<'de, D>(deserializer: D) -> Result<S3Config, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct S3ConfigWire {
        access_key: String,
        secret_key: String,
        bucket_info: S3BucketInfoWire,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct S3BucketInfoWire {
        bucket: String,
        region: String,
    }

    let wire = S3ConfigWire::deserialize(deserializer)?;
    Ok(S3Config {
        access_key: wire.access_key,
        secret_key: wire.secret_key,
        bucket_info: S3BucketInfo {
            bucket: wire.bucket_info.bucket,
            region: wire.bucket_info.region,
        },
    })
}

fn deserialize_limiter_config<'de, D>(deserializer: D) -> Result<LimiterConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct LimiterConfigWire {
        refill_rate: u64,
        max_bucket_capacity: u64,
    }

    let wire = LimiterConfigWire::deserialize(deserializer)?;
    Ok(LimiterConfig {
        refill_rate: wire.refill_rate,
        max_bucket_capacity: wire.max_bucket_capacity,
    })
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
