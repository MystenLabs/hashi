// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use aws_credential_types::provider::ProvideCredentials;
use bitcoin::Network;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use serde::Deserialize;

use crate::kp_roster::KpRosterConfig;

#[derive(Deserialize)]
pub struct Config {
    pub hashi: HashiOnchainConfig,
    pub guardian_s3: GuardianInitS3Config,
    #[serde(deserialize_with = "deserialize_network")]
    pub bitcoin_network: Network,
    pub kp_roster: KpRosterConfig,
    pub limiter_config: LimiterConfig,
    /// Relay endpoint the KP's encrypted share is submitted to.
    pub relay_endpoint: String,
    /// gRPC endpoint of the guardian.
    pub guardian_endpoint: String,
    /// Path to the armored OpenPGP public cert this KP uses to identify itself.
    /// Required by key-provisioner commands.
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

fn deserialize_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_network(&s).map_err(serde::de::Error::custom)
}

fn parse_network(s: &str) -> anyhow::Result<Network> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),
        _ => {
            anyhow::bail!("unknown bitcoin_network `{s}`; expected mainnet/testnet/regtest/signet")
        }
    }
}

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
pub struct GuardianInitS3Config {
    pub bucket: String,
    pub region: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
}

impl GuardianInitS3Config {
    pub async fn resolve(&self) -> anyhow::Result<S3Config> {
        let access_key = self
            .access_key
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        let secret_key = self
            .secret_key
            .as_deref()
            .filter(|value| !value.trim().is_empty());

        let (access_key, secret_key, session_token) = match (access_key, secret_key) {
            (Some(access_key), Some(secret_key)) => {
                (access_key.to_string(), secret_key.to_string(), None)
            }
            (None, None) => {
                let provider =
                    aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                        .build()
                        .await;
                let creds = provider
                    .provide_credentials()
                    .await
                    .context("failed to resolve AWS credentials from the default provider chain")?;
                (
                    creds.access_key_id().to_string(),
                    creds.secret_access_key().to_string(),
                    creds.session_token().map(ToOwned::to_owned),
                )
            }
            _ => anyhow::bail!(
                "guardian_s3 access_key and secret_key must either both be set or both be omitted"
            ),
        };

        Ok(S3Config {
            access_key,
            secret_key,
            session_token,
            bucket_info: S3BucketInfo {
                bucket: self.bucket.clone(),
                region: self.region.clone(),
            },
        })
    }
}
