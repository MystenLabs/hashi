// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use hashi::onchain::ScrapeScope;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::S3Credentials;
use serde::Deserialize;

use crate::kp_roster::KpRosterConfig;
use crate::kp_roster::KpSetConfig;

#[derive(Deserialize)]
pub struct Config {
    pub hashi: HashiOnchainConfig,
    pub deployment: DeploymentConfig,
    /// Omit to use AWS's default credential chain.
    pub s3_credentials: Option<S3Credentials>,
    pub kp_roster: KpRosterConfig,
    /// The KP set a `rotate-kp-set` proposes; `kp_roster` stays the dealt set.
    /// Required by the rotate-kp-set commands only.
    pub new_kp_roster: Option<KpSetConfig>,
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

    pub fn require_new_kp_roster(&self, command: &str) -> anyhow::Result<&KpSetConfig> {
        self.new_kp_roster.as_ref().ok_or_else(|| {
            anyhow::anyhow!("{command} requires new_kp_roster in guardian init config")
        })
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
        // Every provisioning command reads only committee/governance data
        // (verifying key, committee members), so skip the Bitcoin
        // collections: a full scrape walks the entire withdrawal queue and
        // UTXO pool — minutes of sequential paging on testnet — for state
        // none of these commands touch. One-shot reader: the commands act
        // on the snapshot, no watcher needed.
        OnchainState::new_reader(
            &self.sui_rpc,
            self.hashi_ids,
            None,
            ScrapeScope::GovernanceOnly,
        )
        .await
        .with_context(|| format!("failed to connect to Sui RPC at {}", self.sui_rpc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_config_supports_default_and_explicit_credentials() {
        let sample = include_str!("../guardian-init.sample.yaml");
        let config: Config = serde_yaml::from_str(sample).unwrap();
        assert_eq!(config.deployment.bitcoin_network, bitcoin::Network::Signet);
        assert!(config.s3_credentials.is_none());
        config.kp_roster.validate().unwrap();

        let explicit = format!(
            "{sample}\ns3_credentials:\n  access_key: key\n  secret_key: secret\n  session_token: token\n"
        );
        let config: Config = serde_yaml::from_str(&explicit).unwrap();
        let credentials = config.s3_credentials.unwrap();
        assert_eq!(credentials.session_token.as_deref(), Some("token"));

        let incomplete = format!("{sample}\ns3_credentials:\n  access_key: key\n");
        assert!(serde_yaml::from_str::<Config>(&incomplete).is_err());
    }
}
