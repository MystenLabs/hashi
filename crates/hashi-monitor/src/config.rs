// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use aws_credential_types::provider::ProvideCredentials;
use corepc_client::client_sync::Auth;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::S3RetentionEnvironment;
use serde::Deserialize;

use crate::domain::WithdrawalEventType;

/// Configuration for the cursorless batch auditor.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Maximum allowed delay between consecutive events.
    pub next_event_delays: NextEventDelays,

    /// E_{i+1} is allowed to occur up to clock_skew seconds before E_i (default: 300s).
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,

    /// How far before the guardian audit start to search Sui for withdrawal
    /// predecessor events (default: 1 hour).
    #[serde(default = "default_withdrawal_predecessor_lookback")]
    pub withdrawal_predecessor_lookback: u64,

    pub guardian_s3: GuardianS3Config,
    #[serde(flatten)]
    pub pcr_allowlist: PcrAllowlist,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

/// The maximum allowed delay between an event and it's successor in seconds.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Vec<(WithdrawalEventType, u64)>")]
pub struct NextEventDelays(Vec<(WithdrawalEventType, u64)>);

#[derive(Clone, Debug, Deserialize)]
pub struct SuiConfig {
    /// Sui RPC endpoint.
    pub rpc_url: String,

    /// Currently deployed Hashi package.
    pub package_id: String,

    /// Shared Hashi object. Retained in monitor config so it matches the
    /// canonical testnet deployment description even though event filtering
    /// only needs the package ID.
    pub hashi_object_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GuardianS3Config {
    pub bucket: String,
    pub region: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub retention_environment: S3RetentionEnvironment,
}

impl GuardianS3Config {
    /// Resolve explicit credentials or, when both are omitted, use AWS's
    /// default provider chain. This mirrors Guardian Init configuration.
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
                let credentials = provider
                    .provide_credentials()
                    .await
                    .context("failed to resolve AWS credentials from the default provider chain")?;
                (
                    credentials.access_key_id().to_string(),
                    credentials.secret_access_key().to_string(),
                    credentials.session_token().map(ToOwned::to_owned),
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
            retention_environment: self.retention_environment,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcConfig {
    /// Bitcoin Core RPC endpoint.
    ///
    /// Prefix with `env:` to read the URL from an environment variable, which
    /// keeps provider API keys out of YAML.
    pub rpc_url: String,

    /// Bitcoin Core RPC auth.
    #[serde(default)]
    pub rpc_auth: BtcRpcAuth,

    /// Optional HTTP headers for hosted JSON-RPC providers.
    #[serde(default)]
    pub http_headers: BTreeMap<String, String>,
}

impl BtcConfig {
    pub fn resolve_rpc_url(&self) -> anyhow::Result<String> {
        if let Some(variable) = self.rpc_url.strip_prefix("env:") {
            anyhow::ensure!(
                !variable.is_empty(),
                "bitcoin rpc_url environment variable name is empty"
            );
            return std::env::var(variable).with_context(|| {
                format!("bitcoin RPC environment variable {variable} is not set")
            });
        }
        Ok(self.rpc_url.clone())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BtcRpcAuth {
    #[default]
    None,
    UserPass {
        username: String,
        password: String,
    },
    CookieFile {
        path: PathBuf,
    },
}

impl BtcRpcAuth {
    pub fn to_corepc_auth(&self) -> Auth {
        match self {
            BtcRpcAuth::None => Auth::None,
            BtcRpcAuth::UserPass { username, password } => {
                Auth::UserPass(username.clone(), password.clone())
            }
            BtcRpcAuth::CookieFile { path } => Auth::CookieFile(path.clone()),
        }
    }
}

fn default_clock_skew() -> u64 {
    300
}

fn default_withdrawal_predecessor_lookback() -> u64 {
    60 * 60
}

impl NextEventDelays {
    /// The constructor ensures that there is one entry for every non-terminal event.
    pub fn new(inputs: Vec<(WithdrawalEventType, u64)>) -> anyhow::Result<Self> {
        let mut seen_sources = Vec::new();
        for (source, _) in &inputs {
            if seen_sources.contains(source) {
                return Err(anyhow!(format!("duplicate delay entry for {:?}", source)));
            }
            seen_sources.push(*source);
        }

        if seen_sources.contains(&WithdrawalEventType::TERMINAL_EVENT) {
            return Err(anyhow!(
                "delay for terminal event is not allowed".to_string()
            ));
        }

        for source in WithdrawalEventType::NON_TERMINAL_EVENTS {
            if !seen_sources.contains(&source) {
                return Err(anyhow!(format!("missing delay entry for {:?}", source)));
            }
        }

        Ok(Self(inputs))
    }

    pub fn get_delay(&self, source: WithdrawalEventType) -> Option<u64> {
        self.0
            .iter()
            .find(|(event_source, _)| *event_source == source)
            .map(|(_, next_event_delay_secs)| *next_event_delay_secs)
    }
}

impl TryFrom<Vec<(WithdrawalEventType, u64)>> for NextEventDelays {
    type Error = anyhow::Error;

    fn try_from(entries: Vec<(WithdrawalEventType, u64)>) -> Result<Self, Self::Error> {
        Self::new(entries)
    }
}

impl Config {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let cfg = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse config yaml at {}", path.display()))?;
        Ok(cfg)
    }

    pub fn next_event_delay(&self, source: WithdrawalEventType) -> Option<u64> {
        self.next_event_delays.get_delay(source)
    }

    /// The PCR allowlist decoded from `current_build` + `prev_builds`.
    pub fn pcr_allowlist(&self) -> PcrAllowlist {
        self.pcr_allowlist.clone()
    }
}
