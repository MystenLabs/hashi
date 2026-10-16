// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The monitor's config file: the identity of one deployment.
//!
//! Why it exists: the file holds what differs between environments or changes
//! over time, such as the guardian bucket, the accepted enclave builds, the
//! Hashi package and the RPC endpoints. The timing bounds describe the
//! protocol and are the same everywhere, so they live in `timing`, not here.
//!
//! How it works:
//! 1. `load_yaml` parses the file into a YAML tree.
//! 2. Every string value of the form `env:NAME` is replaced by the value of
//!    the environment variable `NAME`. This keeps bucket names, endpoints and
//!    credentials out of the file.
//! 3. The tree is deserialized. Unknown keys are an error, so a typo cannot
//!    be ignored.
//!
//! Assumptions:
//! - `audit.sample.yaml` is the reference for the file's shape. The
//!   deployment in sui-operations stores that shape verbatim.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::S3Credentials;
use serde::Deserialize;

use crate::timing::Timing;

/// Configuration shared by the batch and continuous monitor modes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The timing bounds in force. Not read from the file: production uses
    /// the protocol set in `timing`, and tests set their own.
    #[serde(skip)]
    pub timing: Timing,

    pub deployment: DeploymentConfig,
    /// Omit to use AWS's default credential chain.
    pub s3_credentials: Option<S3Credentials>,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiConfig {
    /// Sui RPC endpoint.
    pub rpc_url: String,

    /// Original Hashi package: the event and object types the monitor reads keep
    /// its address across upgrades.
    pub package_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BtcConfig {
    /// Bitcoin JSON-RPC endpoint.
    pub rpc_url: String,

    /// Optional HTTP headers for the JSON-RPC provider, such as the
    /// authorization a hosted node needs.
    #[serde(default)]
    pub http_headers: BTreeMap<String, String>,
}

impl Config {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        Self::from_yaml(&text)
            .with_context(|| format!("failed to load config yaml at {}", path.display()))
    }

    /// Parse a config file's text. See the module doc for the `env:` rule.
    pub fn from_yaml(text: &str) -> anyhow::Result<Self> {
        let mut tree: serde_yaml::Value =
            serde_yaml::from_str(text).context("failed to parse config yaml")?;
        resolve_env_references(&mut tree, "")?;
        serde_yaml::from_value(tree).context("failed to parse config yaml")
    }
}

/// Replace every `env:NAME` string under `value` with the environment
/// variable `NAME`. `path` names the value in errors.
fn resolve_env_references(value: &mut serde_yaml::Value, path: &str) -> anyhow::Result<()> {
    match value {
        serde_yaml::Value::String(text) => {
            if let Some(variable) = text.strip_prefix("env:") {
                anyhow::ensure!(
                    !variable.is_empty(),
                    "{path}: environment variable name is empty"
                );
                *text = std::env::var(variable).with_context(|| {
                    format!("{path}: environment variable {variable} is not set")
                })?;
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            for (key, child) in mapping.iter_mut() {
                let key = key.as_str().unwrap_or("?");
                resolve_env_references(child, &format!("{path}.{key}"))?;
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                resolve_env_references(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
impl Config {
    /// A regtest config with `Timing::for_tests`, unreachable RPC endpoints,
    /// and explicit S3 credentials. Tests override the fields they exercise.
    pub fn for_tests() -> Self {
        Self {
            timing: Timing::for_tests(),
            deployment: DeploymentConfig {
                bucket_info: hashi_types::guardian::S3BucketInfo {
                    name: "bucket".to_string(),
                    region: "us-east-1".to_string(),
                },
                retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
                bitcoin_network: bitcoin::Network::Regtest,
                pcr_allowlist: hashi_types::guardian::PcrAllowlist::new(
                    hashi_types::guardian::BuildPcrs::mock_for_testing("", 1),
                    vec![],
                )
                .expect("valid PCR allowlist"),
            },
            s3_credentials: Some(S3Credentials {
                access_key: "access-key".to_string(),
                secret_key: "secret-key".to_string(),
                session_token: None,
            }),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
                package_id: format!("0x{}", "11".repeat(32)),
            },
            btc: BtcConfig {
                rpc_url: "http://btc".to_string(),
                http_headers: BTreeMap::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config_yaml() -> String {
        include_str!("../audit.sample.yaml")
            .replace("<PCR0_HEX_FROM_VERIFIED_BUILD>", &"11".repeat(48))
    }

    #[test]
    fn the_sample_parses_once_its_placeholder_is_filled() {
        let sample = include_str!("../audit.sample.yaml");
        assert!(Config::from_yaml(sample).is_err());

        // Cargo and nextest set CARGO_PKG_NAME for test processes.
        let config = Config::from_yaml(&sample_config_yaml()).unwrap();

        assert_eq!(config.deployment.bitcoin_network, bitcoin::Network::Signet);
        assert!(config.s3_credentials.is_none());
        assert_eq!(config.btc.rpc_url, env!("CARGO_PKG_NAME"));
        assert_eq!(
            config.timing.sui_lookback(),
            Timing::default().sui_lookback()
        );
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let yaml = format!("{}\ntyping: {{}}\n", sample_config_yaml());

        let error = format!("{:#}", Config::from_yaml(&yaml).unwrap_err());

        assert!(error.contains("unknown field `typing`"), "{error}");
    }

    #[test]
    fn env_references_resolve_anywhere_in_the_file() {
        let yaml = sample_config_yaml()
            .replace(
                "rpc_url: \"https://fullnode.testnet.sui.io:443\"",
                "rpc_url: \"env:CARGO_PKG_NAME\"",
            )
            .replace(
                "name: \"hashi-guardian-logs\"",
                "name: \"env:CARGO_PKG_NAME\"",
            )
            .replace(
                "  # http_headers:\n  #   Origin: \"https://example.com\"",
                "  http_headers:\n    Origin: \"env:CARGO_PKG_NAME\"",
            );

        let config = Config::from_yaml(&yaml).unwrap();

        assert_eq!(config.sui.rpc_url, env!("CARGO_PKG_NAME"));
        assert_eq!(config.deployment.bucket_info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(config.btc.http_headers["Origin"], env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn an_unset_environment_variable_names_its_key() {
        let yaml = sample_config_yaml().replace(
            "rpc_url: \"env:CARGO_PKG_NAME\"",
            "rpc_url: \"env:HASHI_MONITOR_TEST_UNSET_VARIABLE\"",
        );

        let error = format!("{:#}", Config::from_yaml(&yaml).unwrap_err());

        assert!(
            error.contains(".btc.rpc_url") && error.contains("HASHI_MONITOR_TEST_UNSET_VARIABLE"),
            "{error}"
        );
    }

    #[test]
    fn an_empty_environment_variable_name_is_an_error() {
        let yaml =
            sample_config_yaml().replace("rpc_url: \"env:CARGO_PKG_NAME\"", "rpc_url: \"env:\"");

        let error = format!("{:#}", Config::from_yaml(&yaml).unwrap_err());

        assert!(error.contains(".btc.rpc_url"), "{error}");
    }
}
