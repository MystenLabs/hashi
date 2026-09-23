// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use anyhow::anyhow;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::UnresolvedS3Config;
use serde::Deserialize;

use crate::domain::WithdrawalEventType;

/// Configuration shared by the batch and continuous monitor modes.
///
/// All duration values are expressed in seconds.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Maximum allowed delay between consecutive events.
    pub next_event_delays: NextEventDelays,

    /// E_{i+1} is allowed to occur up to `clock_skew` before E_i (default: 300s).
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,

    /// How far before the guardian audit start to search Sui for withdrawal
    /// predecessor events (default: 1 hour).
    #[serde(default = "default_withdrawal_predecessor_lookback")]
    pub withdrawal_predecessor_lookback: u64,

    pub guardian_s3: UnresolvedS3Config,
    #[serde(flatten)]
    pub pcr_allowlist: PcrAllowlist,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

/// The maximum allowed delay between an event and its successor.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Vec<(WithdrawalEventType, u64)>")]
pub struct NextEventDelays(Vec<(WithdrawalEventType, u64)>);

#[derive(Clone, Debug, Deserialize)]
pub struct SuiConfig {
    /// Sui RPC endpoint.
    pub rpc_url: String,

    /// Original Hashi package: the event and object types the monitor reads keep
    /// its address across upgrades.
    pub package_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcConfig {
    /// Bitcoin JSON-RPC endpoint.
    ///
    /// Prefix with `env:` to read the URL from an environment variable, which
    /// keeps provider API keys out of YAML.
    pub rpc_url: String,

    /// Optional HTTP headers for the JSON-RPC provider.
    ///
    /// Values accept the same `env:` prefix as `rpc_url`.
    #[serde(default)]
    pub http_headers: BTreeMap<String, String>,
}

impl BtcConfig {
    pub fn resolve_rpc_url(&self) -> anyhow::Result<String> {
        resolve_env_reference("rpc_url", &self.rpc_url)
    }

    pub fn resolve_http_headers(&self) -> anyhow::Result<BTreeMap<String, String>> {
        self.http_headers
            .iter()
            .map(|(name, value)| {
                let value = resolve_env_reference(&format!("{name} header"), value)?;
                Ok((name.clone(), value))
            })
            .collect()
    }
}

fn resolve_env_reference(field: &str, value: &str) -> anyhow::Result<String> {
    let Some(variable) = value.strip_prefix("env:") else {
        return Ok(value.to_string());
    };
    anyhow::ensure!(
        !variable.is_empty(),
        "bitcoin {field} environment variable name is empty"
    );
    std::env::var(variable)
        .with_context(|| format!("bitcoin {field} environment variable {variable} is not set"))
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

    pub fn max_delay(&self) -> u64 {
        self.0
            .iter()
            .map(|(_, next_event_delay_secs)| *next_event_delay_secs)
            .max()
            .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn btc_config(rpc_url: &str, headers: &[(&str, &str)]) -> BtcConfig {
        BtcConfig {
            rpc_url: rpc_url.to_string(),
            http_headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn http_header_values_resolve_env_references() {
        // Cargo and nextest set CARGO_PKG_NAME for test processes.
        let cfg = btc_config(
            "http://btc",
            &[
                ("Authorization", "env:CARGO_PKG_NAME"),
                ("Origin", "https://example.com"),
            ],
        );

        let headers = cfg.resolve_http_headers().unwrap();

        assert_eq!(headers["Authorization"], env!("CARGO_PKG_NAME"));
        assert_eq!(headers["Origin"], "https://example.com");
    }

    #[test]
    fn unset_header_environment_variable_is_an_error() {
        let cfg = btc_config(
            "http://btc",
            &[("Authorization", "env:HASHI_MONITOR_TEST_UNSET_VARIABLE")],
        );

        let error = cfg.resolve_http_headers().unwrap_err().to_string();

        assert!(
            error.contains("Authorization header")
                && error.contains("HASHI_MONITOR_TEST_UNSET_VARIABLE"),
            "{error}"
        );
    }

    #[test]
    fn empty_environment_variable_name_is_an_error() {
        assert!(btc_config("env:", &[]).resolve_rpc_url().is_err());
        assert!(
            btc_config("http://btc", &[("Authorization", "env:")])
                .resolve_http_headers()
                .is_err()
        );
    }
}
