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

/// Configuration for the cursorless batch auditor.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Maximum allowed delay between consecutive events.
    pub next_event_delays: NextEventDelays,

    /// E_{i+1} is allowed to occur up to clock_skew seconds before E_i (default: 300s).
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,

    pub guardian_s3: UnresolvedS3Config,
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
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcConfig {
    /// Bitcoin JSON-RPC endpoint.
    ///
    /// Prefix with `env:` to read the URL from an environment variable, which
    /// keeps provider API keys out of YAML.
    pub rpc_url: String,

    /// Optional HTTP headers for the JSON-RPC provider.
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

fn default_clock_skew() -> u64 {
    300
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
