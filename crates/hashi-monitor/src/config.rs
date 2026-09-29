// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use anyhow::anyhow;
use hashi_types::guardian::DeploymentConfig;
use hashi_types::guardian::S3Credentials;
use hashi_types::guardian::time::UnixSeconds;
use serde::Deserialize;

use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;

/// Configuration shared by the batch and continuous monitor modes.
///
/// All duration values are expressed in seconds.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Maximum allowed delay between consecutive events.
    pub next_event_delays: NextEventDelays,

    /// How far each event's successor may occur before it (default: 300s for E1,
    /// 2h for E2). Keep E1's at least the guardian's 5-minute request clock tolerance.
    #[serde(default = "default_clock_skews")]
    pub clock_skews: ClockSkews,

    /// How far a deposit's Bitcoin block time may be after its Sui confirmation
    /// (default: 300s).
    #[serde(default = "default_deposit_clock_skew")]
    pub deposit_clock_skew: u64,

    /// How far before the guardian audit start to search Sui for withdrawal
    /// predecessor events (default: 1 hour).
    #[serde(default = "default_withdrawal_predecessor_lookback")]
    pub withdrawal_predecessor_lookback: u64,

    pub deployment: DeploymentConfig,
    /// Omit to use AWS's default credential chain.
    pub s3_credentials: Option<S3Credentials>,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

/// The maximum allowed delay between an event and its successor.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Vec<(WithdrawalEventType, u64)>")]
pub struct NextEventDelays(Vec<(WithdrawalEventType, u64)>);

/// How far an event's successor may occur before it.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Vec<(WithdrawalEventType, u64)>")]
pub struct ClockSkews(Vec<(WithdrawalEventType, u64)>);

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

fn default_clock_skews() -> ClockSkews {
    // E3's block time is set by its miner and need only exceed the median of the
    // last 11 blocks, which trails real time by about an hour.
    ClockSkews::new(vec![
        (WithdrawalEventType::E1HashiApproved, 5 * 60),
        (WithdrawalEventType::E2GuardianApproved, 2 * 60 * 60),
    ])
    .expect("one entry per non-terminal event")
}

fn default_deposit_clock_skew() -> u64 {
    300
}

fn default_withdrawal_predecessor_lookback() -> u64 {
    60 * 60
}

fn check_one_entry_per_non_terminal_event(
    kind: &str,
    inputs: &[(WithdrawalEventType, u64)],
) -> anyhow::Result<()> {
    let mut seen_sources = Vec::new();
    for (source, _) in inputs {
        if seen_sources.contains(source) {
            return Err(anyhow!("duplicate {kind} entry for {source:?}"));
        }
        seen_sources.push(*source);
    }

    if seen_sources.contains(&WithdrawalEventType::TERMINAL_EVENT) {
        return Err(anyhow!("{kind} for terminal event is not allowed"));
    }

    for source in WithdrawalEventType::NON_TERMINAL_EVENTS {
        if !seen_sources.contains(&source) {
            return Err(anyhow!("missing {kind} entry for {source:?}"));
        }
    }

    Ok(())
}

impl NextEventDelays {
    /// The constructor ensures that there is one entry for every non-terminal event.
    pub fn new(inputs: Vec<(WithdrawalEventType, u64)>) -> anyhow::Result<Self> {
        check_one_entry_per_non_terminal_event("delay", &inputs)?;
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

impl ClockSkews {
    /// The constructor ensures that there is one entry for every non-terminal event.
    pub fn new(inputs: Vec<(WithdrawalEventType, u64)>) -> anyhow::Result<Self> {
        check_one_entry_per_non_terminal_event("clock skew", &inputs)?;
        Ok(Self(inputs))
    }

    pub fn get_skew(&self, source: WithdrawalEventType) -> Option<u64> {
        self.0
            .iter()
            .find(|(event_source, _)| *event_source == source)
            .map(|(_, clock_skew_secs)| *clock_skew_secs)
    }

    pub fn max_skew(&self) -> u64 {
        self.0
            .iter()
            .map(|(_, clock_skew_secs)| *clock_skew_secs)
            .max()
            .unwrap_or_default()
    }
}

impl TryFrom<Vec<(WithdrawalEventType, u64)>> for ClockSkews {
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

    pub fn predecessor_deadline(&self, event: &MonitorWithdrawalEvent) -> UnixSeconds {
        let predecessor = event.event_type.predecessor().expect("has a predecessor");
        event.timestamp_secs
            + self
                .clock_skews
                .get_skew(predecessor)
                .expect("a predecessor has a successor")
    }

    pub fn successor_deadline(&self, event: &MonitorWithdrawalEvent) -> UnixSeconds {
        event.timestamp_secs
            + self
                .next_event_delay(event.event_type)
                .expect("has a successor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_config_contains_deployment_without_credentials() {
        let sample = include_str!("../audit.sample.yaml");
        assert!(serde_yaml::from_str::<Config>(sample).is_err());
        let sample = sample.replace("<PCR0_HEX_FROM_VERIFIED_BUILD>", &"11".repeat(48));
        let config: Config = serde_yaml::from_str(&sample).unwrap();
        assert_eq!(config.deployment.bitcoin_network, bitcoin::Network::Signet);
        assert!(config.s3_credentials.is_none());
    }

    #[test]
    fn clock_skews_default_to_a_looser_bound_before_a_block_time() {
        let config: Config = serde_yaml::from_str(include_str!("../audit.sample.yaml")).unwrap();

        let skew = |source| config.clock_skews.get_skew(source);
        assert_eq!(skew(WithdrawalEventType::E1HashiApproved), Some(300));
        assert_eq!(skew(WithdrawalEventType::E2GuardianApproved), Some(7_200));
        assert_eq!(config.deposit_clock_skew, 300);
    }

    #[test]
    fn clock_skews_need_an_entry_for_every_event_with_a_successor() {
        let yaml = format!(
            "{}\nclock_skews:\n  - [E2GuardianApproved, 3600]\n",
            include_str!("../audit.sample.yaml")
        );

        let error = serde_yaml::from_str::<Config>(&yaml)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("missing clock skew entry for E1HashiApproved"),
            "{error}"
        );
    }

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
