use anyhow::anyhow;
use serde::Deserialize;
use std::path::Path;

use crate::domain::WithdrawalEventType;

/// Configuration for the cursorless batch auditor.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Maximum allowed delay between consecutive events.
    pub next_event_delays: NextEventDelays,

    /// E_{i+1} is allowed to occur up to clock_skew seconds before E_i (default: 300s).
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,

    pub guardian: GuardianConfig,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

/// The maximum allowed delay between an event and it's successor in seconds.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Vec<(WithdrawalEventType, u64)>")]
pub struct NextEventDelays(Vec<(WithdrawalEventType, u64)>);

#[derive(Clone, Debug, Deserialize)]
pub struct GuardianConfig {
    /// S3 bucket holding Guardian logs.
    pub s3_bucket: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SuiConfig {
    /// Sui RPC endpoint.
    pub rpc_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcConfig {
    /// Sui RPC endpoint.
    pub rpc_url: String,
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
        let bytes = std::fs::read(path)?;
        let cfg = serde_yaml::from_slice(&bytes)?;
        Ok(cfg)
    }

    pub fn next_event_delay(&self, source: WithdrawalEventType) -> Option<u64> {
        self.next_event_delays.get_delay(source)
    }
}
