use std::path::Path;

use crate::domain::WithdrawalEventType;
use serde::Deserialize;

/// Configuration for the cursorless batch auditor.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Next event delay bound for E1 -> E2.
    pub e1_e2_delay_secs: u64,

    /// Next event delay bound for E2 -> E3.
    pub e2_e3_delay_secs: u64,

    /// E_{i+1} is allowed to occur up to clock_skew seconds before E_i (default: 60s).
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,

    /// Poll interval for continuous auditor (default: 300s).
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,

    pub guardian: GuardianConfig,
    pub sui: SuiConfig,
    pub btc: BtcConfig,
}

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
    60
}

fn default_poll_interval_secs() -> u64 {
    300 // 5 mins
}

impl Config {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let cfg = serde_yaml::from_slice(&bytes)?;
        Ok(cfg)
    }

    pub fn next_event_delay(&self, source: WithdrawalEventType) -> Option<u64> {
        match source {
            WithdrawalEventType::E1HashiApproved => Some(self.e1_e2_delay_secs),
            WithdrawalEventType::E2GuardianApproved => Some(self.e2_e3_delay_secs),
            WithdrawalEventType::E3BtcConfirmed => None, // no next event
        }
    }
}
