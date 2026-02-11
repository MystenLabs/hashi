use std::path::Path;

use serde::Deserialize;

/// Configuration for the cursorless batch auditor.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Liveness delay bound for E1 -> E2.
    pub e1_e2_delay_secs: u64,

    /// Liveness delay bound for E2 -> E3.
    pub e2_e3_delay_secs: u64,

    /// Liveness delay bound for E3 -> E4.
    pub e3_e4_delay_secs: u64,

    /// Extra slack to account for clock skew and ingestion jitter (default: 60s).
    #[serde(default = "default_slack_secs")]
    pub slack_secs: u64,

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

fn default_slack_secs() -> u64 {
    60
}

impl Config {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let cfg = serde_yaml::from_slice(&bytes)?;
        Ok(cfg)
    }
}
