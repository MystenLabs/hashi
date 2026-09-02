// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Environment-driven proxy configuration (matches the guardian's minimal,
//! env-only config style). TLS for node traffic terminates at the fronting
//! load balancer, so the proxy itself serves plaintext h2c.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use bitcoin::Network;

use crate::remote_write;
use crate::remote_write::RemoteWriteConfig;

pub struct Config {
    /// gRPC endpoint of the enclave guardian to forward to, e.g.
    /// `http://10.0.1.20:3000` (`GUARDIAN_BACKEND_URL`, required).
    pub backend_url: String,
    /// gRPC endpoint of a standby guardian being armed (`STANDBY_GUARDIAN_URL`,
    /// optional). When set, the relay — share submissions and
    /// `GetProvisioningTargetInfo` — targets it while node-facing forwarding
    /// stays on the active backend; unset, the relay provisions the active
    /// backend (first deploy).
    pub standby_backend_url: Option<String>,
    /// Address the proxy serves everything on — gRPC (forwarder + relay + health)
    /// and the HTTP `/info` + `/health` (`PROXY_LISTEN_ADDR`, default `0.0.0.0:3000`).
    pub listen_addr: SocketAddr,
    /// Address the prometheus `/metrics` endpoint listens on
    /// (`METRICS_LISTEN_ADDR`, default `0.0.0.0:9184`).
    pub metrics_listen_addr: SocketAddr,
    /// TTL for the single-slot `/info` response cache
    /// (`INFO_CACHE_TTL_MS`, default 1000).
    pub info_cache_ttl: Duration,
    /// TCP connect timeout to the backend
    /// (`GUARDIAN_CONNECT_TIMEOUT_SECS`, default 5).
    pub connect_timeout: Duration,
    /// HTTP/2 keepalive ping interval to the backend
    /// (`GUARDIAN_KEEPALIVE_SECS`, default 5).
    pub keepalive_interval: Duration,
    /// The guardian's S3 log bucket, read as the wid cache's durable tier
    /// (`GUARDIAN_LOG_BUCKET` + `GUARDIAN_LOG_REGION`, required). Credentials
    /// come from the AWS default provider chain.
    pub log_bucket: String,
    pub log_region: String,
    /// BTC network the guardian signs for (`BTC_NETWORK`, required:
    /// bitcoin|testnet|signet|regtest). Must match the guardian's config; used
    /// to recompute sighashes when verifying a log replay.
    pub btc_network: Network,
    /// Push metrics to a Prometheus remote-write endpoint; `None` leaves them
    /// on `/metrics`, which nothing can scrape (`MIMIR_URL`, `MIMIR_USERNAME`
    /// default `incoming_metrics`, `MIMIR_PASSWORD`, `MIMIR_PUSH_INTERVAL_SECS`
    /// default 60, `MIMIR_EXTERNAL_LABELS` comma-separated `k=v`).
    pub remote_write: Option<RemoteWriteConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let backend_url = std::env::var("GUARDIAN_BACKEND_URL")
            .context("GUARDIAN_BACKEND_URL must be set (gRPC endpoint of the enclave guardian)")?;
        let standby_backend_url = std::env::var("STANDBY_GUARDIAN_URL")
            .ok()
            .filter(|url| !url.is_empty());
        let listen_addr = std::env::var("PROXY_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse()
            .context("PROXY_LISTEN_ADDR must be a valid socket address")?;
        let metrics_listen_addr = std::env::var("METRICS_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9184".to_string())
            .parse()
            .context("METRICS_LISTEN_ADDR must be a valid socket address")?;
        let info_cache_ttl = Duration::from_millis(parse_env_u64("INFO_CACHE_TTL_MS", 1000)?);
        let connect_timeout =
            Duration::from_secs(parse_env_u64("GUARDIAN_CONNECT_TIMEOUT_SECS", 5)?);
        let keepalive_interval = Duration::from_secs(parse_env_u64("GUARDIAN_KEEPALIVE_SECS", 5)?);
        let log_bucket = std::env::var("GUARDIAN_LOG_BUCKET")
            .context("GUARDIAN_LOG_BUCKET must be set (the guardian's S3 log bucket)")?;
        let log_region = std::env::var("GUARDIAN_LOG_REGION")
            .context("GUARDIAN_LOG_REGION must be set (region of the guardian's S3 log bucket)")?;
        let btc_network = std::env::var("BTC_NETWORK")
            .context("BTC_NETWORK must be set (bitcoin|testnet|signet|regtest)")?
            .parse()
            .context("BTC_NETWORK must be one of bitcoin|testnet|signet|regtest")?;
        let remote_write = match std::env::var("MIMIR_URL").ok().filter(|u| !u.is_empty()) {
            None => None,
            Some(url) => {
                let interval_secs = parse_env_u64("MIMIR_PUSH_INTERVAL_SECS", 60)?;
                // `tokio::time::interval` panics on zero, and a panic aborts this binary.
                anyhow::ensure!(
                    interval_secs > 0,
                    "MIMIR_PUSH_INTERVAL_SECS must be at least 1"
                );
                Some(RemoteWriteConfig {
                    url: url.parse().context("MIMIR_URL must be a valid URL")?,
                    username: std::env::var("MIMIR_USERNAME")
                        .unwrap_or_else(|_| "incoming_metrics".to_string()),
                    password: std::env::var("MIMIR_PASSWORD")
                        .context("MIMIR_PASSWORD must be set when MIMIR_URL is")?,
                    interval: Duration::from_secs(interval_secs),
                    external_labels: remote_write::parse_external_labels(
                        &std::env::var("MIMIR_EXTERNAL_LABELS").unwrap_or_default(),
                    )
                    .context("MIMIR_EXTERNAL_LABELS")?,
                })
            }
        };
        Ok(Self {
            backend_url,
            standby_backend_url,
            listen_addr,
            metrics_listen_addr,
            info_cache_ttl,
            connect_timeout,
            keepalive_interval,
            log_bucket,
            log_region,
            btc_network,
            remote_write,
        })
    }
}

fn parse_env_u64(key: &str, default: u64) -> Result<u64> {
    match std::env::var(key) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("{key} must be a non-negative integer")),
        Err(_) => Ok(default),
    }
}
