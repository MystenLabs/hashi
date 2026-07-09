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

pub struct Config {
    /// gRPC endpoint of the enclave guardian to forward to, e.g.
    /// `http://10.0.1.20:3000` (`GUARDIAN_BACKEND_URL`, required).
    pub backend_url: String,
    /// Address the proxy listens on for node traffic
    /// (`PROXY_LISTEN_ADDR`, default `0.0.0.0:3000`).
    pub listen_addr: SocketAddr,
    /// Address the prometheus `/metrics` endpoint listens on
    /// (`METRICS_LISTEN_ADDR`, default `0.0.0.0:9184`).
    pub metrics_listen_addr: SocketAddr,
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
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let backend_url = std::env::var("GUARDIAN_BACKEND_URL")
            .context("GUARDIAN_BACKEND_URL must be set (gRPC endpoint of the enclave guardian)")?;
        let listen_addr = std::env::var("PROXY_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse()
            .context("PROXY_LISTEN_ADDR must be a valid socket address")?;
        let metrics_listen_addr = std::env::var("METRICS_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9184".to_string())
            .parse()
            .context("METRICS_LISTEN_ADDR must be a valid socket address")?;
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
        Ok(Self {
            backend_url,
            listen_addr,
            metrics_listen_addr,
            connect_timeout,
            keepalive_interval,
            log_bucket,
            log_region,
            btc_network,
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
