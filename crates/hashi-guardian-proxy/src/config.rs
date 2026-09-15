// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Environment-driven proxy configuration (matches the guardian's minimal,
//! env-only config style). TLS for node traffic terminates at the fronting
//! load balancer, so the proxy itself serves plaintext h2c.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;

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
    /// TTL for the single-slot `/info` response cache
    /// (`INFO_CACHE_TTL_MS`, default 1000).
    pub info_cache_ttl: Duration,
    /// TCP connect timeout to the backend
    /// (`GUARDIAN_CONNECT_TIMEOUT_SECS`, default 5).
    pub connect_timeout: Duration,
    /// HTTP/2 keepalive ping interval to the backend
    /// (`GUARDIAN_KEEPALIVE_SECS`, default 5).
    pub keepalive_interval: Duration,
    /// The guardian's S3 log bucket, read for the relay's KP roster
    /// (`GUARDIAN_LOG_BUCKET` + `GUARDIAN_LOG_REGION`, required). Credentials
    /// come from the AWS default provider chain.
    pub log_bucket: String,
    pub log_region: String,
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
        let info_cache_ttl = Duration::from_millis(parse_env_u64("INFO_CACHE_TTL_MS", 1000)?);
        let connect_timeout =
            Duration::from_secs(parse_env_u64("GUARDIAN_CONNECT_TIMEOUT_SECS", 5)?);
        let keepalive_interval = Duration::from_secs(parse_env_u64("GUARDIAN_KEEPALIVE_SECS", 5)?);
        let log_bucket = std::env::var("GUARDIAN_LOG_BUCKET")
            .context("GUARDIAN_LOG_BUCKET must be set (the guardian's S3 log bucket)")?;
        let log_region = std::env::var("GUARDIAN_LOG_REGION")
            .context("GUARDIAN_LOG_REGION must be set (region of the guardian's S3 log bucket)")?;
        Ok(Self {
            backend_url,
            standby_backend_url,
            listen_addr,
            info_cache_ttl,
            connect_timeout,
            keepalive_interval,
            log_bucket,
            log_region,
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
