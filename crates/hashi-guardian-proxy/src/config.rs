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
use hashi_types::pgp::Fingerprint;

pub struct Config {
    /// gRPC endpoint of the enclave guardian to forward to, e.g.
    /// `http://10.0.1.20:3000` (`GUARDIAN_BACKEND_URL`, required).
    pub backend_url: String,
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
    /// PGP fingerprints of the KPs allowed to submit shares through the relay
    /// (`AUTHORIZED_KP_FINGERPRINTS`, comma-separated, default empty). Empty
    /// fail-closes the relay; the cache/forwarding paths are unaffected.
    pub authorized_kp_fingerprints: Vec<Fingerprint>,
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
        let authorized_kp_fingerprints =
            parse_kp_roster(&std::env::var("AUTHORIZED_KP_FINGERPRINTS").unwrap_or_default())?;
        Ok(Self {
            backend_url,
            listen_addr,
            metrics_listen_addr,
            info_cache_ttl,
            connect_timeout,
            keepalive_interval,
            log_bucket,
            log_region,
            btc_network,
            authorized_kp_fingerprints,
        })
    }
}

/// Parse the comma-separated KP roster into canonical fingerprints (spacing
/// and case insensitive), so a config typo fails at startup.
fn parse_kp_roster(raw: &str) -> Result<Vec<Fingerprint>> {
    let mut roster = Vec::new();
    for entry in raw.split(',') {
        if entry.trim().is_empty() {
            continue;
        }
        let fp = entry
            .parse::<Fingerprint>()
            .ok()
            // Sequoia parses odd-sized hex into `Fingerprint::Unknown` rather
            // than failing; only real v4/v6 shapes can name a KP cert.
            .filter(|fp| matches!(fp, Fingerprint::V4(_) | Fingerprint::V6(_)))
            .with_context(|| {
                format!(
                    "AUTHORIZED_KP_FINGERPRINTS entry {entry:?} is not a PGP fingerprint \
                     (expected 40 or 64 hex chars; spacing and case are ignored)"
                )
            })?;
        roster.push(fp);
    }
    Ok(roster)
}

fn parse_env_u64(key: &str, default: u64) -> Result<u64> {
    match std::env::var(key) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("{key} must be a non-negative integer")),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kp_roster_accepts_spaced_and_bare_hex() {
        // Spaced gpg form + bare lowercase hex, with a trailing comma.
        let raw = "AAAA BBBB CCCC DDDD EEEE 1111 2222 3333 4444 5555,\
                   aaaabbbbccccddddeeee1111222233334444ffff,";
        let roster = parse_kp_roster(raw).unwrap();
        let expected: Vec<Fingerprint> = vec![
            "AAAABBBBCCCCDDDDEEEE11112222333344445555".parse().unwrap(),
            "AAAABBBBCCCCDDDDEEEE1111222233334444FFFF".parse().unwrap(),
        ];
        assert_eq!(roster, expected);
    }

    #[test]
    fn parse_kp_roster_empty_and_invalid() {
        assert!(parse_kp_roster("").unwrap().is_empty());
        assert!(parse_kp_roster("not-a-fingerprint").is_err());
        // Hex but not a fingerprint length.
        assert!(parse_kp_roster("ABCD").is_err());
    }
}
