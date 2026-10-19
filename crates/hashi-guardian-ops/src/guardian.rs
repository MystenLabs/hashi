// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What the proxy's public `/info` reports about the guardian it fronts.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read_json;

/// How old `/info` can be while the guardian still answers the proxy, which caches it for 30 seconds. When the
/// guardian stops answering, the proxy keeps serving its last view, however old.
pub const CURRENT_FOR: Duration = Duration::from_secs(90);

/// The proxy's public `/info`, which describes the guardian it fronts. Its u64s are strings.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub signing_pub_key: Option<String>,
    pub btc_pubkey: Option<String>,
    pub git_revision: Option<String>,
    pub committee_epoch: Option<String>,
    /// When the guardian answered, in milliseconds since the epoch.
    pub timestamp_ms: Option<String>,
}

impl ProxyInfo {
    /// How long ago the guardian answered, or `None` when `/info` doesn't say.
    pub fn age(&self) -> Option<Duration> {
        let answered = Duration::from_millis(self.timestamp_ms.as_deref()?.parse().ok()?);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        Some(now.saturating_sub(answered))
    }
}

pub fn proxy_info(ctx: &Ctx) -> Result<ProxyInfo> {
    let url = ctx.env.proxy_url()?.url;
    read_json(
        ctx.exec,
        &Cmd::new("curl")
            .args(["-q", "-fsS", "--max-time", "15"])
            .arg(format!("{url}/info")),
    )
    .with_context(|| format!("could not read the proxy's {url}/info"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_proxys_info() {
        // As the proxy's contract test writes it.
        let info: ProxyInfo = serde_json::from_str(
            r#"{"signingPubKey": "aa", "btcPubkey": "bb", "gitRevision": "cc", "committeeEpoch": "7", "timestampMs": "1720000000123", "limiter": null}"#,
        )
        .unwrap();
        assert_eq!(info.committee_epoch.as_deref(), Some("7"));
        assert!(info.age().unwrap() > CURRENT_FOR);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let current = ProxyInfo {
            timestamp_ms: Some((now.as_millis() - 5_000).to_string()),
            ..info.clone()
        };
        assert!(current.age().unwrap() < CURRENT_FOR);
        let unknown = ProxyInfo {
            timestamp_ms: None,
            ..info
        };
        assert_eq!(unknown.age(), None);
    }
}
