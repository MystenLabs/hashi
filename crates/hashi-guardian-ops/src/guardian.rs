// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What the proxy's public `/info` reports about the guardian it fronts.

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read_json;

/// The proxy's public `/info`, which describes the guardian it fronts. Its u64s are strings.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub signing_pub_key: Option<String>,
    pub btc_pubkey: Option<String>,
    pub git_revision: Option<String>,
    pub committee_epoch: Option<String>,
}

pub fn proxy_info(ctx: &Ctx) -> Result<ProxyInfo> {
    let url = ctx.env.proxy_url()?.url;
    read_json(
        ctx.exec,
        &Cmd::new("curl")
            .args(["-fsS", "--max-time", "15"])
            .arg(format!("{url}/info")),
    )
    .with_context(|| format!("The proxy does not answer at {url}/info."))
}
