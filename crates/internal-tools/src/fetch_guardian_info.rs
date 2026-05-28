// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fetch a deployed guardian's signing public key.
//!
//! Calls `GuardianService/GetGuardianInfo` and prints the hex-encoded
//! Ed25519 `signing_pub_key` to stdout. Used by the deploy workflow to feed
//! `hashi publish --guardian-public-key` so the key gets recorded on chain.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;

#[derive(Parser)]
pub struct Args {
    /// gRPC endpoint of the deployed guardian (e.g. `http://localhost:3000`).
    #[arg(long, env = "GUARDIAN_ENDPOINT")]
    pub endpoint: String,
}

pub async fn run(args: Args) -> Result<()> {
    let mut client = GuardianServiceClient::connect(args.endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", args.endpoint))?;
    let resp = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info = GetGuardianInfoResponse::try_from(resp)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    println!("{}", hex::encode(info.signing_pub_key.as_bytes()));
    Ok(())
}
