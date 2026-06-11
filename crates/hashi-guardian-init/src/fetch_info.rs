// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fetch deployed guardian's public keys.
//!
//! Calls `GuardianService/GetGuardianInfo` and prints a hex-encoded key
//! to stdout. Used by the deploy workflow to feed `hashi publish
//! --guardian-public-key` / `--guardian-btc-public-key` so the keys get
//! recorded on chain.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use clap::ValueEnum;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;

#[derive(Parser)]
pub struct Args {
    /// gRPC endpoint of the deployed guardian (e.g. `http://localhost:3000`).
    #[arg(long, env = "GUARDIAN_ENDPOINT")]
    pub endpoint: String,

    /// Which key to print.
    #[arg(long, value_enum, default_value_t = Field::SigningPubKey)]
    pub field: Field,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Field {
    /// Ed25519 RPC identity key (32 bytes hex).
    SigningPubKey,
    /// X-only enclave BTC pubkey (32 bytes hex). Absent before `provisioner_init`.
    EnclaveBtcPubkey,
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
    match args.field {
        Field::SigningPubKey => {
            println!("{}", hex::encode(info.signing_pub_key.as_bytes()));
        }
        Field::EnclaveBtcPubkey => {
            let btc_pk = info.signed_info.data.enclave_btc_pubkey.ok_or_else(|| {
                anyhow!(
                    "guardian /info did not return enclave_btc_pubkey; \
                     provisioner_init may not have completed"
                )
            })?;
            println!("{}", hex::encode(btc_pk.serialize()));
        }
    }
    Ok(())
}
