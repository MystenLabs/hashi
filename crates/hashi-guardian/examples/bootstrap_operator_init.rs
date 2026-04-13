// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap a hashi-guardian instance by calling `OperatorInit` with AWS S3
//! credentials and dummy share commitments. This is a *development-only* helper
//! intended to make a running guardian fully initialized enough to emit
//! heartbeats against a real AWS S3 bucket with Object Lock enabled.
//!
//! It does **not** run a real `SetupNewKey` + `ProvisionerInit` flow — the
//! resulting guardian will accept `OperatorInit` and start heartbeating, but
//! will not be able to sign withdrawals (because no real key shares are ever
//! combined). For production bootstrap use the operator + KP flow, not this.
//!
//! Usage (from repo root):
//!
//!     GUARDIAN_ENDPOINT=http://localhost:3000 \
//!     AWS_S3_BUCKET=mysten-hashi-guardian-dev \
//!     AWS_S3_REGION=us-west-2 \
//!     AWS_ACCESS_KEY_ID=... \
//!     AWS_SECRET_ACCESS_KEY=... \
//!     BITCOIN_NETWORK=signet \
//!     cargo run -p hashi-guardian --example bootstrap_operator_init

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::GuardianShareCommitment;
use hashi_types::proto::GuardianShareId;
use hashi_types::proto::Network as ProtoNetwork;
use hashi_types::proto::OperatorInitRequest;
use hashi_types::proto::S3Config as ProtoS3Config;
use std::env;

/// Must match `hashi_types::guardian::crypto::NUM_OF_SHARES`. We provide that
/// many dummy commitments because `OperatorInitRequest` stores them verbatim;
/// actual share verification happens later in `ProvisionerInit`, which this
/// helper does not drive.
const NUM_OF_SHARES: u32 = 5;

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("required env var `{name}` is not set"))
}

fn parse_network(s: &str) -> Result<ProtoNetwork> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(ProtoNetwork::Mainnet),
        "testnet" => Ok(ProtoNetwork::Testnet),
        "regtest" => Ok(ProtoNetwork::Regtest),
        "signet" => Ok(ProtoNetwork::Signet),
        other => Err(anyhow!(
            "unknown BITCOIN_NETWORK `{other}`; expected mainnet/testnet/regtest/signet"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let endpoint =
        env::var("GUARDIAN_ENDPOINT").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let bucket = required_env("AWS_S3_BUCKET")?;
    let region = required_env("AWS_S3_REGION")?;
    let access_key = required_env("AWS_ACCESS_KEY_ID")?;
    let secret_key = required_env("AWS_SECRET_ACCESS_KEY")?;
    let network_str = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "signet".to_string());
    let network = parse_network(&network_str)?;

    tracing::info!(
        endpoint = %endpoint,
        bucket = %bucket,
        region = %region,
        network = ?network,
        "connecting to guardian"
    );

    let mut client = GuardianServiceClient::connect(endpoint.clone())
        .await
        .with_context(|| format!("failed to connect to guardian at {endpoint}"))?;

    let share_commitments: Vec<GuardianShareCommitment> = (1..=NUM_OF_SHARES)
        .map(|id| GuardianShareCommitment {
            id: Some(GuardianShareId { id: Some(id) }),
            digest_hex: Some(String::new()),
        })
        .collect();

    let request = OperatorInitRequest {
        s3_config: Some(ProtoS3Config {
            access_key: Some(access_key),
            secret_key: Some(secret_key),
            bucket_name: Some(bucket),
            region: Some(region),
        }),
        share_commitments,
        network: Some(network as i32),
    };

    tracing::info!("calling OperatorInit");
    let response = client
        .operator_init(request)
        .await
        .context("operator_init RPC failed")?;
    tracing::info!(?response, "OperatorInit returned successfully");
    println!("OperatorInit complete.");
    Ok(())
}
