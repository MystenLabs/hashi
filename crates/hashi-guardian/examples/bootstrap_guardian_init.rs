// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dev-mode bootstrap: drives a fresh hashi-guardian from heartbeating-only
//! to fully-initialized in one run. Generates BTC master + shares locally,
//! calls `OperatorInit`, `GetGuardianInfo` (to grab the enclave's encryption
//! pubkey), then `ProvisionerInit` until the guardian reaches THRESHOLD shares.
//!
//! Required env: `AWS_S3_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, `HASHI_REFILL_RATE_SATS_PER_SEC`,
//! `HASHI_MAX_BUCKET_CAPACITY_SATS`, `HASHI_COMMITTEE_THRESHOLD`.
//! Optional env: `GUARDIAN_ENDPOINT` (default `http://localhost:3000`),
//! `BITCOIN_NETWORK` (default `signet`).
//!
//! Caveat: the committee submitted to the guardian is a mock single-member
//! committee. The guardian reaches fully-initialized state (so hashi-server
//! can seed its local limiter from `GetGuardianInfo`), but the committee
//! mismatch means actual signed withdrawals will fail signature verification.
//! Real-committee integration is a separate follow-up.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use hashi_guardian::dev_bootstrap;
use hashi_types::guardian::crypto::THRESHOLD;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::proto_conversions::share_commitment_to_pb;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hpke::Deserializable;
use rand::thread_rng;
use std::env;

const DEV_COMMITTEE_EPOCH: u64 = 0;

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("required env var `{name}` is not set"))
}

fn required_env_u64(name: &str) -> Result<u64> {
    required_env(name)?
        .parse::<u64>()
        .map_err(|e| anyhow!("env var `{name}` is not a valid u64: {e}"))
}

fn parse_network(s: &str) -> Result<pb::Network> {
    pb::Network::from_str_name(&s.to_ascii_uppercase()).ok_or_else(|| {
        anyhow!("unknown BITCOIN_NETWORK `{s}`; expected mainnet/testnet/regtest/signet")
    })
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
    let region = required_env("AWS_REGION")?;
    let access_key = required_env("AWS_ACCESS_KEY_ID")?;
    let secret_key = required_env("AWS_SECRET_ACCESS_KEY")?;
    let network_str = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "signet".to_string());
    let network = parse_network(&network_str)?;
    let refill_rate = required_env_u64("HASHI_REFILL_RATE_SATS_PER_SEC")?;
    let max_capacity = required_env_u64("HASHI_MAX_BUCKET_CAPACITY_SATS")?;
    let committee_threshold = required_env_u64("HASHI_COMMITTEE_THRESHOLD")?;

    tracing::info!(
        endpoint = %endpoint,
        bucket = %bucket,
        region = %region,
        network = ?network,
        refill_rate, max_capacity, committee_threshold,
        "connecting to guardian"
    );

    let mut rng = thread_rng();
    let material = dev_bootstrap::generate_dev_share_material(&mut rng);
    tracing::info!(master_pubkey = %hex::encode(material.master_pubkey.serialize()),
        "generated dev share material");

    let mut client = GuardianServiceClient::connect(endpoint.clone())
        .await
        .with_context(|| format!("failed to connect to guardian at {endpoint}"))?;

    // ── 1. OperatorInit ────────────────────────────────────────────────
    let operator_init_req = pb::OperatorInitRequest {
        s3_config: Some(pb::S3Config {
            access_key: Some(access_key),
            secret_key: Some(secret_key),
            bucket_name: Some(bucket),
            region: Some(region),
        }),
        share_commitments: material
            .commitments
            .iter()
            .map(share_commitment_to_pb)
            .collect(),
        network: Some(network as i32),
    };
    tracing::info!("calling OperatorInit");
    client
        .operator_init(operator_init_req)
        .await
        .context("OperatorInit RPC failed")?;
    tracing::info!("OperatorInit complete");

    // ── 2. GetGuardianInfo to pick up the enclave encryption pubkey ────
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    let enc_pubkey = EncPubKey::from_bytes(&info.signed_info.data.encryption_pubkey)
        .map_err(|e| anyhow!("decode guardian encryption pubkey: {e:?}"))?;

    // ── 3. ProvisionerInit × THRESHOLD ─────────────────────────────────
    let committee = dev_bootstrap::mock_dev_committee(DEV_COMMITTEE_EPOCH);
    let withdrawal_config =
        dev_bootstrap::build_withdrawal_config(committee_threshold, refill_rate, max_capacity);
    let limiter_state = dev_bootstrap::full_bucket_state(&withdrawal_config);
    let state = ProvisionerInitState::new(
        committee,
        withdrawal_config,
        limiter_state,
        material.master_pubkey,
    )
    .map_err(|e| anyhow!("build ProvisionerInitState: {e:?}"))?;

    for (i, share) in material.shares.iter().take(THRESHOLD).enumerate() {
        tracing::info!("submitting ProvisionerInit share {}/{THRESHOLD}", i + 1);
        let req = ProvisionerInitRequest::build_from_share_and_state(
            share,
            &enc_pubkey,
            state.clone(),
            &mut rng,
        );
        let pb_req = provisioner_init_request_to_pb(req)
            .map_err(|e| anyhow!("encode ProvisionerInitRequest: {e:?}"))?;
        client
            .provisioner_init(pb_req)
            .await
            .with_context(|| format!("ProvisionerInit share {} RPC failed", i + 1))?;
    }

    println!("Guardian fully initialized.");
    println!(
        "  master pubkey:           {}",
        hex::encode(material.master_pubkey.serialize())
    );
    println!("  refill_rate_sats_per_sec: {refill_rate}");
    println!("  max_bucket_capacity_sats: {max_capacity}");
    println!("  committee_threshold:      {committee_threshold}");
    Ok(())
}
