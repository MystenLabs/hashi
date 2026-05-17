// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drives a fresh hashi-guardian from heartbeating-only to fully-initialized:
//! scrapes the live HashiCommittee off-chain, generates BTC master + shares,
//! calls `OperatorInit`, `GetGuardianInfo` (to grab the enclave's encryption
//! pubkey), then `ProvisionerInit` until the guardian reaches THRESHOLD shares.
//!
//! Lives in its own crate so the guardian image (which is built from a Docker
//! context that doesn't include `crates/hashi`) doesn't pick up a transitive
//! dep on the bridge node. The guardian and the bridge node stay decoupled at
//! the package level — they only meet on the wire via gRPC.
//!
//! Required env: `AWS_S3_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, `HASHI_REFILL_RATE_SATS_PER_SEC`,
//! `HASHI_MAX_BUCKET_CAPACITY_SATS`, `SUI_RPC_URL`, `HASHI_PACKAGE_ID`,
//! `HASHI_OBJECT_ID`.
//! Optional env: `GUARDIAN_ENDPOINT` (default `http://localhost:3000`),
//! `BITCOIN_NETWORK` (default `signet`).
//!
//! Re-run on committee rotation; the guardian holds an in-memory snapshot
//! keyed to the epoch we submit.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi::config::HashiIds;
use hashi::onchain::OnchainState;
use hashi_guardian::dev_bootstrap;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::crypto::THRESHOLD;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::proto_conversions::share_commitment_to_pb;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hpke::Deserializable;
use rand::thread_rng;
use std::env;
use std::str::FromStr;
use sui_sdk_types::Address as SuiAddress;

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("required env var `{name}` is not set"))
}

fn required_env_u64(name: &str) -> Result<u64> {
    required_env(name)?
        .parse::<u64>()
        .map_err(|e| anyhow!("env var `{name}` is not a valid u64: {e}"))
}

fn required_env_address(name: &str) -> Result<SuiAddress> {
    let raw = required_env(name)?;
    SuiAddress::from_str(&raw)
        .map_err(|e| anyhow!("env var `{name}` is not a valid Sui address: {e:?}"))
}

fn parse_network(s: &str) -> Result<pb::Network> {
    pb::Network::from_str_name(&s.to_ascii_uppercase()).ok_or_else(|| {
        anyhow!("unknown BITCOIN_NETWORK `{s}`; expected mainnet/testnet/regtest/signet")
    })
}

/// One-shot scrape of the on-chain `HashiCommittee`. The spawned watcher
/// service is aborted on drop.
async fn fetch_real_committee(
    sui_rpc_url: &str,
    package_id: SuiAddress,
    hashi_object_id: SuiAddress,
) -> Result<HashiCommittee> {
    let ids = HashiIds {
        package_id,
        hashi_object_id,
    };
    let (state, _service) = OnchainState::new(sui_rpc_url, ids, None, None, None)
        .await
        .map_err(|e| anyhow!("OnchainState::new failed: {e:?}"))?;
    state
        .current_committee()
        .ok_or_else(|| anyhow!("no current committee on chain (DKG not yet complete?)"))
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

    // OnchainState's HTTPS connection to Sui RPC needs a default rustls
    // provider — same choice the bridge node makes in `hashi/src/lib.rs`.
    let _ = rustls::crypto::ring::default_provider().install_default();

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
    let sui_rpc_url = required_env("SUI_RPC_URL")?;
    let package_id = required_env_address("HASHI_PACKAGE_ID")?;
    let hashi_object_id = required_env_address("HASHI_OBJECT_ID")?;

    tracing::info!(
        endpoint = %endpoint,
        bucket = %bucket,
        region = %region,
        network = ?network,
        sui_rpc_url = %sui_rpc_url,
        %package_id,
        %hashi_object_id,
        refill_rate, max_capacity,
        "connecting to guardian"
    );

    let committee = fetch_real_committee(&sui_rpc_url, package_id, hashi_object_id)
        .await
        .context("fetch on-chain committee")?;
    let committee_epoch = committee.epoch();
    let committee_threshold = certificate_threshold(committee.total_weight());
    tracing::info!(
        committee_epoch,
        committee_total_weight = committee.total_weight(),
        committee_threshold,
        num_members = committee.members().len(),
        "fetched on-chain committee"
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
        "  master pubkey:            {}",
        hex::encode(material.master_pubkey.serialize())
    );
    println!("  committee_epoch:          {committee_epoch}");
    println!("  committee_threshold:      {committee_threshold}");
    println!("  refill_rate_sats_per_sec: {refill_rate}");
    println!("  max_bucket_capacity_sats: {max_capacity}");
    Ok(())
}
