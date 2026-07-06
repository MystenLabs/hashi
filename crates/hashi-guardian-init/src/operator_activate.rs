// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator activate` derives and submits the activation pin for a provisioned
//! withdraw-mode standby guardian.

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::ActivationState;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::proto_conversions::operator_activate_request_to_pb;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::transport::Channel;
use tracing::info;

use crate::config::Config;

/// Activate a provisioner-initialized standby guardian.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = cfg.guardian_s3.resolve().await?;
    let allowlist = cfg.kp_roster.pcr_allowlist();

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        endpoint = %cfg.guardian_endpoint,
        bitcoin_network = ?cfg.bitcoin_network,
        limiter_refill_rate = cfg.limiter_config.refill_rate,
        limiter_max_capacity = cfg.limiter_config.max_bucket_capacity,
        "running operator activate flow",
    );

    info!(
        phase = "s3 connect",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        current_git_revision = %allowlist.current_build().git_revision(),
        current_pcr0 = hex::encode(allowlist.current_build().pcr0()),
        prev_build_count = allowlist.prev_builds().len(),
        "connecting to guardian log bucket",
    );
    let mut reader = GuardianReader::new(&guardian_s3, allowlist.clone())
        .await
        .context("connect to guardian log bucket")?;
    info!(phase = "s3 connect", "connected to guardian log bucket");

    info!(
        phase = "sui connect",
        sui_rpc = %cfg.hashi.sui_rpc,
        package_id = %cfg.hashi.hashi_ids.package_id,
        hashi_object_id = %cfg.hashi.hashi_ids.hashi_object_id,
        "connecting to Sui RPC for Hashi on-chain state",
    );
    let onchain_state = cfg.hashi.onchain_state().await?;
    info!(phase = "sui connect", "connected to Sui RPC");

    let master_g = onchain_state.onchain_verifying_key_g()?;
    info!(phase = "setup", master_g = ?master_g, "fetched on-chain MPC master G");

    info!(
        phase = "guardian connect",
        endpoint = %cfg.guardian_endpoint,
        "connecting to withdraw-mode guardian",
    );
    let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", cfg.guardian_endpoint))?;
    info!(phase = "guardian connect", endpoint = %cfg.guardian_endpoint, "connected to guardian");

    info!(
        phase = "guardian preflight",
        "fetching + verifying provisioned standby GuardianInfo"
    );
    let preflight = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    let session_id = preflight.session_id.clone();
    let signing_pub_key = preflight.signing_pub_key;
    let pre_info = preflight.info.clone();
    let standby =
        verify_provisioned_standby_info(&pre_info, &guardian_s3, &cfg, &allowlist, &master_g)?;
    info!(
        phase = "guardian preflight",
        session_id = %session_id,
        signing_pubkey = hex::encode(signing_pub_key.as_bytes()),
        config_hash = hex::encode(standby.config_hash),
        enclave_btc_pubkey = ?standby.enclave_btc_pubkey,
        "guardian is current-build, provisioned, and not yet active",
    );

    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "verifying S3 init logs match the live guardian identity/config",
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    ensure!(
        verified_session.signing_pubkey == signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    verify_s3_init_matches_provisioned_standby(&verified_session.info, &pre_info)?;
    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "guardian S3 init logs match live standby identity/config",
    );

    info!(
        phase = "quiet check",
        session_id = %session_id,
        "checking that all other guardian sessions are quiet",
    );
    reader
        .ensure_all_sessions_quiet_except(&session_id)
        .await
        .context("heartbeat quiet check failed")?;

    info!(
        phase = "ceremony instance",
        "scraping authoritative ceremony/ log for the activation instance",
    );
    let (ceremony_session, latest_instance, _, _) = reader
        .read_latest_ceremony(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    ensure!(
        latest_instance == standby.secret_sharing_instance,
        "latest ceremony instance differs from armed instance: latest {}, armed {}",
        latest_instance,
        standby.secret_sharing_instance
    );
    info!(
        phase = "ceremony instance",
        ceremony_session = %ceremony_session,
        sharing_seq = latest_instance.sharing_seq(),
        "latest ceremony instance matches the armed standby",
    );

    info!(
        phase = "activation state",
        "reading latest committee and recovering limiter state",
    );
    let committee = reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no committee-update or genesis record found")?;
    let limiter_state = reader
        .recover_limiter_state(standby.init_config.limiter_config())
        .await
        .context("recover limiter state")?;
    let activation_state = ActivationState::new(
        standby.config_hash,
        latest_instance,
        committee.clone(),
        limiter_state,
    )?;
    let state_hash = activation_state.digest();
    info!(
        phase = "activation state",
        committee_epoch = committee.epoch(),
        limiter_next_seq = limiter_state.next_seq,
        limiter_tokens_available = limiter_state.num_tokens_available,
        limiter_last_updated_at = limiter_state.last_updated_at,
        state_hash = hex::encode(state_hash),
        "computed expected ActivationState hash",
    );

    info!(
        phase = "operator_activate",
        state_hash = hex::encode(state_hash),
        "calling OperatorActivate"
    );
    let activate_req = operator_activate_request_to_pb(OperatorActivateRequest::new(state_hash));
    client
        .operator_activate(activate_req)
        .await
        .context("OperatorActivate RPC failed")?;
    info!(
        phase = "operator_activate",
        "operator_activate RPC complete"
    );

    info!(
        phase = "guardian postcheck",
        "fetching + verifying activated GuardianInfo"
    );
    let post = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    verify_activated_info(
        post,
        &session_id,
        signing_pub_key,
        standby.config_hash,
        standby.enclave_btc_pubkey,
        committee.epoch(),
        limiter_state,
        state_hash,
    )?;

    info!(
        phase = "summary",
        session_id = %session_id,
        ceremony_session = %ceremony_session,
        committee_epoch = committee.epoch(),
        config_hash = hex::encode(standby.config_hash),
        state_hash = hex::encode(state_hash),
        "operator activate complete",
    );
    println!("Guardian operator activate complete.");
    println!("  session_id:      {session_id}");
    println!("  config_hash:     {}", hex::encode(standby.config_hash));
    println!("  state_hash:      {}", hex::encode(state_hash));
    println!("  committee_epoch: {}", committee.epoch());
    println!("  limiter_next_seq: {}", limiter_state.next_seq);
    println!("  bitcoin_network: {}", cfg.bitcoin_network);
    println!("  bucket:          {}", guardian_s3.bucket_name());
    println!("  region:          {}", guardian_s3.region());

    Ok(())
}

struct StandbyChecks {
    init_config: InitConfig,
    config_hash: [u8; 32],
    secret_sharing_instance: hashi_types::guardian::SecretSharingInstance,
    enclave_btc_pubkey: hashi_types::bitcoin::BitcoinPubkey,
}

fn verify_provisioned_standby_info(
    info: &GuardianInfo,
    guardian_s3: &S3Config,
    cfg: &Config,
    allowlist: &hashi_types::guardian::PcrAllowlist,
    master_g: &hashi_types::bitcoin::HashiMasterG,
) -> anyhow::Result<StandbyChecks> {
    let instance = info
        .secret_sharing_instance
        .clone()
        .context("Guardian info missing secret-sharing instance")?;
    let bucket_info = info
        .bucket_info
        .as_ref()
        .context("Guardian info missing bucket info")?;
    let config_hash = info
        .config_hash
        .context("Guardian info missing config_hash")?;
    let enclave_btc_pubkey = info
        .enclave_btc_pubkey
        .context("Guardian info missing enclave BTC pubkey; provisioner_init is not complete")?;
    let limiter_config = info
        .limiter_config
        .context("Guardian info missing limiter config")?;
    let mpc_master_g = info
        .mpc_master_g
        .clone()
        .context("Guardian info missing MPC master G")?;

    ensure!(
        info.state_hash.is_none(),
        "Guardian has state_hash => operator activation already ran"
    );
    ensure!(
        info.limiter_state.is_none(),
        "Guardian has limiter_state => operator activation already ran"
    );
    ensure!(
        info.current_committee_epoch.is_none(),
        "Guardian has current_committee_epoch => operator activation already ran"
    );
    ensure!(
        &guardian_s3.bucket_info == bucket_info,
        "Guardian bucket info mismatch: expected {:?}, got {:?}",
        guardian_s3.bucket_info,
        bucket_info
    );
    ensure!(
        cfg.limiter_config == limiter_config,
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        cfg.limiter_config,
        limiter_config
    );
    ensure!(
        master_g == &mpc_master_g,
        "Guardian MPC master G mismatch: expected {:?}, got {:?}",
        master_g,
        mpc_master_g
    );

    let init_config = InitConfig::new(
        guardian_s3.bucket_info.clone(),
        cfg.limiter_config,
        master_g.clone(),
        allowlist.clone(),
        cfg.bitcoin_network,
    )?;
    let expected_config_hash = init_config.digest();
    ensure!(
        expected_config_hash == config_hash,
        "Guardian config_hash mismatch: expected {}, got {}",
        hex::encode(expected_config_hash),
        hex::encode(config_hash)
    );

    Ok(StandbyChecks {
        init_config,
        config_hash,
        secret_sharing_instance: instance,
        enclave_btc_pubkey,
    })
}

fn verify_s3_init_matches_provisioned_standby(
    s3_info: &GuardianInfo,
    live_info: &GuardianInfo,
) -> anyhow::Result<()> {
    ensure!(
        s3_info.enclave_btc_pubkey.is_none(),
        "guardian S3 init GuardianInfo unexpectedly has a BTC pubkey"
    );
    ensure!(
        s3_info.state_hash.is_none(),
        "guardian S3 init GuardianInfo unexpectedly has state_hash"
    );
    ensure!(
        s3_info.limiter_state.is_none(),
        "guardian S3 init GuardianInfo unexpectedly has limiter_state"
    );
    ensure!(
        s3_info.current_committee_epoch.is_none(),
        "guardian S3 init GuardianInfo unexpectedly has current_committee_epoch"
    );
    ensure!(
        s3_info.secret_sharing_instance == live_info.secret_sharing_instance,
        "guardian S3 init secret-sharing instance differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.bucket_info == live_info.bucket_info,
        "guardian S3 init bucket info differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.encryption_pubkey == live_info.encryption_pubkey,
        "guardian S3 init encryption pubkey differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.config_hash == live_info.config_hash,
        "guardian S3 init config_hash differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.untrusted_git_revision == live_info.untrusted_git_revision,
        "guardian S3 init git revision differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.limiter_config == live_info.limiter_config,
        "guardian S3 init limiter config differs from live standby GuardianInfo"
    );
    ensure!(
        s3_info.mpc_master_g == live_info.mpc_master_g,
        "guardian S3 init MPC master G differs from live standby GuardianInfo"
    );
    Ok(())
}

fn verify_activated_info(
    post: VerifiedGuardianInfo,
    expected_session_id: &str,
    expected_signing_key: hashi_types::guardian::GuardianPubKey,
    expected_config_hash: [u8; 32],
    expected_enclave_btc_pubkey: hashi_types::bitcoin::BitcoinPubkey,
    expected_committee_epoch: u64,
    expected_limiter_state: hashi_types::guardian::LimiterState,
    expected_state_hash: [u8; 32],
) -> anyhow::Result<()> {
    ensure!(
        post.session_id == expected_session_id,
        "guardian session changed during operator activation: started {}, now {}",
        expected_session_id,
        post.session_id
    );
    ensure!(
        post.signing_pub_key == expected_signing_key,
        "guardian signing key changed during operator activation"
    );
    ensure!(
        post.info.config_hash == Some(expected_config_hash),
        "Guardian config_hash changed during operator activation"
    );
    ensure!(
        post.info.state_hash == Some(expected_state_hash),
        "Guardian state_hash mismatch: expected {}, got {:?}",
        hex::encode(expected_state_hash),
        post.info.state_hash.map(hex::encode)
    );
    ensure!(
        post.info.enclave_btc_pubkey == Some(expected_enclave_btc_pubkey),
        "Guardian BTC pubkey changed during operator activation"
    );
    ensure!(
        post.info.current_committee_epoch == Some(expected_committee_epoch),
        "Guardian committee epoch mismatch: expected {}, got {:?}",
        expected_committee_epoch,
        post.info.current_committee_epoch
    );
    ensure!(
        post.info.limiter_state == Some(expected_limiter_state),
        "Guardian limiter state mismatch: expected {:?}, got {:?}",
        expected_limiter_state,
        post.info.limiter_state
    );
    Ok(())
}

async fn verified_live_guardian_info(
    client: &mut GuardianServiceClient<Channel>,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    info_resp
        .verify(current_build)
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e:?}"))
}
