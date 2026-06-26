// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::WithdrawModeConfig;
use hashi_types::guardian::WithdrawModeState;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::transport::Channel;
use tracing::info;

use crate::config::Config;
use crate::heartbeat_checks;
use crate::kp_roster::VerifiedCeremonyState;
use crate::limiter_recovery;

/// Initialize a fresh withdraw-mode guardian with operator-supplied state.
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
        num_shares = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        limiter_refill_rate = cfg.limiter_config.refill_rate,
        limiter_max_capacity = cfg.limiter_config.max_bucket_capacity,
        "running operator provision flow",
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
        "fetching + verifying uninitialized GuardianInfo"
    );
    let preflight = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    ensure_uninitialized(&preflight.info)?;
    let session_id = preflight.session_id.clone();
    let signing_pub_key = preflight.signing_pub_key;
    info!(
        phase = "guardian preflight",
        session_id = %session_id,
        signing_pubkey = hex::encode(signing_pub_key.as_bytes()),
        "guardian is current-build, attested, and uninitialized",
    );

    info!(
        phase = "roster load",
        cert_count = cfg.kp_roster.kp_pgp_cert_paths.len(),
        "loading + validating full KP cert roster",
    );
    let certs = load_certs(&cfg.kp_roster.kp_pgp_cert_paths)?;
    info!(
        phase = "roster load",
        cert_count = certs.len(),
        "KP cert roster loaded"
    );

    info!(
        phase = "ceremony instance",
        "scraping authoritative ceremony/ log for the secret-sharing instance",
    );
    let (ceremony_session, scraped_instance, roster) = reader
        .read_latest_ceremony(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    let sharing_seq = scraped_instance.sharing_seq();
    let encrypted_shares = reader
        .read_shares(&ceremony_session, sharing_seq, BuildPolicy::AnyAllowlisted)
        .await?;
    let ceremony_state = VerifiedCeremonyState::from_scraped(
        ceremony_session.clone(),
        scraped_instance.clone(),
        encrypted_shares,
        &roster,
        cfg.kp_roster.num_shares,
        cfg.kp_roster.threshold,
    )?;
    ceremony_state.verify_encrypted_share_recipients(&certs)?;
    info!(
        phase = "ceremony instance",
        ceremony_session = %ceremony_session,
        sharing_seq,
        n = scraped_instance.num_shares(),
        t = scraped_instance.threshold(),
        share_count = ceremony_state.encrypted_shares.len(),
        "ceremony instance and encrypted shares verified against expected roster",
    );

    info!(
        phase = "heartbeat quiet",
        "checking all prior guardian sessions are quiet before limiter recovery",
    );
    heartbeat_checks::ensure_all_sessions_quiet(&mut reader).await?;

    info!(
        phase = "limiter recovery",
        "recovering initial limiter state from prior enclave's withdraw logs",
    );
    let limiter_state = match limiter_recovery::recover_limiter_state(&mut reader).await? {
        Some(mut recovered) => {
            recovered.num_tokens_available = recovered
                .num_tokens_available
                .min(cfg.limiter_config.max_bucket_capacity);
            info!(
                phase = "limiter recovery",
                source = "recovered",
                next_seq = recovered.next_seq,
                num_tokens_available = recovered.num_tokens_available,
                last_updated_at = recovered.last_updated_at,
                "recovered limiter state from prior enclave's max-seq Success log",
            );
            recovered
        }
        None => {
            info!(
                phase = "limiter recovery",
                source = "genesis",
                "no prior Success withdrawal logs found; initializing limiter from genesis",
            );
            LimiterState::genesis(&cfg.limiter_config)
        }
    };

    info!(
        phase = "committee",
        "sourcing committee from latest committee-update log or on-chain Hashi state",
    );
    let committee = match reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await?
    {
        Some(scraped) => {
            info!(
                phase = "committee",
                epoch = scraped.epoch,
                source = "committee-update log",
                "scraped latest committee-update log",
            );
            scraped.try_into()?
        }
        None => {
            let committee = onchain_state
                .current_committee()
                .context("no current committee on chain (DKG not yet complete?)")?;
            info!(
                phase = "committee",
                epoch = committee.epoch(),
                source = "on-chain Hashi state",
                "no committee-update log; falling back to on-chain current committee",
            );
            committee
        }
    };
    let committee_epoch = committee.epoch();

    let withdraw_config = WithdrawModeConfig::new(
        committee,
        cfg.limiter_config,
        limiter_state,
        master_g,
        scraped_instance.clone(),
        cfg.bitcoin_network,
    )?;
    let expected_state = withdraw_config.state().clone();
    let state_hash = expected_state.digest();
    info!(
        phase = "state build",
        committee_epoch,
        state_hash = hex::encode(state_hash),
        bitcoin_network = ?cfg.bitcoin_network,
        "built withdraw-mode config",
    );

    info!(
        phase = "operator_init",
        "calling OperatorInit (withdraw mode)"
    );
    let oi_req = operator_init_request_to_pb(OperatorInitRequest::new_withdraw_mode(
        guardian_s3.clone(),
        withdraw_config,
    ))
    .map_err(|e| anyhow!("encode OperatorInitRequest: {e:?}"))?;
    client
        .operator_init(oi_req)
        .await
        .context("OperatorInit RPC failed")?;
    info!(
        phase = "operator_init",
        "operator_init complete; guardian state installed"
    );

    info!(
        phase = "guardian postcheck",
        "fetching + verifying initialized GuardianInfo"
    );
    let post = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    ensure!(
        post.session_id == session_id,
        "guardian session changed during operator provision: started {}, now {}",
        session_id,
        post.session_id
    );
    ensure!(
        post.signing_pub_key == signing_pub_key,
        "guardian signing key changed during operator provision"
    );
    verify_initialized_info(
        post.info.clone(),
        &guardian_s3,
        &scraped_instance,
        &expected_state,
        state_hash,
        committee_epoch,
    )?;
    info!(
        phase = "guardian postcheck",
        session_id = %session_id,
        state_hash = hex::encode(state_hash),
        "live GuardianInfo matches operator-supplied state",
    );

    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "verifying S3 init logs match the live guardian session",
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    ensure!(
        verified_session.signing_pubkey == signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    ensure!(
        verified_session.info == post.info,
        "guardian S3 init GuardianInfo differs from post-OperatorInit gRPC GuardianInfo"
    );
    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "guardian S3 init logs match live GuardianInfo",
    );

    info!(
        phase = "summary",
        session_id = %session_id,
        ceremony_session = %ceremony_session,
        sharing_seq,
        committee_epoch,
        state_hash = hex::encode(state_hash),
        bitcoin_network = ?cfg.bitcoin_network,
        "operator provision complete",
    );
    println!("Guardian operator provision complete.");
    println!("  session_id:      {session_id}");
    println!("  state_hash:      {}", hex::encode(state_hash));
    println!("  committee_epoch: {committee_epoch}");
    println!("  sharing_seq:     {sharing_seq}");
    println!("  num_shares:      {}", scraped_instance.num_shares());
    println!("  threshold:       {}", scraped_instance.threshold());
    println!("  bitcoin_network: {}", cfg.bitcoin_network);
    println!("  bucket:          {}", guardian_s3.bucket_name());
    println!("  region:          {}", guardian_s3.region());

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

fn ensure_uninitialized(info: &GuardianInfo) -> anyhow::Result<()> {
    ensure!(
        info.secret_sharing_instance.is_none(),
        "guardian already has a secret-sharing instance"
    );
    ensure!(
        info.bucket_info.is_none(),
        "guardian already has bucket info"
    );
    ensure!(info.state_hash.is_none(), "guardian already has state_hash");
    ensure!(
        info.enclave_btc_pubkey.is_none(),
        "guardian already has a BTC pubkey"
    );
    ensure!(
        info.limiter_state.is_none(),
        "guardian already has limiter state"
    );
    ensure!(
        info.limiter_config.is_none(),
        "guardian already has limiter config"
    );
    ensure!(
        info.current_committee_epoch.is_none(),
        "guardian already has a committee epoch"
    );
    ensure!(
        info.mpc_master_g.is_none(),
        "guardian already has MPC master G"
    );
    Ok(())
}

fn verify_initialized_info(
    info: GuardianInfo,
    guardian_s3: &S3Config,
    expected_instance: &SecretSharingInstance,
    expected_state: &WithdrawModeState,
    expected_state_hash: [u8; 32],
    expected_committee_epoch: u64,
) -> anyhow::Result<()> {
    let (
        instance,
        bucket_info,
        _enc_pubkey,
        state_hash,
        _git_revision,
        enclave_btc_pubkey,
        limiter_state,
        limiter_config,
        current_committee_epoch,
        mpc_master_g,
    ) = info
        .into_parts()
        .context("Guardian info has missing operator-initialized fields")?;
    let (_, expected_limiter_config, expected_limiter_state, expected_master_g) =
        expected_state.clone().into_parts();

    ensure!(
        instance == *expected_instance,
        "Guardian secret-sharing instance mismatch: expected {:?}, got {:?}",
        expected_instance,
        instance
    );
    ensure!(
        bucket_info == guardian_s3.bucket_info,
        "Guardian bucket info mismatch: expected {:?}, got {:?}",
        guardian_s3.bucket_info,
        bucket_info
    );
    ensure!(
        state_hash == expected_state_hash,
        "Guardian state_hash mismatch: expected {}, got {}",
        hex::encode(expected_state_hash),
        hex::encode(state_hash)
    );
    ensure!(
        enclave_btc_pubkey.is_none(),
        "Guardian has a BTC pubkey before provisioner init"
    );
    ensure!(
        limiter_state == expected_limiter_state,
        "Guardian limiter state mismatch: expected {:?}, got {:?}",
        expected_limiter_state,
        limiter_state
    );
    ensure!(
        limiter_config == expected_limiter_config,
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        expected_limiter_config,
        limiter_config
    );
    ensure!(
        current_committee_epoch == expected_committee_epoch,
        "Guardian committee epoch mismatch: expected {}, got {}",
        expected_committee_epoch,
        current_committee_epoch
    );
    ensure!(
        mpc_master_g == expected_master_g,
        "Guardian MPC master G mismatch: expected {:?}, got {:?}",
        expected_master_g,
        mpc_master_g
    );
    Ok(())
}
