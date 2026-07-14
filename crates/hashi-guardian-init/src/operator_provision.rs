// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::LifecycleStage;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::OperatorWriteGenesisRequest;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::operator_write_genesis_request_to_pb;
use hashi_types::pgp::load_certs;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::verified_live_guardian_info;
use crate::kp_roster::VerifiedCeremonyState;

/// Initialize a fresh withdraw-mode guardian with operator-supplied stable config.
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
        phase = "committee",
        "checking latest committee-update/genesis record before operator_init",
    );
    let genesis_bootstrap_committee = match reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await?
    {
        Some(committee) => {
            info!(
                phase = "committee",
                epoch = committee.epoch,
                "serving committee already exists in S3; genesis bootstrap not needed",
            );
            None
        }
        None => {
            let committee = onchain_state
                .current_committee()
                .context("no current committee on chain (DKG not yet complete?)")?;
            info!(
                phase = "committee",
                epoch = committee.epoch(),
                "no committee-update/genesis record; will write on-chain committee to genesis after operator_init",
            );
            Some(committee)
        }
    };

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
    let (ceremony_session, scraped_instance, btc_master_pubkey) = reader
        .read_latest_ceremony(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    let sharing_seq = scraped_instance.sharing_seq();
    let (kp_share_session, kp_share_state) = reader
        .read_latest_kp_share_state(sharing_seq, BuildPolicy::AnyAllowlisted)
        .await?
        .context("no kp-shares log found in S3; key setup has not run")?;
    let ceremony_state = VerifiedCeremonyState::from_scraped(
        ceremony_session.clone(),
        kp_share_session.clone(),
        scraped_instance.clone(),
        kp_share_state,
        btc_master_pubkey,
        cfg.kp_roster.num_shares,
        cfg.kp_roster.threshold,
    )?;
    ceremony_state.verify_encrypted_share_recipients(&certs)?;
    info!(
        phase = "ceremony instance",
        ceremony_session = %ceremony_session,
        kp_share_session = %kp_share_session,
        sharing_seq,
        cert_seq = ceremony_state.kp_share_cert_seq,
        n = scraped_instance.num_shares(),
        t = scraped_instance.threshold(),
        share_count = ceremony_state.encrypted_shares.len(),
        "ceremony instance and KP share state verified against expected roster",
    );

    let init_config = InitConfig::new(
        cfg.limiter_config,
        master_g,
        allowlist.clone(),
        cfg.bitcoin_network,
    )?;
    let config_hash = init_config.digest();
    info!(
        phase = "config build",
        config_hash = hex::encode(config_hash),
        bitcoin_network = ?cfg.bitcoin_network,
        "built InitConfig",
    );

    info!(
        phase = "operator_init",
        "calling OperatorInit (withdraw mode)"
    );
    let oi_req = operator_init_request_to_pb(OperatorInitRequest::new_withdraw_mode(
        guardian_s3.clone(),
        init_config.clone(),
    ))
    .map_err(|e| anyhow!("encode OperatorInitRequest: {e:?}"))?;
    client
        .operator_init(oi_req)
        .await
        .context("OperatorInit RPC failed")?;
    info!(
        phase = "operator_init",
        "operator_init complete; standby config installed"
    );

    if let Some(committee) = genesis_bootstrap_committee {
        info!(
            phase = "operator_write_genesis",
            epoch = committee.epoch(),
            "writing operator-trusted genesis bootstrap committee"
        );
        let genesis_req =
            operator_write_genesis_request_to_pb(OperatorWriteGenesisRequest::new(committee));
        client
            .operator_write_genesis(genesis_req)
            .await
            .context("OperatorWriteGenesis RPC failed")?;
        info!(
            phase = "operator_write_genesis",
            "genesis bootstrap committee written"
        );
    }

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
        &init_config,
        config_hash,
    )?;
    info!(
        phase = "guardian postcheck",
        session_id = %session_id,
        config_hash = hex::encode(config_hash),
        "live GuardianInfo matches operator-supplied config",
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
    let oi_info = verified_session.info;
    ensure!(
        oi_info.lifecycle_stage == LifecycleStage::Uninitialized,
        "S3 OI GuardianInfo has an unexpected lifecycle stage"
    );
    // The S3 record is the pre-transition snapshot; only its lifecycle differs
    // from the live post-OI snapshot.
    let mut normalized_oi_info = oi_info.clone();
    normalized_oi_info.lifecycle_stage = LifecycleStage::OperatorInitialized;
    ensure!(
        normalized_oi_info == post.info,
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
        config_hash = hex::encode(config_hash),
        bitcoin_network = ?cfg.bitcoin_network,
        "operator provision complete",
    );
    println!("Guardian operator provision complete.");
    println!("  session_id:      {session_id}");
    println!("  config_hash:     {}", hex::encode(config_hash));
    println!("  sharing_seq:     {sharing_seq}");
    println!("  num_shares:      {}", scraped_instance.num_shares());
    println!("  threshold:       {}", scraped_instance.threshold());
    println!("  bitcoin_network: {}", cfg.bitcoin_network);
    println!("  bucket:          {}", guardian_s3.bucket_name());
    println!("  region:          {}", guardian_s3.region());

    Ok(())
}

fn ensure_uninitialized(info: &GuardianInfo) -> anyhow::Result<()> {
    ensure!(
        info.enclave_mode == EnclaveMode::Withdraw,
        "guardian is not in withdraw mode"
    );
    ensure!(
        info.lifecycle_stage == LifecycleStage::Uninitialized,
        "guardian is not uninitialized"
    );
    ensure!(
        info.secret_sharing_instance.is_none(),
        "guardian already has a secret-sharing instance"
    );
    ensure!(
        info.bucket_info.is_none(),
        "guardian already has bucket info"
    );
    ensure!(
        info.config_hash.is_none(),
        "guardian already has config_hash"
    );
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
    expected_config: &InitConfig,
    expected_config_hash: [u8; 32],
) -> anyhow::Result<()> {
    ensure!(
        info.enclave_mode == EnclaveMode::Withdraw,
        "guardian is not in withdraw mode"
    );
    ensure!(
        info.lifecycle_stage == LifecycleStage::OperatorInitialized,
        "guardian is not operator initialized"
    );
    let instance = info
        .secret_sharing_instance
        .context("Guardian info missing secret-sharing instance")?;
    let bucket_info = info
        .bucket_info
        .context("Guardian info missing bucket info")?;
    let config_hash = info
        .config_hash
        .context("Guardian info missing config_hash")?;
    let limiter_config = info
        .limiter_config
        .context("Guardian info missing limiter config")?;
    let mpc_master_g = info
        .mpc_master_g
        .context("Guardian info missing MPC master G")?;

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
        config_hash == expected_config_hash,
        "Guardian config_hash mismatch: expected {}, got {}",
        hex::encode(expected_config_hash),
        hex::encode(config_hash)
    );
    ensure!(
        info.enclave_btc_pubkey.is_none(),
        "Guardian has a BTC pubkey before provisioner init"
    );
    ensure!(
        info.limiter_state.is_none(),
        "Guardian has limiter state before operator activation"
    );
    ensure!(
        limiter_config == *expected_config.limiter_config(),
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        expected_config.limiter_config(),
        limiter_config
    );
    ensure!(
        info.current_committee_epoch.is_none(),
        "Guardian has committee epoch before operator activation"
    );
    ensure!(
        mpc_master_g == expected_config.hashi_btc_master_pubkey(),
        "Guardian MPC master G mismatch: expected {:?}, got {:?}",
        expected_config.hashi_btc_master_pubkey(),
        mpc_master_g
    );
    Ok(())
}
