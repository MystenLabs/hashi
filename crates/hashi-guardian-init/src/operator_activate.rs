// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator activate` derives and submits the activation pin for a provisioned
//! withdraw-mode standby guardian.

use anyhow::Context;
use anyhow::ensure;
use hashi_guardian::HEARTBEAT_INTERVAL;
use hashi_guardian::OTHER_SESSION_QUIET_PERIOD;
use hashi_guardian::S3_WRITE_ATTEMPT_TIMEOUT;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::ActivationState;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::OperatorInitInfo;
use hashi_types::guardian::OperatorInitMode;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::WithdrawStage;
use hashi_types::guardian::proto_conversions::operator_activate_request_to_pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use std::time::Duration;
use tokio::time::Instant;
use tokio::time::sleep_until;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::guardian_info::verified_live_guardian_info;

// The retry window is long enough for the next scheduled heartbeat to start a
// complete S3 attempt: one heartbeat interval plus five minutes. A not-live
// session may therefore still recover before the ten-minute window expires.
const CURRENT_SESSION_HEARTBEAT_RETRY_WINDOW: Duration = Duration::from_mins(10);
const _: () = assert!(
    HEARTBEAT_INTERVAL.as_secs() + S3_WRITE_ATTEMPT_TIMEOUT.as_secs()
        < CURRENT_SESSION_HEARTBEAT_RETRY_WINDOW.as_secs()
);

// Allow a prior guardian time to stop while retaining enough time to observe
// the complete quiet period afterward.
const ACTIVATION_HEARTBEAT_WAIT_BUFFER: Duration = Duration::from_mins(5);

/// Activate a provisioner-initialized standby guardian.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    cfg.kp_roster.validate()?;
    let s3_credentials =
        hashi_guardian::resolve_s3_credentials(cfg.s3_credentials.as_ref()).await?;
    let allowlist = cfg.deployment.pcr_allowlist.clone();

    info!(
        phase = "setup",
        bucket = cfg.deployment.bucket_info.name,
        region = cfg.deployment.bucket_info.region,
        endpoint = %cfg.guardian_endpoint,
        bitcoin_network = ?cfg.deployment.bitcoin_network,
        limiter_refill_rate = cfg.limiter_config.refill_rate,
        limiter_max_capacity = cfg.limiter_config.max_bucket_capacity,
        "running operator activate flow",
    );

    info!(
        phase = "s3 connect",
        bucket = cfg.deployment.bucket_info.name,
        region = cfg.deployment.bucket_info.region,
        current_git_revision = %allowlist.current_build().git_revision(),
        current_pcr0 = hex::encode(allowlist.current_build().pcr0()),
        prev_build_count = allowlist.prev_builds().len(),
        "connecting to guardian log bucket",
    );
    let mut reader = GuardianReader::new(cfg.deployment.clone(), s3_credentials.clone())
        .await
        .context("connect to guardian log bucket")?;
    info!(phase = "s3 connect", "connected to guardian log bucket");

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
    let standby = verify_provisioned_standby_info(&pre_info, &cfg)?;
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
        "verifying OI GuardianInfo matches the live guardian identity/config",
    );
    let verified_session = reader.get_current_session_info(&session_id).await?;
    ensure!(
        verified_session.signing_pubkey() == &signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    verify_oi_info_matches_provisioned_standby(verified_session.info(), &pre_info)?;
    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "OI GuardianInfo matches live standby identity/config",
    );

    info!(
        phase = "heartbeat check",
        session_id = %session_id,
        "checking that the standby session is live and all other sessions are quiet",
    );
    wait_for_activation_heartbeat_conditions(&mut reader, &session_id)
        .await
        .context("heartbeat activation check failed")?;

    info!(
        phase = "activation state",
        "reading latest committee and recovering limiter state",
    );
    let move_committee = reader
        .read_latest_committee()
        .await?
        .context("no committee-update or genesis record found")?;
    let committee_epoch = move_committee.epoch;
    let committee: HashiCommittee = move_committee
        .try_into()
        .context("invalid serving committee")?;
    let limiter_state = reader
        .recover_limiter_state(standby.init_config.limiter_config())
        .await
        .context("recover limiter state")?;
    let activation_state = ActivationState::new(
        standby.config_hash,
        standby.secret_sharing_instance.clone(),
        committee,
        limiter_state,
    );
    let state_hash = activation_state.digest();
    info!(
        phase = "activation state",
        committee_epoch,
        limiter_next_seq = limiter_state.next_seq,
        limiter_tokens_available = limiter_state.num_tokens_available,
        limiter_last_updated_at = limiter_state.last_updated_at,
        state_hash = hex::encode(state_hash),
        "computed expected ActivationState hash",
    );

    info!(
        phase = "operator_activate",
        session_id = %session_id,
        committee_epoch,
        limiter_next_seq = limiter_state.next_seq,
        state_hash = hex::encode(state_hash),
        "calling OperatorActivate",
    );
    let activate_req = operator_activate_request_to_pb(OperatorActivateRequest::new(state_hash));
    client
        .operator_activate(activate_req)
        .await
        .context("OperatorActivate RPC failed")?;
    info!(
        phase = "operator_activate",
        session_id = %session_id,
        "operator_activate RPC returned; verifying activated GuardianInfo",
    );

    info!(
        phase = "guardian postcheck",
        session_id = %session_id,
        "fetching + verifying activated GuardianInfo"
    );
    let post = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    verify_activated_info(
        post,
        &session_id,
        signing_pub_key,
        standby.enclave_btc_pubkey,
        committee_epoch,
        limiter_state,
    )?;
    info!(
        phase = "guardian postcheck",
        session_id = %session_id,
        committee_epoch,
        limiter_next_seq = limiter_state.next_seq,
        "activated GuardianInfo matches expected state",
    );

    info!(
        phase = "summary",
        session_id = %session_id,
        committee_epoch,
        config_hash = hex::encode(standby.config_hash),
        state_hash = hex::encode(state_hash),
        "operator activate complete",
    );
    println!("Guardian operator activate complete.");
    println!("  session_id:       {session_id}");
    println!("  config_hash:      {}", hex::encode(standby.config_hash));
    println!("  state_hash:       {}", hex::encode(state_hash));
    println!("  committee_epoch:  {committee_epoch}");
    println!("  limiter_next_seq: {}", limiter_state.next_seq);
    println!("  bitcoin_network:  {}", cfg.deployment.bitcoin_network);
    println!("  bucket:           {}", cfg.deployment.bucket_info.name);
    println!("  region:           {}", cfg.deployment.bucket_info.region);

    Ok(())
}

async fn wait_for_activation_heartbeat_conditions(
    reader: &mut GuardianReader,
    session_id: &str,
) -> GuardianResult<()> {
    let now = Instant::now();
    let current_session_deadline = now + CURRENT_SESSION_HEARTBEAT_RETRY_WINDOW;
    let prior_session_deadline =
        now + OTHER_SESSION_QUIET_PERIOD + ACTIVATION_HEARTBEAT_WAIT_BUFFER;
    loop {
        match reader
            .ensure_session_live_and_others_quiet(session_id)
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                let deadline = match &error {
                    GuardianError::CurrentSessionHeartbeatNotLive { .. } => {
                        current_session_deadline
                    }
                    GuardianError::PriorSessionHeartbeatStillRecent { .. } => {
                        prior_session_deadline
                    }
                    _ => return Err(error),
                };
                let Some(retry_after_secs) = error.retry_after_secs() else {
                    return Err(error);
                };
                let retry_delay = Duration::from_secs(retry_after_secs);

                let now = Instant::now();
                if now >= deadline {
                    return Err(error);
                }

                let retry_at = (now + retry_delay).min(deadline);
                warn!(
                    error = %error,
                    retry_in_secs = retry_at.duration_since(now).as_secs(),
                    "activation heartbeat conditions are not ready; retrying"
                );
                sleep_until(retry_at).await;
            }
        }
    }
}

struct StandbyChecks {
    init_config: InitConfig,
    config_hash: [u8; 32],
    secret_sharing_instance: hashi_types::guardian::SecretSharingInstance,
    enclave_btc_pubkey: hashi_types::bitcoin::BitcoinPubkey,
}

fn verify_provisioned_standby_info(
    info: &GuardianInfo,
    cfg: &Config,
) -> anyhow::Result<StandbyChecks> {
    ensure!(
        info.lifecycle == WithdrawStage::ProvisionerInitialized.into(),
        "guardian is not a provisioner-initialized withdraw enclave"
    );
    let instance = info
        .secret_sharing_instance
        .clone()
        .context("Guardian info missing secret-sharing instance")?;
    let deployment = info.deployment_info()?;
    let config_hash = info
        .config_hash
        .context("Guardian info missing config_hash")?;
    let enclave_btc_pubkey = info
        .enclave_btc_pubkey
        .context("Guardian info missing enclave BTC pubkey; provisioner_init is not complete")?;
    let limiter_config = info
        .limiter_config
        .context("Guardian info missing limiter config")?;
    ensure!(
        info.limiter_state.is_none(),
        "Guardian has limiter_state => operator activation already ran"
    );
    ensure!(
        info.current_committee_epoch.is_none(),
        "Guardian has current_committee_epoch => operator activation already ran"
    );
    ensure!(
        deployment == &cfg.deployment.summary(),
        "Guardian deployment mismatch: expected {:?}, got {:?}",
        cfg.deployment.summary(),
        deployment
    );
    ensure!(
        cfg.limiter_config == limiter_config,
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        cfg.limiter_config,
        limiter_config
    );
    let init_config = InitConfig::new(cfg.limiter_config, cfg.deployment.clone());
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

fn verify_oi_info_matches_provisioned_standby(
    oi_info: &OperatorInitInfo,
    live_info: &GuardianInfo,
) -> anyhow::Result<()> {
    let OperatorInitMode::Withdraw(withdraw) = &oi_info.initialization else {
        anyhow::bail!("OI record is not withdraw-mode initialization");
    };
    ensure!(
        oi_info.mode() == live_info.lifecycle.mode(),
        "OI enclave mode differs from live standby GuardianInfo"
    );
    ensure!(
        Some(&withdraw.secret_sharing_instance) == live_info.secret_sharing_instance.as_ref(),
        "OI record secret-sharing instance differs from live standby GuardianInfo"
    );
    ensure!(
        Some(&oi_info.deployment_info) == live_info.deployment_info.as_ref(),
        "OI record deployment differs from live standby GuardianInfo"
    );
    ensure!(
        oi_info.encryption_pubkey == live_info.encryption_pubkey,
        "OI record encryption pubkey differs from live standby GuardianInfo"
    );
    ensure!(
        Some(withdraw.config_hash) == live_info.config_hash,
        "OI record config_hash differs from live standby GuardianInfo"
    );
    ensure!(
        withdraw.genesis_state_hash == live_info.genesis_state_hash,
        "OI record genesis_state_hash differs from live standby GuardianInfo"
    );
    ensure!(
        Some(withdraw.limiter_config) == live_info.limiter_config,
        "OI record limiter config differs from live standby GuardianInfo"
    );
    ensure!(
        Some(withdraw.mpc_master_g) == live_info.mpc_master_g,
        "OI record MPC master G differs from live standby GuardianInfo"
    );
    Ok(())
}

fn verify_activated_info(
    post: VerifiedGuardianInfo,
    expected_session_id: &str,
    expected_signing_key: hashi_types::guardian::GuardianPubKey,
    expected_enclave_btc_pubkey: hashi_types::bitcoin::BitcoinPubkey,
    expected_committee_epoch: u64,
    expected_limiter_state: hashi_types::guardian::LimiterState,
) -> anyhow::Result<()> {
    ensure!(
        post.session_id.as_str() == expected_session_id,
        "guardian session changed during operator activation: started {}, now {}",
        expected_session_id,
        post.session_id
    );
    ensure!(
        post.signing_pub_key == expected_signing_key,
        "guardian signing key changed during operator activation"
    );
    ensure!(
        post.info.lifecycle == WithdrawStage::Activated.into(),
        "guardian is not an activated withdraw enclave"
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
