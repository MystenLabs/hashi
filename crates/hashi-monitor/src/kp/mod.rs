// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hpke::Deserializable;
mod config;
mod heartbeat_checks;

use crate::domain::now_unix_seconds;
use crate::kp::config::GuardianConfig;
use crate::rpc::guardian::GuardianLogDir;
use crate::rpc::guardian::GuardianPollerCore;
use anyhow::Context;
use hashi_guardian::s3_logger::S3Logger;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::WithdrawalConfig;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::guardian::verify_enclave_attestation;
use hashi_types::proto as pb;
use rand::thread_rng;
use std::collections::HashSet;
use tracing::info;
use tracing::warn;

pub use config::ProvisionerConfig;

/// Read up to this many hours of withdrawal logs when rehydrating limiter
/// state on a new session's ProvisionerInit. Matches the retention window
/// for withdrawal logs so we never race Object Lock expiry on boot.
const REHYDRATE_HISTORY_HOURS: u64 = 2;

pub async fn run(cfg: ProvisionerConfig) -> anyhow::Result<()> {
    let s3_client = S3Logger::new_checked(&cfg.s3)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // 1. Check no past enclave's heartbeats remain & gather the latest enclave's session id.
    let session_id = heartbeat_checks::kp_heartbeat_audit(&s3_client).await?;
    info!(session_id, "heartbeat checks passed for selected session");

    // 2. Check that enclave's config is as expected (valid attestation, expected s3 bucket & share commitments)
    let guardian_info = get_guardian_info_from_s3(&s3_client, &session_id).await?;
    let expected_guardian_config = cfg.expected_guardian_config()?;
    expected_guardian_config.ensure_matches_info(&guardian_info)?;
    info!(session_id, "init checks passed for selected session");

    // 3. Rehydrate LimiterState from prior-session withdrawal logs. The
    //    prior session already consumed from the bucket and advanced
    //    `next_seq`; if we initialized the new session at (max_capacity,
    //    0, 0) we would let the bucket drift past the real cap.
    let committee = cfg.hashi_committee.try_into()?;
    let limiter_state =
        rehydrate_limiter_state(&s3_client, &session_id, &cfg.withdrawal_config).await?;
    let state = ProvisionerInitState::new(
        committee,
        cfg.withdrawal_config,
        limiter_state,
        cfg.hashi_btc_master_pubkey,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let guardian_pub_key =
        EncPubKey::from_bytes(&guardian_info.encryption_pubkey).map_err(|e| anyhow::anyhow!(e))?;
    let request = ProvisionerInitRequest::build_from_share_and_state(
        &cfg.share.to_domain()?,
        &guardian_pub_key,
        state,
        &mut thread_rng(),
    );
    let share_id = request.encrypted_share().id.get();
    let state_digest_hex = hex::encode(request.state().digest());
    info!(
        share_id,
        state_digest = state_digest_hex,
        "built provisioner-init request"
    );

    if let Some(endpoint) = cfg.guardian_endpoint {
        submit_provisioner_init_to_guardian(
            &endpoint,
            &session_id,
            &expected_guardian_config,
            request,
        )
        .await?;
    }
    Ok(())
}

/// Reconstruct the authoritative `LimiterState` for the new session from
/// prior-session withdrawal logs in S3.
///
/// A prior session is any session whose heartbeats appear in the recent
/// window but that is not the newly-provisioned `live_session_id`. Each
/// successful withdrawal is logged with a `limiter_state_post` snapshot,
/// so we pick the highest-seq snapshot across all prior sessions. If no
/// prior success logs are found we fall back to a fresh max-capacity
/// state (first-ever provisioning, or all prior logs expired).
pub async fn rehydrate_limiter_state(
    s3_client: &S3Logger,
    live_session_id: &str,
    withdrawal_config: &WithdrawalConfig,
) -> anyhow::Result<LimiterState> {
    let sessions = heartbeat_checks::collect_recent_sessions(s3_client).await?;
    let prior_sessions: HashSet<String> = sessions
        .into_iter()
        .map(|s| s.session_id)
        .filter(|id| id != live_session_id)
        .collect();

    if prior_sessions.is_empty() {
        info!("No prior sessions found; starting fresh at max bucket capacity");
        return Ok(fresh_limiter_state(withdrawal_config));
    }

    info!(
        prior_session_count = prior_sessions.len(),
        "Rehydrating LimiterState from prior session withdrawal logs",
    );

    let start = now_unix_seconds().saturating_sub(REHYDRATE_HISTORY_HOURS * 60 * 60);
    let mut poller =
        GuardianPollerCore::from_s3_client(s3_client.clone(), start, GuardianLogDir::Withdraw);

    let mut best_seq: Option<u64> = None;
    let mut best_state: Option<LimiterState> = None;

    for _ in 0..=REHYDRATE_HISTORY_HOURS {
        let logs = match poller.read_cur_dir().await {
            Ok(logs) => logs,
            Err(e) => {
                // A missing directory (no withdrawals in that hour) is a
                // normal condition — log and move on.
                warn!(
                    error = %e,
                    "Skipping withdrawal log directory during rehydration",
                );
                poller.advance_cursor();
                continue;
            }
        };

        for log in logs {
            if !prior_sessions.contains(&log.session_id) {
                continue;
            }
            let LogMessage::Withdrawal(withdrawal_message) = log.message else {
                continue;
            };
            let WithdrawalLogMessage::Success {
                request_data,
                limiter_state_post,
                ..
            } = *withdrawal_message
            else {
                continue;
            };
            let Some(snap) = limiter_state_post else {
                // Old-format logs (pre-PR-5) have no snapshot; skip.
                continue;
            };
            let seq = request_data.seq;
            if best_seq.is_none_or(|s| seq > s) {
                best_seq = Some(seq);
                best_state = Some(snap);
            }
        }

        poller.advance_cursor();
    }

    match best_state {
        Some(state) => {
            info!(
                next_seq = state.next_seq,
                last_updated_at = state.last_updated_at,
                num_tokens_available = state.num_tokens_available,
                "Rehydrated LimiterState from prior session logs",
            );
            Ok(state)
        }
        None => {
            warn!(
                "No prior withdrawal success logs found; starting fresh \
                 at max bucket capacity. Retries of prior-session \
                 withdrawals will be rejected rather than idempotently \
                 served.",
            );
            Ok(fresh_limiter_state(withdrawal_config))
        }
    }
}

fn fresh_limiter_state(withdrawal_config: &WithdrawalConfig) -> LimiterState {
    LimiterState {
        num_tokens_available: withdrawal_config.max_bucket_capacity_sats,
        last_updated_at: 0,
        next_seq: 0,
    }
}

/// Implements check B of IOP-225.
pub async fn get_guardian_info_from_s3(
    s3_client: &S3Logger,
    session_id: &str,
) -> anyhow::Result<GuardianInfo> {
    let (attestation, signing_pubkey) = s3_client
        .get_attestation(session_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    verify_enclave_attestation(attestation).map_err(|e| anyhow::anyhow!(e))?;

    s3_client
        .get_guardian_info(session_id, &signing_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!(e))
}

async fn submit_provisioner_init_to_guardian(
    endpoint: &str,
    expected_session_id: &str,
    expected_guardian_config: &GuardianConfig,
    request: ProvisionerInitRequest,
) -> anyhow::Result<()> {
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(endpoint.to_string())
            .await
            .with_context(|| format!("failed to connect to guardian endpoint {endpoint}"))?;

    prechecks(&mut client, expected_session_id, expected_guardian_config)
        .await
        .with_context(|| "guardian endpoint pre-check failed")?;

    info!("prechecks passed, submitting ProvisionerInit");
    let pb_request = provisioner_init_request_to_pb(request)?;
    client
        .provisioner_init(pb_request)
        .await
        .with_context(|| format!("guardian ProvisionerInit RPC failed at {endpoint}"))?;

    info!("successfully submitted ProvisionerInit request");
    Ok(())
}

async fn prechecks(
    client: &mut pb::guardian_service_client::GuardianServiceClient<tonic::transport::Channel>,
    expected_session_id: &str,
    expected_guardian_config: &GuardianConfig,
) -> anyhow::Result<()> {
    let resp_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .with_context(|| "GetGuardianInfo RPC failed")?
        .into_inner();

    let resp = <GetGuardianInfoResponse as TryFrom<pb::GetGuardianInfoResponse>>::try_from(resp_pb)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let signing_pub_key = resp.signing_pub_key;
    let actual_session_id = session_id_from_signing_pubkey(&signing_pub_key);
    anyhow::ensure!(
        actual_session_id == expected_session_id,
        "guardian endpoint session mismatch: expected {}, got {}",
        expected_session_id,
        actual_session_id
    );

    let info = resp
        .signed_info
        .verify(&signing_pub_key)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    expected_guardian_config.ensure_matches_info(&info)?;

    Ok(())
}
