// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod config;
mod heartbeat_checks;
mod limiter_recovery;

use anyhow::Context;
use hashi_guardian::s3_logger::S3Logger;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::S3_DIR_INIT;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::guardian::verify_enclave_attestation;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::provisioner::config::GuardianConfig;

pub use config::ProvisionerConfig;

pub async fn run(cfg: ProvisionerConfig) -> anyhow::Result<()> {
    let s3_client = S3Logger::new_checked(&cfg.s3)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // 1. Check no past enclave's heartbeats remain & gather the latest enclave's session id.
    let session_id = heartbeat_checks::heartbeat_audit(&s3_client).await?;
    info!(session_id, "heartbeat checks passed for selected session");

    // 2. Check that enclave's config is as expected (valid attestation, expected s3 bucket & share commitments)
    let guardian_info = get_guardian_info_from_s3(&s3_client, &session_id).await?;
    let expected_guardian_config = cfg.expected_guardian_config()?;
    expected_guardian_config.ensure_matches_info(&guardian_info)?;
    info!(session_id, "init checks passed for selected session");

    // 3. Detect whether this is a first deployment or a rotation, and source
    // the initial limiter state accordingly.
    let mode = detect_deployment_mode(&s3_client, &session_id).await?;
    info!(?mode, "detected deployment mode");
    let limiter_state = match mode {
        DeploymentMode::Rotation => {
            match limiter_recovery::recover_limiter_state(s3_client.clone()).await? {
                Some(mut recovered) => {
                    // Cap to the current config's bucket capacity in case max capacity
                    // was lowered across the rotation. (Raising is fine — refill will
                    // fill it.)
                    recovered.num_tokens_available = recovered
                        .num_tokens_available
                        .min(cfg.withdrawal_config.max_bucket_capacity_sats);
                    recovered
                }
                None => {
                    tracing::warn!(
                        "rotation detected but prior enclave has no Success logs within walk-back window; falling back to genesis limiter state"
                    );
                    LimiterState::genesis(&cfg.withdrawal_config)
                }
            }
        }
        DeploymentMode::Genesis => LimiterState::genesis(&cfg.withdrawal_config),
    };

    let committee = cfg.hashi_committee.try_into()?;
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

/// Whether this provisioner-init is for the very first enclave in this S3
/// bucket or a rotation onto a successor enclave. Determined from S3 init logs
/// — see [`detect_deployment_mode`] — and used to switch between sourcing
/// initial state from config (genesis) vs. recovering it from the prior
/// enclave's logs (rotation). Future genesis/rotation-aware behaviors (e.g.,
/// committee fetch) can match on the same enum.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DeploymentMode {
    Genesis,
    Rotation,
}

/// Inspects S3 init logs for any session other than `current_session_id`.
/// Presence of one or more such session ⇒ Rotation; otherwise Genesis.
///
/// Bails on any key under `init/` that doesn't match the expected
/// `{session_id}-{suffix}` layout — unexpected keys shouldn't exist there
/// and silently ignoring them could mask a real prior session.
async fn detect_deployment_mode(
    s3_client: &S3Logger,
    current_session_id: &str,
) -> anyhow::Result<DeploymentMode> {
    let prefix = format!("{}/", S3_DIR_INIT);
    let keys = s3_client
        .list_all_keys_in_dir(&prefix)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    for key in keys {
        let session_id = extract_session_id_from_init_key(&key, &prefix)?;
        if session_id != current_session_id {
            return Ok(DeploymentMode::Rotation);
        }
    }
    Ok(DeploymentMode::Genesis)
}

/// Extracts the session_id from an `init/{session_id}-{suffix}.json` key.
/// session_id is the lowercase hex of the enclave signing pubkey, so it
/// contains no dashes — the first '-' after the prefix delimits it.
fn extract_session_id_from_init_key<'a>(key: &'a str, prefix: &str) -> anyhow::Result<&'a str> {
    let after_prefix = key
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("unexpected init log key (missing prefix): {key}"))?;
    let (session_id, _suffix) = after_prefix
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("unexpected init log key (no suffix delimiter): {key}"))?;
    Ok(session_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_session_id_strips_prefix_and_takes_up_to_first_dash() {
        let session = "abcdef1234567890";
        let key = format!("init/{session}-oi-attestation-unsigned.json");
        assert_eq!(
            extract_session_id_from_init_key(&key, "init/").unwrap(),
            session
        );
    }

    #[test]
    fn extract_session_id_rejects_missing_prefix() {
        let err = extract_session_id_from_init_key("withdraw/abc-suffix.json", "init/")
            .expect_err("must fail on wrong prefix");
        assert!(err.to_string().contains("missing prefix"));
    }

    #[test]
    fn extract_session_id_rejects_missing_suffix_delimiter() {
        let err = extract_session_id_from_init_key("init/abcdef.json", "init/")
            .expect_err("must fail on no dash after prefix");
        assert!(err.to_string().contains("no suffix delimiter"));
    }
}
