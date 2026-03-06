use bitcoin::Amount;
use hpke::Deserializable;
mod config;
mod heartbeat_checks;

use crate::kp::config::GuardianConfig;
use anyhow::Context;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::WithdrawalState;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::guardian::verify_enclave_attestation;
use hashi_types::proto as pb;
use rand::thread_rng;
use tracing::info;

pub use config::ProvisionerConfig;

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

    // TODO: replace mock withdrawal state with actual state from S3 logs.
    let mock_withdrawal_state = WithdrawalState::mock_for_testing(
        cfg.hashi_committees.epoch_window(),
        Amount::from_sat(100_000),
    );
    let state = ProvisionerInitState::new(
        cfg.hashi_committees.try_into()?,
        cfg.withdrawal_config,
        mock_withdrawal_state,
        cfg.hashi_btc_master_pubkey,
    )?;

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
