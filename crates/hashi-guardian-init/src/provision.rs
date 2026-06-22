// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianEncryptedShare;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::WithdrawModeState;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::heartbeat_checks;
use crate::limiter_recovery;

pub use crate::config::ProvisionConfig;

pub async fn run(cfg: ProvisionConfig) -> anyhow::Result<()> {
    cfg.common.validate()?;

    // One reader for the whole run: it owns the S3 client and a cache that
    // reuses verified session info and exposes attested build revisions to the caller.
    let allowlist = cfg.common.pcr_allowlist();
    let mut reader = GuardianReader::new(&cfg.common.guardian_s3, allowlist.clone()).await?;
    let master_g = cfg.mpc_master_g()?;

    // 1. Check no past enclave's heartbeats remain & gather the latest enclave's session id.
    let session_id = heartbeat_checks::heartbeat_audit(&mut reader).await?;
    info!(session_id, "heartbeat checks passed for selected session");

    // 2. Check that the enclave's config is as expected: current build, valid
    // attestation, expected S3 bucket, and share commitments matching the
    // authoritative `ceremony/` log (written from initial key setup onward).
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    let guardian_info = verified_session.info;
    let (
        enclave_ss_instance,
        enclave_bucket_info,
        enclave_enc_pubkey_bytes,
        enclave_state_hash,
        enclave_git_revision,
        enclave_btc_pubkey,
        enclave_limiter_state,
        enclave_limiter_config,
        enclave_current_committee_epoch,
        enclave_mpc_master_g,
    ) = guardian_info
        .clone()
        .into_parts()
        .context("Guardian info has missing fields")?;
    anyhow::ensure!(
        enclave_git_revision == allowlist.current_build().git_revision(),
        "Guardian git revision mismatch: expected {}, got {}",
        allowlist.current_build().git_revision(),
        enclave_git_revision
    );
    anyhow::ensure!(
        cfg.common.guardian_s3.bucket_info == enclave_bucket_info,
        "Guardian bucket info mismatch: expected {:?}, got {:?}",
        cfg.common.guardian_s3.bucket_info,
        enclave_bucket_info
    );
    anyhow::ensure!(
        cfg.limiter_config == enclave_limiter_config,
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        cfg.limiter_config,
        enclave_limiter_config
    );
    anyhow::ensure!(
        enclave_btc_pubkey.is_none(),
        "Guardian has a BTC pubkey => provisioner init over"
    );
    anyhow::ensure!(
        master_g == enclave_mpc_master_g,
        "MPC master g mismatch: expected {:?}, got {:?}",
        master_g,
        enclave_mpc_master_g
    );

    let instance = reader
        .read_latest_ceremony_instance(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    anyhow::ensure!(
        instance == enclave_ss_instance,
        "Enclave secret sharing instance mismatch: expected {:?}, got {:?}",
        instance,
        enclave_ss_instance
    );

    info!(session_id, "init checks passed for selected session");

    // 3. Source the initial limiter state. If a prior enclave left Success
    // withdrawal logs we recover from them; otherwise (first deployment, or a
    // rotation where the prior enclave processed no withdrawals) we initialize
    // from genesis.
    let limiter_state = match limiter_recovery::recover_limiter_state(&mut reader).await? {
        Some(mut recovered) => {
            // Cap to the current config's bucket capacity in case max capacity
            // was lowered across the rotation. (Raising is fine — refill will
            // fill it.)
            recovered.num_tokens_available = recovered
                .num_tokens_available
                .min(cfg.limiter_config.max_bucket_capacity);
            recovered
        }
        None => {
            info!("no prior Success withdrawal logs found; initializing limiter from genesis");
            LimiterState::genesis(&cfg.limiter_config)
        }
    };
    anyhow::ensure!(
        limiter_state == enclave_limiter_state,
        "limiter state mismatch: expected {:?}, got {:?}",
        limiter_state,
        enclave_limiter_state
    );

    // Recompute the init state the operator booted the enclave with; its digest is
    // the state_hash we bind as the share's AAD. The committee comes from the
    // latest signed `committee-update/` log; before any update exists (genesis) we
    // fall back to the trusted local value. `master_g` is the MPC committee `G`
    // (see config doc), NOT the guardian's own BTC key.
    let committee = match reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await?
    {
        Some(scraped) => scraped,
        None => cfg
            .hashi_committee_genesis
            .clone()
            .context("no committee-update log in S3 and no hashi_committee_genesis in config")?,
    };
    anyhow::ensure!(
        committee.epoch == enclave_current_committee_epoch,
        "committee epoch mismatch: expected {}, got {}",
        committee.epoch,
        enclave_current_committee_epoch
    );
    let expected_state = WithdrawModeState::new(
        committee.try_into()?,
        cfg.limiter_config,
        limiter_state,
        master_g,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let state_hash = expected_state.digest();
    anyhow::ensure!(
        state_hash == enclave_state_hash,
        "state_hash mismatch: expected {}, got {}",
        hex::encode(state_hash),
        hex::encode(enclave_state_hash)
    );

    let guardian_pub_key =
        EncPubKey::from_bytes(&enclave_enc_pubkey_bytes).map_err(|e| anyhow::anyhow!(e))?;
    let encrypted_share = ProvisionerInitRequest::build_from_share(
        &cfg.share.to_domain()?,
        &guardian_pub_key,
        state_hash,
        &mut thread_rng(),
    );
    let share_id = encrypted_share.id.get();
    info!(
        share_id,
        state_hash = hex::encode(state_hash),
        "built provisioner-init share"
    );

    // Send this KP's single share to the relay, which collects T-of-N shares
    // before forwarding them to the guardian in one ProvisionerInit call.
    if let Some(endpoint) = cfg.relay_endpoint {
        submit_provisioner_init_to_relay(
            &endpoint,
            &session_id,
            guardian_info,
            encrypted_share,
            allowlist.current_build(),
        )
        .await?;
    }
    Ok(())
}

/// Run the relay-side pre-checks for this KP's share. The relay fronts the
/// guardian's `GetGuardianInfo`, so we verify it against the expected session
/// and config before handing over the share.
///
/// TODO: once the relay exposes `single_provisioner_init`, send `encrypted_share`
/// to it here. The relay collects T-of-N shares before calling the guardian's
/// batch `provisioner_init`.
async fn submit_provisioner_init_to_relay(
    endpoint: &str,
    expected_session_id: &str,
    expected_guardian_info: GuardianInfo,
    encrypted_share: GuardianEncryptedShare,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(endpoint.to_string())
            .await
            .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;

    prechecks(
        &mut client,
        expected_session_id,
        expected_guardian_info,
        current_build,
    )
    .await
    .with_context(|| "relay endpoint pre-check failed")?;

    info!(
        share_id = encrypted_share.id.get(),
        "relay prechecks passed; share submission awaits single_provisioner_init"
    );
    Ok(())
}

async fn prechecks(
    client: &mut pb::guardian_service_client::GuardianServiceClient<tonic::transport::Channel>,
    expected_session_id: &str,
    expected_guardian_info: GuardianInfo,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
    let resp_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .with_context(|| "GetGuardianInfo RPC failed")?
        .into_inner();

    let resp = <GetGuardianInfoResponse as TryFrom<pb::GetGuardianInfoResponse>>::try_from(resp_pb)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Attestation-anchored, signature-verified GuardianInfo in one call.
    let verified = resp
        .verify(current_build)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let info = verified.info;

    let actual_session_id = verified.session_id;
    anyhow::ensure!(
        actual_session_id == expected_session_id,
        "relay endpoint session mismatch: expected {}, got {}",
        expected_session_id,
        actual_session_id
    );
    anyhow::ensure!(
        info == expected_guardian_info,
        "relay endpoint GuardianInfo mismatch: expected {:?}, got {:?}",
        expected_guardian_info,
        info
    );

    Ok(())
}
