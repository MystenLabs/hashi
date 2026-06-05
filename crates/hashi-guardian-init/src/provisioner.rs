// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianEncryptedShare;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::WithdrawModeState;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::GuardianConfig;
use crate::heartbeat_checks;
use crate::limiter_recovery;

pub use crate::config::ProvisionerConfig;

pub async fn run(cfg: ProvisionerConfig) -> anyhow::Result<()> {
    // One reader for the whole run: it owns the S3 client and the trusted-key
    // cache, so each session's attestation is verified once whichever check
    // reads that session first.
    let mut reader = GuardianReader::new(&cfg.s3).await?;

    // 1. Check no past enclave's heartbeats remain & gather the latest enclave's session id.
    let session_id = heartbeat_checks::heartbeat_audit(&mut reader).await?;
    info!(session_id, "heartbeat checks passed for selected session");

    // 2. Check that the enclave's config is as expected: valid attestation,
    // expected S3 bucket, and share commitments matching the authoritative
    // `ceremony/` log (written from initial key setup onward).
    let guardian_info = reader.get_info(&session_id).await?;
    let instance = reader
        .read_latest_ceremony_instance()
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    let expected_guardian_config = GuardianConfig {
        bucket_info: cfg.s3.bucket_info.clone(),
        share_commitments: instance.commitments().clone(),
    };
    expected_guardian_config.ensure_matches_info(&guardian_info)?;
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

    // Recompute the init state the operator booted the enclave with; its digest is
    // the state_hash we bind as the share's AAD. The committee comes from the
    // latest signed `committee-update/` log; before any update exists (genesis) we
    // fall back to the trusted local value. `master_g` is the MPC committee `G`
    // (see config doc), NOT the guardian's own BTC key.
    let master_g = cfg.mpc_master_g()?;
    let committee = match reader.read_latest_committee().await? {
        Some(scraped) => scraped,
        None => cfg
            .hashi_committee_genesis
            .clone()
            .context("no committee-update log in S3 and no hashi_committee_genesis in config")?,
    };
    if let Some(enclave_epoch) = guardian_info.current_committee_epoch {
        anyhow::ensure!(
            committee.epoch == enclave_epoch,
            "committee epoch mismatch: sourced epoch {}, enclave reports {}",
            committee.epoch,
            enclave_epoch
        );
    }
    let expected_state = WithdrawModeState::new(
        committee.try_into()?,
        cfg.limiter_config,
        limiter_state,
        master_g,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let state_hash = expected_state.digest();

    // Fail fast (IOP-225 step D): the enclave must have been booted with the
    // state we expect, else our share won't decrypt under its state_hash AAD.
    let enclave_state_hash = guardian_info
        .state_hash
        .context("guardian info is missing state_hash")?;
    anyhow::ensure!(
        state_hash == enclave_state_hash,
        "state_hash mismatch: enclave booted with a different init state"
    );

    let guardian_pub_key =
        EncPubKey::from_bytes(&guardian_info.encryption_pubkey).map_err(|e| anyhow::anyhow!(e))?;
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
            &expected_guardian_config,
            encrypted_share,
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
    expected_guardian_config: &GuardianConfig,
    encrypted_share: GuardianEncryptedShare,
) -> anyhow::Result<()> {
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(endpoint.to_string())
            .await
            .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;

    prechecks(&mut client, expected_session_id, expected_guardian_config)
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
        "relay endpoint session mismatch: expected {}, got {}",
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
