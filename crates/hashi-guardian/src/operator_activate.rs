// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_activate`: turns a provisioner-initialized standby into the active
//! withdrawal enclave by deriving live serving state from S3 logs and checking the
//! operator-pinned `ActivationState` hash.

use crate::s3_reader::BuildPolicy;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use hashi_types::guardian::ActivationState;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::RateLimiter;
use hashi_types::guardian::WithdrawStage;
use std::sync::Arc;
use tracing::info;
use GuardianError::InternalError;
use GuardianError::InvalidInputs;

pub async fn operator_activate(
    enclave: Arc<Enclave>,
    request: OperatorActivateRequest,
) -> GuardianResult<()> {
    info!("/operator_activate - Received request.");

    let _guard = enclave.control_lock.lock().await;

    enclave.require_lifecycle(WithdrawStage::ProvisionerInitialized.into())?;

    let init_config = enclave
        .init_config()
        .ok_or_else(|| InvalidInputs("InitConfig not set".into()))?
        .clone();
    let config_hash = enclave
        .config_hash()
        .ok_or_else(|| InvalidInputs("config_hash not set".into()))?;
    let armed_instance = enclave
        .secret_sharing_instance()
        .map_err(|_| InvalidInputs("secret-sharing instance not set".into()))?
        .clone();

    let s3 = enclave
        .config
        .s3_logger()
        .map_err(|_| InvalidInputs("S3 logger not set".into()))?
        .clone();
    let mut reader = GuardianReader::from_s3_client(s3, init_config.pcr_allowlist().clone());

    reader
        .ensure_session_live_and_others_quiet(&enclave.s3_session_id())
        .await
        .map_err(|e| InvalidInputs(format!("heartbeat activation check failed: {e}")))?;

    let (_, latest_instance, _) = reader
        .read_latest_ceremony(BuildPolicy::AnyAllowlisted)
        .await
        .map_err(|e| InternalError(format!("read latest ceremony: {e}")))?
        .ok_or_else(|| InvalidInputs("no ceremony log found during activation".into()))?;
    if latest_instance != armed_instance {
        return Err(InvalidInputs(format!(
            "latest ceremony instance differs from armed instance: latest {latest_instance}, armed {armed_instance}"
        )));
    }

    let committee: HashiCommittee = reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await
        .map_err(|e| InternalError(format!("read latest serving committee: {e}")))?
        .ok_or_else(|| InvalidInputs("no committee-update or genesis record found".into()))?
        .try_into()
        .map_err(|e| InvalidInputs(format!("invalid serving committee: {e}")))?;

    let limiter_state = reader
        .recover_limiter_state(init_config.limiter_config())
        .await
        .map_err(|e| InvalidInputs(format!("recover limiter state: {e}")))?;
    let rate_limiter = RateLimiter::new(*init_config.limiter_config(), limiter_state)?;
    let sharing_seq = armed_instance.sharing_seq();
    let committee_epoch = committee.epoch();

    let activation_state = ActivationState::new(
        config_hash,
        armed_instance,
        committee.clone(),
        limiter_state,
    );
    let state_hash = activation_state.digest();
    if &state_hash != request.expected_state_hash() {
        return Err(InvalidInputs(format!(
            "ActivationState hash mismatch: expected {}, got {}",
            hex::encode(request.expected_state_hash()),
            hex::encode(state_hash)
        )));
    }

    enclave
        .state
        .init(committee, rate_limiter)
        .expect("Unable to init activation state");
    enclave
        .log_init(InitLogMessage::OAActivated {
            state_hash,
            config_hash,
            sharing_seq,
            committee_epoch,
            limiter_state,
        })
        .await
        .expect("Unable to log operator activation");
    enclave
        .advance_lifecycle_into(WithdrawStage::Activated.into())
        .expect("operator_activate should advance a provisioner-initialized enclave");

    info!("Operator activation complete.");
    Ok(())
}
