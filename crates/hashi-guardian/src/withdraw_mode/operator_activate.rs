// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_activate`: turns a provisioner-initialized standby into the active
//! withdrawal enclave by deriving live serving state from S3 logs and checking the
//! operator-pinned `ActivationState` hash.

use crate::s3_reader::BuildPolicy;
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
use GuardianError::InvalidInputs;

/// S3-derived activation state ready for its fail-stop commit.
///
/// Construction performs every request-dependent fallible operation without
/// mutating the enclave. Once built, the commit must either complete or abort
/// the enclave process.
struct OAInstall {
    committee: HashiCommittee,
    rate_limiter: RateLimiter,
    completion_log: InitLogMessage,
}

impl OAInstall {
    async fn from_request(
        enclave: &Enclave,
        request: OperatorActivateRequest,
    ) -> GuardianResult<Self> {
        let limiter_config = enclave.limiter_config()?;
        let initialization = enclave
            .temporary_init_state()
            .map_err(|_| InvalidInputs("temporary initialization state not set".into()))?;
        let config_hash = initialization.config_hash;
        let armed_instance = initialization.ceremony_state.secret_sharing_instance;

        let mut reader = enclave.new_guardian_reader()?;

        reader
            .ensure_session_live_and_others_quiet(&enclave.s3_session_id())
            .await
            .map_err(|e| InvalidInputs(format!("heartbeat activation check failed: {e}")))?;

        let committee: HashiCommittee = reader
            .read_latest_committee(BuildPolicy::AnyAllowlisted)
            .await?
            .ok_or_else(|| InvalidInputs("no committee-update or genesis record found".into()))?
            .try_into()
            .map_err(|e| InvalidInputs(format!("invalid serving committee: {e}")))?;

        let limiter_state = reader.recover_limiter_state(&limiter_config).await?;
        let rate_limiter = RateLimiter::new(limiter_config, limiter_state)?;
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

        Ok(Self {
            committee,
            rate_limiter,
            completion_log: InitLogMessage::OAActivated {
                state_hash,
                config_hash,
                sharing_seq,
                committee_epoch,
                limiter_state,
            },
        })
    }
}

pub async fn operator_activate(
    enclave: Arc<Enclave>,
    request: OperatorActivateRequest,
) -> GuardianResult<()> {
    info!("/operator_activate - Received request.");

    enclave.require_lifecycle(WithdrawStage::ProvisionerInitialized.into())?;
    info!("Lifecycle stage validated.");

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----
    let install = OAInstall::from_request(&enclave, request).await?;

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    info!("Committing committee and rate limiter.");
    commit_operator_activate(&enclave, install).await;

    info!("Operator activation complete.");
    Ok(())
}

/// Install the prepared serving state, durably mark OA complete, clear stale
/// initialization inputs, and then expose the active lifecycle. This fail-stop
/// phase never returns an error after mutation begins.
async fn commit_operator_activate(enclave: &Enclave, install: OAInstall) {
    enclave
        .state
        .init(install.committee, install.rate_limiter)
        .expect("Unable to init activation state");

    enclave
        .log_init(install.completion_log)
        .await
        .expect("Unable to log operator activation");

    enclave.clear_temporary_init_state();

    enclave
        .advance_lifecycle_into(WithdrawStage::Activated.into())
        .expect("operator_activate should advance a provisioner-initialized enclave");
}
