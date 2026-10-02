// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Task spawning and serialization for guardian RPCs.
//!
//! Transport conversion stays in `rpc`; endpoint modules contain domain logic.
//! This module routes each request through the enclave's appropriate
//! cancellation-safe execution policy.
//!
//! All state-touching RPCs, including withdrawals and GuardianInfo reads, use
//! `spawn_control_task` to share the control lock.

use crate::ceremony_mode::confirm;
use crate::ceremony_mode::rotate;
use crate::ceremony_mode::setup;
use crate::info;
use crate::operator_init as operator_init_domain;
use crate::withdraw_mode::committee_update;
use crate::withdraw_mode::heartbeat::HeartbeatWriter;
use crate::withdraw_mode::operator_activate as operator_activate_domain;
use crate::withdraw_mode::provisioner_init as provisioner_init_domain;
use crate::withdraw_mode::provisioner_rotate_cert as provisioner_rotate_cert_domain;
use crate::withdraw_mode::standard_withdrawal as standard_withdrawal_domain;
use crate::Enclave;
use crate::HEARTBEAT_INTERVAL;
use hashi_types::guardian::AttestedGuardianInfo;
use hashi_types::guardian::BatchProvisionerInitRequest;
use hashi_types::guardian::BatchProvisionerRotateKpSetRequest;
use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::CeremonyConfirmationResponse;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianResponse;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::ProvisionerRotateCertResponse;
use hashi_types::guardian::RotateKpSetResponse;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalResponse;
use std::sync::Arc;

/// Control operations install fields before their S3 records are durable and the
/// lifecycle advances. Serialize status requests with those operations so info
/// responses cannot expose partially committed state, without per-stage masking.
pub async fn get_guardian_info(
    enclave: Arc<Enclave>,
) -> GuardianResult<GuardianResponse<GuardianInfo>> {
    enclave
        .spawn_control_task((), |enclave, state, input| {
            Box::pin(info::get_guardian_info(enclave, state, input))
        })
        .await
}

/// Generate a fresh attestation under the same control lock as ordinary info reads.
pub async fn get_attested_guardian_info(
    enclave: Arc<Enclave>,
) -> GuardianResult<AttestedGuardianInfo> {
    enclave
        .spawn_control_task((), |enclave, state, input| {
            Box::pin(info::get_attested_guardian_info(enclave, state, input))
        })
        .await
}

pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSignedResponse<SetupNewKeyResponse>> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(setup::setup_new_key(enclave, state, input))
        })
        .await
}

pub async fn rotate_kp_set(
    enclave: Arc<Enclave>,
    request: BatchProvisionerRotateKpSetRequest,
) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(rotate::rotate_kp_set(enclave, state, input))
        })
        .await
}

pub async fn confirm_ceremony(
    enclave: Arc<Enclave>,
    signed: KpSigned<CeremonyConfirmationRequest>,
) -> GuardianResult<CeremonyConfirmationResponse> {
    enclave
        .spawn_control_task(signed, |enclave, state, input| {
            Box::pin(confirm::confirm_ceremony(enclave, state, input))
        })
        .await
}

pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(async move {
                operator_init_domain::operator_init(enclave.clone(), state, input).await?;
                // Initialization commits once under this guard. Start the independent
                // writer here so caller cancellation cannot skip heartbeat startup.
                if state.mode() == Some(EnclaveMode::Withdraw) {
                    drop(tokio::spawn(
                        HeartbeatWriter::new(enclave).run(HEARTBEAT_INTERVAL),
                    ));
                }
                Ok(())
            })
        })
        .await
}

pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: BatchProvisionerInitRequest,
) -> GuardianResult<()> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(provisioner_init_domain::provisioner_init(
                enclave, state, input,
            ))
        })
        .await
}

pub async fn operator_activate(
    enclave: Arc<Enclave>,
    request: OperatorActivateRequest,
) -> GuardianResult<()> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(operator_activate_domain::operator_activate(
                enclave, state, input,
            ))
        })
        .await
}

pub async fn provisioner_rotate_cert(
    enclave: Arc<Enclave>,
    signed_request: KpSigned<ProvisionerRotateCertRequest>,
) -> GuardianResult<GuardianSignedResponse<ProvisionerRotateCertResponse>> {
    enclave
        .spawn_control_task(signed_request, |enclave, state, input| {
            Box::pin(provisioner_rotate_cert_domain::provisioner_rotate_cert(
                enclave, state, input,
            ))
        })
        .await
}

pub async fn standard_withdrawal(
    enclave: Arc<Enclave>,
    request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<GuardianSignedResponse<StandardWithdrawalResponse>> {
    enclave
        .spawn_control_task(request, |enclave, state, input| {
            Box::pin(standard_withdrawal_domain::standard_withdrawal(
                enclave, state, input,
            ))
        })
        .await
}

pub async fn update_committee(
    enclave: Arc<Enclave>,
    signed: HashiSigned<CommitteeTransitionRequest>,
) -> GuardianResult<u64> {
    enclave
        .spawn_control_task(signed, |enclave, state, input| {
            Box::pin(committee_update::update_committee(enclave, state, input))
        })
        .await
}

pub async fn update_committee_chain(
    enclave: Arc<Enclave>,
    transitions: Vec<HashiSigned<CommitteeTransitionRequest>>,
) -> GuardianResult<u64> {
    enclave
        .spawn_control_task(transitions, |enclave, state, input| {
            Box::pin(committee_update::update_committee_chain(
                enclave, state, input,
            ))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::GuardianEncKeyPair;
    use hashi_types::guardian::GuardianSignKeyPair;
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// A task body that reports when it starts, waits for the test to let it
    /// continue, then reports completion.
    struct PausedTask {
        started: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
        finished: oneshot::Sender<()>,
    }

    fn test_enclave() -> Arc<Enclave> {
        Arc::new(Enclave::new(
            GuardianSignKeyPair::new(rand::thread_rng()),
            GuardianEncKeyPair::random(&mut rand::thread_rng()),
        ))
    }

    async fn pause_after_start(_enclave: Arc<Enclave>, task: PausedTask) -> GuardianResult<()> {
        task.started.send(()).unwrap();
        task.resume.await.unwrap();
        task.finished.send(()).unwrap();
        Ok(())
    }

    async fn signal_started(
        _enclave: Arc<Enclave>,
        started: oneshot::Sender<()>,
    ) -> GuardianResult<()> {
        started.send(()).unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn root_owned_task_survives_caller_cancellation() {
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let (finished_tx, finished_rx) = oneshot::channel();

        // This outer task represents the Tonic RPC handler awaiting the
        // independently spawned guardian task.
        let caller = tokio::spawn(test_enclave().spawn_task(
            PausedTask {
                started: started_tx,
                resume: resume_rx,
                finished: finished_tx,
            },
            pause_after_start,
        ));
        // Ensure the guardian accepted and started the task before simulating
        // the client disconnect.
        started_rx.await.unwrap();

        // Cancelling the RPC handler drops only its waiter. The guardian task
        // spawned by `spawn_task` must continue independently.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        // Allow the guardian task to finish and prove that caller cancellation
        // did not cancel it.
        resume_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .expect("root-owned task should finish")
            .unwrap();
    }

    #[tokio::test]
    async fn control_tasks_are_serialized() {
        let enclave = test_enclave();
        let (first_started_tx, first_started_rx) = oneshot::channel();
        let (first_resume_tx, first_resume_rx) = oneshot::channel();
        let (first_finished_tx, first_finished_rx) = oneshot::channel();

        // The first task acquires the control lock, then pauses while holding it.
        let first = tokio::spawn(enclave.clone().spawn_control_task(
            PausedTask {
                started: first_started_tx,
                resume: first_resume_rx,
                finished: first_finished_tx,
            },
            |enclave, _state, task| Box::pin(pause_after_start(enclave, task)),
        ));
        first_started_rx.await.unwrap();

        // A second control task is accepted and spawned, but must wait for the
        // first task to release the control lock.
        let (second_started_tx, mut second_started_rx) = oneshot::channel();
        let second = tokio::spawn(
            enclave.spawn_control_task(second_started_tx, |enclave, _state, started| {
                Box::pin(signal_started(enclave, started))
            }),
        );
        // Yield this test task to give Tokio an opportunity to poll the second
        // task and let it reach the control lock. This is a scheduling hint,
        // not proof that the second task reached the lock-waiting point.
        tokio::task::yield_now().await;
        assert!(matches!(
            second_started_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // Finishing the first task releases the lock, after which the second
        // task may enter and signal that it started.
        first_resume_tx.send(()).unwrap();
        first_finished_rx.await.unwrap();
        second_started_rx.await.unwrap();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_task_retains_state_after_caller_cancellation() {
        use hashi_types::guardian::CeremonyStage;
        use hashi_types::guardian::DeploymentConfig;

        let enclave = test_enclave();
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let caller = tokio::spawn(enclave.clone().spawn_control_task(
            (),
            move |enclave, state, ()| {
                Box::pin(async move {
                    enclave
                        .config
                        .set_deployment(DeploymentConfig::mock_for_testing())?;
                    enclave
                        .config
                        .set_s3_logger(crate::test_utils::mock_logger())?;
                    started_tx.send(()).unwrap();
                    resume_rx.await.unwrap();
                    state.advance_lifecycle_into(
                        &enclave.config,
                        CeremonyStage::OperatorInitialized.into(),
                    )
                })
            },
        ));
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        // Cancellation must neither release the state nor expose the partial install.
        let mut info = std::pin::pin!(get_guardian_info(enclave));
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut info)
            .await
            .is_err());
        resume_tx.send(()).unwrap();
        let info = tokio::time::timeout(Duration::from_secs(1), info)
            .await
            .expect("accepted control task must finish")
            .unwrap();
        assert_eq!(
            info.response.lifecycle,
            CeremonyStage::OperatorInitialized.into()
        );
    }
}
