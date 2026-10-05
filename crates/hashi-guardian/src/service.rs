// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian service: cancellation-safe execution and serialized enclave access.
//!
//! Transport conversion stays in `rpc`; endpoint modules contain domain logic.
//! The service owns the control mutex; domain handlers only borrow the enclave.
//!
//! RPCs and heartbeats use the same control lock, including every S3 write.
//! RPCs also hold a one-at-a-time turnstile for their whole run. The heartbeat
//! skips the turnstile. Invariant: at most one RPC holds or waits on the
//! control lock at any time. Bound: a heartbeat waits for at most the one
//! running operation, never for queued RPCs.

use crate::ceremony_mode::confirm;
use crate::ceremony_mode::rotate;
use crate::ceremony_mode::setup;
use crate::info;
use crate::operator_init;
use crate::withdraw_mode::committee_update;
use crate::withdraw_mode::operator_activate;
use crate::withdraw_mode::provisioner_init;
use crate::withdraw_mode::provisioner_rotate_cert;
use crate::withdraw_mode::standard_withdrawal;
use crate::Enclave;
use crate::HEARTBEAT_INTERVAL;
use hashi_types::guardian::AttestedGuardianInfo;
use hashi_types::guardian::BatchProvisionerInitRequest;
use hashi_types::guardian::BatchProvisionerRotateKpSetRequest;
use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::CeremonyConfirmationResponse;
use hashi_types::guardian::CommitteeTransitionRequest;
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
use hashi_types::guardian::SignedStandardWithdrawalRequestWire;
use hashi_types::guardian::StandardWithdrawalResponse;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Owns request execution. The enclave itself contains no control mutex.
#[derive(Clone)]
pub struct GuardianService {
    enclave: Arc<tokio::sync::Mutex<Enclave>>,
    /// RPC turnstile, held for the whole RPC. Only one RPC may hold or wait on
    /// the enclave lock. The heartbeat skips it. Lock order: `rpc_turn`, `enclave`.
    rpc_turn: Arc<tokio::sync::Mutex<()>>,
}

impl GuardianService {
    pub fn new(enclave: Enclave) -> Self {
        Self {
            enclave: Arc::new(tokio::sync::Mutex::new(enclave)),
            rpc_turn: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Inspect or initialize a served enclave in an in-process test harness.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn enclave_for_testing(&self) -> tokio::sync::MutexGuard<'_, Enclave> {
        self.enclave.lock().await
    }

    /// Spawn before locking so accepted work survives caller cancellation,
    /// including while queued. Domain handlers receive only the borrowed enclave.
    /// Hold the turnstile until the task ends, so no other RPC reaches the
    /// enclave lock queue while this one runs.
    async fn run_rpc<Output, Task>(&self, task: Task) -> GuardianResult<Output>
    where
        Output: Send + 'static,
        Task: for<'a> FnOnce(
                &'a mut Enclave,
            )
                -> Pin<Box<dyn Future<Output = GuardianResult<Output>> + Send + 'a>>
            + Send
            + 'static,
    {
        let enclave = self.enclave.clone();
        let rpc_turn = self.rpc_turn.clone();
        tokio::spawn(async move {
            let _turn = rpc_turn.lock().await;
            let mut enclave = enclave.lock().await;
            task(&mut enclave).await
        })
        .await
        .expect("guardian task failed")
    }

    /// Control operations install fields before their S3 records are durable and the
    /// lifecycle advances. Serialize status requests with those operations so info
    /// responses cannot expose partially committed state, without per-stage masking.
    pub async fn get_guardian_info(&self) -> GuardianResult<GuardianResponse<GuardianInfo>> {
        self.run_rpc(|enclave| Box::pin(async move { Ok(info::get_guardian_info(enclave)) }))
            .await
    }

    /// Generate a fresh attestation under the same control lock as ordinary info reads.
    pub async fn get_attested_guardian_info(&self) -> GuardianResult<AttestedGuardianInfo> {
        self.run_rpc(|enclave| Box::pin(async move { info::get_attested_guardian_info(enclave) }))
            .await
    }

    pub async fn setup_new_key(
        &self,
        request: SetupNewKeyRequest,
    ) -> GuardianResult<GuardianSignedResponse<SetupNewKeyResponse>> {
        self.run_rpc(move |enclave| Box::pin(setup::setup_new_key(enclave, request)))
            .await
    }

    pub async fn rotate_kp_set(
        &self,
        request: BatchProvisionerRotateKpSetRequest,
    ) -> GuardianResult<GuardianSignedResponse<RotateKpSetResponse>> {
        self.run_rpc(move |enclave| Box::pin(rotate::rotate_kp_set(enclave, request)))
            .await
    }

    pub async fn confirm_ceremony(
        &self,
        signed: KpSigned<CeremonyConfirmationRequest>,
    ) -> GuardianResult<CeremonyConfirmationResponse> {
        self.run_rpc(move |enclave| Box::pin(confirm::confirm_ceremony(enclave, signed)))
            .await
    }

    pub async fn operator_init(&self, request: OperatorInitRequest) -> GuardianResult<()> {
        self.run_rpc(move |enclave| Box::pin(operator_init::operator_init(enclave, request)))
            .await
    }

    pub async fn provisioner_init(
        &self,
        request: BatchProvisionerInitRequest,
    ) -> GuardianResult<()> {
        self.run_rpc(move |enclave| Box::pin(provisioner_init::provisioner_init(enclave, request)))
            .await
    }

    pub async fn operator_activate(&self, request: OperatorActivateRequest) -> GuardianResult<()> {
        self.run_rpc(move |enclave| {
            Box::pin(operator_activate::operator_activate(enclave, request))
        })
        .await
    }

    pub async fn provisioner_rotate_cert(
        &self,
        signed_request: KpSigned<ProvisionerRotateCertRequest>,
    ) -> GuardianResult<GuardianSignedResponse<ProvisionerRotateCertResponse>> {
        self.run_rpc(move |enclave| {
            Box::pin(provisioner_rotate_cert::provisioner_rotate_cert(
                enclave,
                signed_request,
            ))
        })
        .await
    }

    pub async fn standard_withdrawal(
        &self,
        request: SignedStandardWithdrawalRequestWire,
    ) -> GuardianResult<GuardianSignedResponse<StandardWithdrawalResponse>> {
        self.run_rpc(move |enclave| {
            Box::pin(standard_withdrawal::standard_withdrawal(enclave, request))
        })
        .await
    }

    pub async fn update_committee(
        &self,
        signed: HashiSigned<CommitteeTransitionRequest>,
    ) -> GuardianResult<u64> {
        self.run_rpc(move |enclave| Box::pin(committee_update::update_committee(enclave, signed)))
            .await
    }

    pub async fn update_committee_chain(
        &self,
        transitions: Vec<HashiSigned<CommitteeTransitionRequest>>,
    ) -> GuardianResult<u64> {
        self.run_rpc(move |enclave| {
            Box::pin(committee_update::update_committee_chain(
                enclave,
                transitions,
            ))
        })
        .await
    }

    /// Run the heartbeat loop started once at boot. Ticks are no-ops until
    /// withdraw-mode initialization completes and remain no-ops in ceremony mode.
    /// Sleep after each tick, so delayed ticks do not accumulate. The heartbeat
    /// skips the RPC turnstile, so it waits for at most the one running
    /// operation. One long operation may still delay it until the existing
    /// write fence forces a stop.
    pub async fn run_heartbeats(self) {
        loop {
            let enclave = self.enclave.clone();
            tokio::spawn(async move {
                let mut enclave = enclave.lock().await;
                enclave.heartbeat().await
            })
            .await
            .expect("heartbeat task failed")
            .expect("heartbeat write failed unexpectedly");
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::CeremonyStage;
    use hashi_types::guardian::DeploymentConfig;
    use std::time::Duration;
    use tokio::sync::oneshot;

    fn test_service() -> GuardianService {
        GuardianService::new(Enclave::create_with_random_keys())
    }

    #[tokio::test]
    async fn control_tasks_are_serialized() {
        let service = test_service();
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let first = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .run(move |_enclave| {
                        Box::pin(async move {
                            started_tx.send(()).unwrap();
                            resume_rx.await.unwrap();
                            Ok(())
                        })
                    })
                    .await
            })
        };
        started_rx.await.unwrap();

        let (second_started_tx, mut second_started_rx) = oneshot::channel();
        let second = tokio::spawn(async move {
            service
                .run(move |_enclave| {
                    Box::pin(async move {
                        second_started_tx.send(()).unwrap();
                        Ok(())
                    })
                })
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second_started_rx)
                .await
                .is_err()
        );
        resume_tx.send(()).unwrap();
        second_started_rx.await.unwrap();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_task_retains_state_after_caller_cancellation() {
        let service = test_service();
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let caller = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .run(move |enclave| {
                        Box::pin(async move {
                            enclave
                                .config
                                .set_deployment(DeploymentConfig::mock_for_testing())?;
                            enclave
                                .config
                                .set_s3_logger(crate::test_utils::mock_logger())?;
                            started_tx.send(()).unwrap();
                            resume_rx.await.unwrap();
                            enclave
                                .advance_lifecycle_into(CeremonyStage::OperatorInitialized.into())
                        })
                    })
                    .await
            })
        };
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        let mut info = std::pin::pin!(service.get_guardian_info());
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
        assert!(info.response.deployment_info.is_some());
    }

    #[tokio::test]
    async fn queued_control_task_survives_caller_cancellation() {
        let service = test_service();
        let guard = service.enclave.lock().await;
        let (finished_tx, finished_rx) = oneshot::channel();
        let caller = service.run(move |_enclave| {
            Box::pin(async move {
                finished_tx.send(()).unwrap();
                Ok(())
            })
        });
        // Poll once to submit the owned task, then cancel the caller while the
        // enclave is still locked. The queued operation must remain accepted.
        let mut caller = Box::pin(caller);
        std::future::poll_fn(|cx| {
            assert!(caller.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(caller);
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn heartbeats_wait_for_control_lock_before_writing() {
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            crate::OperatorInitTestArgs::default().with_s3_logger(logger),
        );
        let service = GuardianService::new(enclave);
        let guard = service.enclave.lock().await;
        let mut tick = Box::pin(service.run(|enclave| Box::pin(enclave.heartbeat())));
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut tick)
            .await
            .is_err());
        assert!(captures.lock().unwrap().is_empty());
        drop(guard);

        tokio::time::timeout(Duration::from_secs(1), tick)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(captures.lock().unwrap().len(), 1);
    }
}
