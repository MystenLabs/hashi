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
            pause_after_start,
        ));
        first_started_rx.await.unwrap();

        // A second control task is accepted and spawned, but must wait for the
        // first task to release the control lock.
        let (second_started_tx, mut second_started_rx) = oneshot::channel();
        let second = tokio::spawn(enclave.spawn_control_task(second_started_tx, signal_started));
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
}
