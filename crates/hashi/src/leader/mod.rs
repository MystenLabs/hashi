// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod garbage_collection;
mod retry;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::config::ForceRunAsLeader;
use crate::leader::retry::GlobalRetryTracker;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::WithdrawalRequest;
use crate::onchain::types::WithdrawalTransaction;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use crate::withdrawals::WithdrawalTxSigning;

pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use futures::future::OptionFuture;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::bitcoin_utils;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;
const LEADER_TASK_TIMEOUT: Duration = Duration::from_secs(60);

pub struct LeaderService {
    inner: Arc<Hashi>,
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    withdrawal_commitment_retry_tracker: GlobalRetryTracker<WithdrawalCommitmentErrorKind>,
    deposit_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    inflight_deposits: HashSet<Address>,
    withdrawal_approval_task: Option<JoinHandle<anyhow::Result<()>>>,
    withdrawal_commitment_task: Option<JoinHandle<anyhow::Result<()>>>,
    withdrawal_signing_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    inflight_withdrawal_signings: HashSet<Address>,
    withdrawal_broadcast_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    inflight_withdrawal_broadcasts: HashSet<Address>,
    deposit_gc_task: Option<JoinHandle<anyhow::Result<()>>>,
    proposal_gc_task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: GlobalRetryTracker::new(),
            deposit_tasks: JoinSet::new(),
            inflight_deposits: HashSet::new(),
            withdrawal_approval_task: None,
            withdrawal_commitment_task: None,
            withdrawal_signing_tasks: JoinSet::new(),
            inflight_withdrawal_signings: HashSet::new(),
            withdrawal_broadcast_tasks: JoinSet::new(),
            inflight_withdrawal_broadcasts: HashSet::new(),
            deposit_gc_task: None,
            proposal_gc_task: None,
        }
    }

    /// Start the leader service and return a `Service` for lifecycle management.
    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    #[tracing::instrument(name = "leader", skip_all)]
    async fn run(mut self) {
        info!("Starting leader service");

        // Wait for DKG to complete before processing any checkpoints.
        let mpc_handle = self.inner.mpc_handle().expect("MpcHandle not initialized");
        info!("Waiting for MPC key to become available...");
        mpc_handle.wait_for_key_ready().await;
        info!("MPC key is ready, starting leader loop");

        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();
        let mut btc_block_rx = self.inner.btc_monitor().subscribe_block_height();

        loop {
            trace!("Waiting for next checkpoint or task completion...");
            tokio::select! {
                wait_result = checkpoint_rx.changed() => {
                    if let Err(e) = wait_result {
                        error!("Error waiting for checkpoint change: {e}");
                        break;
                    }
                    let (checkpoint_height, checkpoint_timestamp_ms) = {
                        let checkpoint_info = checkpoint_rx.borrow_and_update();
                        (checkpoint_info.height, checkpoint_info.timestamp_ms)
                    };

                    let is_leader = self.is_current_leader(checkpoint_height);
                    self.inner.metrics.is_leader.set(i64::from(is_leader));
                    if is_leader {
                        debug!("Checkpoint {checkpoint_height}: We are the leader node");
                    } else {
                        trace!("We are not the leader node");
                        continue;
                    }

                    self.process_unapproved_withdrawal_requests(checkpoint_timestamp_ms);
                    self.process_approved_withdrawal_requests(checkpoint_timestamp_ms);
                    self.process_unsigned_withdrawal_txns();
                    self.process_signed_withdrawal_txns();
                    self.check_delete_proposals(checkpoint_timestamp_ms);
                }
                wait_result = btc_block_rx.changed() => {
                    if let Err(e) = wait_result {
                        error!("Error waiting for Bitcoin block height change: {e}");
                        break;
                    }
                    let block_height = *btc_block_rx.borrow_and_update();
                    let (checkpoint_height, checkpoint_timestamp_ms) = {
                        let checkpoint_info = checkpoint_rx.borrow();
                        (checkpoint_info.height, checkpoint_info.timestamp_ms)
                    };

                    if !self.is_current_leader(checkpoint_height) {
                        continue;
                    }

                    debug!("New Bitcoin block {block_height}: processing deposit requests");

                    while let Some(result) = self.deposit_tasks.try_join_next() {
                        self.handle_completed_deposit_task(result);
                    }

                    self.process_deposit_requests(checkpoint_timestamp_ms);
                }
                Some(result) = self.deposit_tasks.join_next() => {
                    self.handle_completed_deposit_task(result);
                    // Drain any other completed tasks while we're here.
                    while let Some(result) = self.deposit_tasks.try_join_next() {
                        self.handle_completed_deposit_task(result);
                    }
                }
                Some(result) = self.withdrawal_signing_tasks.join_next() => {
                    self.handle_completed_withdrawal_signing_task(result);
                }
                Some(result) = self.withdrawal_broadcast_tasks.join_next() => {
                    self.handle_completed_withdrawal_broadcast_task(result);
                }
                Some(result) = OptionFuture::from(self.withdrawal_approval_task.as_mut()) => {
                    self.withdrawal_approval_task = None;
                    Self::log_task_result("withdrawal_approval", result);
                }
                Some(result) = OptionFuture::from(self.withdrawal_commitment_task.as_mut()) => {
                    self.withdrawal_commitment_task = None;
                    Self::log_task_result("withdrawal_commitment", result);
                }
                Some(result) = OptionFuture::from(self.deposit_gc_task.as_mut()) => {
                    self.deposit_gc_task = None;
                    Self::log_task_result("deposit_gc", result);
                }
                Some(result) = OptionFuture::from(self.proposal_gc_task.as_mut()) => {
                    self.proposal_gc_task = None;
                    Self::log_task_result("proposal_gc", result);
                }

            }
        }
    }

    fn handle_completed_deposit_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((deposit_id, inner)) => {
                self.inflight_deposits.remove(&deposit_id);
                Ok(inner)
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("deposit", mapped);
    }

    fn handle_completed_withdrawal_signing_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_signings.remove(&withdrawal_id);
                Ok(inner)
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_signing", mapped);
    }

    fn handle_completed_withdrawal_broadcast_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_broadcasts.remove(&withdrawal_id);
                Ok(inner)
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_broadcast", mapped);
    }

    fn log_task_result(label: &str, result: Result<anyhow::Result<()>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("{label} task failed: {err:#}"),
            Err(err) if err.is_panic() => error!("{label} task panicked: {err}"),
            Err(err) => error!("{label} task failed to join: {err}"),
        }
    }

    pub fn is_current_leader(&self, checkpoint_height: u64) -> bool {
        if self.inner.onchain_state().state().hashi().config.paused() {
            debug!("Bridge is paused, not acting as leader");
            return false;
        }

        match self.inner.config.force_run_as_leader() {
            ForceRunAsLeader::Always => return true,
            ForceRunAsLeader::Never => return false,
            ForceRunAsLeader::Default => (),
        }

        let Some(committee) = self.inner.onchain_state().current_committee() else {
            // TODO: do we need to do anything when bootstrapping? At genesis there is no committee.
            return false;
        };
        let this_validator_address = self
            .inner
            .config
            .validator_address()
            .expect("No configured validator address");
        let Some(this_validator_idx) = committee
            .index_of(&this_validator_address)
            .map(|i| i as u64)
        else {
            // We are not in the committee yet, so we cannot be the leader
            return false;
        };
        let num_validators = committee.members().len() as u64;

        let current_turn = checkpoint_height / NUM_CONSECUTIVE_LEADER_CHECKPOINTS;
        let is_leader = (current_turn % num_validators) == this_validator_idx;

        trace!("Node index {this_validator_idx} is leader node: {is_leader}");
        is_leader
    }

    fn is_reconfiguring(&self) -> bool {
        self.inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .pending_epoch_change()
            .is_some()
    }

    fn process_deposit_requests(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_deposit_requests");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping deposit request processing");
            return;
        }

        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        // Sort deposit_requests by timestamp, from earliest to latest
        deposit_requests.sort_by_key(|r| r.timestamp_ms);
        let deposit_ids: Vec<Address> = deposit_requests.iter().map(|r| r.id).collect();
        // TODO: If we keep AbortHandles for deposit tasks, explicitly abort tasks whose
        // deposit IDs are no longer present here so they do not linger until timeout.
        self.inflight_deposits
            .retain(|deposit_id| deposit_ids.contains(deposit_id));

        debug!("Processing {} deposit requests", deposit_requests.len());

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        for deposit_request in deposit_requests.iter().cloned() {
            if self.deposit_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_deposits.contains(&deposit_request.id) {
                continue;
            }

            let deposit_id = deposit_request.id;
            let inner = self.inner.clone();

            self.inflight_deposits.insert(deposit_id);
            self.deposit_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::process_deposit_request(inner, deposit_request),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "deposit {deposit_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (deposit_id, result)
            });
        }

        self.check_delete_expired_deposit_requests(&deposit_requests, checkpoint_timestamp_ms);
    }

    #[tracing::instrument(level = "info", skip_all, fields(deposit_id = %deposit_request.id))]
    async fn process_deposit_request(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
    ) -> anyhow::Result<()> {
        info!("Processing deposit request");

        // Validate deposit_request before asking for signatures
        inner
            .validate_deposit_request(&deposit_request)
            .await
            .map_err(|e| {
                debug!("Deposit validation failed: {e}");
                anyhow::anyhow!(e)
            })?;

        info!("Deposit request validated successfully");

        let proto_request = deposit_request_to_proto(&deposit_request);
        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let required_weight = certificate_threshold(committee.total_weight());

        // Fan out signature requests to all members in parallel.
        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            sig_tasks.spawn(async move {
                Self::request_deposit_confirmation_signature(&inner, proto_request, &member).await
            });
        }

        // Collect signatures, stopping once we reach quorum.
        let confirmation_message = DepositConfirmationMessage {
            request_id: deposit_request.id,
            utxo: deposit_request.utxo.clone(),
        };
        let mut aggregator = BlsSignatureAggregator::new(&committee, confirmation_message);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add deposit signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        if aggregator.weight() < required_weight {
            anyhow::bail!(
                "Aggregate weight of signatures {} is less than required weight {required_weight}",
                aggregator.weight()
            );
        }

        let signed_message = aggregator.finish()?;
        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_confirm_deposit(&deposit_request, signed_message)
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_deposit", "success"])
                    .inc();
                inner.metrics.deposits_confirmed_total.inc();
                info!("Successfully submitted deposit confirmation");
            })
            .inspect_err(|e| {
                error!("Failed to submit deposit confirmation: {e}");
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_deposit", "failure"])
                    .inc();
            })?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_deposit_confirmation_signature(
        inner: &Arc<Hashi>,
        proto_request: SignDepositConfirmationRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting deposit confirmation signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_deposit_confirmation(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get deposit confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved deposit confirmation signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    // ========================================================================
    // Step 1: Approve unapproved withdrawal requests
    // ========================================================================

    fn process_unapproved_withdrawal_requests(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_unapproved_withdrawal_requests");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal approval processing");
            return;
        }

        if self.withdrawal_approval_task.is_some() {
            debug!("Withdrawal approval task already in-flight, skipping");
            return;
        }

        let mut unapproved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| r.status.is_requested())
            .collect();
        unapproved.sort_by_key(|r| r.timestamp_ms);

        let unapproved_ids: Vec<Address> = unapproved.iter().map(|r| r.id).collect();
        self.withdrawal_approval_retry_tracker
            .prune(&unapproved_ids);

        let to_process: Vec<_> = unapproved
            .into_iter()
            .filter(|r| {
                !self
                    .withdrawal_approval_retry_tracker
                    .should_skip(&r.id, checkpoint_timestamp_ms)
            })
            .collect();

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["withdrawal_approval"])
            .set(
                self.withdrawal_approval_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );

        if to_process.is_empty() {
            return;
        }

        let inner = self.inner.clone();
        let retry_tracker = self.withdrawal_approval_retry_tracker.clone();

        self.withdrawal_approval_task = Some(tokio::task::spawn(async move {
            Self::process_unapproved_withdrawal_requests_task(
                inner,
                retry_tracker,
                to_process,
                checkpoint_timestamp_ms,
            )
            .await
        }));
    }

    #[tracing::instrument(level = "info", skip_all, fields(batch_size = to_process.len()))]
    async fn process_unapproved_withdrawal_requests_task(
        inner: Arc<Hashi>,
        retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
        to_process: Vec<WithdrawalRequest>,
        checkpoint_timestamp_ms: u64,
    ) -> anyhow::Result<()> {
        let max_concurrent = inner.config.max_concurrent_leader_job_tasks();

        let this_validator_address = inner
            .config
            .validator_address()
            .expect("No configured validator address");

        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let mut tasks = JoinSet::new();
        let mut certified: Vec<(Address, CommitteeSignature)> = Vec::new();

        for request in to_process {
            if tasks.len() >= max_concurrent {
                // Wait for one to finish before spawning more.
                if let Some(result) = tasks.join_next().await {
                    match &result {
                        Err(err) if err.is_panic() => {
                            error!("Withdrawal approval task panicked: {err}")
                        }
                        Err(err) => error!("Withdrawal approval task failed to join: {err}"),
                        Ok(_) => {}
                    }
                    if let Ok((_request_id, Ok(Some(cert)))) = result {
                        certified.push(cert);
                    }
                }
            }

            let inner = inner.clone();
            let retry_tracker = retry_tracker.clone();
            let members = members.clone();
            let committee = committee.clone();
            tasks.spawn(async move {
                let request_id = request.id;
                let task_result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::process_unapproved_withdrawal_request(
                        inner.clone(),
                        retry_tracker.clone(),
                        request,
                        checkpoint_timestamp_ms,
                        this_validator_address,
                        &members,
                        &committee,
                    ),
                )
                .await;

                let (result, failure_kind) = match task_result {
                    Ok(result) => (result, None),
                    Err(_) => {
                        let kind = WithdrawalApprovalErrorKind::TimedOut;
                        inner
                            .metrics
                            .leader_retries_total
                            .with_label_values(&["withdrawal_approval", &format!("{kind:?}")])
                            .inc();
                        retry_tracker.record_failure(kind, request_id, checkpoint_timestamp_ms);
                        (Ok(None), Some(kind))
                    }
                };

                if result.is_err() && failure_kind.is_none() {
                    let kind = WithdrawalApprovalErrorKind::TaskFailed;
                    inner
                        .metrics
                        .leader_retries_total
                        .with_label_values(&["withdrawal_approval", &format!("{kind:?}")])
                        .inc();
                    retry_tracker.record_failure(kind, request_id, checkpoint_timestamp_ms);
                }
                if let Err(err) = &result {
                    error!(request_id = %request_id, "Withdrawal approval failed: {err:#}");
                }

                (request_id, result)
            });
        }

        while let Some(result) = tasks.join_next().await {
            match &result {
                Err(err) if err.is_panic() => error!("Withdrawal approval task panicked: {err}"),
                Err(err) => error!("Withdrawal approval task failed to join: {err}"),
                Ok(_) => {}
            }
            if let Ok((_request_id, Ok(Some(cert)))) = result {
                certified.push(cert);
            }
        }

        if certified.is_empty() {
            return Ok(());
        }

        Self::submit_approve_withdrawal_requests_with_retry(&inner, certified).await;
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(request_id = %request.id))]
    async fn process_unapproved_withdrawal_request(
        inner: Arc<Hashi>,
        retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
        request: WithdrawalRequest,
        checkpoint_timestamp_ms: u64,
        this_validator_address: Address,
        members: &[CommitteeMember],
        committee: &hashi_types::committee::Committee,
    ) -> anyhow::Result<Option<(Address, CommitteeSignature)>> {
        let approval = WithdrawalRequestApproval {
            request_id: request.id,
        };

        // Validate, screen, and sign locally first
        let local_sig = match inner
            .validate_and_sign_withdrawal_request_approval(&approval)
            .await
        {
            Ok(sig) => {
                retry_tracker.clear(&request.id);
                parse_member_signature(sig).unwrap()
            }
            Err(e) => {
                let kind = e.kind();
                inner
                    .metrics
                    .leader_retries_total
                    .with_label_values(&["withdrawal_approval", &format!("{kind:?}")])
                    .inc();
                retry_tracker.record_failure(kind, request.id, checkpoint_timestamp_ms);
                return Ok(None);
            }
        };

        let proto_request = approval.to_proto();
        let required_weight = certificate_threshold(committee.total_weight());

        let mut aggregator = BlsSignatureAggregator::new(committee, approval);
        if let Err(e) = aggregator.add_signature(local_sig) {
            error!("Failed to add local approval signature: {e}");
        }

        // Fan out signature requests to remote members in parallel.
        let mut sig_tasks = JoinSet::new();
        for member in members {
            if member.validator_address() == this_validator_address {
                continue;
            }
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_approval_signature(&inner, proto_request, &member).await
            });
        }

        // Collect signatures, stopping once we reach quorum.
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add approval signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_approval", "FailedQuorum"])
                .inc();
            retry_tracker.record_failure(
                WithdrawalApprovalErrorKind::FailedQuorum,
                request.id,
                checkpoint_timestamp_ms,
            );
            error!("Insufficient approval signatures: weight {weight} < {required_weight}");
            return Ok(None);
        }

        match aggregator.finish() {
            Ok(signed) => Ok(Some((request.id, signed.committee_signature().clone()))),
            Err(e) => {
                error!("Failed to build approval certificate: {e}");
                Ok(None)
            }
        }
    }

    async fn submit_approve_withdrawal_requests_with_retry(
        inner: &Arc<Hashi>,
        mut certified: Vec<(Address, CommitteeSignature)>,
    ) {
        loop {
            let approvals: Vec<(Address, &CommitteeSignature)> =
                certified.iter().map(|(id, cert)| (*id, cert)).collect();

            let result = Self::submit_approve_withdrawal_requests(inner, &approvals)
                .await
                .inspect(|()| {
                    inner
                        .metrics
                        .sui_tx_submissions_total
                        .with_label_values(&["approve_withdrawal", "success"])
                        .inc();
                })
                .inspect_err(|_| {
                    inner
                        .metrics
                        .sui_tx_submissions_total
                        .with_label_values(&["approve_withdrawal", "failure"])
                        .inc();
                });
            let Err(e) = result else { return };

            let err_msg = format!("{e}");
            error!("approve_request PTB failed: {err_msg}");

            // Try to identify which request caused the failure by checking
            // which ones no longer exist in the queue (canceled).
            let before_len = certified.len();
            certified.retain(|(id, _)| inner.onchain_state().withdrawal_request(id).is_some());

            if certified.len() == before_len {
                error!("Could not identify failed request, aborting retry");
                return;
            }
            if certified.is_empty() {
                return;
            }

            info!(
                "Retrying approve_request with {} remaining requests",
                certified.len()
            );
        }
    }

    // ========================================================================
    // Step 2: Construct withdrawal tx for approved requests
    // ========================================================================

    fn process_approved_withdrawal_requests(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_approved_withdrawal_requests");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal commitment processing");
            return;
        }

        if self.withdrawal_commitment_task.is_some() {
            debug!("Withdrawal commitment task already in-flight, skipping");
            return;
        }

        let mut approved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| r.status.is_approved())
            .collect();
        approved.sort_by_key(|r| r.timestamp_ms);

        if self
            .withdrawal_commitment_retry_tracker
            .should_skip(checkpoint_timestamp_ms)
        {
            self.inner
                .metrics
                .leader_items_in_backoff
                .with_label_values(&["withdrawal_commitment"])
                .set(
                    self.withdrawal_commitment_retry_tracker
                        .in_backoff_count(checkpoint_timestamp_ms) as i64,
                );
            return;
        }

        // Collect all approved requests and process them as a single batch.
        // The coin selection algorithm picks up to
        // max_withdrawal_requests oldest requests from the slice.
        let batch: Vec<WithdrawalRequest> = approved.into_iter().collect();

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["withdrawal_commitment"])
            .set(
                self.withdrawal_commitment_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );

        if batch.is_empty() {
            return;
        }

        let max_batch = self.inner.config.withdrawal_max_batch_size();
        let delay_ms = self.inner.config.withdrawal_batching_delay_ms();

        let batch_is_full = batch.len() >= max_batch;
        let oldest_has_waited = batch
            .first()
            .is_some_and(|r| checkpoint_timestamp_ms >= r.timestamp_ms + delay_ms);

        if !batch_is_full && !oldest_has_waited {
            debug!(
                "Holding {} approved request(s): oldest is {}ms old, \
                 waiting for {}ms delay or {} requests",
                batch.len(),
                checkpoint_timestamp_ms.saturating_sub(batch[0].timestamp_ms),
                delay_ms,
                max_batch,
            );
            return;
        }

        let inner = self.inner.clone();
        let retry_tracker = self.withdrawal_commitment_retry_tracker.clone();

        self.withdrawal_commitment_task = Some(tokio::task::spawn(async move {
            let task_result = tokio::time::timeout(
                LEADER_TASK_TIMEOUT,
                Self::process_approved_withdrawal_request_batch(
                    inner.clone(),
                    retry_tracker.clone(),
                    batch,
                    checkpoint_timestamp_ms,
                ),
            )
            .await;

            match task_result {
                Ok(result) => result,
                Err(_) => {
                    let kind = WithdrawalCommitmentErrorKind::TimedOut;
                    inner
                        .metrics
                        .leader_retries_total
                        .with_label_values(&["withdrawal_commitment", &format!("{kind:?}")])
                        .inc();
                    Err(anyhow::anyhow!(
                        "withdrawal commitment timed out after {LEADER_TASK_TIMEOUT:?}"
                    ))
                }
            }
        }));
    }

    #[tracing::instrument(level = "info", skip_all, fields(batch_size = requests.len()))]
    async fn process_approved_withdrawal_request_batch(
        inner: Arc<Hashi>,
        retry_tracker: GlobalRetryTracker<WithdrawalCommitmentErrorKind>,
        requests: Vec<WithdrawalRequest>,
        checkpoint_timestamp_ms: u64,
    ) -> anyhow::Result<()> {
        info!(
            withdrawal_request_ids = ?requests.iter().map(|r| r.id).collect::<Vec<_>>(),
            "Processing batch of {} approved withdrawal request(s)",
            requests.len(),
        );

        // Build the withdrawal tx commitment for the batch.
        let approval = match inner.build_withdrawal_tx_commitment(&requests).await {
            Ok(approval) => {
                retry_tracker.clear();
                approval
            }
            Err(e) => {
                let kind = e.kind();
                inner
                    .metrics
                    .leader_retries_total
                    .with_label_values(&["withdrawal_commitment", &format!("{kind:?}")])
                    .inc();
                retry_tracker.record_failure(kind, checkpoint_timestamp_ms);
                return Ok(());
            }
        };

        // Fan out to committee for BLS signatures over the commitment message
        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let required_weight = certificate_threshold(committee.total_weight());
        let proto_request = approval.to_proto();

        // Fan out signature requests to all members in parallel.
        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_tx_commitment_signature(&inner, proto_request, &member)
                    .await
            });
        }

        // Collect signatures, stopping once we reach quorum.
        let mut aggregator = BlsSignatureAggregator::new(&committee, approval.clone());
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add withdrawal commitment signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        if aggregator.weight() < required_weight {
            inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_commitment", "FailedQuorum"])
                .inc();
            retry_tracker.record_failure(
                WithdrawalCommitmentErrorKind::FailedQuorum,
                checkpoint_timestamp_ms,
            );
            error!(
                "Insufficient withdrawal commitment signatures: weight {} < {required_weight}",
                aggregator.weight()
            );
            return Ok(());
        }

        let signed_approval = match aggregator.finish() {
            Ok(signed_approval) => signed_approval,
            Err(e) => {
                error!("Failed to build withdrawal commitment certificate: {e}");
                return Ok(());
            }
        };

        // Proactively trigger a presig refill if this commit will allocate
        // indices beyond the current pool.
        {
            let num_inputs = approval.selected_utxos.len() as u64;
            let num_consumed = inner.onchain_state().state().hashi().num_consumed_presigs;
            let needed_end = num_consumed + num_inputs;
            if let Some(sm) = inner.try_signing_manager() {
                let mgr = sm.read().unwrap();
                let available_end = mgr.available_presig_end_index();
                if needed_end > available_end {
                    info!(
                        "Presig pool may be insufficient for this withdrawal: \
                         need index {needed_end}, pool ends at {available_end}. \
                         Triggering proactive refill.",
                    );
                    mgr.trigger_refill();
                }
            }
        }

        // Submit commit_withdrawal_tx to Sui
        Self::submit_commit_withdrawal_tx(&inner, &approval, signed_approval.committee_signature())
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["commit_withdrawal", "success"])
                    .inc();
            })
            .inspect_err(|e| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["commit_withdrawal", "failure"])
                    .inc();
                error!("Failed to submit commit_withdrawal_tx: {e}");
            })?;

        Ok(())
    }

    // ========================================================================
    // Step 3: MPC sign withdrawal transactions and store signatures on-chain
    // ========================================================================

    fn process_unsigned_withdrawal_txns(&mut self) {
        debug!("Entering process_unsigned_withdrawal_txns");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal tx signing");
            return;
        }

        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.signatures.is_none());
        withdrawal_txns.sort_by_key(|p| p.timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_signings
            .retain(|id| pending_ids.contains(id));

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        for txn in withdrawal_txns {
            if self.withdrawal_signing_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_withdrawal_signings.contains(&txn.id) {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_signings.insert(txn_id);
            self.withdrawal_signing_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::process_unsigned_withdrawal_txn(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "withdrawal signing for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (txn_id, result)
            });
        }
    }

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn process_unsigned_withdrawal_txn(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        // If the withdrawal transaction is from a previous epoch, reassign its presig
        // indices from the new epoch's counter before signing.
        // TODO: Batch multiple stale-epoch withdrawals into a single PTB.
        let current_epoch = inner.onchain_state().epoch();
        if txn.epoch != current_epoch {
            info!(
                "Withdrawal transaction from epoch {} (current {}), reassigning presig indices",
                txn.epoch, current_epoch,
            );
            let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
            executor
                .execute_allocate_presigs_for_withdrawal_txn(txn.id)
                .await?;
            info!("Presig indices reassigned, will sign on next checkpoint");
            // Return and let the next checkpoint iteration pick up the updated state.
            return Ok(());
        }
        info!("MPC signing withdrawal transaction");

        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // 1. Request signed withdrawal tx witnesses from committee members.
        // MPC signing requires all threshold members to participate simultaneously
        // via P2P, so we must fan out requests in parallel.
        let signatures_by_input = Self::collect_withdrawal_tx_signatures(&inner, &txn.id, &members)
            .await
            .ok_or_else(|| anyhow::anyhow!("Failed to collect MPC signatures for {:?}", txn.id))?;

        // 2. Extract raw signature bytes for on-chain storage
        let witness_signatures: Vec<Vec<u8>> = signatures_by_input
            .iter()
            .map(|s| s.to_byte_array().to_vec())
            .collect();

        // 3. Build the WithdrawalTxSigning and get BLS certificate via fan-out
        let signed_message = WithdrawalTxSigning {
            withdrawal_id: txn.id,
            request_ids: txn.request_ids.clone(),
            signatures: witness_signatures.clone(),
        };

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let required_weight = certificate_threshold(committee.total_weight());
        let proto_request = signed_message.to_proto();

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_tx_signing_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(withdrawal_txn_id = %txn.id, "Failed to add withdrawal sign message signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient signatures for sign_withdrawal: weight {weight} < {required_weight}"
            );
        }

        let signed = aggregator.finish()?;

        // 4. Submit sign_withdrawal to Sui (writes signatures on-chain).
        // Broadcast + confirm happens via process_signed_withdrawal_txns on the next tick.
        Self::submit_sign_withdrawal(
            &inner,
            &txn.id,
            &txn.request_ids.clone(),
            &witness_signatures,
            signed.committee_signature(),
        )
        .await
        .inspect(|()| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["sign_withdrawal", "success"])
                .inc();
        })
        .inspect_err(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["sign_withdrawal", "failure"])
                .inc();
        })?;

        Ok(())
    }

    // ========================================================================
    // Step 4-5: Broadcast signed tx and confirm on-chain
    // ========================================================================

    fn process_signed_withdrawal_txns(&mut self) {
        debug!("Entering process_signed_withdrawal_txns");
        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.signatures.is_some());
        withdrawal_txns.sort_by_key(|p| p.timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_broadcasts
            .retain(|id| pending_ids.contains(id));

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        for txn in withdrawal_txns {
            if self.withdrawal_broadcast_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_withdrawal_broadcasts.contains(&txn.id) {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_broadcasts.insert(txn_id);
            self.withdrawal_broadcast_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::handle_signed_withdrawal(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "withdrawal broadcast for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (txn_id, result)
            });
        }
    }

    /// Check BTC tx status, broadcast/re-broadcast if needed, confirm when
    /// enough BTC confirmations are reached.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid))]
    async fn handle_signed_withdrawal(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        let confirmation_threshold = inner.onchain_state().bitcoin_confirmation_threshold();
        let txid: bitcoin::Txid = txn.txid.into();
        tracing::Span::current().record("bitcoin_txid", tracing::field::display(&txid));

        match inner.btc_monitor().get_transaction_status(txid).await {
            Ok(TxStatus::Confirmed { confirmations })
                if confirmations >= confirmation_threshold =>
            {
                info!(
                    confirmations,
                    "Withdrawal tx confirmed, proceeding to on-chain confirmation"
                );
                Self::confirm_withdrawal_on_sui(&inner, &txn).await?;
            }
            Ok(TxStatus::Confirmed { confirmations }) => {
                debug!(
                    confirmations,
                    confirmation_threshold, "Withdrawal tx waiting for more confirmations"
                );
            }
            Ok(TxStatus::InMempool) => {
                debug!("Withdrawal tx in mempool, waiting for confirmations");
            }
            Ok(TxStatus::NotFound) => {
                Self::rebuild_and_broadcast_withdrawal_btc_tx(&inner, &txn, txid).await;
            }
            Err(e) => {
                anyhow::bail!(
                    "failed to query transaction status for withdrawal transaction {}: {e}",
                    txn.id
                );
            }
        }
        Ok(())
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain WithdrawalTransaction
    /// data (stored witness signatures) and broadcast it to the Bitcoin network.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid = %txid))]
    async fn rebuild_and_broadcast_withdrawal_btc_tx(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        txid: bitcoin::Txid,
    ) {
        warn!("Withdrawal tx not found, re-broadcasting from on-chain signatures");

        let tx = match Self::rebuild_signed_tx_from_onchain(inner, txn) {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to rebuild signed withdrawal tx: {e}");
                return;
            }
        };

        match inner.btc_monitor().broadcast_transaction(tx).await {
            Ok(()) => {
                info!("Re-broadcast withdrawal tx");
            }
            Err(e) => {
                error!("Failed to re-broadcast withdrawal tx: {e}");
            }
        }
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain WithdrawalTransaction
    fn rebuild_signed_tx_from_onchain(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let raw_sigs = txn
            .signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No signatures on withdrawal transaction"))?;

        let mut tx = inner.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;

        anyhow::ensure!(
            raw_sigs.len() == tx.input.len(),
            "Signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_sigs.len()
        );
        anyhow::ensure!(
            tx.input.len() == txn.inputs.len(),
            "Input count mismatch: tx has {} inputs, txn has {}",
            tx.input.len(),
            txn.inputs.len()
        );

        let hashi_pubkey = inner.get_hashi_pubkey()?;
        for ((input, txn_input), sig_bytes) in
            tx.input.iter_mut().zip(txn.inputs.iter()).zip(raw_sigs)
        {
            let pubkey = inner.deposit_pubkey(&hashi_pubkey, txn_input.derivation_path.as_ref())?;
            let (script, control_block, _) =
                bitcoin_utils::single_key_taproot_script_path_spend_artifacts(&pubkey);
            let mut witness = bitcoin::Witness::new();
            witness.push(sig_bytes);
            witness.push(script.to_bytes());
            witness.push(control_block.serialize());
            input.witness = witness;
        }

        Ok(tx)
    }

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn confirm_withdrawal_on_sui(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        let members = inner
            .onchain_state()
            .current_committee_members()
            .ok_or_else(|| anyhow::anyhow!("No current committee members for confirmation"))?;

        let confirmation_cert =
            Self::collect_withdrawal_confirmation_signature(inner, txn.id, &members).await?;

        Self::submit_confirm_withdrawal(inner, &txn.id, &confirmation_cert)
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "success"])
                    .inc();
                inner.metrics.withdrawals_finalized_total.inc();
            })
            .inspect_err(|_| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "failure"])
                    .inc();
            })?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(withdrawal_txn_id = %withdrawal_txn_id))]
    async fn collect_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let confirmation = crate::withdrawals::WithdrawalConfirmation {
            withdrawal_id: withdrawal_txn_id,
        };

        let required_weight = certificate_threshold(committee.total_weight());

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_confirmation_signature(&inner, withdrawal_txn_id, &member)
                    .await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, confirmation);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add withdrawal confirmation signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient withdrawal confirmation signatures for {:?}: weight {weight} < {required_weight}",
                withdrawal_txn_id
            );
        }

        Ok(aggregator.finish()?.into_parts().0)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_commitment_signature(
        inner: &Arc<Hashi>,
        proto_request: SignWithdrawalTxConstructionRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx commitment signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_tx_construction(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal approval signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal approval signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal approval response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_approval_signature(
        inner: &Arc<Hashi>,
        proto_request: SignWithdrawalRequestApprovalRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal request approval signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_request_approval(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal request approval signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal request approval signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal request approval response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signing_signature(
        inner: &Arc<Hashi>,
        proto_request: SignWithdrawalTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signing signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_tx_signing(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal tx signing signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal tx signing signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal tx signing response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        member: &CommitteeMember,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                )
            })?;

        let proto_request = SignWithdrawalTransactionRequest {
            withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
        };

        let response = rpc_client
            .sign_withdrawal_transaction(proto_request)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to get withdrawal tx signature from {validator_address}: {e}"
                )
            })?;

        trace!(
            "Retrieved withdrawal tx signature from {}",
            validator_address
        );

        response
            .into_inner()
            .signatures_by_input
            .iter()
            .map(|sig_bytes| {
                let bytes: [u8; 64] = sig_bytes.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("Invalid Schnorr signature length from {validator_address}")
                })?;
                SchnorrSignature::from_byte_array(&bytes).map_err(|e| {
                    anyhow::anyhow!("Invalid Schnorr signature from {validator_address}: {e}")
                })
            })
            .collect()
    }

    async fn collect_withdrawal_tx_signatures(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        members: &[CommitteeMember],
    ) -> Option<Vec<SchnorrSignature>> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| Self::request_withdrawal_tx_signature(inner, withdrawal_txn_id, member))
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut results = results.into_iter();
        loop {
            match results.next() {
                Some(Ok(signatures)) => return Some(signatures),
                Some(Err(e)) => {
                    warn!("Could not get signatures from a node: {e}");
                }
                None => {
                    error!(
                        "Could not get mpc signatures for {:?}; stopping processing",
                        withdrawal_txn_id
                    );
                    return None;
                }
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal confirmation signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_confirmation(SignWithdrawalConfirmationRequest {
                withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
            })
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal confirmation signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal confirmation response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn submit_approve_withdrawal_requests(
        inner: &Arc<Hashi>,
        approvals: &[(Address, &CommitteeSignature)],
    ) -> anyhow::Result<()> {
        info!(
            "Submitting approve_request PTB for {} requests",
            approvals.len()
        );

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_approve_withdrawal_requests(approvals)
            .await
    }

    async fn submit_commit_withdrawal_tx(
        inner: &Arc<Hashi>,
        approval: &WithdrawalTxCommitment,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!(
            "Submitting commit_withdrawal_tx for txid {:?}",
            approval.txid
        );

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor.execute_commit_withdrawal_tx(approval, cert).await
    }

    async fn submit_sign_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_id: &Address,
        request_ids: &[Address],
        signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Submitting sign_withdrawal for {:?}", withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_sign_withdrawal(withdrawal_id, request_ids, signatures, cert)
            .await
    }

    async fn submit_confirm_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Confirming withdrawal {:?}", withdrawal_txn_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_confirm_withdrawal(withdrawal_txn_id, cert)
            .await?;

        info!("Successfully confirmed withdrawal {:?}", withdrawal_txn_id);
        Ok(())
    }
}

fn deposit_request_to_proto(req: &DepositRequest) -> SignDepositConfirmationRequest {
    SignDepositConfirmationRequest {
        id: req.id.as_bytes().to_vec().into(),
        txid: req.utxo.id.txid.as_bytes().to_vec().into(),
        vout: req.utxo.id.vout,
        amount: req.utxo.amount,
        derivation_path: req
            .utxo
            .derivation_path
            .map(|p| p.as_bytes().to_vec().into()),
        timestamp_ms: req.timestamp_ms,
        requester_address: req.sender.as_bytes().to_vec().into(),
        sui_tx_digest: req.sui_tx_digest.as_bytes().to_vec().into(),
    }
}

fn parse_member_signature(
    member_signature: hashi_types::proto::MemberSignature,
) -> anyhow::Result<MemberSignature> {
    let epoch = member_signature
        .epoch
        .ok_or(anyhow::anyhow!("No epoch in MemberSignature"))?;
    let address_string = member_signature
        .address
        .ok_or(anyhow::anyhow!("No address in MemberSignature"))?;
    let address = address_string
        .parse::<Address>()
        .map_err(|e| anyhow::anyhow!("Unable to parse Address: {}", e))?;
    let signature = BLS12381Signature::from_bytes(
        member_signature
            .signature
            .ok_or(anyhow::anyhow!("No signature in MemberSignature"))?
            .as_bytes(),
    )?;
    Ok(MemberSignature::new(epoch, address, signature))
}

impl WithdrawalRequestApproval {
    fn to_proto(&self) -> SignWithdrawalRequestApprovalRequest {
        SignWithdrawalRequestApprovalRequest {
            request_id: self.request_id.as_bytes().to_vec().into(),
        }
    }
}

impl WithdrawalTxCommitment {
    fn to_proto(&self) -> SignWithdrawalTxConstructionRequest {
        SignWithdrawalTxConstructionRequest {
            request_ids: self
                .request_ids
                .iter()
                .map(|id| id.as_bytes().to_vec().into())
                .collect(),
            selected_utxos: self
                .selected_utxos
                .iter()
                .map(|utxo_id| hashi_types::proto::UtxoId {
                    txid: Some(utxo_id.txid.as_bytes().to_vec().into()),
                    vout: Some(utxo_id.vout),
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| hashi_types::proto::WithdrawalOutput {
                    amount: output.amount,
                    bitcoin_address: output.bitcoin_address.clone().into(),
                })
                .collect(),
            txid: self.txid.as_bytes().to_vec().into(),
        }
    }
}

impl WithdrawalTxSigning {
    fn to_proto(&self) -> SignWithdrawalTxSigningRequest {
        SignWithdrawalTxSigningRequest {
            withdrawal_id: self.withdrawal_id.as_bytes().to_vec().into(),
            request_ids: self
                .request_ids
                .iter()
                .map(|id| id.as_bytes().to_vec().into())
                .collect(),
            signatures: self
                .signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
        }
    }
}
