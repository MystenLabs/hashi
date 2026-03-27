// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod garbage_collection;
mod retry;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::config::ForceRunAsLeader;
use crate::deposits::DepositRequestErrorKind;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::PendingWithdrawal;
use crate::onchain::types::WithdrawalRequest;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use crate::withdrawals::WithdrawalTxSigning;
use bitcoin::hashes::Hash;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
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
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;
const LEADER_PHASE_TIMEOUT: Duration = Duration::from_secs(60);
const DEPOSIT_TASK_TIMEOUT: Duration = Duration::from_secs(60);

pub struct LeaderService {
    inner: Arc<Hashi>,
    deposit_retry_tracker: RetryTracker<DepositRequestErrorKind>,
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    withdrawal_commitment_retry_tracker: RetryTracker<WithdrawalCommitmentErrorKind>,
    deposit_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    deposit_gc_tasks: JoinSet<(Vec<Address>, anyhow::Result<usize>)>,
    inflight_deposits: HashSet<Address>,
    inflight_deposit_gc_requests: HashSet<Address>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            deposit_retry_tracker: RetryTracker::new(),
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: RetryTracker::new(),
            deposit_tasks: JoinSet::new(),
            deposit_gc_tasks: JoinSet::new(),
            inflight_deposits: HashSet::new(),
            inflight_deposit_gc_requests: HashSet::new(),
        }
    }

    /// Start the leader service and return a `Service` for lifecycle management.
    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    async fn run(mut self) {
        info!("Starting leader service");

        // Wait for DKG to complete before processing any checkpoints.
        let mpc_handle = self.inner.mpc_handle().expect("MpcHandle not initialized");
        info!("Waiting for MPC key to become available...");
        mpc_handle.wait_for_key_ready().await;
        info!("MPC key is ready, starting leader loop");

        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();

        loop {
            trace!("Waiting for next checkpoint or deposit completion...");
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

                    self.process_deposit_requests(checkpoint_timestamp_ms);

                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.process_unapproved_withdrawal_requests(checkpoint_timestamp_ms),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.process_approved_withdrawal_requests(checkpoint_timestamp_ms),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.process_unsigned_pending_withdrawals(),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.process_signed_pending_withdrawals(),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.check_delete_proposals(checkpoint_timestamp_ms),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        LEADER_PHASE_TIMEOUT,
                        self.check_delete_spent_utxos(),
                    )
                    .await;
                }
                Some(result) = self.deposit_tasks.join_next() => {
                    self.handle_completed_deposit_task(result);
                }
                Some(result) = self.deposit_gc_tasks.join_next() => {
                    self.handle_completed_deposit_gc_task(result);
                }
            }
        }
    }

    fn handle_completed_deposit_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((deposit_id, Ok(()))) => {
                self.inflight_deposits.remove(&deposit_id);
            }
            Ok((deposit_id, Err(err))) => {
                self.inflight_deposits.remove(&deposit_id);
                error!(deposit_request_id = %deposit_id, "Deposit task failed: {err:#}");
            }
            Err(err) if err.is_panic() => {
                error!("Deposit task panicked: {err}");
            }
            Err(err) => {
                error!("Deposit task failed to join: {err}");
            }
        }
    }

    fn handle_completed_deposit_gc_task(
        &mut self,
        result: Result<(Vec<Address>, anyhow::Result<usize>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((deposit_ids, Ok(deleted_count))) => {
                for deposit_id in deposit_ids {
                    self.inflight_deposit_gc_requests.remove(&deposit_id);
                }
                info!(
                    "Successfully deleted {} expired deposit requests",
                    deleted_count
                );
            }
            Ok((deposit_ids, Err(err))) => {
                for deposit_id in deposit_ids {
                    self.inflight_deposit_gc_requests.remove(&deposit_id);
                }
                error!("Failed to delete expired deposit requests: {err}");
            }
            Err(err) if err.is_panic() => {
                error!("Deposit request GC task panicked: {err}");
            }
            Err(err) => {
                error!("Deposit request GC task failed to join: {err}");
            }
        }
    }

    pub fn is_current_leader(&self, checkpoint_height: u64) -> bool {
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

    fn process_deposit_requests(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_deposit_requests");
        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        // Sort deposit_requests by timestamp, from earliest to latest
        deposit_requests.sort_by_key(|r| r.timestamp_ms);
        let deposit_ids: Vec<Address> = deposit_requests.iter().map(|r| r.id).collect();
        self.deposit_retry_tracker.prune(&deposit_ids);
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
            if self
                .deposit_retry_tracker
                .should_skip(&deposit_request.id, checkpoint_timestamp_ms)
            {
                continue;
            }

            let deposit_id = deposit_request.id;
            let inner = self.inner.clone();
            let deposit_retry_tracker = self.deposit_retry_tracker.clone();

            self.inflight_deposits.insert(deposit_id);
            self.deposit_tasks.spawn(async move {
                let task_result = tokio::time::timeout(
                    DEPOSIT_TASK_TIMEOUT,
                    Self::process_deposit_request(
                        inner.clone(),
                        deposit_retry_tracker.clone(),
                        deposit_request,
                        checkpoint_timestamp_ms,
                    ),
                )
                .await;

                let (result, failure_kind) = match task_result {
                    Ok(result) => (result, None),
                    Err(_) => {
                        let kind = DepositRequestErrorKind::TimedOut;
                        inner
                            .metrics
                            .leader_retries_total
                            .with_label_values(&["deposit", &format!("{kind:?}")])
                            .inc();
                        deposit_retry_tracker.record_failure(
                            kind,
                            deposit_id,
                            checkpoint_timestamp_ms,
                        );
                        (
                            Err(anyhow::anyhow!(
                                "deposit task timed out after {DEPOSIT_TASK_TIMEOUT:?}"
                            )),
                            Some(kind),
                        )
                    }
                };

                if let Err(err) = &result {
                    if failure_kind.is_none() {
                        let kind = DepositRequestErrorKind::TaskFailed;
                        inner
                            .metrics
                            .leader_retries_total
                            .with_label_values(&["deposit", &format!("{kind:?}")])
                            .inc();
                        deposit_retry_tracker.record_failure(
                            kind,
                            deposit_id,
                            checkpoint_timestamp_ms,
                        );
                    }
                    error!(deposit_request_id = %deposit_id, "Deposit task will retry after failure: {err:#}");
                }

                (deposit_id, result)
            });
        }

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["deposit"])
            .set(
                self.deposit_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );

        self.check_delete_expired_deposit_requests(&deposit_requests, checkpoint_timestamp_ms);
    }

    async fn process_deposit_request(
        inner: Arc<Hashi>,
        deposit_retry_tracker: RetryTracker<DepositRequestErrorKind>,
        deposit_request: DepositRequest,
        checkpoint_timestamp_ms: u64,
    ) -> anyhow::Result<()> {
        // TODO: parallelize, and after we have a quorum of sigs, stop waiting for sigs from any
        // additional validators

        info!(deposit_request_id = %deposit_request.id, "Processing deposit request");

        // Validate deposit_request before asking for signatures
        match inner.validate_deposit_request(&deposit_request).await {
            Ok(()) => {}
            Err(e) => {
                debug!(request_id = ?deposit_request.id, "Deposit validation failed: {e}");
                let kind = e.kind();
                inner
                    .metrics
                    .leader_retries_total
                    .with_label_values(&["deposit", &format!("{kind:?}")])
                    .inc();
                deposit_retry_tracker.record_failure(
                    kind,
                    deposit_request.id,
                    checkpoint_timestamp_ms,
                );
                return Ok(());
            }
        }

        info!(deposit_request_id = %deposit_request.id, "Deposit request validated successfully");

        let proto_request = deposit_request.to_proto();
        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) =
                Self::request_deposit_confirmation_signature(&inner, proto_request.clone(), &member)
                    .await
            {
                signatures.push(signature);
            }
        }

        Self::submit_deposit_confirmation(&inner, deposit_request.clone(), signatures).await?;
        deposit_retry_tracker.clear(&deposit_request.id);
        Ok(())
    }

    async fn request_deposit_confirmation_signature(
        inner: &Arc<Hashi>,
        proto_request: SignDepositConfirmationRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting deposit confirmation signature from {}",
            validator_address
        );

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

    async fn submit_deposit_confirmation(
        inner: &Arc<Hashi>,
        deposit_request: DepositRequest,
        signatures: Vec<MemberSignature>,
    ) -> anyhow::Result<()> {
        info!(deposit_request_id = %deposit_request.id, "Aggregating signatures and submitting deposit confirmation");

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        // Aggregate signatures
        let mut signature_aggregator =
            BlsSignatureAggregator::new(&committee, deposit_request.clone());
        for signature in signatures {
            signature_aggregator.add_signature(signature)?;
        }

        // Check for quorum
        // TODO: better way to check for quorom than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            anyhow::bail!(
                "Aggregate weight of signatures {weight} is less than required weight {required_weight}"
            );
        }

        // Submit onchain
        let signed_message = signature_aggregator.finish()?;
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
                info!(deposit_request_id = %deposit_request.id, "Successfully submitted deposit confirmation");
            })
            .inspect_err(|_| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_deposit", "failure"])
                    .inc();
            })
    }

    // ========================================================================
    // Step 1: Approve unapproved withdrawal requests
    // ========================================================================

    async fn process_unapproved_withdrawal_requests(&self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_unapproved_withdrawal_requests");
        let mut unapproved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| !r.approved)
            .collect();
        unapproved.sort_by_key(|r| r.timestamp_ms);

        let unapproved_ids: Vec<Address> = unapproved.iter().map(|r| r.id).collect();
        self.withdrawal_approval_retry_tracker
            .prune(&unapproved_ids);

        if unapproved.is_empty() {
            return;
        }

        let this_validator_address = self
            .inner
            .config
            .validator_address()
            .expect("No configured validator address");

        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        // Collect a per-request BLS certificate for each unapproved request.
        // Validators independently validate each request (including sanctions checks),
        let mut certified: Vec<(Address, CommitteeSignature)> = Vec::new();
        for request in &unapproved {
            if self
                .withdrawal_approval_retry_tracker
                .should_skip(&request.id, checkpoint_timestamp_ms)
            {
                continue;
            }

            let approval = WithdrawalRequestApproval {
                request_id: request.id,
            };

            // Validate, screen, and sign locally first
            let local_sig = match self
                .inner
                .validate_and_sign_withdrawal_request_approval(&approval)
                .await
            {
                Ok(sig) => {
                    self.withdrawal_approval_retry_tracker.clear(&request.id);
                    parse_member_signature(sig).unwrap()
                }
                Err(e) => {
                    let kind = e.kind();
                    self.inner
                        .metrics
                        .leader_retries_total
                        .with_label_values(&["withdrawal_approval", &format!("{kind:?}")])
                        .inc();
                    self.withdrawal_approval_retry_tracker.record_failure(
                        kind,
                        request.id,
                        checkpoint_timestamp_ms,
                    );
                    continue;
                }
            };

            let proto_request = approval.to_proto();
            let mut signatures: Vec<MemberSignature> = vec![local_sig];
            for member in &members {
                if member.validator_address() == this_validator_address {
                    continue;
                }
                if let Some(signature) = self
                    .request_withdrawal_approval_signature(proto_request.clone(), member)
                    .await
                {
                    signatures.push(signature);
                }
            }

            let mut aggregator = BlsSignatureAggregator::new(&committee, approval);
            for sig in signatures {
                if let Err(e) = aggregator.add_signature(sig) {
                    error!(withdrawal_request_id = %request.id, "Failed to add approval signature: {e}");
                }
            }

            let weight = aggregator.weight();
            let required_weight = certificate_threshold(committee.total_weight());
            if weight < required_weight {
                self.inner
                    .metrics
                    .leader_retries_total
                    .with_label_values(&["withdrawal_approval", "FailedQuorum"])
                    .inc();
                self.withdrawal_approval_retry_tracker.record_failure(
                    WithdrawalApprovalErrorKind::FailedQuorum,
                    request.id,
                    checkpoint_timestamp_ms,
                );
                error!(withdrawal_request_id = %request.id, "Insufficient approval signatures: weight {weight} < {required_weight}");
                continue;
            }

            match aggregator.finish() {
                Ok(signed) => {
                    certified.push((request.id, signed.committee_signature().clone()));
                }
                Err(e) => {
                    error!(withdrawal_request_id = %request.id, "Failed to build approval certificate: {e}");
                }
            }
        }

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["withdrawal_approval"])
            .set(
                self.withdrawal_approval_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );

        if certified.is_empty() {
            return;
        }

        // Submit all certified approvals in a single PTB.
        // On failure (e.g. a request was canceled mid-flight), remove the
        // offending request and retry until we succeed or run out of requests.
        self.submit_approve_withdrawal_requests_with_retry(certified)
            .await;
    }

    async fn submit_approve_withdrawal_requests_with_retry(
        &self,
        mut certified: Vec<(Address, CommitteeSignature)>,
    ) {
        loop {
            let approvals: Vec<(Address, &CommitteeSignature)> =
                certified.iter().map(|(id, cert)| (*id, cert)).collect();

            let result = self
                .submit_approve_withdrawal_requests(&approvals)
                .await
                .inspect(|()| {
                    self.inner
                        .metrics
                        .sui_tx_submissions_total
                        .with_label_values(&["approve_withdrawal", "success"])
                        .inc();
                })
                .inspect_err(|_| {
                    self.inner
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
            certified.retain(|(id, _)| self.inner.onchain_state().withdrawal_request(id).is_some());

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

    async fn process_approved_withdrawal_requests(&self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_approved_withdrawal_requests");
        let mut approved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| r.approved)
            .collect();
        approved.sort_by_key(|r| r.timestamp_ms);

        let approved_ids: Vec<Address> = approved.iter().map(|r| r.id).collect();
        self.withdrawal_commitment_retry_tracker
            .prune(&approved_ids);

        // Collect all non-backoff approved requests and process them as a
        // single batch. The coin selection algorithm picks up to
        // max_withdrawal_requests oldest requests from the slice.
        let batch: Vec<&WithdrawalRequest> = approved
            .iter()
            .filter(|r| {
                !self
                    .withdrawal_commitment_retry_tracker
                    .should_skip(&r.id, checkpoint_timestamp_ms)
            })
            .collect();

        if !batch.is_empty() {
            self.process_approved_withdrawal_request_batch(&batch, checkpoint_timestamp_ms)
                .await;
        }

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["withdrawal_commitment"])
            .set(
                self.withdrawal_commitment_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );
    }

    async fn process_approved_withdrawal_request_batch(
        &self,
        requests: &[&WithdrawalRequest],
        checkpoint_timestamp_ms: u64,
    ) {
        let oldest_id = requests[0].id;
        info!(
            withdrawal_request_ids = ?requests.iter().map(|r| r.id).collect::<Vec<_>>(),
            "Processing batch of {} approved withdrawal request(s)",
            requests.len(),
        );

        let requests_owned: Vec<WithdrawalRequest> =
            requests.iter().map(|r| (*r).clone()).collect();

        // Build the withdrawal tx commitment for the batch.
        let approval = match self
            .inner
            .build_withdrawal_tx_commitment(&requests_owned)
            .await
        {
            Ok(approval) => {
                // Clear backoff for all requests included in this commitment.
                for id in &approval.request_ids {
                    self.withdrawal_commitment_retry_tracker.clear(id);
                }
                approval
            }
            Err(e) => {
                // Record the failure against the oldest request in the batch so
                // it enters backoff. The next iteration will exclude it and retry
                // with a smaller batch.
                let kind = e.kind();
                self.inner
                    .metrics
                    .leader_retries_total
                    .with_label_values(&["withdrawal_commitment", &format!("{kind:?}")])
                    .inc();
                self.withdrawal_commitment_retry_tracker.record_failure(
                    kind,
                    oldest_id,
                    checkpoint_timestamp_ms,
                );
                return;
            }
        };

        // Fan out to committee for BLS signatures over the commitment message
        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");
        let proto_request = approval.to_proto();
        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in &members {
            if let Some(signature) = self
                .request_withdrawal_tx_commitment_signature(proto_request.clone(), member)
                .await
            {
                signatures.push(signature);
            }
        }

        // 4. Aggregate BLS signatures and check quorum
        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let mut signature_aggregator = BlsSignatureAggregator::new(&committee, approval.clone());
        for signature in signatures {
            if let Err(e) = signature_aggregator.add_signature(signature) {
                error!(oldest_request_id = %oldest_id, "Failed to add withdrawal commitment signature: {e}");
            }
        }

        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            self.inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_commitment", "FailedQuorum"])
                .inc();
            self.withdrawal_commitment_retry_tracker.record_failure(
                WithdrawalCommitmentErrorKind::FailedQuorum,
                oldest_id,
                checkpoint_timestamp_ms,
            );
            error!(oldest_request_id = %oldest_id, "Insufficient withdrawal commitment signatures: weight {weight} < {required_weight}");
            return;
        }

        let signed_approval = match signature_aggregator.finish() {
            Ok(signed_approval) => signed_approval,
            Err(e) => {
                error!(oldest_request_id = %oldest_id, "Failed to build withdrawal commitment certificate: {e}");
                return;
            }
        };

        // 5. Submit commit_withdrawal_tx to Sui
        let _ = self
            .submit_commit_withdrawal_tx(&approval, signed_approval.committee_signature())
            .await
            .inspect(|()| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["commit_withdrawal", "success"])
                    .inc();
            })
            .inspect_err(|e| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["commit_withdrawal", "failure"])
                    .inc();
                error!(oldest_request_id = %oldest_id, "Failed to submit commit_withdrawal_tx: {e}");
            });
    }

    // ========================================================================
    // Step 3: MPC sign pending withdrawals and store signatures on-chain
    // ========================================================================

    async fn process_unsigned_pending_withdrawals(&self) {
        debug!("Entering process_unsigned_pending_withdrawals");
        let mut pending_withdrawals = self.inner.onchain_state().pending_withdrawals();
        pending_withdrawals.retain(|p| p.signatures.is_none());
        pending_withdrawals.sort_by_key(|p| p.timestamp_ms);

        // TODO: process multiple at a time.
        if let Some(pending) = pending_withdrawals.first() {
            self.process_unsigned_pending_withdrawal(pending).await;
        }
    }

    async fn process_unsigned_pending_withdrawal(&self, pending: &PendingWithdrawal) {
        // If the pending withdrawal is from a previous epoch, reassign its presig
        // indices from the new epoch's counter before signing.
        // TODO: Batch multiple stale-epoch withdrawals into a single PTB.
        let current_epoch = self.inner.onchain_state().epoch();
        if pending.epoch != current_epoch {
            info!(
                pending_withdrawal_id = %pending.id,
                "Pending withdrawal from epoch {} (current {}), reassigning presig indices",
                pending.epoch, current_epoch,
            );
            let result = async {
                let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor
                    .execute_allocate_presigs_for_pending_withdrawal(pending.id)
                    .await
            }
            .await;
            match result {
                Ok(()) => {
                    info!(
                        pending_withdrawal_id = %pending.id,
                        "Presig indices reassigned, will sign on next checkpoint"
                    );
                }
                Err(e) => {
                    error!(
                        pending_withdrawal_id = %pending.id,
                        "Failed to reassign presig indices: {e}"
                    );
                }
            }
            // Return and let the next checkpoint iteration pick up the updated state.
            return;
        }
        info!(pending_withdrawal_id = %pending.id, "MPC signing pending withdrawal");

        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // 1. Request signed withdrawal tx witnesses from committee members.
        // MPC signing requires all threshold members to participate simultaneously
        // via P2P, so we must fan out requests in parallel.
        let Some(signatures_by_input) = self
            .collect_withdrawal_tx_signatures(&pending.id, &members)
            .await
        else {
            return;
        };

        // 2. Extract raw signature bytes for on-chain storage
        let witness_signatures: Vec<Vec<u8>> = signatures_by_input
            .iter()
            .map(|s| s.to_byte_array().to_vec())
            .collect();

        // 3. Build the WithdrawalTxSigning and get BLS certificate via fan-out
        let signed_message = WithdrawalTxSigning {
            withdrawal_id: pending.id,
            request_ids: pending.request_ids(),
            signatures: witness_signatures.clone(),
        };

        let proto_request = signed_message.to_proto();
        let mut bls_signatures: Vec<MemberSignature> = Vec::new();
        for member in &members {
            if let Some(signature) = self
                .request_withdrawal_tx_signing_signature(proto_request.clone(), member)
                .await
            {
                bls_signatures.push(signature);
            }
        }

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        for sig in bls_signatures {
            if let Err(e) = aggregator.add_signature(sig) {
                error!(pending_withdrawal_id = %pending.id, "Failed to add withdrawal sign message signature: {e}");
            }
        }

        let weight = aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            error!(pending_withdrawal_id = %pending.id, "Insufficient signatures for sign_withdrawal: weight {weight} < {required_weight}");
            return;
        }

        let signed = match aggregator.finish() {
            Ok(s) => s,
            Err(e) => {
                error!(pending_withdrawal_id = %pending.id, "Failed to build sign_withdrawal certificate: {e}");
                return;
            }
        };

        // 4. Submit sign_withdrawal to Sui (writes signatures on-chain).
        // Broadcast + confirm happens via process_signed_pending_withdrawals on the next tick.
        let _ = self
            .submit_sign_withdrawal(
                &pending.id,
                &pending.request_ids(),
                &witness_signatures,
                signed.committee_signature(),
            )
            .await
            .inspect(|()| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["sign_withdrawal", "success"])
                    .inc();
            })
            .inspect_err(|e| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["sign_withdrawal", "failure"])
                    .inc();
                error!(pending_withdrawal_id = %pending.id, "Failed to submit sign_withdrawal: {e}");
            });
    }

    // ========================================================================
    // Step 4-5: Broadcast signed tx and confirm on-chain
    // ========================================================================

    async fn process_signed_pending_withdrawals(&self) {
        debug!("Entering process_signed_pending_withdrawals");
        let mut pending_withdrawals = self.inner.onchain_state().pending_withdrawals();
        pending_withdrawals.retain(|p| p.signatures.is_some());
        pending_withdrawals.sort_by_key(|p| p.timestamp_ms);

        for pending in &pending_withdrawals {
            self.handle_signed_withdrawal(pending).await;
        }
    }

    /// Check BTC tx status, broadcast/re-broadcast if needed, confirm when
    /// enough BTC confirmations are reached.
    async fn handle_signed_withdrawal(&self, pending: &PendingWithdrawal) {
        let confirmation_threshold = self.inner.onchain_state().bitcoin_confirmation_threshold();
        let txid = bitcoin::Txid::from_byte_array(pending.txid.into());

        match self.inner.btc_monitor().get_transaction_status(txid).await {
            Ok(TxStatus::Confirmed { confirmations })
                if confirmations >= confirmation_threshold =>
            {
                info!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Withdrawal tx confirmed with {confirmations} confirmations, proceeding to on-chain confirmation");
                self.confirm_withdrawal_on_sui(pending).await;
            }
            Ok(TxStatus::Confirmed { confirmations }) => {
                debug!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Withdrawal tx has {confirmations}/{confirmation_threshold} confirmations, waiting for more");
            }
            Ok(TxStatus::InMempool) => {
                debug!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Withdrawal tx in mempool, waiting for confirmations");
            }
            Ok(TxStatus::NotFound) => {
                self.rebuild_and_broadcast_withdrawal_btc_tx(pending, txid)
                    .await;
            }
            Err(e) => {
                error!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Failed to query transaction status: {e}");
            }
        }
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain PendingWithdrawal
    /// data (stored witness signatures) and broadcast it to the Bitcoin network.
    async fn rebuild_and_broadcast_withdrawal_btc_tx(
        &self,
        pending: &PendingWithdrawal,
        txid: bitcoin::Txid,
    ) {
        warn!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Withdrawal tx not found, re-broadcasting from on-chain signatures");

        let tx = match self.rebuild_signed_tx_from_onchain(pending) {
            Ok(tx) => tx,
            Err(e) => {
                error!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Failed to rebuild signed withdrawal tx: {e}");
                return;
            }
        };

        match self.inner.btc_monitor().broadcast_transaction(tx).await {
            Ok(()) => {
                info!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Re-broadcast withdrawal tx");
            }
            Err(e) => {
                error!(pending_withdrawal_id = %pending.id, bitcoin_txid = %txid, "Failed to re-broadcast withdrawal tx: {e}");
            }
        }
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain PendingWithdrawal
    fn rebuild_signed_tx_from_onchain(
        &self,
        pending: &PendingWithdrawal,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let raw_sigs = pending
            .signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No signatures on pending withdrawal"))?;

        let mut tx = self
            .inner
            .build_unsigned_withdrawal_tx(&pending.inputs, &pending.all_outputs())?;

        anyhow::ensure!(
            raw_sigs.len() == tx.input.len(),
            "Signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_sigs.len()
        );
        anyhow::ensure!(
            tx.input.len() == pending.inputs.len(),
            "Input count mismatch: tx has {} inputs, pending has {}",
            tx.input.len(),
            pending.inputs.len()
        );

        let hashi_pubkey = self.inner.get_hashi_pubkey()?;
        for ((input, pending_input), sig_bytes) in
            tx.input.iter_mut().zip(pending.inputs.iter()).zip(raw_sigs)
        {
            let pubkey = self
                .inner
                .deposit_pubkey(&hashi_pubkey, pending_input.derivation_path.as_ref())?;
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

    async fn confirm_withdrawal_on_sui(&self, pending: &PendingWithdrawal) {
        let members = match self.inner.onchain_state().current_committee_members() {
            Some(m) => m,
            None => {
                error!(pending_withdrawal_id = %pending.id, "No current committee members for confirmation");
                return;
            }
        };

        let confirmation_cert = match self
            .collect_withdrawal_confirmation_signature(pending.id, &members)
            .await
        {
            Ok(cert) => cert,
            Err(e) => {
                error!(pending_withdrawal_id = %pending.id, "Failed to collect withdrawal confirmation signatures: {e}");
                return;
            }
        };

        let _ = self
            .submit_confirm_withdrawal(&pending.id, &confirmation_cert)
            .await
            .inspect(|()| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "success"])
                    .inc();
                self.inner.metrics.withdrawals_finalized_total.inc();
            })
            .inspect_err(|e| {
                self.inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "failure"])
                    .inc();
                error!(pending_withdrawal_id = %pending.id, "Failed to submit confirm_withdrawal: {e}");
            });
    }

    async fn collect_withdrawal_confirmation_signature(
        &self,
        pending_id: Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) = self
                .request_withdrawal_confirmation_signature(pending_id, member)
                .await
            {
                signatures.push(signature);
            }
        }

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let confirmation = crate::withdrawals::WithdrawalConfirmation {
            withdrawal_id: pending_id,
        };
        let mut signature_aggregator = BlsSignatureAggregator::new(&committee, confirmation);
        for signature in signatures {
            if let Err(e) = signature_aggregator.add_signature(signature) {
                error!(pending_withdrawal_id = %pending_id, "Failed to add withdrawal confirmation signature: {e}");
            }
        }

        // TODO: better way to check for quorum than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient withdrawal confirmation signatures for pending {:?}: weight {weight} < {required_weight}",
                pending_id
            );
        }

        Ok(signature_aggregator.finish()?.into_parts().0)
    }

    async fn request_withdrawal_tx_commitment_signature(
        &self,
        proto_request: SignWithdrawalTxConstructionRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal approval signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
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

    async fn request_withdrawal_approval_signature(
        &self,
        proto_request: SignWithdrawalRequestApprovalRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal request approval signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
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

    async fn request_withdrawal_tx_signing_signature(
        &self,
        proto_request: SignWithdrawalTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal tx signing signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
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

    async fn request_withdrawal_tx_signature(
        &self,
        pending_withdrawal_id: &Address,
        member: &CommitteeMember,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal tx signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                )
            })?;

        let proto_request = SignWithdrawalTransactionRequest {
            pending_withdrawal_id: pending_withdrawal_id.as_bytes().to_vec().into(),
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
        &self,
        pending_withdrawal_id: &Address,
        members: &[CommitteeMember],
    ) -> Option<Vec<SchnorrSignature>> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| self.request_withdrawal_tx_signature(pending_withdrawal_id, member))
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
                        pending_withdrawal_id
                    );
                    return None;
                }
            }
        }
    }

    async fn request_withdrawal_confirmation_signature(
        &self,
        pending_withdrawal_id: Address,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal confirmation signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
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
                pending_withdrawal_id: pending_withdrawal_id.as_bytes().to_vec().into(),
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
        &self,
        approvals: &[(Address, &CommitteeSignature)],
    ) -> anyhow::Result<()> {
        info!(
            "Submitting approve_request PTB for {} requests",
            approvals.len()
        );

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_approve_withdrawal_requests(approvals)
            .await
    }

    async fn submit_commit_withdrawal_tx(
        &self,
        approval: &WithdrawalTxCommitment,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!(
            "Submitting commit_withdrawal_tx for txid {:?}",
            approval.txid
        );

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor.execute_commit_withdrawal_tx(approval, cert).await
    }

    async fn submit_sign_withdrawal(
        &self,
        withdrawal_id: &Address,
        request_ids: &[Address],
        signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Submitting sign_withdrawal for {:?}", withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_sign_withdrawal(withdrawal_id, request_ids, signatures, cert)
            .await
    }

    async fn submit_confirm_withdrawal(
        &self,
        pending_withdrawal_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Confirming withdrawal {:?}", pending_withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_confirm_withdrawal(pending_withdrawal_id, cert)
            .await?;

        info!(
            "Successfully confirmed withdrawal {:?}",
            pending_withdrawal_id
        );
        Ok(())
    }
}

impl DepositRequest {
    fn to_proto(&self) -> SignDepositConfirmationRequest {
        SignDepositConfirmationRequest {
            id: self.id.as_bytes().to_vec().into(),
            txid: self.utxo.id.txid.as_bytes().to_vec().into(),
            vout: self.utxo.id.vout,
            amount: self.utxo.amount,
            derivation_path: self
                .utxo
                .derivation_path
                .map(|p| p.as_bytes().to_vec().into()),
            timestamp_ms: self.timestamp_ms,
            requester_address: self.requester_address.as_bytes().to_vec().into(),
            sui_tx_digest: self.sui_tx_digest.as_bytes().to_vec().into(),
        }
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
