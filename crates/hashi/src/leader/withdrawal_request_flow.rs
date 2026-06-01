// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LEADER_TASK_TIMEOUT;
use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::leader::retry::GlobalRetryTracker;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::WithdrawalRequest;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use std::collections::HashSet;
use std::sync::Arc;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

impl LeaderService {
    // ========================================================================
    // Step 1: Approve unapproved withdrawal requests
    // ========================================================================

    pub(super) fn process_unapproved_withdrawal_requests(&mut self, checkpoint_timestamp_ms: u64) {
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

        self.withdrawal_approval_task =
            Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
                Self::process_unapproved_withdrawal_requests_task(
                    inner,
                    retry_tracker,
                    to_process,
                    checkpoint_timestamp_ms,
                )
                .await
            })));
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

    // ========================================================================
    // Step 2: Construct withdrawal tx for approved requests
    // ========================================================================

    pub(super) fn process_approved_withdrawal_requests(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering process_approved_withdrawal_requests");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal commitment processing");
            return;
        }

        if self.withdrawal_commitment_task.is_some() {
            debug!("Withdrawal commitment task already in-flight, skipping");
            return;
        }

        // Pairs with the spawn-side `max_concurrent = 1` cap: don't
        // double-commit before the prior signing task has spawned.
        if self.inner.onchain_state().has_unsigned_withdrawal_txn() {
            debug!("Unsigned withdrawal txn already on-chain, skipping commitment");
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

        // Prune stuck-warn entries so a re-stuck request warns again.
        let pending_ids: HashSet<Address> = approved.iter().map(|r| r.id).collect();
        self.stuck_withdrawal_warned
            .retain(|id| pending_ids.contains(id));

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

        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["withdrawal_commitment"])
            .set(
                self.withdrawal_commitment_retry_tracker
                    .in_backoff_count(checkpoint_timestamp_ms) as i64,
            );

        if approved.is_empty() {
            return;
        }

        // Skip oversize requests (would HOL-block forever) and take the
        // longest prefix of the rest that fits current capacity. The
        // dropped tail flips `at_capacity` so we don't sit on demand for
        // the full batching window.
        let (batch, at_capacity) = if let Some(limiter) = self.inner.local_limiter() {
            let timestamp_secs = checkpoint_timestamp_ms / 1000;
            let max_bucket = limiter.config().max_bucket_capacity;
            let capacity = limiter.capacity_at(timestamp_secs);

            let mut batch: Vec<WithdrawalRequest> = Vec::new();
            let mut cumulative = 0u64;
            let mut at_capacity = false;
            for req in approved {
                if req.btc_amount > max_bucket {
                    if self.stuck_withdrawal_warned.insert(req.id) {
                        warn!(
                            request_id = %req.id,
                            btc_amount = req.btc_amount,
                            max_bucket_capacity = max_bucket,
                            "Withdrawal exceeds limiter max bucket; skipping"
                        );
                        self.inner
                            .metrics
                            .guardian_limiter_stuck_oversize_skipped_total
                            .inc();
                    }
                    continue;
                }
                let Some(next) = cumulative.checked_add(req.btc_amount) else {
                    at_capacity = true;
                    break;
                };
                if next > capacity {
                    at_capacity = true;
                    break;
                }
                cumulative = next;
                batch.push(req);
            }

            if batch.is_empty() {
                // All-oversize (already warned) or refill-bound head.
                self.inner
                    .metrics
                    .guardian_limiter_batch_stuck_head_total
                    .inc();
                return;
            }
            if at_capacity {
                self.inner
                    .metrics
                    .guardian_limiter_batch_truncated_total
                    .inc();
            }
            (batch, at_capacity)
        } else {
            (approved, false)
        };

        let max_batch = self.inner.config.withdrawal_max_batch_size();
        let delay_ms = self.inner.config.withdrawal_batching_delay_ms();

        let batch_is_full = batch.len() >= max_batch;
        let oldest_has_waited = batch
            .first()
            .is_some_and(|r| checkpoint_timestamp_ms >= r.timestamp_ms + delay_ms);

        if !batch_is_full && !oldest_has_waited && !at_capacity {
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

        self.withdrawal_commitment_task =
            Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
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
            })));
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
            let num_consumed = inner
                .onchain_state()
                .state()
                .hashi()
                .schnorr_consumed_presigs();
            let needed_end = num_consumed + num_inputs;
            if let Some(signing_manager) = inner.current_signing_manager() {
                let available_end = signing_manager.available_presig_end_index();
                if needed_end > available_end {
                    info!(
                        "Presig pool may be insufficient for this withdrawal: \
                         need index {needed_end}, pool ends at {available_end}. \
                         Triggering proactive refill.",
                    );
                    signing_manager.trigger_refill();
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
