// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LEADER_TASK_TIMEOUT;
use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::deposits::ApprovedDepositError;
use crate::deposits::UnapprovedDepositError;
use crate::deposits::UnapprovedDepositErrorKind;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::UtxoId;
use crate::sui_tx_executor::SuiTxExecutor;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::proto::SignDepositConfirmationRequest;
use std::collections::HashSet;
use std::sync::Arc;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

#[derive(Clone, Copy, Debug)]
enum UnapprovedDepositReloadMode {
    All,
    StaleEpochApprovalOnly,
}

pub(super) struct UnapprovedDepositTaskResult {
    deposit_id: Address,
    outpoint: bitcoin::OutPoint,
    block_sequence: u64,
    bitcoin_generation: u64,
    result: Result<(), UnapprovedDepositError>,
}

impl LeaderService {
    pub(super) fn process_actionable_unapproved_deposits(&mut self) {
        self.reload_pending_unapproved_deposit_requests(UnapprovedDepositReloadMode::All);
        self.process_unapproved_deposit_requests();
    }

    pub(super) fn process_stale_unapproved_deposits_if_new_epoch(&mut self) {
        let current_epoch = self.inner.onchain_state().epoch();
        // This is a local-view optimization, not a correctness check: a stale
        // view can miss an in-flight reconfig, but Move rejects approval during
        // reconfig. Avoid doing obviously doomed work when we already know.
        if !self.is_reconfiguring() && self.last_unapproved_deposit_epoch != Some(current_epoch) {
            self.reload_pending_unapproved_deposit_requests(
                UnapprovedDepositReloadMode::StaleEpochApprovalOnly,
            );
            self.process_unapproved_deposit_requests();
            self.last_unapproved_deposit_epoch = Some(current_epoch);
        }
    }

    pub(super) fn needs_actionable_deposit_reload(&self) -> bool {
        self.last_reload_confirmation_threshold
            != Some(self.inner.onchain_state().bitcoin_confirmation_threshold())
    }

    fn reload_pending_unapproved_deposit_requests(&mut self, mode: UnapprovedDepositReloadMode) {
        let threshold = self.inner.onchain_state().bitcoin_confirmation_threshold();
        if matches!(mode, UnapprovedDepositReloadMode::All) {
            self.last_reload_confirmation_threshold = Some(threshold);
        }
        let current_epoch = self.inner.onchain_state().epoch();
        let deposit_tracker = self.inner.onchain_state().deposit_tracker().clone();
        let deposit_ids = deposit_tracker.actionable_requests(threshold);
        let deposit_requests = self
            .inner
            .onchain_state()
            .deposit_requests_by_ids(&deposit_ids);
        self.inflight_deposits
            .retain(|deposit_id| deposit_tracker.contains_request(deposit_id));
        self.never_retry_deposit_ids
            .retain(|deposit_id| deposit_tracker.contains_request(deposit_id));
        let candidates: Vec<_> = deposit_requests
            .into_iter()
            .map(|request| (request.utxo.id.into(), request))
            .collect();
        let active_outpoints: HashSet<_> =
            candidates.iter().map(|(outpoint, _)| *outpoint).collect();
        self.unapproved_deposits_waiting_for_btc_block
            .retain(|outpoint, _| active_outpoints.contains(outpoint));
        let bitcoin_generation = deposit_tracker.bitcoin_generation();
        self.spent_deposit_outpoints.retain(|outpoint, generation| {
            *generation == bitcoin_generation && active_outpoints.contains(outpoint)
        });
        let blocked_outpoints: HashSet<_> = self
            .unapproved_deposits_waiting_for_btc_block
            .keys()
            .chain(self.spent_deposit_outpoints.keys())
            .copied()
            .collect();
        self.inner
            .metrics
            .never_retry_deposit_ids
            .set(self.never_retry_deposit_ids.len() as i64);

        self.pending_unapproved_deposit_requests = select_deposit_requests_to_approve(
            candidates,
            &self.never_retry_deposit_ids,
            &blocked_outpoints,
            current_epoch,
            mode,
        )
        .into_iter()
        .filter(|request| !self.inflight_deposits.contains(&request.id))
        .collect();
        debug!(
            reload_mode = ?mode,
            pending_unapproved_deposits = self.pending_unapproved_deposit_requests.len(),
            never_retry_deposits = self.never_retry_deposit_ids.len(),
            "Reloaded pending unapproved deposit worklist"
        );
    }

    fn process_unapproved_deposit_requests(&mut self) {
        if self.check_halt_deposit_processing() {
            return;
        }

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        while self.unapproved_deposit_tasks.len() < max_concurrent {
            let Some(deposit_request) = self.pending_unapproved_deposit_requests.pop_front() else {
                break;
            };
            let deposit_id = deposit_request.id;
            if self.inflight_deposits.contains(&deposit_id) {
                continue;
            }

            let inner = self.inner.clone();
            let outpoint = deposit_request.utxo.id.into();
            let block_sequence = self.inner.btc_monitor().block_sequence();
            let bitcoin_generation = self
                .inner
                .onchain_state()
                .deposit_tracker()
                .bitcoin_generation();

            self.inflight_deposits.insert(deposit_id);
            let task = async move {
                let task = Self::process_unapproved_deposit(inner, deposit_request);
                let result = match tokio::time::timeout(LEADER_TASK_TIMEOUT, task).await {
                    Ok(result) => result,
                    Err(_) => Err(UnapprovedDepositError::TimedOut(LEADER_TASK_TIMEOUT)),
                };

                UnapprovedDepositTaskResult {
                    deposit_id,
                    outpoint,
                    block_sequence,
                    bitcoin_generation,
                    result,
                }
            };
            self.unapproved_deposit_tasks.spawn(task);
        }
    }

    pub(super) fn process_approved_deposit_requests(&mut self) {
        if self.check_halt_deposit_processing() {
            return;
        }

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        let now_ms = self.inner.onchain_state().latest_checkpoint_timestamp_ms();
        let delay_ms = self.inner.onchain_state().bitcoin_deposit_time_delay_ms();
        let current_epoch = self.inner.onchain_state().epoch();

        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        deposit_requests.sort_by_key(|r| (r.created_timestamp_ms, r.id));
        let mut deposit_confirmation_candidates: Vec<_> = deposit_requests
            .into_iter()
            .filter(|request| !self.never_retry_deposit_ids.contains(&request.id))
            .filter(|request| {
                request
                    .approval_cert
                    .as_ref()
                    .is_some_and(|cert| cert.epoch == current_epoch)
            })
            .collect();

        let approved_deposit_ids: Vec<Address> = deposit_confirmation_candidates
            .iter()
            .map(|r| r.id)
            .collect();
        let spent_or_active_utxo_ids = self.inner.onchain_state().find_spent_or_active_utxo_ids(
            deposit_confirmation_candidates.iter().map(|r| r.utxo.id),
        );
        let (utxo_already_used_count, duplicate_utxo_count) =
            filter_deposit_confirmation_candidates(
                &mut deposit_confirmation_candidates,
                &spent_or_active_utxo_ids,
            );

        self.inner
            .metrics
            .leader_approved_deposit_requests_ignored_current
            .with_label_values(&["duplicate_utxo"])
            .set(duplicate_utxo_count as i64);
        self.inner
            .metrics
            .leader_approved_deposit_requests_ignored_current
            .with_label_values(&["utxo_already_used"])
            .set(utxo_already_used_count as i64);

        self.approved_deposit_retry_tracker
            .prune(&approved_deposit_ids);
        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["approved_deposit_confirmation"])
            .set(self.approved_deposit_retry_tracker.in_backoff_count(now_ms) as i64);

        for deposit_request in deposit_confirmation_candidates {
            let deposit_id = deposit_request.id;
            if self.inflight_deposits.contains(&deposit_id) {
                continue;
            }
            if self
                .approved_deposit_retry_tracker
                .should_skip(&deposit_id, now_ms)
            {
                continue;
            }

            let Some(approved_ms) = deposit_request.approved_timestamp_ms else {
                warn!(
                    deposit_id = %deposit_id,
                    "Skipping deposit confirmation: approval timestamp is missing",
                );
                continue;
            };
            if approved_ms.saturating_add(delay_ms) > now_ms {
                trace!(
                    deposit_id = %deposit_id,
                    approved_ms,
                    delay_ms,
                    now_ms,
                    "Skipping deposit confirmation: time-delay has not elapsed",
                );
                continue;
            }

            if self.approved_deposit_tasks.len() >= max_concurrent {
                break;
            }

            let inner = self.inner.clone();
            self.inflight_deposits.insert(deposit_id);
            self.approved_deposit_tasks.spawn(async move {
                let deadline = Instant::now() + LEADER_TASK_TIMEOUT;
                let result = Self::process_approved_deposit(inner, deposit_request, deadline).await;

                (deposit_id, result)
            });
        }
    }

    pub(super) fn handle_completed_unapproved_deposit_task(
        &mut self,
        result: Result<UnapprovedDepositTaskResult, tokio::task::JoinError>,
    ) {
        match result {
            Ok(UnapprovedDepositTaskResult {
                deposit_id,
                outpoint,
                block_sequence: observed_block_sequence,
                bitcoin_generation: observed_bitcoin_generation,
                result,
            }) => {
                let mut reload_after_failure = false;
                self.inflight_deposits.remove(&deposit_id);
                match result {
                    Ok(()) => {
                        info!(deposit_id = %deposit_id, "Deposit processed successfully");
                    }
                    Err(err @ UnapprovedDepositError::BitcoinUtxoSpent(_)) => {
                        let current_generation = self
                            .inner
                            .onchain_state()
                            .deposit_tracker()
                            .bitcoin_generation();
                        if current_generation == observed_bitcoin_generation {
                            self.spent_deposit_outpoints
                                .insert(outpoint, observed_bitcoin_generation);
                            warn!(deposit_id = %deposit_id, "Suppressing spent deposit until Bitcoin state resets: {err:#}");
                        }
                        reload_after_failure = true;
                    }
                    Err(err @ UnapprovedDepositError::AlreadyApprovedThisEpoch) => {
                        debug!(deposit_id = %deposit_id, "Skipping stale deposit approval work: {err:#}");
                    }
                    Err(err) => match err.kind() {
                        UnapprovedDepositErrorKind::RetryOnNextBlock => {
                            let current_block_sequence = self.inner.btc_monitor().block_sequence();
                            if current_block_sequence > observed_block_sequence {
                                reload_after_failure = true;
                            } else {
                                self.unapproved_deposits_waiting_for_btc_block
                                    .insert(outpoint, observed_block_sequence);
                                // Not-yet-confirmed is the expected path for
                                // every fresh deposit; keep warn for the rest.
                                if matches!(err, UnapprovedDepositError::BitcoinNotConfirmed(_)) {
                                    debug!(deposit_id = %deposit_id, "Deferring deposit retry: {err:#}");
                                } else {
                                    warn!(deposit_id = %deposit_id, "Deferring deposit retry: {err:#}");
                                }
                            }
                        }
                        UnapprovedDepositErrorKind::NeverRetry => {
                            self.never_retry_deposit_ids.insert(deposit_id);
                            self.inner
                                .metrics
                                .never_retry_deposit_ids
                                .set(self.never_retry_deposit_ids.len() as i64);
                            warn!(deposit_id = %deposit_id, "Marking deposit as never retry: {err:#}");
                            reload_after_failure = true;
                        }
                    },
                }
                if self.is_leader {
                    if reload_after_failure {
                        self.reload_pending_unapproved_deposit_requests(
                            UnapprovedDepositReloadMode::All,
                        );
                    }
                    self.process_unapproved_deposit_requests();
                } else {
                    self.pending_unapproved_deposit_requests.clear();
                }
            }
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => error!("deposit task failed to join: {err}"),
        }
    }

    pub(super) fn handle_completed_approved_deposit_task(
        &mut self,
        result: Result<(Address, Result<(), ApprovedDepositError>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((deposit_id, result)) => {
                self.inflight_deposits.remove(&deposit_id);
                match result {
                    Ok(()) => {
                        self.approved_deposit_retry_tracker.clear(&deposit_id);
                        info!(deposit_id = %deposit_id, "Deposit processed successfully");
                    }
                    Err(err) => {
                        if !self.inner.onchain_state().has_deposit_request(&deposit_id) {
                            self.approved_deposit_retry_tracker.clear(&deposit_id);
                            info!(deposit_id = %deposit_id, "Deposit confirmation task failed after request left the queue");
                            return;
                        }

                        if matches!(err, ApprovedDepositError::CheckpointWaitTimedOut) {
                            self.approved_deposit_retry_tracker.clear(&deposit_id);
                            warn!(deposit_id = %deposit_id, "Deposit confirmation checkpoint wait timed out; retrying without backoff");
                            return;
                        }

                        let kind = err.kind();
                        self.inner
                            .metrics
                            .leader_retries_total
                            .with_label_values(&[
                                "approved_deposit_confirmation",
                                &format!("{kind:?}"),
                            ])
                            .inc();
                        self.approved_deposit_retry_tracker.record_failure(
                            kind,
                            deposit_id,
                            self.inner.onchain_state().latest_checkpoint_timestamp_ms(),
                        );
                    }
                }
            }
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => error!("deposit task failed to join: {err}"),
        }
    }

    fn check_halt_deposit_processing(&mut self) -> bool {
        // Evaluate all predicates from one consistent state snapshot.
        let halt = {
            let state = self.inner.onchain_state().state();
            state.hashi().config.paused()
                || state
                    .version_support(crate::constants::SUPPORTED_PACKAGE_VERSIONS)
                    .must_halt()
                || state.hashi().committees.pending_epoch_change().is_some()
        };
        if halt {
            self.stop_deposit_processing();
        }
        halt
    }

    pub(super) fn stop_deposit_processing(&mut self) {
        self.last_reload_confirmation_threshold = None;
        self.unapproved_deposit_tasks = JoinSet::new();
        self.approved_deposit_tasks = JoinSet::new();
        self.pending_unapproved_deposit_requests.clear();
        self.inflight_deposits.clear();
        self.reset_approved_deposit_metrics();
    }

    pub(super) fn activate_unapproved_deposits_for_btc_block(&mut self, block_sequence: u64) {
        let previous_len = self.unapproved_deposits_waiting_for_btc_block.len();
        self.unapproved_deposits_waiting_for_btc_block
            .retain(|_, failed_at| *failed_at >= block_sequence);
        if self.is_leader && self.unapproved_deposits_waiting_for_btc_block.len() != previous_len {
            self.process_actionable_unapproved_deposits();
        }
    }

    async fn process_unapproved_deposit(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
    ) -> Result<(), UnapprovedDepositError> {
        info!("Approving deposit request");

        // Validate deposit_request before asking for signatures
        inner
            .validate_deposit_request(&deposit_request)
            .await
            .inspect_err(|err| debug!("Deposit validation failed: {err}"))?;

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
            return Err(UnapprovedDepositError::FailedQuorum {
                weight: aggregator.weight(),
                required_weight,
            });
        }

        let signed_message = match aggregator.finish() {
            Ok(signed_message) => signed_message,
            Err(err) => return Err(UnapprovedDepositError::CertificateBuildFailed(err.into())),
        };
        let mut executor = match SuiTxExecutor::from_hashi(inner.clone()) {
            Ok(executor) => executor,
            Err(err) => return Err(UnapprovedDepositError::ExecutorInitFailed(err)),
        };
        let checkpoint = executor
            .execute_approve_deposit(&deposit_request, signed_message)
            .await
            .inspect(|checkpoint| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["approve_deposit", "success"])
                    .inc();
                info!(checkpoint, "Successfully submitted deposit approval");
            })
            .inspect_err(|e| {
                error!("Failed to submit deposit approval: {e}");
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["approve_deposit", "failure"])
                    .inc();
            })
            .map_err(UnapprovedDepositError::ApproveDepositFailed)?;
        inner
            .onchain_state()
            .wait_until_checkpoint(checkpoint)
            .await;
        Ok(())
    }

    /// Submit `confirm_deposit` for a deposit that has already been
    /// approved on-chain and whose time-delay window has elapsed. The
    /// caller (`process_approved_deposit_requests`) checks the delay before
    /// scheduling the task.
    async fn process_approved_deposit(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
        deadline: Instant,
    ) -> Result<(), ApprovedDepositError> {
        info!("Confirming approved deposit request");

        let mut executor = match SuiTxExecutor::from_hashi(inner.clone()) {
            Ok(executor) => executor,
            Err(err) => return Err(ApprovedDepositError::ExecutorInitFailed(err)),
        };
        let checkpoint = tokio::time::timeout_at(
            deadline,
            executor.execute_confirm_deposit(deposit_request.id),
        )
        .await
        .map_err(|_| ApprovedDepositError::TimedOut(LEADER_TASK_TIMEOUT))?
        .inspect(|checkpoint| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["confirm_deposit", "success"])
                .inc();
            info!(checkpoint, "Successfully submitted deposit confirmation");
        })
        .inspect_err(|e| {
            error!("Failed to submit deposit confirmation: {e}");
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["confirm_deposit", "failure"])
                .inc();
        })
        .map_err(ApprovedDepositError::ConfirmDepositFailed)?;
        inner.metrics.deposits_confirmed_total.inc();
        tokio::time::timeout_at(
            deadline,
            inner.onchain_state().wait_until_checkpoint(checkpoint),
        )
        .await
        .map_err(|_| ApprovedDepositError::CheckpointWaitTimedOut)?;
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
            .sign_deposit_confirmation(proto_request)
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

    pub(super) fn reset_approved_deposit_metrics(&self) {
        for reason in ["duplicate_utxo", "utxo_already_used"] {
            self.inner
                .metrics
                .leader_approved_deposit_requests_ignored_current
                .with_label_values(&[reason])
                .set(0);
        }
        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["approved_deposit_confirmation"])
            .set(0);
    }
}

fn select_deposit_requests_to_approve(
    mut candidates: Vec<(bitcoin::OutPoint, DepositRequest)>,
    never_retry_deposit_ids: &HashSet<Address>,
    blocked_outpoints: &HashSet<bitcoin::OutPoint>,
    current_epoch: u64,
    mode: UnapprovedDepositReloadMode,
) -> Vec<DepositRequest> {
    let approval_epoch =
        |request: &DepositRequest| request.approval_cert.as_ref().map(|cert| cert.epoch);
    let approved_outpoints: HashSet<_> = candidates
        .iter()
        .filter(|(_, request)| approval_epoch(request) == Some(current_epoch))
        .map(|(outpoint, _)| *outpoint)
        .collect();
    candidates.retain(|(outpoint, request)| {
        let request_approval_epoch = approval_epoch(request);
        !approved_outpoints.contains(outpoint)
            && !never_retry_deposit_ids.contains(&request.id)
            && !blocked_outpoints.contains(outpoint)
            && match mode {
                UnapprovedDepositReloadMode::All => request_approval_epoch != Some(current_epoch),
                UnapprovedDepositReloadMode::StaleEpochApprovalOnly => {
                    request_approval_epoch.is_some_and(|epoch| epoch != current_epoch)
                }
            }
    });
    candidates.sort_by_key(|(_, request)| (request.created_timestamp_ms, request.id));

    let mut selected_outpoints = HashSet::new();
    candidates
        .into_iter()
        .filter_map(|(outpoint, request)| selected_outpoints.insert(outpoint).then_some(request))
        .collect()
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
        timestamp_ms: req.created_timestamp_ms,
        requester_address: req.sender.as_bytes().to_vec().into(),
        sui_tx_digest: req.sui_tx_digest.as_bytes().to_vec().into(),
    }
}

fn filter_deposit_confirmation_candidates(
    candidates: &mut Vec<DepositRequest>,
    spent_or_active_utxo_ids: &HashSet<UtxoId>,
) -> (usize, usize) {
    // Remove requests for spent or active UTXOs and count them.
    let count_before_filter = candidates.len();
    candidates.retain(|r| !spent_or_active_utxo_ids.contains(&r.utxo.id));
    let utxo_already_used_count = count_before_filter - candidates.len();

    // Keep the earliest-approved request per UTXO and count later duplicates.
    let count_before_filter = candidates.len();
    candidates.sort_by_key(|r| {
        (
            r.approved_timestamp_ms.is_none(),
            r.approved_timestamp_ms.unwrap_or_default(),
            r.created_timestamp_ms,
            r.id,
        )
    });
    let mut selected_utxo_ids = HashSet::new();
    candidates.retain(|r| selected_utxo_ids.insert(r.utxo.id));
    let duplicate_utxo_count = count_before_filter - candidates.len();

    // Preserve the existing scheduling order between unrelated UTXOs.
    candidates.sort_by_key(|r| (r.created_timestamp_ms, r.id));

    (utxo_already_used_count, duplicate_utxo_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain::types::Utxo;
    use hashi_types::move_types::CommitteeSignature;
    use sui_sdk_types::Digest;

    fn deposit_request(request_id: u8, utxo_id: u8) -> DepositRequest {
        DepositRequest {
            id: Address::new([request_id; 32]),
            sender: Address::ZERO,
            created_timestamp_ms: request_id.into(),
            sui_tx_digest: Digest::new([request_id; 32]),
            utxo: Utxo {
                id: UtxoId {
                    txid: Address::new([utxo_id; 32]).into(),
                    vout: 0,
                },
                amount: 1_000,
                derivation_path: None,
            },
            approval_cert: None,
            approved_timestamp_ms: None,
            confirmed_timestamp_ms: None,
        }
    }

    fn outpoint(request: &DepositRequest) -> bitcoin::OutPoint {
        request.utxo.id.into()
    }

    #[test]
    fn filters_used_and_duplicate_deposit_confirmation_candidates() {
        let used = deposit_request(1, 1);
        let first = deposit_request(2, 2);
        let distinct = deposit_request(3, 3);
        let used_duplicate = deposit_request(4, 1);
        let duplicate = deposit_request(5, 2);
        let spent_or_active_utxo_ids = HashSet::from([used.utxo.id]);
        let mut candidates = vec![
            used,
            first.clone(),
            distinct.clone(),
            used_duplicate,
            duplicate,
        ];

        let counts =
            filter_deposit_confirmation_candidates(&mut candidates, &spent_or_active_utxo_ids);

        assert_eq!(candidates, vec![first, distinct]);
        assert_eq!(counts, (2, 1));
    }

    #[test]
    fn selects_earliest_approved_deposit_confirmation_candidate() {
        let mut oldest = deposit_request(1, 1);
        oldest.approved_timestamp_ms = Some(200);
        let mut earliest_approved = deposit_request(2, 1);
        earliest_approved.approved_timestamp_ms = Some(100);
        let missing_approval_timestamp = deposit_request(3, 1);
        let mut candidates = vec![
            oldest,
            earliest_approved.clone(),
            missing_approval_timestamp,
        ];

        let counts = filter_deposit_confirmation_candidates(&mut candidates, &HashSet::new());

        assert_eq!(candidates, vec![earliest_approved]);
        assert_eq!(counts, (0, 2));
    }

    #[test]
    fn selects_one_unapproved_candidate_per_outpoint_oldest_first() {
        let mut selected_duplicate = deposit_request(1, 1);
        selected_duplicate.created_timestamp_ms = 10;
        let mut higher_id_duplicate = deposit_request(3, 1);
        higher_id_duplicate.created_timestamp_ms = 10;
        let mut distinct = deposit_request(2, 2);
        distinct.created_timestamp_ms = 15;
        let candidates = vec![
            (outpoint(&higher_id_duplicate), higher_id_duplicate),
            (outpoint(&distinct), distinct.clone()),
            (outpoint(&selected_duplicate), selected_duplicate.clone()),
        ];

        let selected = select_deposit_requests_to_approve(
            candidates,
            &HashSet::new(),
            &HashSet::new(),
            0,
            UnapprovedDepositReloadMode::All,
        );

        assert_eq!(selected, vec![selected_duplicate, distinct]);
    }

    #[test]
    fn filters_never_retry_before_selecting_duplicate() {
        let first = deposit_request(1, 1);
        let second = deposit_request(2, 1);
        let candidates = vec![
            (outpoint(&first), first.clone()),
            (outpoint(&second), second.clone()),
        ];

        let selected = select_deposit_requests_to_approve(
            candidates,
            &HashSet::from([first.id]),
            &HashSet::new(),
            0,
            UnapprovedDepositReloadMode::All,
        );

        assert_eq!(selected, vec![second]);
    }

    #[test]
    fn current_approval_blocks_other_requests_for_the_same_outpoint() {
        let mut approved = deposit_request(1, 1);
        approved.approval_cert = Some(CommitteeSignature {
            epoch: 7,
            signature: vec![],
            signers_bitmap: vec![],
        });
        let duplicate = deposit_request(2, 1);
        let distinct = deposit_request(3, 2);
        let candidates = vec![
            (outpoint(&approved), approved),
            (outpoint(&duplicate), duplicate),
            (outpoint(&distinct), distinct.clone()),
        ];

        let selected = select_deposit_requests_to_approve(
            candidates,
            &HashSet::new(),
            &HashSet::new(),
            7,
            UnapprovedDepositReloadMode::All,
        );

        assert_eq!(selected, vec![distinct]);
    }

    #[test]
    fn filters_deferred_deposits_until_next_bitcoin_block() {
        let deferred = deposit_request(1, 1);
        let duplicate = deposit_request(3, 1);
        let actionable = deposit_request(2, 2);
        let candidates = vec![
            (outpoint(&deferred), deferred.clone()),
            (outpoint(&duplicate), duplicate),
            (outpoint(&actionable), actionable.clone()),
        ];

        let selected = select_deposit_requests_to_approve(
            candidates,
            &HashSet::new(),
            &HashSet::from([outpoint(&deferred)]),
            0,
            UnapprovedDepositReloadMode::All,
        );

        assert_eq!(selected, vec![actionable]);
    }
}
