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

impl LeaderService {
    pub(super) fn process_deposits_on_bitcoin_block(&mut self) {
        self.reload_pending_unapproved_deposit_requests(UnapprovedDepositReloadMode::All);
        self.process_unapproved_deposit_requests();
    }

    pub(super) fn process_stale_unapproved_deposits_if_new_epoch(&mut self) {
        let current_epoch = self.inner.onchain_state().epoch();
        if !self.is_reconfiguring() && self.last_unapproved_deposit_epoch != Some(current_epoch) {
            self.reload_pending_unapproved_deposit_requests(
                UnapprovedDepositReloadMode::StaleEpochApprovalOnly,
            );
            self.process_unapproved_deposit_requests();
            self.last_unapproved_deposit_epoch = Some(current_epoch);
        }
    }

    fn reload_pending_unapproved_deposit_requests(&mut self, mode: UnapprovedDepositReloadMode) {
        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        deposit_requests.sort_by_key(|r| r.timestamp_ms);
        let deposit_ids: HashSet<Address> =
            deposit_requests.iter().map(|request| request.id).collect();
        self.inflight_deposits
            .retain(|deposit_id| deposit_ids.contains(deposit_id));
        self.never_retry_deposit_ids
            .retain(|deposit_id| deposit_ids.contains(deposit_id));
        self.inner
            .metrics
            .never_retry_deposit_ids
            .set(self.never_retry_deposit_ids.len() as i64);

        let current_epoch = self.inner.onchain_state().epoch();
        self.pending_unapproved_deposit_requests = deposit_requests
            .into_iter()
            .filter(|request| !self.never_retry_deposit_ids.contains(&request.id))
            .filter(|request| match mode {
                UnapprovedDepositReloadMode::All => request
                    .approval_cert
                    .as_ref()
                    .is_none_or(|cert| cert.epoch != current_epoch),
                UnapprovedDepositReloadMode::StaleEpochApprovalOnly => request
                    .approval_cert
                    .as_ref()
                    .is_some_and(|cert| cert.epoch != current_epoch),
            })
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
        for deposit_request in self.pending_unapproved_deposit_requests.clone() {
            if self.unapproved_deposit_tasks.len() >= max_concurrent {
                break;
            }
            let deposit_id = deposit_request.id;
            if self.inflight_deposits.contains(&deposit_id) {
                continue;
            }

            let inner = self.inner.clone();

            self.inflight_deposits.insert(deposit_id);
            let task = async move {
                let task = Self::process_unapproved_deposit(inner, deposit_request);
                let result = match tokio::time::timeout(LEADER_TASK_TIMEOUT, task).await {
                    Ok(result) => result,
                    Err(_) => Err(UnapprovedDepositError::TimedOut(LEADER_TASK_TIMEOUT)),
                };

                (deposit_id, result)
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
        deposit_requests.sort_by_key(|r| r.timestamp_ms);
        let approved_deposit_requests: Vec<_> = deposit_requests
            .into_iter()
            .filter(|request| !self.never_retry_deposit_ids.contains(&request.id))
            .filter(|request| {
                request
                    .approval_cert
                    .as_ref()
                    .is_some_and(|cert| cert.epoch == current_epoch)
            })
            .collect();

        let approved_deposit_ids: Vec<Address> = approved_deposit_requests
            .iter()
            .map(|request| request.id)
            .collect();
        self.approved_deposit_retry_tracker
            .prune(&approved_deposit_ids);
        self.inner
            .metrics
            .leader_items_in_backoff
            .with_label_values(&["approved_deposit_confirmation"])
            .set(self.approved_deposit_retry_tracker.in_backoff_count(now_ms) as i64);

        for deposit_request in approved_deposit_requests {
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

            let Some(approved_ms) = deposit_request.approval_timestamp_ms else {
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
                let task = Self::process_approved_deposit(inner, deposit_request);
                let result = match tokio::time::timeout(LEADER_TASK_TIMEOUT, task).await {
                    Ok(result) => result,
                    Err(_) => Err(ApprovedDepositError::TimedOut(LEADER_TASK_TIMEOUT)),
                };

                (deposit_id, result)
            });
        }
    }

    pub(super) fn handle_completed_unapproved_deposit_task(
        &mut self,
        result: Result<(Address, Result<(), UnapprovedDepositError>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((deposit_id, result)) => {
                self.inflight_deposits.remove(&deposit_id);
                self.pending_unapproved_deposit_requests
                    .retain(|request| request.id != deposit_id);
                match result {
                    Ok(()) => {
                        info!(deposit_id = %deposit_id, "Deposit processed successfully");
                    }
                    Err(err) => match err.kind() {
                        UnapprovedDepositErrorKind::RetryOnNextBlock => {
                            warn!(deposit_id = %deposit_id, "Deferring deposit retry: {err:#}");
                        }
                        UnapprovedDepositErrorKind::NeverRetry => {
                            self.never_retry_deposit_ids.insert(deposit_id);
                            self.inner
                                .metrics
                                .never_retry_deposit_ids
                                .set(self.never_retry_deposit_ids.len() as i64);
                            warn!(deposit_id = %deposit_id, "Marking deposit as never retry: {err:#}");
                        }
                    },
                }
                self.process_unapproved_deposit_requests();
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

                        if err.to_string().contains("checkpoint wait timed out") {
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
        if !(self.inner.onchain_state().state().hashi().config.paused() || self.is_reconfiguring())
        {
            return false;
        }

        self.unapproved_deposit_tasks.abort_all();
        self.approved_deposit_tasks.abort_all();
        self.pending_unapproved_deposit_requests.clear();
        self.inflight_deposits.clear();
        true
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
        executor
            .execute_approve_deposit(&deposit_request, signed_message)
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["approve_deposit", "success"])
                    .inc();
                info!("Successfully submitted deposit approval");
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
        Ok(())
    }

    /// Submit `confirm_deposit` for a deposit that has already been
    /// approved on-chain and whose time-delay window has elapsed. The
    /// caller (`process_approved_deposit_requests`) checks the delay before
    /// scheduling the task.
    async fn process_approved_deposit(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
    ) -> Result<(), ApprovedDepositError> {
        info!("Confirming approved deposit request");

        let mut executor = match SuiTxExecutor::from_hashi(inner.clone()) {
            Ok(executor) => executor,
            Err(err) => return Err(ApprovedDepositError::ExecutorInitFailed(err)),
        };
        executor
            .execute_confirm_deposit(deposit_request.id)
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
            })
            .map_err(ApprovedDepositError::ConfirmDepositFailed)?;
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
