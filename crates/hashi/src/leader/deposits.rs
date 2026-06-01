// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LEADER_TASK_TIMEOUT;
use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::deposits::DepositError;
use crate::deposits::DepositErrorKind;
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
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

#[derive(Clone, Copy, Debug)]
enum DepositPhase {
    Approve,
    Confirm,
}

impl LeaderService {
    pub(super) fn reload_pending_deposit_requests(&mut self) {
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
        self.pending_deposit_requests = deposit_requests
            .into_iter()
            .filter(|request| !self.never_retry_deposit_ids.contains(&request.id))
            .collect();
        debug!(
            pending_deposits = self.pending_deposit_requests.len(),
            never_retry_deposits = self.never_retry_deposit_ids.len(),
            "Reloaded pending deposit worklist"
        );
    }

    pub(super) fn process_deposit_requests(&mut self) {
        if self.inner.onchain_state().state().hashi().config.paused() || self.is_reconfiguring() {
            self.deposit_tasks.abort_all();
            self.pending_deposit_requests.clear();
            self.inflight_deposits.clear();
            return;
        }

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        let now_ms = self.inner.onchain_state().latest_checkpoint_timestamp_ms();
        let delay_ms = self.inner.onchain_state().bitcoin_deposit_time_delay_ms();
        let current_epoch = self.inner.onchain_state().epoch();
        for deposit_request in &self.pending_deposit_requests {
            if self.deposit_tasks.len() >= max_concurrent {
                break;
            }
            let deposit_id = deposit_request.id;
            if self.inflight_deposits.contains(&deposit_id) {
                continue;
            }

            // Decide whether to approve or confirm based on the on-chain
            // approval state.
            //
            // - No cert, or a cert from a rotated-out committee: approve.
            //   The on-chain `approve_deposit` rejects re-approval by the
            //   same committee but accepts a fresh cert from the current
            //   one, which is what re-approval after rotation needs.
            // - Cert from the current committee, delay still open: skip
            //   here entirely so we don't burn a task slot on work that
            //   would just bail; the next checkpoint will re-evaluate.
            // - Cert from the current committee, delay elapsed: confirm.
            let phase = if let Some(cert) = &deposit_request.approval_cert
                && cert.epoch == current_epoch
            {
                let approved_ms = deposit_request
                    .approval_timestamp_ms
                    .expect("approval_cert is set, so approval_timestamp_ms must be set");
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
                DepositPhase::Confirm
            } else {
                DepositPhase::Approve
            };

            let inner = self.inner.clone();
            let deposit_request = deposit_request.clone();

            self.inflight_deposits.insert(deposit_id);
            self.deposit_tasks.spawn(async move {
                let task = async {
                    match phase {
                        DepositPhase::Approve => {
                            Self::process_unapproved_deposit(inner, deposit_request).await
                        }
                        DepositPhase::Confirm => {
                            Self::process_approved_deposit(inner, deposit_request).await
                        }
                    }
                };
                let result = match tokio::time::timeout(LEADER_TASK_TIMEOUT, task).await {
                    Ok(result) => result,
                    Err(_) => Err(DepositError::TimedOut(LEADER_TASK_TIMEOUT)),
                };

                (deposit_id, result)
            });
        }
    }

    pub(super) fn schedule_delayed_deposit_processing(&mut self) {
        let delay =
            Duration::from_millis(self.inner.onchain_state().bitcoin_deposit_time_delay_ms());
        self.delayed_deposit_processing_task =
            Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
                tokio::time::sleep(delay).await;
                Ok(())
            })));
    }

    pub(super) fn handle_delayed_deposit_processing(
        &mut self,
        result: Result<anyhow::Result<()>, tokio::task::JoinError>,
        checkpoint_height: u64,
    ) {
        self.delayed_deposit_processing_task = None;
        Self::log_task_result("delayed_deposit_processing", result);

        self.reload_pending_deposit_requests();

        if self.is_current_leader(checkpoint_height) {
            debug!("Processing deposit requests after Bitcoin deposit time-delay");
            self.process_deposit_requests();
        }
    }

    pub(super) fn handle_completed_deposit_task(
        &mut self,
        result: Result<(Address, Result<(), DepositError>), tokio::task::JoinError>,
    ) {
        match result {
            Ok((deposit_id, result)) => {
                self.inflight_deposits.remove(&deposit_id);
                self.pending_deposit_requests
                    .retain(|request| request.id != deposit_id);
                match result {
                    Ok(()) => {
                        info!(deposit_id = %deposit_id, "Deposit processed successfully");
                    }
                    Err(err) => match err.kind() {
                        DepositErrorKind::RetryOnNextBlock => {
                            warn!(deposit_id = %deposit_id, "Deferring deposit until next block: {err:#}");
                        }
                        DepositErrorKind::NeverRetry => {
                            self.never_retry_deposit_ids.insert(deposit_id);
                            self.inner
                                .metrics
                                .never_retry_deposit_ids
                                .set(self.never_retry_deposit_ids.len() as i64);
                            warn!(deposit_id = %deposit_id, "Marking deposit as never retry: {err:#}");
                        }
                    },
                }
            }
            Err(err) if err.is_panic() => error!("deposit task panicked: {err}"),
            Err(err) => error!("deposit task failed to join: {err}"),
        }
    }

    async fn process_unapproved_deposit(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
    ) -> Result<(), DepositError> {
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
            return Err(DepositError::FailedQuorum {
                weight: aggregator.weight(),
                required_weight,
            });
        }

        let signed_message = match aggregator.finish() {
            Ok(signed_message) => signed_message,
            Err(err) => return Err(DepositError::CertificateBuildFailed(err.into())),
        };
        let mut executor = match SuiTxExecutor::from_hashi(inner.clone()) {
            Ok(executor) => executor,
            Err(err) => return Err(DepositError::ExecutorInitFailed(err)),
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
            .map_err(DepositError::ApproveDepositFailed)?;
        Ok(())
    }

    /// Submit `confirm_deposit` for a deposit that has already been
    /// approved on-chain and whose time-delay window has elapsed. The
    /// caller (`process_deposit_requests`) checks the delay before
    /// scheduling the task.
    async fn process_approved_deposit(
        inner: Arc<Hashi>,
        deposit_request: DepositRequest,
    ) -> Result<(), DepositError> {
        info!("Confirming approved deposit request");

        let mut executor = match SuiTxExecutor::from_hashi(inner.clone()) {
            Ok(executor) => executor,
            Err(err) => return Err(DepositError::ExecutorInitFailed(err)),
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
            .map_err(DepositError::ConfirmDepositFailed)?;
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
