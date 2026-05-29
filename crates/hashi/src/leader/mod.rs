// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod garbage_collection;
mod retry;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::config::ForceRunAsLeader;
use crate::deposits::DepositError;
use crate::deposits::DepositErrorKind;
use crate::leader::retry::GlobalRetryTracker;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::UtxoId;
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
use hashi_types::committee::SignedMessage;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::CommitteeTransition;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::bitcoin_utils;
use hashi_types::guardian::proto_conversions::signed_committee_transition_to_pb;
use hashi_types::guardian::proto_conversions::signed_standard_withdrawal_request_to_pb;
use hashi_types::proto::SignCommitteeTransitionRequest;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignGuardianWithdrawalRequestRequest;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;
const LEADER_TASK_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct PendingUtxoCleanup {
    pub utxo_ids: Vec<UtxoId>,
}

/// Result of a withdrawal broadcast task: `Some(spent_utxo_ids)` when the
/// withdrawal was confirmed on Sui, `None` when it was not yet ready.
type WithdrawalBroadcastResult = anyhow::Result<Option<Vec<UtxoId>>>;

#[derive(Clone, Copy, Debug)]
enum DepositPhase {
    Approve,
    Confirm,
}

pub struct LeaderService {
    inner: Arc<Hashi>,
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    withdrawal_commitment_retry_tracker: GlobalRetryTracker<WithdrawalCommitmentErrorKind>,
    deposit_tasks: JoinSet<(Address, Result<(), DepositError>)>,
    pending_deposit_requests: Vec<DepositRequest>,
    never_retry_deposit_ids: HashSet<Address>,
    inflight_deposits: HashSet<Address>,
    withdrawal_approval_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    withdrawal_commitment_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    withdrawal_signing_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    inflight_withdrawal_signings: HashSet<Address>,
    withdrawal_broadcast_tasks: JoinSet<(Address, WithdrawalBroadcastResult)>,
    inflight_withdrawal_broadcasts: HashSet<Address>,
    stuck_withdrawal_warned: HashSet<Address>,
    deposit_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    proposal_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    pending_utxo_cleanups: VecDeque<PendingUtxoCleanup>,
    utxo_cleanup_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    utxo_cleanup_scan_needed: bool,
    guardian_committee_reconcile_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Last hashi epoch we triggered a guardian-committee reconcile for, so
    // we only kick a new task when the chain advances (not every checkpoint).
    // `None` triggers an initial reconcile on the first leader tick.
    last_guardian_reconcile_epoch: Option<u64>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: GlobalRetryTracker::new(),
            deposit_tasks: JoinSet::new(),
            pending_deposit_requests: Vec::new(),
            never_retry_deposit_ids: HashSet::new(),
            inflight_deposits: HashSet::new(),
            withdrawal_approval_task: None,
            withdrawal_commitment_task: None,
            withdrawal_signing_tasks: JoinSet::new(),
            inflight_withdrawal_signings: HashSet::new(),
            withdrawal_broadcast_tasks: JoinSet::new(),
            inflight_withdrawal_broadcasts: HashSet::new(),
            stuck_withdrawal_warned: HashSet::new(),
            deposit_gc_task: None,
            proposal_gc_task: None,
            pending_utxo_cleanups: VecDeque::new(),
            utxo_cleanup_gc_task: None,
            utxo_cleanup_scan_needed: true,
            guardian_committee_reconcile_task: None,
            last_guardian_reconcile_epoch: None,
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

                    self.check_reconcile_guardian_committee();
                    self.process_unapproved_withdrawal_requests(checkpoint_timestamp_ms);
                    self.process_approved_withdrawal_requests(checkpoint_timestamp_ms);
                    self.process_unsigned_withdrawal_txns();
                    self.process_signed_withdrawal_txns();
                    self.check_delete_proposals(checkpoint_timestamp_ms);
                    self.check_cleanup_spent_utxos();

                    if !self.pending_deposit_requests.is_empty() {
                        self.process_deposit_requests();
                    }
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

                    // We want to unconditionally reload deposits, even if we aren't the leader to
                    // avoid only the leader being able to reload the moment a block is seen.
                    self.reload_pending_deposit_requests();

                    if !self.is_current_leader(checkpoint_height) {
                        continue;
                    }

                    debug!("New Bitcoin block {block_height}: processing deposit requests");

                    self.check_delete_expired_deposit_requests(checkpoint_timestamp_ms);
                    self.process_deposit_requests();
                }
                Some(result) = self.deposit_tasks.join_next() => {
                    self.handle_completed_deposit_task(result);
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
                Some(result) = OptionFuture::from(self.utxo_cleanup_gc_task.as_mut()) => {
                    self.utxo_cleanup_gc_task = None;
                    Self::log_task_result("utxo_cleanup_gc", result);
                    self.utxo_cleanup_scan_needed = true;
                    self.check_cleanup_spent_utxos();
                }
                Some(result) = OptionFuture::from(self.guardian_committee_reconcile_task.as_mut()) => {
                    self.guardian_committee_reconcile_task = None;
                    // On failure, clear the epoch gate so the next tick retries
                    // (e.g. transient guardian downtime); success holds the gate
                    // until the hashi epoch advances again.
                    if !matches!(&result, Ok(Ok(()))) {
                        self.last_guardian_reconcile_epoch = None;
                    }
                    Self::log_task_result("guardian_committee_reconcile", result);
                }

            }
        }
    }

    fn check_reconcile_guardian_committee(&mut self) {
        if self.inner.guardian_client().is_none() {
            return;
        }
        // Don't overwrite an existing handle — finished or not. The select!
        // arm clears the slot and logs the result. Letting it run first
        // avoids dropping a completed task's error on the floor.
        if self.guardian_committee_reconcile_task.is_some() {
            return;
        }
        // Only kick a reconcile when the hashi epoch advances (or on the
        // first leader tick). A no-op reconcile still costs a GetGuardianInfo
        // RPC, so don't run it every checkpoint.
        let hashi_epoch = self.inner.onchain_state().epoch();
        if self.last_guardian_reconcile_epoch == Some(hashi_epoch) {
            return;
        }
        self.last_guardian_reconcile_epoch = Some(hashi_epoch);
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { Self::reconcile_guardian_committee(&inner).await });
        self.guardian_committee_reconcile_task = Some(AbortOnDropHandle::new(handle));
    }

    fn handle_completed_deposit_task(
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
        result: Result<(Address, WithdrawalBroadcastResult), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_broadcasts.remove(&withdrawal_id);
                if let Ok(Some(utxo_ids)) = &inner {
                    self.pending_utxo_cleanups.push_back(PendingUtxoCleanup {
                        utxo_ids: utxo_ids.clone(),
                    });
                }
                Ok(inner.map(|_| ()))
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_broadcast", mapped);
    }

    fn log_task_result(label: &str, result: Result<anyhow::Result<()>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("{label} task failed: {err:#?}"),
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

    fn reload_pending_deposit_requests(&mut self) {
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

    fn is_reconfiguring(&self) -> bool {
        self.inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .pending_epoch_change()
            .is_some()
    }

    fn process_deposit_requests(&mut self) {
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
            let num_consumed = inner.onchain_state().state().hashi().num_consumed_presigs;
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

        // Cap to 1 when the limiter is in play: the watcher advances
        // `next_seq` per signed event, and the guardian rejects
        // out-of-order `timestamp_secs` — both serialise on this path.
        let max_concurrent = if self.inner.guardian_client().is_some() {
            1
        } else {
            self.inner.config.max_concurrent_leader_job_tasks()
        };
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

        // Fresh per-attempt timestamp from the leader's current checkpoint;
        // using `txn.timestamp_ms` lets stuck batches age past the per-node
        // `GUARDIAN_TIMESTAMP_TOLERANCE_SECS` check on retries.
        let timestamp_secs = inner.onchain_state().latest_checkpoint_timestamp_ms() / 1000;

        // Fail fast before MPC if our own limiter would reject.
        let expected_limiter_seq = if let Some(limiter) = inner.local_limiter() {
            let amount_sats = crate::withdrawals::withdrawal_limiter_consumption_amount(&txn);
            let next_seq = limiter.next_seq();
            let result = limiter.validate_consume(next_seq, timestamp_secs, amount_sats);
            inner.metrics.record_limiter_validate(
                &result,
                crate::metrics::GUARDIAN_LIMITER_CALLSITE_LEADER_PRE_MPC,
            );
            if let Err(e) = result {
                warn!(
                    withdrawal_txn_id = %txn.id,
                    "Leader local limiter rejected withdrawal; will retry on next checkpoint: {e}"
                );
                return Ok(());
            }
            // Pace guardian finalize on the local limiter to avoid reusing a consumed seq.
            if inner.guardian_client().is_some()
                && inner.guardian_should_defer_finalize(next_seq, txn.id)
            {
                debug!(
                    withdrawal_txn_id = %txn.id,
                    next_seq,
                    "Deferring guardian finalize until local limiter catches up to guardian seq"
                );
                inner.metrics.guardian_finalize_deferred_total.inc();
                return Ok(());
            }
            Some(next_seq)
        } else {
            None
        };

        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // 1. Request signed withdrawal tx witnesses from committee members.
        // MPC signing requires all threshold members to participate simultaneously
        // via P2P, so we must fan out requests in parallel.
        let signatures_by_input =
            Self::collect_withdrawal_tx_signatures(&inner, &txn.id, expected_limiter_seq, &members)
                .await
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to collect MPC signatures for {:?}", txn.id)
                })?;

        // 2. Extract raw signature bytes for on-chain storage
        let witness_signatures: Vec<Vec<u8>> = signatures_by_input
            .iter()
            .map(|s| s.to_byte_array().to_vec())
            .collect();

        // 3. Post-MPC: forward to guardian for the enclave signature. Reuses
        // the `timestamp_secs` from the pre-MPC validate so the BLS-signed
        // certificate covers a consistent `(timestamp, seq, amount)` triple.
        if let (Some(guardian), Some(seq)) = (inner.guardian_client(), expected_limiter_seq) {
            Self::finalize_withdrawal_through_guardian(
                &inner,
                &txn,
                &members,
                guardian,
                timestamp_secs,
                seq,
            )
            .await?;
            inner.record_guardian_finalized(seq, txn.id);
        }

        // 4. Build the WithdrawalTxSigning and get BLS certificate via fan-out
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

        // 5. Submit sign_withdrawal to Sui (writes signatures on-chain).
        // Broadcast + confirm happens via process_signed_withdrawal_txns on the next tick.
        let included_checkpoint_seq = Self::submit_sign_withdrawal(
            &inner,
            &txn.id,
            &txn.request_ids.clone(),
            &witness_signatures,
            signed.committee_signature(),
        )
        .await
        .inspect(|_| {
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

        // Wait for our watcher to catch up to the checkpoint that included
        // the sign_withdrawal txn before returning, so the next tick
        // doesn't respawn with stale state.
        const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner
                .onchain_state()
                .wait_until_checkpoint(included_checkpoint_seq),
        )
        .await
        .is_err()
        {
            warn!(
                withdrawal_txn_id = %txn.id,
                included_checkpoint_seq,
                "Timeout waiting for watcher to reach the included checkpoint; \
                 a duplicate sign attempt may follow"
            );
        }

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
    ///
    /// Returns `Some(utxo_ids)` when the withdrawal was confirmed on Sui,
    /// signalling that UTXO cleanup should be scheduled.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid))]
    async fn handle_signed_withdrawal(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> WithdrawalBroadcastResult {
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
                let utxo_ids: Vec<UtxoId> = txn.inputs.iter().map(|u| u.id).collect();
                Self::confirm_withdrawal_on_sui(&inner, &txn).await?;
                return Ok(Some(utxo_ids));
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
        Ok(None)
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
        expected_limiter_seq: Option<u64>,
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
            expected_limiter_seq,
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
        expected_limiter_seq: Option<u64>,
        members: &[CommitteeMember],
    ) -> Option<Vec<SchnorrSignature>> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| {
                Self::request_withdrawal_tx_signature(
                    inner,
                    withdrawal_txn_id,
                    expected_limiter_seq,
                    member,
                )
            })
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
    ) -> anyhow::Result<u64> {
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

    // ========================================================================
    // Guardian: post-MPC enclave-signature RPC
    // ========================================================================

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, seq))]
    async fn finalize_withdrawal_through_guardian(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        guardian: &crate::grpc::guardian_client::GuardianClient,
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<()> {
        let signed_request =
            Self::collect_guardian_withdrawal_signatures(inner, txn, members, timestamp_secs, seq)
                .await?;
        let proto_request = signed_standard_withdrawal_request_to_pb(&signed_request);

        let rpc_start = std::time::Instant::now();
        let rpc_result = guardian.standard_withdrawal(proto_request).await;
        let rpc_elapsed = rpc_start.elapsed().as_secs_f64();

        let response_pb = rpc_result.map_err(|status| {
            let (rpc_outcome, retry_label) = if status.message().contains("seq mismatch") {
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_SEQ_MISMATCH,
                    "GuardianSeqMismatch",
                )
            } else if status.message().contains("Rate limit exceeded") {
                warn!("Guardian rate-limited withdrawal, will retry later");
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_RATE_LIMITED,
                    "GuardianRateLimited",
                )
            } else {
                error!("Guardian call failed: {}", status.message());
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                    "GuardianUnavailable",
                )
            };
            Self::record_guardian_rpc_outcome(inner, rpc_outcome, rpc_elapsed);
            inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_signing", retry_label])
                .inc();
            anyhow::anyhow!("Guardian rejected withdrawal: {}", status.message())
        })?;

        let pubkey = inner
            .guardian_signing_pubkey()
            .expect("guardian signing pubkey set during bootstrap");
        let signed_response: GuardianSigned<StandardWithdrawalResponse> = response_pb
            .try_into()
            .inspect_err(|_| {
                Self::record_guardian_rpc_outcome(
                    inner,
                    crate::metrics::GUARDIAN_RPC_OUTCOME_PARSE_ERROR,
                    rpc_elapsed,
                );
            })
            .map_err(|e| anyhow::anyhow!("Failed to parse guardian withdrawal response: {e}"))?;
        signed_response
            .verify(pubkey)
            .inspect_err(|_| {
                Self::record_guardian_rpc_outcome(
                    inner,
                    crate::metrics::GUARDIAN_RPC_OUTCOME_SIGNATURE_ERROR,
                    rpc_elapsed,
                );
            })
            .map_err(|e| {
                anyhow::anyhow!("Guardian response signature verification failed: {e:?}")
            })?;

        Self::record_guardian_rpc_outcome(
            inner,
            crate::metrics::GUARDIAN_RPC_OUTCOME_OK,
            rpc_elapsed,
        );
        info!(seq, "Guardian approved withdrawal");
        Ok(())
    }

    fn record_guardian_rpc_outcome(inner: &Arc<Hashi>, outcome: &str, elapsed_secs: f64) {
        inner.metrics.record_guardian_rpc(
            crate::metrics::GUARDIAN_RPC_METHOD_STANDARD_WITHDRAWAL,
            outcome,
            elapsed_secs,
        );
    }

    async fn collect_guardian_withdrawal_signatures(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<SignedMessage<StandardWithdrawalRequest>> {
        let guardian_request =
            crate::withdrawals::build_guardian_withdrawal_request(inner, txn, timestamp_secs, seq)?;

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let required_weight = certificate_threshold(committee.total_weight());

        let proto_request = SignGuardianWithdrawalRequestRequest {
            withdrawal_txn_id: txn.id.as_bytes().to_vec().into(),
            timestamp_secs,
            seq,
        };

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_guardian_withdrawal_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, guardian_request);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    withdrawal_txn_id = %txn.id,
                    "Failed to add guardian withdrawal signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient guardian withdrawal signatures: weight {weight} < {required_weight}"
            );
        }

        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_guardian_withdrawal_signature(
        inner: &Arc<Hashi>,
        proto_request: SignGuardianWithdrawalRequestRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting guardian withdrawal signature");

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
            .sign_guardian_withdrawal_request(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!("Failed to get guardian withdrawal signature from {validator_address}: {e}");
            })
            .ok()?;

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse guardian withdrawal member signature from {validator_address}: {e}"
                );
            })
            .ok()
    }

    // ========================================================================
    // Guardian: committee handoff (post-rotation)
    // ========================================================================

    /// Walk the guardian forward one epoch at a time until it matches the chain.
    async fn reconcile_guardian_committee(inner: &Arc<Hashi>) -> anyhow::Result<()> {
        let Some(guardian) = inner.guardian_client() else {
            return Ok(());
        };

        const MAX_TRANSITIONS_PER_RECONCILE: usize = 8;

        // Seed `guardian_epoch` once from `GetGuardianInfo`; subsequent
        // iterations reuse `current_committee_epoch` from `UpdateCommittee`
        // and skip the extra round-trip.
        let info_pb = guardian
            .get_guardian_info()
            .await
            .map_err(|e| anyhow::anyhow!("GetGuardianInfo failed: {e}"))?;
        let info: hashi_types::guardian::GetGuardianInfoResponse = info_pb
            .try_into()
            .map_err(|e| anyhow::anyhow!("parse GetGuardianInfoResponse: {e:?}"))?;
        let Some(mut guardian_epoch) = info.current_committee_epoch else {
            // ProvisionerInit hasn't run yet; the bootstrap CLI seeds it.
            return Ok(());
        };
        inner
            .metrics
            .guardian_current_committee_epoch
            .set(guardian_epoch as i64);

        for _ in 0..MAX_TRANSITIONS_PER_RECONCILE {
            let hashi_epoch = inner.onchain_state().epoch();
            if guardian_epoch > hashi_epoch {
                // The guardian only advances via certs that hashi signs, so
                // it should never run ahead of the hashi chain. If we see
                // this, something is wrong (e.g., a stale onchain read).
                warn!(
                    guardian_epoch,
                    hashi_epoch, "guardian is ahead of hashi — unexpected"
                );
                return Ok(());
            }
            if guardian_epoch == hashi_epoch {
                return Ok(());
            }

            let from_epoch = guardian_epoch;
            info!(
                from_epoch,
                hashi_epoch, "Driving guardian committee handoff"
            );
            let signed = Self::collect_committee_transition_signatures(inner, from_epoch).await?;
            let to_epoch = signed.message().new_committee.epoch;
            let proto = signed_committee_transition_to_pb(&signed);

            let resp = guardian.update_committee(proto).await.map_err(|status| {
                anyhow::anyhow!("UpdateCommittee failed: {}", status.message())
            })?;
            let new_guardian_epoch = resp.current_committee_epoch.ok_or_else(|| {
                anyhow::anyhow!(
                    "UpdateCommittee response missing current_committee_epoch \
                     after sending {from_epoch}->{to_epoch}"
                )
            })?;
            inner
                .metrics
                .guardian_current_committee_epoch
                .set(new_guardian_epoch as i64);
            info!(
                from_epoch,
                to_epoch = new_guardian_epoch,
                "Advanced guardian committee"
            );

            // Bail out instead of looping if the guardian didn't advance.
            if new_guardian_epoch <= from_epoch {
                anyhow::bail!(
                    "guardian failed to advance: still at {new_guardian_epoch} after sending {from_epoch}->{to_epoch}"
                );
            }
            guardian_epoch = new_guardian_epoch;
        }
        warn!(
            "reconcile_guardian_committee hit MAX_TRANSITIONS_PER_RECONCILE; \
             next leader tick will continue"
        );
        Ok(())
    }

    async fn collect_committee_transition_signatures(
        inner: &Arc<Hashi>,
        from_epoch: u64,
    ) -> anyhow::Result<SignedMessage<CommitteeTransition>> {
        let (to_epoch, from_committee, new_committee) = {
            let onchain = inner.onchain_state();
            let state = onchain.state();
            let committees_map = state.hashi().committees.committees();
            let from = committees_map
                .get(&from_epoch)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no on-chain committee for epoch {from_epoch}"))?;
            // Hashi committee epochs are sparse: each reconfig only adds a
            // new entry when Sui's epoch advances past hashi's AND the MPC
            // reconfig completes, so the next entry is generally not
            // `from_epoch + 1`. Both leader and followers derive the same
            // `to_epoch` from on-chain state, so they sign the same transition.
            let (to_epoch, to) = committees_map
                .range((from_epoch + 1)..)
                .next()
                .map(|(&k, c)| (k, c.clone()))
                .ok_or_else(|| anyhow::anyhow!("no on-chain committee epoch after {from_epoch}"))?;
            (to_epoch, from, to)
        };

        let transition = CommitteeTransition {
            new_committee: hashi_types::move_types::Committee::from(&new_committee),
        };
        let required_weight = certificate_threshold(from_committee.total_weight());

        let proto_request = SignCommitteeTransitionRequest { from_epoch };
        let mut sig_tasks = JoinSet::new();
        for member in from_committee.members() {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_committee_transition_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&from_committee, transition);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    from_epoch,
                    "Failed to add committee transition signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }
        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "insufficient committee transition signatures for {from_epoch}->{to_epoch}: weight {weight} < {required_weight}"
            );
        }
        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(validator = %member.validator_address())
    )]
    async fn request_committee_transition_signature(
        inner: &Arc<Hashi>,
        proto_request: SignCommitteeTransitionRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
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
            .sign_committee_transition(proto_request)
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get committee transition signature from {validator_address}: {e}"
                );
            })
            .ok()?;
        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse committee transition signature from {validator_address}: {e}"
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
