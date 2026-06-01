// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod deposits;
mod garbage_collection;
mod guardian;
mod retry;
mod withdrawal_request_flow;
mod withdrawal_transactions;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::config::ForceRunAsLeader;
use crate::deposits::DepositError;
use crate::leader::retry::GlobalRetryTracker;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::DepositRequest;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;

use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::traits::ToFromBytes;
use futures::future::OptionFuture;
use hashi_types::committee::MemberSignature;
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
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;
const LEADER_TASK_TIMEOUT: Duration = Duration::from_secs(60);

/// Result of a withdrawal broadcast task: `Some(spent_utxo_ids)` when the
/// withdrawal was confirmed on Sui, `None` when it was not yet ready.
type WithdrawalBroadcastResult = anyhow::Result<Option<Vec<crate::onchain::types::UtxoId>>>;

pub(crate) struct LeaderService {
    inner: Arc<Hashi>,
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    withdrawal_commitment_retry_tracker: GlobalRetryTracker<WithdrawalCommitmentErrorKind>,
    deposit_tasks: JoinSet<(Address, Result<(), DepositError>)>,
    pending_deposit_requests: Vec<DepositRequest>,
    never_retry_deposit_ids: HashSet<Address>,
    inflight_deposits: HashSet<Address>,
    delayed_deposit_processing_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    withdrawal_approval_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    withdrawal_commitment_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    withdrawal_signing_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    inflight_withdrawal_signings: HashSet<Address>,
    withdrawal_broadcast_tasks: JoinSet<(Address, WithdrawalBroadcastResult)>,
    inflight_withdrawal_broadcasts: HashSet<Address>,
    stuck_withdrawal_warned: HashSet<Address>,
    deposit_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    proposal_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    pending_utxo_cleanups: VecDeque<garbage_collection::PendingUtxoCleanup>,
    utxo_cleanup_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    utxo_cleanup_scan_needed: bool,
    guardian_committee_reconcile_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Last hashi epoch we triggered a guardian-committee reconcile for, so
    // we only kick a new task when the chain advances (not every checkpoint).
    // `None` triggers an initial reconcile on the first leader tick.
    last_guardian_reconcile_epoch: Option<u64>,
}

impl LeaderService {
    pub(crate) fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: GlobalRetryTracker::new(),
            deposit_tasks: JoinSet::new(),
            pending_deposit_requests: Vec::new(),
            never_retry_deposit_ids: HashSet::new(),
            inflight_deposits: HashSet::new(),
            delayed_deposit_processing_task: None,
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
    pub(crate) fn start(self) -> Service {
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
                    // Approved deposits may only become confirmable after the configured
                    // Bitcoin deposit time-delay elapses, without another Bitcoin block.
                    self.schedule_delayed_deposit_processing();

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
                Some(result) = OptionFuture::from(self.delayed_deposit_processing_task.as_mut()) => {
                    let checkpoint_height = checkpoint_rx.borrow().height;
                    self.handle_delayed_deposit_processing(result, checkpoint_height);
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

    fn log_task_result(label: &str, result: Result<anyhow::Result<()>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("{label} task failed: {err:#?}"),
            Err(err) if err.is_panic() => error!("{label} task panicked: {err}"),
            Err(err) => error!("{label} task failed to join: {err}"),
        }
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

    fn is_current_leader(&self, checkpoint_height: u64) -> bool {
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
