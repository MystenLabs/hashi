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
use crate::deposits::ApprovedDepositError;
use crate::deposits::ApprovedDepositErrorKind;
use crate::deposits::UnapprovedDepositError;
use crate::grpc::BoxedChannel;
use crate::leader::retry::GlobalRetryTracker;
use crate::leader::retry::RetryTracker;
use crate::leader::withdrawal_transactions::WithdrawalBroadcastResult;
use crate::onchain::types::DepositRequest;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalBroadcastErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;

use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::traits::ToFromBytes;
use futures::future::OptionFuture;
use hashi_types::committee::MemberSignature;
use hashi_types::proto::bridge_service_client::BridgeServiceClient;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::future::Future;
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

pub(crate) struct LeaderService {
    // Shared application state and external service clients used by leader jobs.
    inner: Arc<Hashi>,

    // Background tasks currently approving Bitcoin deposits.
    unapproved_deposit_tasks: JoinSet<(Address, Result<(), UnapprovedDepositError>)>,
    // Background tasks currently confirming approved Bitcoin deposits.
    approved_deposit_tasks: JoinSet<(Address, Result<(), ApprovedDepositError>)>,
    // Deposit requests loaded from Bitcoin/on-chain state and waiting for approval processing.
    pending_unapproved_deposit_requests: Vec<DepositRequest>,
    // Deposit IDs that should not be retried by this leader process.
    never_retry_deposit_ids: HashSet<Address>,
    // Deposit IDs currently running in either deposit task pool.
    inflight_deposits: HashSet<Address>,
    // Singleton task that deletes expired or spent deposit-related on-chain state.
    deposit_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,

    // Singleton task that batches withdrawal request approval work.
    withdrawal_approval_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Per-withdrawal retry state for collecting withdrawal approval signatures.
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    // Singleton task that commits approved withdrawal requests into withdrawal txns.
    withdrawal_commitment_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Global retry state for committing approved withdrawal requests into withdrawal txns.
    withdrawal_commitment_retry_tracker: GlobalRetryTracker<WithdrawalCommitmentErrorKind>,

    // Background tasks currently signing unsigned withdrawal transactions.
    withdrawal_signing_tasks: JoinSet<(Address, anyhow::Result<()>)>,
    // Withdrawal transaction IDs currently running in the signing task pool.
    inflight_withdrawal_signings: HashSet<Address>,

    // Normal checkpoint-triggered signed-withdrawal broadcast/status tasks.
    withdrawal_broadcast_tasks: JoinSet<(Address, WithdrawalBroadcastResult)>,
    // Withdrawal transaction IDs currently running in the normal broadcast task pool.
    inflight_withdrawal_broadcasts: HashSet<Address>,
    // Signed withdrawals parked until Bitcoin advances because they are in the
    // mempool or confirmed below threshold.
    withdrawals_waiting_for_btc_block: HashSet<Address>,
    // Parked withdrawals made eligible again by a new Bitcoin block.
    pending_btc_block_withdrawal_checks: HashSet<Address>,
    // Separate task pool for Bitcoin-block-triggered status checks so normal
    // checkpoint-triggered checks cannot starve them or be starved by them.
    withdrawal_btc_block_check_tasks: JoinSet<(Address, WithdrawalBroadcastResult)>,
    // Withdrawal IDs currently running in the Bitcoin-block-triggered task pool.
    inflight_withdrawal_btc_block_checks: HashSet<Address>,
    // Withdrawal IDs that have already emitted the stuck-withdrawal warning.
    stuck_withdrawal_warned: HashSet<Address>,
    // Per-deposit retry state for approved deposit confirmations.
    approved_deposit_retry_tracker: RetryTracker<ApprovedDepositErrorKind>,
    // Per-withdrawal retry state for signed withdrawal broadcast/status errors.
    withdrawal_broadcast_retry_tracker: RetryTracker<WithdrawalBroadcastErrorKind>,

    // Singleton task that deletes stale governance proposals.
    proposal_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,

    // UTXO cleanup requests discovered after withdrawals are confirmed on Sui.
    pending_utxo_cleanups: VecDeque<garbage_collection::PendingUtxoCleanup>,
    // Singleton task that cleans up spent withdrawal input UTXOs on-chain.
    utxo_cleanup_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Forces a fresh scan for UTXO cleanup work after cleanup state changes.
    utxo_cleanup_scan_needed: bool,

    // Singleton task that reconciles the guardian committee with the on-chain committee.
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
            withdrawal_broadcast_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: GlobalRetryTracker::new(),
            unapproved_deposit_tasks: JoinSet::new(),
            approved_deposit_tasks: JoinSet::new(),
            pending_unapproved_deposit_requests: Vec::new(),
            never_retry_deposit_ids: HashSet::new(),
            inflight_deposits: HashSet::new(),
            withdrawal_approval_task: None,
            withdrawal_commitment_task: None,
            withdrawal_signing_tasks: JoinSet::new(),
            inflight_withdrawal_signings: HashSet::new(),
            withdrawal_broadcast_tasks: JoinSet::new(),
            inflight_withdrawal_broadcasts: HashSet::new(),
            withdrawals_waiting_for_btc_block: HashSet::new(),
            pending_btc_block_withdrawal_checks: HashSet::new(),
            withdrawal_btc_block_check_tasks: JoinSet::new(),
            inflight_withdrawal_btc_block_checks: HashSet::new(),
            stuck_withdrawal_warned: HashSet::new(),
            approved_deposit_retry_tracker: RetryTracker::new(),
            deposit_gc_task: None,
            proposal_gc_task: None,
            pending_utxo_cleanups: VecDeque::new(),
            utxo_cleanup_gc_task: None,
            utxo_cleanup_scan_needed: true,
            guardian_committee_reconcile_task: None,
            last_guardian_reconcile_epoch: None,
        }
    }

    /// Invoke a peer's bridge-service signing RPC, retrying on transient
    /// transport failures. `call` is handed a freshly-fetched client each
    /// attempt so the retry reconnects (tonic reconnects lazily) rather than
    /// reusing the connection the peer just tore down. Returns `None` once
    /// attempts are exhausted or on a non-transport error.
    async fn call_peer_with_retry<Resp, F, Fut>(
        inner: &Arc<Hashi>,
        validator: Address,
        what: &str,
        mut call: F,
    ) -> Option<tonic::Response<Resp>>
    where
        F: FnMut(BridgeServiceClient<BoxedChannel>) -> Fut,
        Fut: Future<Output = Result<tonic::Response<Resp>, tonic::Status>>,
    {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 1..=MAX_ATTEMPTS {
            let Some(client) = inner.onchain_state().bridge_service_client(&validator) else {
                error!("Cannot find bridge-service client for validator: {validator:?}");
                return None;
            };
            match call(client).await {
                Ok(response) => return Some(response),
                Err(status) if attempt < MAX_ATTEMPTS && is_retriable_transport(&status) => {
                    warn!(
                        "Failed to get {what} from {validator} (attempt {attempt}/{MAX_ATTEMPTS}): \
                         {status}; retrying on a fresh connection"
                    );
                    tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
                }
                Err(status) => {
                    error!("Failed to get {what} from {validator}: {status}");
                    return None;
                }
            }
        }
        None
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
                    self.check_delete_expired_deposit_requests(checkpoint_timestamp_ms);
                    self.check_delete_proposals(checkpoint_timestamp_ms);
                    self.check_cleanup_spent_utxos();
                    self.process_approved_deposit_requests();
                }
                wait_result = btc_block_rx.changed() => {
                    if let Err(e) = wait_result {
                        error!("Error waiting for Bitcoin block height change: {e}");
                        break;
                    }

                    let block_height = *btc_block_rx.borrow_and_update();
                    let checkpoint_height = checkpoint_rx.borrow().height;

                    self.schedule_withdrawal_checks_for_btc_block();

                    if self.is_current_leader(checkpoint_height) {
                        self.process_deposits_on_bitcoin_block(block_height);
                    }
                }
                Some(result) = self.unapproved_deposit_tasks.join_next() => {
                    self.handle_completed_unapproved_deposit_task(result);
                    while let Some(result) = self.unapproved_deposit_tasks.try_join_next() {
                        self.handle_completed_unapproved_deposit_task(result);
                    }
                }
                Some(result) = self.approved_deposit_tasks.join_next() => {
                    self.handle_completed_approved_deposit_task(result);
                    while let Some(result) = self.approved_deposit_tasks.try_join_next() {
                        self.handle_completed_approved_deposit_task(result);
                    }
                }
                Some(result) = self.withdrawal_signing_tasks.join_next() => {
                    self.handle_completed_withdrawal_signing_task(result);
                }
                Some(result) = self.withdrawal_broadcast_tasks.join_next() => {
                    self.handle_completed_withdrawal_broadcast_task(result);
                }
                Some(result) = self.withdrawal_btc_block_check_tasks.join_next() => {
                    self.handle_completed_withdrawal_btc_block_check_task(result);
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

/// Whether a failed peer RPC is worth retrying. Under sustained load a peer's
/// HTTP/2 server tears the whole multiplexed connection down — `GoAway`
/// (surfaced as `Internal`), broken pipe (`Unknown`), or the usual
/// `Unavailable` — failing every in-flight request to that peer at once. The
/// peer signing RPCs are idempotent, so retrying these transport-class codes is
/// safe and lets the request land on a fresh connection.
fn is_retriable_transport(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::Internal
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
    )
}

#[cfg(test)]
mod tests {
    use super::is_retriable_transport;
    use tonic::Code;
    use tonic::Status;

    #[test]
    fn classifies_transport_errors_as_retriable() {
        // A peer tearing the connection down surfaces as these codes: GoAway ->
        // Internal, broken pipe -> Unknown, plus the usual transient codes.
        for code in [
            Code::Unavailable,
            Code::Unknown,
            Code::Internal,
            Code::Cancelled,
            Code::DeadlineExceeded,
        ] {
            assert!(
                is_retriable_transport(&Status::new(code, "boom")),
                "{code:?} should be retried"
            );
        }
        // Genuine application rejections from the peer must not be retried.
        for code in [
            Code::InvalidArgument,
            Code::FailedPrecondition,
            Code::PermissionDenied,
            Code::NotFound,
            Code::AlreadyExists,
        ] {
            assert!(
                !is_retriable_transport(&Status::new(code, "nope")),
                "{code:?} should not be retried"
            );
        }
    }
}
