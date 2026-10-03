// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod deposits;
mod garbage_collection;
mod guardian;
mod retry;
mod withdrawal_request_flow;
mod withdrawal_transactions;
use deposits::ApprovedDepositOutcome;
use deposits::UnapprovedDepositTaskResult;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::config::ForceRunAsLeader;
use crate::deposits::ApprovedDepositError;
use crate::deposits::ApprovedDepositErrorKind;
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
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::intent::IntentMessage;
use hashi_types::proto::bridge_service_client::BridgeServiceClient;
use std::collections::HashMap;
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

/// Throttle for the "binary unsupported for the on-chain version" leader
/// warning. `node_is_leader` runs every checkpoint (and from re-checking
/// tasks), so an unthrottled `warn!` would flood logs for the whole time the
/// chain sits ahead of this binary; the `hashi_package_version_unsupported`
/// metric is the durable signal, so we log on first detection and then only
/// periodically. Stores the last checkpoint height it warned at (0 = never).
static LAST_UNSUPPORTED_WARN_CHECKPOINT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
const UNSUPPORTED_WARN_EVERY_CHECKPOINTS: u64 = 240;

pub(crate) struct LeaderService {
    // Shared application state and external service clients used by leader jobs.
    inner: Arc<Hashi>,
    // Leadership decision cached for the latest observed checkpoint.
    is_leader: bool,

    // Background tasks currently approving Bitcoin deposits.
    unapproved_deposit_tasks: JoinSet<UnapprovedDepositTaskResult>,
    // Background tasks currently confirming approved Bitcoin deposits.
    approved_deposit_tasks: JoinSet<(
        Address,
        Result<ApprovedDepositOutcome, ApprovedDepositError>,
    )>,
    // Deposit requests loaded from Bitcoin/on-chain state and waiting for approval processing.
    pending_unapproved_deposit_requests: VecDeque<DepositRequest>,
    // Last hashi epoch processed by the checkpoint-triggered deposit path.
    last_unapproved_deposit_epoch: Option<u64>,
    // Deposit IDs that should not be retried by this leader process.
    never_retry_deposit_ids: HashSet<Address>,
    // Deposit outpoints parked until Bitcoin advances after a transient failure.
    unapproved_deposits_waiting_for_btc_block: HashMap<bitcoin::OutPoint, u64>,
    // Spent observations are suppressed until a reorg resets Bitcoin state.
    spent_deposit_outpoints: HashMap<bitcoin::OutPoint, u64>,
    // Confirmation threshold used by the last full actionable-deposit reload;
    // None after processing was stopped (halt or leadership change), which may
    // have dropped deposit work. The checkpoint arm reloads whenever this
    // differs from the live threshold, since neither a lifted halt nor a
    // governance threshold change produces a tracker event of its own.
    last_reload_confirmation_threshold: Option<u32>,
    // Deposit IDs currently running in either deposit task pool.
    inflight_deposits: HashSet<Address>,
    // Singleton task that deletes expired or spent deposit-related on-chain state.
    deposit_gc_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,

    // Background tasks currently approving withdrawal requests, one
    // transaction per request (mirroring the deposit approval pool). Each
    // task holds its request in `inflight_withdrawal_approvals` until the
    // object mirror has applied the approval, so a later cycle cannot
    // re-approve it, while other requests keep flowing.
    withdrawal_approval_tasks: JoinSet<Address>,
    // Withdrawal request IDs currently running in the approval task pool.
    inflight_withdrawal_approvals: HashSet<Address>,
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

    // Singleton task that cleans up spent withdrawal input UTXOs on-chain;
    // resolves to how many UTXOs it cleaned.
    utxo_cleanup_gc_task: Option<AbortOnDropHandle<anyhow::Result<usize>>>,
    utxo_cleanup_retry: GlobalRetryTracker<garbage_collection::UtxoCleanupErrorKind>,
    // Arms the cleanup scan: set at boot (crash recovery), when a withdrawal
    // confirms on Sui, and after a cleanup task that did work or failed. The
    // check-side mirror probe also arms it while disarmed, since a confirm
    // submitted by another leader (or one whose local result was lost)
    // leaves victims visible in the mirror without ever setting the flag.
    utxo_cleanup_scan_needed: bool,
    // Checkpoint the scan's mirror read must cover before deciding: the
    // highest checkpoint a confirm tx landed in (monotonic). A scan from a
    // mirror that has not applied the confirm's spent markings yet would
    // find nothing and disarm, stranding the records until the next
    // confirm. Zero at boot: the bootstrap mirror is fresh by construction.
    utxo_cleanup_scan_target: u64,

    // Singleton task that archives confirmed withdrawals (moving them and
    // their requests to the cold bags on-chain); resolves to how many txns
    // it archived. Same arming/retry/freshness shape as the UTXO cleanup;
    // only spawned once the active package version has the archival entry.
    withdrawal_archive_gc_task: Option<AbortOnDropHandle<anyhow::Result<usize>>>,
    withdrawal_archive_retry: GlobalRetryTracker<garbage_collection::WithdrawalArchiveErrorKind>,
    withdrawal_archive_scan_needed: bool,
    withdrawal_archive_scan_target: u64,
    // Singleton task that destroys dead TOB cert buckets on-chain; resolves
    // to the sweep's outcome (epoch swept, whether the backlog drained).
    tob_prune_task: Option<AbortOnDropHandle<anyhow::Result<garbage_collection::TobPruneOutcome>>>,
    tob_prune_retry: GlobalRetryTracker<garbage_collection::TobPruneErrorKind>,
    // Last hashi epoch whose TOB prune sweep fully drained the backlog.
    // `None` triggers a sweep on the first leader tick (boot backlog); a
    // cap-limited or failed sweep leaves it unset so the next tick re-runs.
    last_tob_prune_epoch: Option<u64>,

    // Singleton task that reconciles the guardian committee with the on-chain committee.
    guardian_committee_reconcile_task: Option<AbortOnDropHandle<anyhow::Result<()>>>,
    // Last hashi epoch we triggered a guardian-committee reconcile for, so
    // we only kick a new task when the chain advances (not every checkpoint).
    // `None` triggers an initial reconcile on the first leader tick.
    last_guardian_reconcile_epoch: Option<u64>,
    // Last observed (effective, active) withdrawal package version pair, so
    // the semantics-selection log fires only on change. `None` logs the
    // initial selection on the first tick.
}

impl LeaderService {
    pub(crate) fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            is_leader: false,
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_broadcast_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: GlobalRetryTracker::new(),
            unapproved_deposit_tasks: JoinSet::new(),
            approved_deposit_tasks: JoinSet::new(),
            pending_unapproved_deposit_requests: VecDeque::new(),
            last_unapproved_deposit_epoch: None,
            never_retry_deposit_ids: HashSet::new(),
            unapproved_deposits_waiting_for_btc_block: HashMap::new(),
            spent_deposit_outpoints: HashMap::new(),
            last_reload_confirmation_threshold: None,
            inflight_deposits: HashSet::new(),
            withdrawal_approval_tasks: JoinSet::new(),
            inflight_withdrawal_approvals: HashSet::new(),
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
            utxo_cleanup_gc_task: None,
            utxo_cleanup_retry: GlobalRetryTracker::new(),
            utxo_cleanup_scan_needed: true,
            utxo_cleanup_scan_target: 0,
            withdrawal_archive_gc_task: None,
            withdrawal_archive_retry: GlobalRetryTracker::new(),
            // Armed at boot for crash-between-confirm-and-archive recovery;
            // a no-op pre-upgrade (the version gate skips the spawn).
            withdrawal_archive_scan_needed: true,
            withdrawal_archive_scan_target: 0,
            tob_prune_task: None,
            tob_prune_retry: GlobalRetryTracker::new(),
            last_tob_prune_epoch: None,
            guardian_committee_reconcile_task: None,
            last_guardian_reconcile_epoch: None,
        }
    }

    /// [`retry_peer_call`] against the peer's bridge-service client, logging
    /// the final error. Returns `None` once attempts are exhausted or on a
    /// non-transport error.
    async fn call_peer_with_retry<Resp, F, Fut>(
        inner: &Arc<Hashi>,
        validator: Address,
        what: &str,
        call: F,
    ) -> Option<tonic::Response<Resp>>
    where
        F: FnMut(BridgeServiceClient<BoxedChannel>) -> Fut,
        Fut: Future<Output = Result<tonic::Response<Resp>, tonic::Status>>,
    {
        retry_peer_call(
            validator,
            what,
            || inner.onchain_state().bridge_service_client(&validator),
            call,
        )
        .await
        .inspect_err(|status| error!("Failed to get {what} from {validator}: {status}"))
        .ok()
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
        let mut deposit_work_rx = self
            .inner
            .onchain_state()
            .deposit_tracker()
            .subscribe_work();

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

                    // Every node reports its withdrawal semantics selection,
                    // not just the current leader.
                    // Heartbeat before checking leadership so followers report liveness too.
                    self.inner.metrics.task_heartbeat("leader_loop");
                    let was_leader = self.is_leader;
                    if self.update_leadership(checkpoint_height) {
                        debug!("Checkpoint {checkpoint_height}: We are the leader node");
                        self.process_stale_unapproved_deposits_if_new_epoch();
                        // Also replay deposit work dropped while processing
                        // was stopped (e.g. a reconfig halt consumed a tracker
                        // notification) and pick up confirmation-threshold
                        // changes; neither produces another tracker event.
                        if !was_leader || self.needs_actionable_deposit_reload() {
                            self.process_actionable_unapproved_deposits();
                        }
                        self.process_approved_deposit_requests();
                        self.check_reconcile_guardian_committee();
                        self.process_unapproved_withdrawal_requests(checkpoint_timestamp_ms);
                        self.process_approved_withdrawal_requests(checkpoint_timestamp_ms);
                        self.process_unsigned_withdrawal_txns();
                        self.process_signed_withdrawal_txns();
                        self.check_delete_expired_deposit_requests(checkpoint_timestamp_ms);
                        self.check_delete_proposals(checkpoint_timestamp_ms);
                        self.check_cleanup_spent_utxos(checkpoint_timestamp_ms);
                        self.check_archive_confirmed_withdrawals(checkpoint_timestamp_ms);
                        self.check_prune_tob_certs(checkpoint_timestamp_ms);
                    } else {
                        trace!("We are not the leader node");
                    }
                }
                wait_result = deposit_work_rx.changed() => {
                    if let Err(e) = wait_result {
                        error!("Error waiting for deposit tracker work change: {e}");
                        break;
                    }
                    if self.is_leader {
                        debug!("Deposit tracker changed: processing deposit requests");
                        self.process_actionable_unapproved_deposits();
                    }
                }
                wait_result = btc_block_rx.changed() => {
                    if let Err(e) = wait_result {
                        error!("Error waiting for Bitcoin block height change: {e}");
                        break;
                    }

                    let block_sequence = self.inner.btc_monitor().block_sequence();
                    self.activate_unapproved_deposits_for_btc_block(block_sequence);
                    self.schedule_withdrawal_checks_for_btc_block();
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
                Some(result) = self.withdrawal_approval_tasks.join_next() => {
                    self.handle_completed_withdrawal_approval_task(result);
                    while let Some(result) = self.withdrawal_approval_tasks.try_join_next() {
                        self.handle_completed_withdrawal_approval_task(result);
                    }
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
                    // Re-arm the scan when the task did work (more may exist
                    // past the per-GC cap, or new spends raced in) or failed
                    // (retry after backoff); a barren scan stays disarmed
                    // until a withdrawal confirms. Rescheduling is left to
                    // the leader-gated checkpoint arm: respawning here ran
                    // ungated (leader or not) with no backoff, which kept a
                    // node resubmitting cleanups indefinitely.
                    match &result {
                        Ok(Ok(0)) => self.utxo_cleanup_retry.clear(),
                        Ok(Ok(_)) => {
                            self.utxo_cleanup_retry.clear();
                            self.utxo_cleanup_scan_needed = true;
                        }
                        _ => {
                            self.utxo_cleanup_retry.record_failure(
                                garbage_collection::UtxoCleanupErrorKind::Failed,
                                checkpoint_rx.borrow().timestamp_ms,
                            );
                            self.utxo_cleanup_scan_needed = true;
                        }
                    }
                    Self::log_task_result("utxo_cleanup_gc", result);
                }
                Some(result) = OptionFuture::from(self.withdrawal_archive_gc_task.as_mut()) => {
                    self.withdrawal_archive_gc_task = None;
                    // Same re-arm policy as the UTXO cleanup arm above.
                    match &result {
                        Ok(Ok(0)) => self.withdrawal_archive_retry.clear(),
                        Ok(Ok(_)) => {
                            self.withdrawal_archive_retry.clear();
                            self.withdrawal_archive_scan_needed = true;
                        }
                        _ => {
                            self.withdrawal_archive_retry.record_failure(
                                garbage_collection::WithdrawalArchiveErrorKind::Failed,
                                checkpoint_rx.borrow().timestamp_ms,
                            );
                            self.withdrawal_archive_scan_needed = true;
                        }
                    }
                    Self::log_task_result("withdrawal_archive_gc", result);
                }
                Some(result) = OptionFuture::from(self.tob_prune_task.as_mut()) => {
                    self.tob_prune_task = None;
                    match &result {
                        Ok(Ok(outcome)) => {
                            self.tob_prune_retry.clear();
                            // Only a fully-drained sweep closes the epoch
                            // gate; a cap-limited one re-runs next tick.
                            if outcome.drained {
                                self.last_tob_prune_epoch = Some(outcome.swept_epoch);
                            }
                        }
                        _ => self.tob_prune_retry.record_failure(
                            garbage_collection::TobPruneErrorKind::Failed,
                            checkpoint_rx.borrow().timestamp_ms,
                        ),
                    }
                    Self::log_task_result("tob_prune", result);
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

    fn log_task_result<T>(label: &str, result: Result<anyhow::Result<T>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(_)) => {}
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

    /// Whether this node is the leader for the given checkpoint. An
    /// associated function (rather than a method) so long-running leader
    /// tasks can re-check leadership mid-flight and stop driving work that
    /// has rotated to another node.
    pub(super) fn node_is_leader(inner: &Arc<Hashi>, checkpoint_height: u64) -> bool {
        match inner.onchain_state().autonomous_halt_reason() {
            None => {}
            Some(crate::onchain::HaltReason::Paused) => {
                debug!("Bridge is paused, not acting as leader");
                return false;
            }
            Some(crate::onchain::HaltReason::BinaryUnsupported {
                supported_max,
                live_max,
            }) => {
                // Throttle: loud on first detection, then periodic (the metric
                // carries the steady-state signal).
                use std::sync::atomic::Ordering;
                let last = LAST_UNSUPPORTED_WARN_CHECKPOINT.load(Ordering::Relaxed);
                if last == 0
                    || checkpoint_height.saturating_sub(last) >= UNSUPPORTED_WARN_EVERY_CHECKPOINTS
                {
                    LAST_UNSUPPORTED_WARN_CHECKPOINT
                        .store(checkpoint_height.max(1), Ordering::Relaxed);
                    warn!(
                        supported_max,
                        live_max,
                        checkpoint_height,
                        "binary supports no live on-chain package version; not acting as leader — \
                         upgrade required"
                    );
                }
                return false;
            }
        }

        match inner.config.force_run_as_leader() {
            ForceRunAsLeader::Always => return true,
            ForceRunAsLeader::Never => return false,
            ForceRunAsLeader::Default => (),
        }

        let Some(committee) = inner.onchain_state().current_committee() else {
            // TODO: do we need to do anything when bootstrapping? At genesis there is no committee.
            return false;
        };
        let this_validator_address = inner
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

    /// Only the checkpoint arm of the leader loop calls this: leadership is a
    /// function of checkpoint height, so it cannot change between checkpoints,
    /// and a single writer keeps its regain catch-up reliable. Other arms read
    /// the cached `is_leader`.
    fn update_leadership(&mut self, checkpoint_height: u64) -> bool {
        let is_leader = Self::node_is_leader(&self.inner, checkpoint_height);
        self.inner.metrics.is_leader.set(i64::from(is_leader));
        if self.is_leader && !is_leader {
            self.stop_deposit_processing();
        }
        self.is_leader = is_leader;
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

/// Invoke a peer's signing RPC, retrying on transient transport failures, and
/// hand back the peer's final status otherwise. A retry goes out on a new
/// connection because the peer's shared tonic channel reconnects lazily once
/// the old one is torn down.
async fn retry_peer_call<C, Resp, F, Fut>(
    validator: Address,
    what: &str,
    mut client: impl FnMut() -> Option<C>,
    mut call: F,
) -> Result<tonic::Response<Resp>, tonic::Status>
where
    F: FnMut(C) -> Fut,
    Fut: Future<Output = Result<tonic::Response<Resp>, tonic::Status>>,
{
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempt = 1;
    loop {
        let Some(client) = client() else {
            return Err(tonic::Status::unavailable(format!(
                "no bridge-service client for validator {validator}"
            )));
        };
        match call(client).await {
            Err(status) if attempt < MAX_ATTEMPTS && is_retriable_transport(&status) => {
                warn!(
                    "Failed to get {what} from {validator} (attempt {attempt}/{MAX_ATTEMPTS}): \
                     {status}; retrying on a fresh connection"
                );
                tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
                attempt += 1;
            }
            result => return result,
        }
    }
}

enum NoSignature {
    AlreadyApproved,
    Failed,
}

/// Peers refuse a request their mirror shows already approved, or a withdrawal
/// it shows finalized, with `AlreadyExists` (`deposit_refusal_status`,
/// `withdrawal_approval_refusal_status`, `withdrawal_signing_refusal_status`).
fn is_already_approved_refusal(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::AlreadyExists
}

enum NoQuorum {
    AlreadyApproved,
    Short { weight: u64, required_weight: u64 },
}

/// Add each member's signature to `aggregator` until it reaches a certificate
/// quorum, stopping early once members reporting the request already approved
/// rule a quorum out.
async fn collect_signatures<T: IntentMessage + Clone>(
    sig_tasks: &mut JoinSet<(u64, Result<MemberSignature, NoSignature>)>,
    aggregator: &mut BlsSignatureAggregator<'_, T>,
    total_weight: u64,
) -> Result<(), NoQuorum> {
    let required_weight = certificate_threshold(total_weight);
    let mut already_approved_weight = 0;
    while let Some(result) = sig_tasks.join_next().await {
        let Ok((weight, reply)) = result else {
            continue;
        };
        match reply {
            Ok(sig) => {
                if let Err(e) = aggregator.add_signature(sig) {
                    error!("Failed to add member signature: {e}");
                }
            }
            Err(NoSignature::AlreadyApproved) => {
                already_approved_weight += weight;
                // Past `total - required`, quorum is out of reach, and that is more weight
                // than faulty members can hold, so an approval really landed.
                if already_approved_weight > total_weight.saturating_sub(required_weight) {
                    return Err(NoQuorum::AlreadyApproved);
                }
            }
            Err(NoSignature::Failed) => {}
        }
        if aggregator.weight() >= required_weight {
            break;
        }
    }

    if aggregator.weight() < required_weight {
        return Err(NoQuorum::Short {
            weight: aggregator.weight(),
            required_weight,
        });
    }
    Ok(())
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
    use super::NoQuorum;
    use super::NoSignature;
    use super::collect_signatures;
    use super::is_already_approved_refusal;
    use super::is_retriable_transport;
    use super::retry_peer_call;
    use crate::withdrawals::WithdrawalAlreadyFinalized;
    use crate::withdrawals::WithdrawalApprovalError;
    use crate::withdrawals::WithdrawalRequestApproval;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::Committee;
    use sui_sdk_types::Address;
    use tokio::task::JoinSet;
    use tonic::Code;
    use tonic::Response;
    use tonic::Status;

    #[test]
    fn tells_withdrawal_already_approved_refusals_from_other_refusals() {
        let refusal = crate::grpc::bridge_service::withdrawal_approval_refusal_status;
        assert!(is_already_approved_refusal(&refusal(
            WithdrawalApprovalError::AlreadyApproved(anyhow::anyhow!("already committed"))
        )));
        for err in [
            WithdrawalApprovalError::NeverRetry(anyhow::anyhow!("not found in queue")),
            WithdrawalApprovalError::AmlServiceError(anyhow::anyhow!("TRM unavailable")),
        ] {
            assert!(!is_already_approved_refusal(&refusal(err)));
        }
        // Older peers send the same refusal as `failed_precondition`.
        assert!(!is_already_approved_refusal(&Status::failed_precondition(
            "Never retry: Withdrawal request 0x1 is already approved"
        )));
    }

    #[test]
    fn tells_withdrawal_already_finalized_refusals_from_other_refusals() {
        let refusal = crate::grpc::bridge_service::withdrawal_signing_refusal_status;
        assert!(is_already_approved_refusal(&refusal(
            WithdrawalAlreadyFinalized(Address::ZERO).into()
        )));
        assert!(!is_already_approved_refusal(&refusal(anyhow::anyhow!(
            "Limiter rejected withdrawal 0x1: insufficient tokens"
        ))));
        // Older peers send the same refusal as `failed_precondition`.
        assert!(!is_already_approved_refusal(&Status::failed_precondition(
            WithdrawalAlreadyFinalized(Address::ZERO).to_string()
        )));
    }

    fn aggregator(committee: &Committee) -> BlsSignatureAggregator<'_, WithdrawalRequestApproval> {
        let message = WithdrawalRequestApproval {
            request_id: Address::ZERO,
        };
        BlsSignatureAggregator::new(Address::ZERO, committee, message)
    }

    #[tokio::test]
    async fn stops_collecting_once_already_approved_weight_rules_out_quorum() {
        let committee = Committee::new(vec![], 0, 0, 5_000);
        let mut aggregator = aggregator(&committee);
        let mut sig_tasks = JoinSet::new();
        sig_tasks.spawn(async { (3_334, Err(NoSignature::AlreadyApproved)) });
        sig_tasks.spawn(std::future::pending());

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            collect_signatures(&mut sig_tasks, &mut aggregator, 10_000),
        )
        .await
        .expect("should stop without waiting for the member that never answers");

        assert!(matches!(result, Err(NoQuorum::AlreadyApproved)));
    }

    #[tokio::test]
    async fn keeps_collecting_while_already_approved_weight_leaves_quorum_reachable() {
        let committee = Committee::new(vec![], 0, 0, 5_000);
        let mut aggregator = aggregator(&committee);
        let mut sig_tasks = JoinSet::new();
        sig_tasks.spawn(async { (3_333, Err(NoSignature::AlreadyApproved)) });
        sig_tasks.spawn(async { (6_667, Err(NoSignature::Failed)) });

        let result = collect_signatures(&mut sig_tasks, &mut aggregator, 10_000).await;

        assert!(matches!(
            result,
            Err(NoQuorum::Short {
                weight: 0,
                required_weight: 6_667,
            })
        ));
    }

    /// Runs `retry_peer_call` against a peer that answers attempt `n` (from 1)
    /// with `reply(n)`; returns the result and how many clients were fetched.
    async fn call_peer(
        reply: impl Fn(u32) -> Result<Response<()>, Status>,
    ) -> (Result<Response<()>, Status>, u32) {
        let mut clients = 0;
        let mut attempts = 0;
        let result = retry_peer_call(
            Address::ZERO,
            "test signature",
            || {
                clients += 1;
                Some(())
            },
            |()| {
                attempts += 1;
                std::future::ready(reply(attempts))
            },
        )
        .await;
        (result, clients)
    }

    #[tokio::test(start_paused = true)]
    async fn retries_transport_errors_on_a_fresh_client() {
        let (result, clients) = call_peer(|attempt| match attempt {
            1 => Err(Status::internal("h2 protocol error: http2 error")),
            2 => Err(Status::cancelled("operation was canceled")),
            _ => Ok(Response::new(())),
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(clients, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn hands_back_a_refusal_without_retrying() {
        let (result, clients) =
            call_peer(|_| Err(Status::already_exists("already approved"))).await;
        assert_eq!(result.unwrap_err().code(), Code::AlreadyExists);
        assert_eq!(clients, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn hands_back_the_last_transport_error_once_attempts_run_out() {
        let (result, clients) = call_peer(|_| Err(Status::unavailable("tls handshake eof"))).await;
        assert_eq!(result.unwrap_err().code(), Code::Unavailable);
        assert_eq!(clients, 3);
    }

    #[tokio::test]
    async fn fails_without_calling_when_the_peer_has_no_client() {
        let result: Result<Response<()>, Status> = retry_peer_call(
            Address::ZERO,
            "test signature",
            || None::<()>,
            |()| async { unreachable!("no client, so nothing to call") },
        )
        .await;
        assert_eq!(result.unwrap_err().code(), Code::Unavailable);
    }

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
