// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MPC (Multi-Party Computation) Service

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use futures::future::join_all;
use std::collections::HashMap;
use std::collections::HashSet;
use sui_futures::service::Service;
use sui_rpc::proto::sui::rpc::v2::ExecutionError;
use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;
use tokio::sync::watch;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::communication::SuiTobSessionChannel;
use crate::communication::key_generation_certificates;
use crate::communication::tob_certificates;
use crate::constants::PRESIG_REFILL_DIVISOR;
use crate::metrics::MPC_LABEL_DKG;
use crate::metrics::MPC_LABEL_KEY_ROTATION;
use crate::metrics::MPC_LABEL_NONCE_GENERATION;
use crate::metrics::Metrics;
use crate::mpc::MpcManager;
use crate::mpc::MpcOutput;
use crate::mpc::SigningManager;
use crate::mpc::mpc_except_signing::VerifiedNonceCerts;
use crate::mpc::mpc_except_signing::spawn_blocking;
use crate::mpc::rpc::RpcP2PChannel;
use crate::mpc::signing::IdentityInputs;
use crate::mpc::types::CertificateV1;
use crate::mpc::types::MpcOutputRecoveryOutcome;
use crate::mpc::types::NonceCertToVerify;
use crate::mpc::types::ProtocolType;
use crate::mpc::types::ReconfigOutcome;
use crate::mpc::types::RotationRole;
use crate::mpc::types::VerifiedCertificateV1;
use crate::onchain::Notification;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types;
use hashi_types::move_types::ReconfigCompletionMessage;

const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROTOCOL_ATTEMPTS: u32 = 3;
const START_RECONFIG_POLL_INTERVAL: Duration = Duration::from_millis(500);
const RECONFIG_RECEIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const RECONCILE_TICK: Duration = Duration::from_secs(15);
const REPAIR_MIN_INTERVAL: Duration = Duration::from_secs(900);
const REPAIR_HEARTBEAT_TICK: Duration = Duration::from_secs(10);
const NONCE_WINDOW_WAIT_POLL: Duration = Duration::from_millis(200);
const NONCE_WINDOW_WAIT_SLACK: Duration = Duration::from_secs(30);
const MAX_KEY_REREGISTRATION_BUMPS: u32 = 3;
const NONCE_RECEIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const NONCE_WAIT_TOTAL_BUDGET: Duration = Duration::from_secs(600);
const USE_LEGACY_PRESIG_DERIVATION: bool = false;
/// Move `hashi::reconfig` abort constants, matched by their clever-error
/// constant names (the `#[error]` abort code encodes a source line, so the
/// numeric code is not stable). Together they tell the benign "another node
/// already completed it" race from a dead target: aborted, aborted and
/// replaced by a different pending epoch, or past its Sui epoch window.
const RECONFIG_E_NOT_RECONFIGURING: &str = "ENotReconfiguring";
const RECONFIG_E_ALREADY_COMPLETED: &str = "EReconfigAlreadyCompleted";
const RECONFIG_E_WINDOW_CLOSED: &str = "EReconfigWindowClosed";
/// Raised by both completion entries when a different epoch is pending (the
/// target is dead) and by `abort_reconfig` when the chain already resolved
/// the named target.
const RECONFIG_E_WRONG_EPOCH: &str = "EWrongReconfigEpoch";
/// `abort_reconfig` refused because the chain still protects the target.
const COMMITTEE_SET_E_PENDING_EPOCH_STILL_CURRENT: &str = "EPendingEpochStillCurrent";

#[derive(Clone)]
pub struct MpcHandle {
    key_ready_rx: watch::Receiver<Option<G>>,
}

impl std::fmt::Debug for MpcHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcHandle").finish_non_exhaustive()
    }
}

impl MpcHandle {
    pub async fn wait_for_key_ready(&self) -> G {
        let mut rx = self.key_ready_rx.clone();
        loop {
            {
                let value = rx.borrow();
                if let Some(pk) = value.as_ref() {
                    return *pk;
                }
            }
            if rx.changed().await.is_err() {
                std::future::pending().await
            }
        }
    }

    pub fn public_key(&self) -> Option<G> {
        *self.key_ready_rx.borrow()
    }
}

pub struct MpcService {
    inner: Arc<Hashi>,
    key_ready_tx: watch::Sender<Option<G>>,
    refill_tx: Arc<watch::Sender<u32>>,
    refill_rx: watch::Receiver<u32>,
    reconciling: Arc<tokio::sync::Mutex<()>>,
    next_batch_repair: Mutex<Option<(u64, u32, tokio::time::Instant)>>,
    backup_handle: crate::backup::BackupHandle,
    replacement_keys_target_epoch: Mutex<Option<u64>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalkStep {
    Continue(usize),
    Last(usize),
    Stop,
    Missing,
}

fn repair_rate_limited(
    gate: Option<(u64, u32, tokio::time::Instant)>,
    epoch: u64,
    batch_index: u32,
    now: tokio::time::Instant,
) -> bool {
    matches!(gate, Some((e, b, not_before)) if e == epoch && b == batch_index && now < not_before)
}

fn walk_step(size: Option<usize>, batch_start: u64, num_consumed: u64) -> WalkStep {
    match size {
        Some(size) if num_consumed < batch_start + size as u64 => WalkStep::Last(size),
        Some(size) => WalkStep::Continue(size),
        None if batch_start < num_consumed => WalkStep::Missing,
        None => WalkStep::Stop,
    }
}

enum PresigRecovery {
    Installed,
    MissingBatch {
        epoch: u64,
        batch_index: u32,
        batch_start: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backup {
    Write,
    Skip,
}

impl MpcService {
    pub fn new(hashi: Arc<Hashi>, backup_handle: crate::backup::BackupHandle) -> (Self, MpcHandle) {
        let (key_ready_tx, key_ready_rx) = watch::channel(None);
        let (refill_tx, refill_rx) = watch::channel(0u32);
        let service = Self {
            inner: hashi,
            key_ready_tx,
            refill_tx: Arc::new(refill_tx),
            refill_rx,
            reconciling: Arc::new(tokio::sync::Mutex::new(())),
            next_batch_repair: Mutex::new(None),
            backup_handle,
            replacement_keys_target_epoch: Mutex::new(None),
        };
        let handle = MpcHandle { key_ready_rx };
        (service, handle)
    }

    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    #[tracing::instrument(name = "mpc_service", skip_all)]
    async fn run(mut self) {
        let pending = self.get_pending_epoch_change();
        let is_in_committee = self.inner.is_in_current_committee();
        info!(
            "MPC service starting: pending_epoch_change={pending:?}, \
             is_in_current_committee={is_in_committee}",
        );
        self.run_major_compaction(self.inner.onchain_state().epoch())
            .await;
        let mut notifications = self.inner.onchain_state().subscribe();
        if let Some(epoch) = pending {
            self.drive_reconfig(epoch).await;
        } else if self.is_awaiting_genesis() {
            // No committee has been formed yet (epoch 0, no committee for epoch 0).
            // Wait for enough validators to register then trigger genesis reconfig.
            info!("No initial committee yet; waiting for enough validators to register...");
            self.try_submit_genesis_reconfig().await;
        } else if self.inner.is_in_current_committee() {
            loop {
                self.inner.metrics.task_heartbeat("mpc_service");
                if let Some(epoch) = self.get_pending_epoch_change() {
                    self.drive_reconfig(epoch).await;
                    continue;
                }
                self.sync_if_stale().await;
                let epoch = self.inner.onchain_state().epoch();
                if self.inner.signing_manager_for(epoch).is_some() {
                    break;
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        } else {
            info!("Node is not in the current committee, waiting for reconfig notification...");
        }
        // Hashi lagging Sui with nothing pending is what a manual abort, or a
        // boundary missed while this node was down, leaves behind; catch up
        // now rather than wait for the next boundary.
        self.try_submit_start_reconfig(self.inner.onchain_state().latest_checkpoint_epoch())
            .await;

        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();
        let mut reconcile_tick = tokio::time::interval(RECONCILE_TICK);
        reconcile_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            self.inner.metrics.task_heartbeat("mpc_service");
            // Re-sample the presig pool every iteration (at least each
            // RECONCILE_TICK): the signing-time update in
            // `forward_signing_results` alone leaves the gauge frozen — at 0
            // after a restart — whenever no withdrawals are flowing.
            if let Some(manager) = self.inner.current_signing_manager() {
                self.inner
                    .metrics
                    .presig_pool_remaining
                    .set(manager.presignatures_remaining() as i64);
            }
            // Check for pending reconfig before blocking on `recv()`.
            if let Some(epoch) = self.get_pending_epoch_change() {
                self.drive_reconfig(epoch).await;
                continue;
            }
            tokio::select! {
                notification = notifications.recv() => {
                    match notification {
                        Ok(notification) => match notification {
                            Notification::StartReconfig(epoch) => {
                                self.drive_reconfig(epoch).await;
                            }
                            Notification::SuiEpochChanged(sui_epoch) => {
                                self.try_submit_start_reconfig(sui_epoch).await;
                            }
                            Notification::ReconfigAborted(epoch) => {
                                // Whoever tore it down, Hashi now lags Sui;
                                // start the replacement rather than wait for
                                // the next boundary.
                                warn!("reconfiguration to epoch {epoch} was aborted on chain");
                                let sui_epoch =
                                    self.inner.onchain_state().latest_checkpoint_epoch();
                                self.try_submit_start_reconfig(sui_epoch).await;
                            }
                            _ => {}
                        },
                        Err(e) => {
                            error!("MPC notification recv error: {e:?}, resubscribing");
                            notifications = self.inner.onchain_state().subscribe();
                        }
                    }
                }
                Ok(()) = checkpoint_rx.changed() => {
                    self.sync_if_stale().await;
                }
                _ = reconcile_tick.tick() => {
                    self.sync_if_stale().await;
                }
                Ok(()) = self.refill_rx.changed() => {
                    let next_batch = *self.refill_rx.borrow();
                    self.refill_with_retries(next_batch).await;
                }
            }
        }
    }

    async fn refill_with_retries(&self, next_batch: u32) {
        for attempt in 1..=MAX_PROTOCOL_ATTEMPTS {
            if let Err(e) = self.bail_if_reconfig_pending() {
                info!("presignature refill stopped: {e}");
                return;
            }
            match self.refill_presignatures(next_batch).await {
                Ok(()) => break,
                Err(e) => {
                    error!(
                        "Presignature refill attempt {attempt}/{MAX_PROTOCOL_ATTEMPTS} failed: {e}"
                    );
                    if attempt < MAX_PROTOCOL_ATTEMPTS {
                        tokio::time::sleep(RETRY_INTERVAL).await;
                    }
                }
            }
        }
    }

    async fn post_reconfig_housekeeping(
        &self,
        target_epoch: u64,
        epoch_change_confirmed: bool,
        backup: Backup,
    ) {
        let current_epoch = self.inner.onchain_state().epoch();
        let tombstoned = if epoch_change_confirmed || current_epoch >= target_epoch {
            let pruning_references = {
                let state = self.inner.onchain_state().state();
                build_pruning_references(&state.hashi().committees, target_epoch)
            };
            match self
                .inner
                .db
                .prune_messages_below(target_epoch, &pruning_references)
            {
                Ok(deleted) => deleted > 0,
                Err(e) => {
                    error!("Failed to prune old MPC messages below epoch {target_epoch}: {e}");
                    true
                }
            }
        } else {
            info!(
                "handle_reconfig: still on epoch {current_epoch}; skipping the prune for \
                 epoch {target_epoch}"
            );
            false
        };
        if tombstoned {
            self.run_major_compaction(target_epoch).await;
        }
        self.backup_handle
            .maintain_backups_after_epoch_change(target_epoch, backup == Backup::Write);
    }

    async fn sleep_if_still_pending(&self, epoch: u64) {
        if self.reconfig_target_pending(epoch) {
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }

    /// Whether `target_epoch` is still the live reconfiguration: pending on
    /// chain and inside its Sui epoch window. Once a checkpoint from a later
    /// Sui epoch has been observed the chain refuses to complete it
    /// (`EReconfigWindowClosed`) and only an abort can resolve it, so any
    /// further protocol work on it is wasted.
    fn reconfig_target_pending(&self, target_epoch: u64) -> bool {
        reconfig_target_pending(
            self.get_pending_epoch_change(),
            self.inner.onchain_state().latest_checkpoint_epoch(),
            target_epoch,
        )
    }

    fn reconfig_window_closed(&self, target_epoch: u64) -> bool {
        reconfig_window_closed(
            self.inner.onchain_state().latest_checkpoint_epoch(),
            target_epoch,
        )
    }

    /// Advance the pending reconfiguration to `epoch`: run it while its Sui
    /// epoch window is open, then reconcile with Sui's epoch, which aborts
    /// it if the window closed without `end_reconfig` landing and starts a
    /// replacement whenever Hashi lags Sui with nothing pending (the abort
    /// path, a manual abort observed from inside `handle_reconfig`, or a
    /// completion that itself overran the boundary).
    async fn drive_reconfig(&self, epoch: u64) {
        if !self.reconfig_window_closed(epoch) {
            info!("Entering handle_reconfig for epoch {epoch}");
            self.handle_reconfig(epoch).await;
        }
        let sui_epoch = self.inner.onchain_state().latest_checkpoint_epoch();
        self.try_submit_start_reconfig(sui_epoch).await;
    }

    /// Submit `abort_reconfig` for a pending reconfiguration whose Sui epoch
    /// window has closed, then wait (bounded) for the mirror to reflect it.
    /// Any node may do this and several usually race to; the chain settles
    /// the race, so "nothing pending" or "wrong epoch" back from it means
    /// another node got there first.
    async fn abort_stale_reconfig(&self, epoch: u64) {
        warn!(
            "reconfiguration to epoch {epoch} overran its Sui epoch window without completing; \
             submitting abort_reconfig"
        );
        let result = async {
            let mut executor =
                crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
            executor.execute_abort_reconfig(epoch).await
        };
        match result.await {
            Ok(()) => info!("abort_reconfig for epoch {epoch} landed"),
            Err(e) => match classify_abort_submission_error(&e) {
                AbortSubmissionErrorKind::AlreadyResolved => {
                    info!("abort_reconfig for epoch {epoch}: already resolved on chain: {e:#}");
                }
                AbortSubmissionErrorKind::StillCurrent => {
                    // Our checkpoint view of Sui's epoch ran ahead of the
                    // chain's, which should not happen; let the chain win.
                    warn!(
                        "abort_reconfig for epoch {epoch} refused: the chain still considers \
                         its Sui epoch current: {e:#}"
                    );
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    return;
                }
                AbortSubmissionErrorKind::Other => {
                    warn!("abort_reconfig for epoch {epoch} failed: {e:#}; retrying later");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    return;
                }
            },
        }
        self.wait_for_pending_clear_visibility(epoch).await;
    }

    /// Wait (bounded) for the object mirror to reflect that `epoch` is no
    /// longer pending: another node's `end_reconfig` activated it, or an
    /// abort tore it down. The lossless watcher applies the winning
    /// transaction as a root object write within a few checkpoints; clock
    /// ticks pace the re-checks.
    async fn wait_for_pending_clear_visibility(&self, epoch: u64) {
        const VISIBILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();
        let _ = tokio::time::timeout(VISIBILITY_TIMEOUT, async {
            while self.get_pending_epoch_change() == Some(epoch) {
                if checkpoint_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    }

    fn get_pending_epoch_change(&self) -> Option<u64> {
        self.inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .pending_epoch_change()
    }

    fn is_awaiting_genesis(&self) -> bool {
        self.inner.is_awaiting_genesis()
    }

    /// Wait for enough validators to register, then submit `start_reconfig`
    /// to form the initial committee. Blocks until a pending epoch change
    /// appears (either from our own submission or another node's).
    async fn try_submit_genesis_reconfig(&self) {
        loop {
            if self.get_pending_epoch_change().is_some() {
                return;
            }
            match self.inner.next_reconfig_epoch().await {
                Ok(target) => {
                    if let Err(e) = self.inner.prepare_and_register_keys(target).await {
                        debug!(
                            "Encryption/signing key registration for epoch {target} failed: {e}; \
                             will retry on next genesis_reconfig iteration"
                        );
                    }
                }
                Err(e) => debug!("Failed to compute next_reconfig_epoch: {e}"),
            }
            // Attempt to submit start_reconfig. This will fail on-chain until
            // the publisher sends finish_publish (the launch switch).
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor.execute_start_reconfig().await
            };
            match result.await {
                Ok(()) => {
                    info!("Genesis start_reconfig submitted successfully");
                    return;
                }
                Err(e) => {
                    debug!("Genesis start_reconfig not yet possible: {e}");
                    // Poll for pending epoch change while waiting, in case
                    // another node submitted start_reconfig.
                    let polls = (RETRY_INTERVAL.as_millis()
                        / START_RECONFIG_POLL_INTERVAL.as_millis())
                        as u32;
                    for _ in 0..polls {
                        if self.get_pending_epoch_change().is_some() {
                            return;
                        }
                        tokio::time::sleep(START_RECONFIG_POLL_INTERVAL).await;
                    }
                }
            }
        }
    }

    async fn recover_mpc_state(&self) -> anyhow::Result<MpcOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let epoch = onchain_state.epoch();
        let is_key_rotation = onchain_state.is_key_rotation_epoch(epoch);
        let onchain_mpc_key = onchain_state.mpc_public_key();
        info!(
            "recover_mpc_state: epoch={epoch}, is_key_rotation={is_key_rotation}, \
             onchain_mpc_key_len={}",
            onchain_mpc_key.len(),
        );
        let output = if is_key_rotation {
            self.recover_current_rotation(epoch, &onchain_mpc_key).await
        } else {
            self.recover_current_dkg(epoch, &onchain_mpc_key).await
        }?;
        info!(
            "recover_mpc_state: recovered vk={}",
            hex::encode(output.public_key.to_byte_array())
        );
        Ok(output)
    }

    async fn recover_current_dkg(
        &self,
        epoch: u64,
        onchain_mpc_key: &[u8],
    ) -> anyhow::Result<MpcOutput> {
        self.setup_initial_dkg(epoch)?;
        let onchain_state = self.inner.onchain_state().clone();
        let certs: Vec<CertificateV1> =
            tob_certificates(&onchain_state, epoch, None, move_types::ProtocolType::Dkg)
                .map_err(|e| anyhow::anyhow!("failed to read DKG certs for epoch {epoch}: {e}"))?
                .into_iter()
                .map(|(_, cert)| cert)
                .collect();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized for DKG recovery"))?;
        let certs = verify_fetched_certificates(&mpc_manager, certs, &self.inner.metrics).await;
        match MpcManager::reconstruct_current_dkg_output(&mpc_manager, &certs, onchain_mpc_key) {
            MpcOutputRecoveryOutcome::Recovered(output) => {
                info!(
                    "recover_current_dkg: recovered current epoch {epoch} from local DKG \
                     messages (no peers)"
                );
                Ok(output)
            }
            MpcOutputRecoveryOutcome::NotApplicable => match self.run_dkg(epoch).await? {
                ReconfigOutcome::Output(output) => Ok(output),
                other => Err(anyhow::anyhow!(
                    "dkg for epoch {epoch} produced no output ({}): this node has no \
                         share state to recover",
                    other.label()
                )),
            },
            MpcOutputRecoveryOutcome::Suspicious(reason) => {
                error!(
                    "recover_current_dkg: local DKG state for epoch {epoch} contradicts on-chain \
                     truth ({reason}); observing this epoch, will recover at the next rotation"
                );
                self.inner.metrics.mpc_recovery_suspicious_total.inc();
                Err(anyhow::anyhow!(
                    "suspicious local DKG state for epoch {epoch}: {reason}"
                ))
            }
        }
    }

    async fn recover_current_rotation(
        &self,
        epoch: u64,
        onchain_mpc_key: &[u8],
    ) -> anyhow::Result<MpcOutput> {
        self.setup_key_rotation(epoch)?;
        let onchain_state = self.inner.onchain_state().clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized for rotation recovery"))?;
        let previous_epoch = mpc_manager.read().unwrap().previous_epoch;
        let current_certs: Vec<CertificateV1> = tob_certificates(
            &onchain_state,
            epoch,
            None,
            move_types::ProtocolType::KeyRotation,
        )
        .map_err(|e| anyhow::anyhow!("failed to read rotation certs for epoch {epoch}: {e}"))?
        .into_iter()
        .map(|(_, cert)| cert)
        .collect();
        let previous_certs: Vec<CertificateV1> =
            key_generation_certificates(&onchain_state, previous_epoch)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read certs for previous epoch {previous_epoch}: {e}")
                })?
                .into_iter()
                .map(|(_, cert)| cert)
                .collect();
        let current_certs =
            verify_fetched_certificates(&mpc_manager, current_certs, &self.inner.metrics).await;
        let previous_certs =
            verify_fetched_certificates(&mpc_manager, previous_certs, &self.inner.metrics).await;
        match MpcManager::reconstruct_current_rotation_output(
            &mpc_manager,
            &current_certs,
            &previous_certs,
            onchain_mpc_key,
        ) {
            MpcOutputRecoveryOutcome::Recovered(output) => {
                info!(
                    "recover_current_rotation: recovered current epoch {epoch} and previous \
                     {previous_epoch} from local rotation messages (no peers)"
                );
                Ok(output)
            }
            MpcOutputRecoveryOutcome::NotApplicable => match self.run_key_rotation(epoch).await? {
                ReconfigOutcome::Output(output) => Ok(output),
                other => Err(anyhow::anyhow!(
                    "rotation for epoch {epoch} produced no output ({}): this node has no \
                         share state to recover",
                    other.label()
                )),
            },
            MpcOutputRecoveryOutcome::Suspicious(reason) => {
                error!(
                    "recover_current_rotation: local rotation state for epoch {epoch} contradicts \
                     on-chain truth ({reason}); observing this epoch, will recover at the next \
                     rotation"
                );
                self.inner.metrics.mpc_recovery_suspicious_total.inc();
                Err(anyhow::anyhow!(
                    "suspicious local rotation state for epoch {epoch}: {reason}"
                ))
            }
        }
    }

    #[tracing::instrument(level = "info", skip_all, fields(target_epoch))]
    async fn run_dkg(&self, target_epoch: u64) -> anyhow::Result<ReconfigOutcome> {
        let onchain_state = self.inner.onchain_state().clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .expect("MpcManager must be set before run_dkg");
        if !mpc_manager.read().unwrap().is_committee_member() {
            info!("run_dkg: not in the epoch {target_epoch} committee, no role in its DKG");
            return Ok(ReconfigOutcome::NoRole);
        }
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), target_epoch, MPC_LABEL_DKG);
        let mut tob_channel = SuiTobSessionChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            None,
            move_types::ProtocolType::Dkg,
            signer,
        )
        .with_idle_timeout(RECONFIG_RECEIVE_IDLE_TIMEOUT);
        let output = MpcManager::run_dkg(
            &mpc_manager,
            &p2p_channel,
            &mut tob_channel,
            &self.inner.metrics,
        )
        .await
        .map_err(|e| anyhow::anyhow!("DKG failed: {e}"))?;
        Ok(ReconfigOutcome::Output(output))
    }

    async fn generate_presignatures(
        &self,
        epoch: u64,
        batch_index: u32,
    ) -> anyhow::Result<(Committee, Presignatures, u16)> {
        let onchain_state = self.inner.onchain_state().clone();
        let committee = onchain_state
            .state()
            .hashi()
            .committees
            .committees()
            .get(&epoch)
            .ok_or_else(|| anyhow::anyhow!("No committee found for epoch {}", epoch))?
            .clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized"))?;
        mpc_manager.read().unwrap().ensure_manager_epoch(epoch)?;
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel =
            RpcP2PChannel::new(onchain_state.clone(), epoch, MPC_LABEL_NONCE_GENERATION);
        let onchain_state_for_certs = onchain_state.clone();
        let mut tob_channel = SuiTobSessionChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            Some(batch_index),
            move_types::ProtocolType::NonceGeneration,
            signer,
        )
        .with_idle_timeout(NONCE_RECEIVE_IDLE_TIMEOUT);
        let metrics = &self.inner.metrics;
        let _timer = metrics
            .mpc_total_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        MpcManager::run_nonce_dealer_phase(
            &mpc_manager,
            batch_index,
            &p2p_channel,
            &mut tob_channel,
            metrics,
        )
        .await;
        let cert_wait_timer = metrics
            .mpc_tob_poll_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let (final_certs, settled_cutoff_ms) = Self::fetch_final_nonce_certs(
            &onchain_state_for_certs,
            &mpc_manager,
            epoch,
            batch_index,
            true,
            metrics,
        )
        .await?;
        drop(cert_wait_timer);
        let canonical = nonce_certificates(&final_certs, epoch, batch_index);
        let admitted = {
            let mgr = mpc_manager.read().unwrap();
            mgr.avid_admitted_nonce_dealers(&canonical, settled_cutoff_ms)?
        };
        let served_weight = admitted.weight;
        if !admitted.floor_reached() {
            return Err(admitted.below_floor_error(batch_index, metrics).into());
        }
        let nonce_result = MpcManager::run_avid_nonce_party_phase(
            &mpc_manager,
            batch_index,
            &p2p_channel,
            &admitted,
            Some((onchain_state_for_certs.clone(), epoch)),
            metrics,
        )
        .await;
        drop(_timer);
        let outcome = nonce_result.map_err(|e| anyhow::anyhow!("Nonce generation failed: {e}"))?;
        if outcome.local_skips > 0 {
            metrics.mpc_nonce_local_skip_batches_total.inc();
            anyhow::bail!(
                "nonce batch {batch_index} for epoch {epoch} skipped {} dealer(s) for \
                 node-local reasons; discarding so this node does not install a batch its peers did not build",
                outcome.local_skips,
            );
        }
        let dealer_count = outcome.outputs.len();
        let (batch_size_per_weight, params) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                Parameters {
                    t: mgr.mpc_config.threshold,
                    f: mgr.mpc_config.max_faulty,
                },
            )
        };
        let _timer = metrics
            .mpc_presig_conversion_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let presignatures = Presignatures::new(
            outcome.outputs,
            batch_size_per_weight,
            params,
            USE_LEGACY_PRESIG_DERIVATION,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        drop(_timer);
        let served_implies = presig_count(served_weight as usize, params, batch_size_per_weight);
        if presignatures.len() != served_implies {
            metrics.mpc_nonce_size_mismatch_total.inc();
            anyhow::bail!(
                "nonce batch {batch_index} for epoch {epoch}: built {} presigs but the \
                 served certs size to {served_implies} (weight {served_weight}); a dealer \
                 dealt for a weight other than its configured reduced weight, refusing \
                 to install",
                presignatures.len(),
            );
        }
        metrics.mpc_nonce_batch_index.set(batch_index as i64);
        metrics.mpc_nonce_batch_dealers.set(dealer_count as i64);
        info!(
            "nonce batch {batch_index} for epoch {epoch}: {} presigs from the admitted set",
            presignatures.len(),
        );
        Ok((committee, presignatures, batch_size_per_weight))
    }

    async fn prepare_signing(&self, epoch: u64, output: &MpcOutput) -> anyhow::Result<()> {
        let (committee, presignatures, batch_size_per_weight) =
            self.generate_presignatures(epoch, 0).await?;
        let address = self.inner.config.validator_address()?;
        let share_owners = self.share_owners_for_epoch(epoch)?;
        let (signing_manager, _identity) = SigningManager::new(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            share_owners,
            presignatures,
            0, // batch_index
            0, // batch_start_index
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
            self.identity_inputs(epoch, batch_size_per_weight),
        );
        self.inner.store_signing_manager(signing_manager);
        Ok(())
    }

    /// The authoritative share-index → owner map for `epoch`, from the MPC
    /// manager's reduced node set.
    fn share_owners_for_epoch(
        &self,
        epoch: u64,
    ) -> anyhow::Result<
        std::collections::HashMap<fastcrypto_tbls::types::ShareIndex, sui_sdk_types::Address>,
    > {
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized"))?;
        let owners = mpc_manager
            .read()
            .unwrap()
            .share_owners_for_epoch(epoch)
            .map_err(|e| anyhow::anyhow!("Failed to derive share owners for epoch {epoch}: {e}"))?;
        Ok(owners)
    }

    fn bail_if_reconfig_pending(&self) -> anyhow::Result<()> {
        match self.get_pending_epoch_change() {
            Some(p) => anyhow::bail!("superseded by pending reconfig to epoch {p}"),
            None => Ok(()),
        }
    }

    fn reconfig_target_live(&self, target_epoch: u64) -> bool {
        let state = self.inner.onchain_state().state();
        let committees = &state.hashi().committees;
        reconfig_target_live(
            committees.pending_epoch_change(),
            committees.epoch(),
            committees.current_committee().is_some(),
            target_epoch,
        )
    }

    async fn recover_presigning_state(&self, output: &MpcOutput) -> anyhow::Result<PresigRecovery> {
        let (num_consumed, epoch, committee, pending) = {
            let state = self.inner.onchain_state().state();
            let hashi = state.hashi();
            let num_consumed = hashi.num_consumed_presigs;
            let epoch = hashi.committees.epoch();
            let committee = hashi
                .committees
                .committees()
                .get(&epoch)
                .ok_or_else(|| anyhow::anyhow!("No committee found for epoch {epoch}"))?
                .clone();
            let mut pending: HashSet<u64> = HashSet::new();
            for txn in hashi.bitcoin().withdrawal_queue.withdrawal_txns().values() {
                if txn.signing_epoch() != epoch {
                    continue;
                }
                for signature in &txn.signing.signatures {
                    if let move_types::MpcSig::Pending(index) = signature {
                        anyhow::ensure!(
                            *index < num_consumed,
                            "pending presig index {index} is not below allocation cursor {num_consumed}",
                        );
                        anyhow::ensure!(
                            pending.insert(*index),
                            "pending presig index {index} is assigned more than once",
                        );
                    }
                }
            }
            (num_consumed, epoch, committee, pending)
        };
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized"))?;
        let (batch_size_per_weight, params, floor) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                Parameters {
                    t: mgr.mpc_config.threshold,
                    f: mgr.mpc_config.max_faulty,
                },
                mgr.required_nonce_weight(),
            )
        };
        mpc_manager.read().unwrap().ensure_manager_epoch(epoch)?;
        let mut boundaries: Vec<(u32, u64, usize)> = Vec::new();
        let mut batch_start = 0u64;
        let mut batch_index = 0u32;
        loop {
            self.bail_if_reconfig_pending()?;
            let size = self
                .nonce_batch_size_from_certs(
                    &mpc_manager,
                    epoch,
                    batch_index,
                    params,
                    batch_size_per_weight,
                    floor,
                )
                .await?;
            let (size, holds_cursor) = match walk_step(size, batch_start, num_consumed) {
                WalkStep::Missing => {
                    return Ok(PresigRecovery::MissingBatch {
                        epoch,
                        batch_index,
                        batch_start,
                    });
                }
                WalkStep::Stop => break,
                WalkStep::Last(size) => (size, true),
                WalkStep::Continue(size) => (size, false),
            };
            boundaries.push((batch_index, batch_start, size));
            if holds_cursor {
                break;
            }
            batch_start += size as u64;
            batch_index += 1;
        }
        anyhow::ensure!(
            !boundaries.is_empty(),
            "no certified nonce batches for epoch {epoch}: batch 0 is not yet sizeable and \
             the cursor has drawn nothing",
        );
        let recovered_end = boundaries
            .last()
            .map_or(0, |&(_, start, size)| start + size as u64);
        let first_pending = boundaries
            .iter()
            .position(|&(_, start, size)| {
                let end = start + size as u64;
                pending.iter().any(|&p| p >= start && p < end)
            })
            .unwrap_or_else(|| boundaries.len().saturating_sub(1));
        let mut retained: Vec<(Presignatures, u32, u64)> = Vec::new();
        // TODO(IOP-529): Avoid the double cert-fetch in presig recovery.
        for &(bidx, start, size) in boundaries.iter().skip(first_pending) {
            self.bail_if_reconfig_pending()?;
            let presigs = self
                .recover_presignatures_from_certs(
                    &mpc_manager,
                    epoch,
                    bidx,
                    batch_size_per_weight,
                    params,
                )
                .await?;
            anyhow::ensure!(
                presigs.len() == size,
                "batch {bidx} boundary size {size} (Phase 1) != reconstructed len {} (Phase 2)",
                presigs.len(),
            );
            retained.push((presigs, bidx, start));
        }
        anyhow::ensure!(
            self.inner.onchain_state().epoch() == epoch,
            "epoch changed during presigning recovery",
        );
        let latest_cursor = self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .num_consumed_presigs;
        anyhow::ensure!(
            latest_cursor <= recovered_end,
            "cursor {latest_cursor} advanced past recovered end {recovered_end} during recovery",
        );
        let address = self.inner.config.validator_address()?;
        let retained_count = retained.len();
        let share_owners = self.share_owners_for_epoch(epoch)?;
        let (signing_manager, _identities) = SigningManager::new_recovered(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            share_owners,
            retained,
            num_consumed,
            &pending,
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
            self.identity_inputs(epoch, batch_size_per_weight),
        )?;
        self.inner.store_signing_manager(signing_manager);
        info!(
            "Recovered presigning state: {retained_count} of {} batch(es) retained from \
             first_pending_batch={first_pending}, recovered_end={recovered_end}, \
             num_consumed_presigs={num_consumed}, pending={}",
            boundaries.len(),
            pending.len(),
        );
        Ok(PresigRecovery::Installed)
    }

    fn identity_inputs(&self, epoch: u64, batch_size_per_weight: u16) -> IdentityInputs {
        IdentityInputs {
            epoch,
            batch_size_per_weight,
        }
    }

    async fn nonce_batch_size_from_certs(
        &self,
        mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
        epoch: u64,
        batch_index: u32,
        params: Parameters,
        batch_size_per_weight: u16,
        floor: u32,
    ) -> anyhow::Result<Option<usize>> {
        let onchain_state = self.inner.onchain_state().clone();
        let (certs, settled_cutoff_ms) = Self::fetch_final_nonce_certs(
            &onchain_state,
            mpc_manager,
            epoch,
            batch_index,
            false,
            &self.inner.metrics,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "nonce cert fetch for epoch {epoch} batch {batch_index} (boundary rebuild): {e}"
            )
        })?;
        let weight = {
            let avid_certs = nonce_certificates(&certs, epoch, batch_index);
            mpc_manager
                .read()
                .unwrap()
                .avid_admitted_nonce_weight(&avid_certs, settled_cutoff_ms)
        };
        if weight < floor {
            return Ok(None);
        }
        Ok(Some(presig_count(
            weight as usize,
            params,
            batch_size_per_weight,
        )))
    }

    /// Put the `MpcManager` back on the current epoch once the
    /// reconfiguration that displaced it is dead. `handle_reconfig` installs
    /// a manager for its target before running the protocol, and every
    /// give-up exit leaves it there; after an abort that manager is for an
    /// epoch that will never exist. The current epoch's `SigningManager`
    /// survived the whole time, which is exactly why `sync_if_stale` rebuilds
    /// nothing, yet presignature refill and batch repair both run through
    /// `ensure_manager_epoch` and fail against the dead manager, so the pool
    /// could not refill until the next `end_reconfig` landed. A fresh manager
    /// is all they need: the recovery path builds the same one from scratch.
    fn restore_current_manager(&self, epoch: u64) {
        let pinned = self
            .inner
            .mpc_manager()
            .map(|manager| manager.read().unwrap().mpc_config.epoch);
        if !manager_needs_restore(pinned, epoch, self.get_pending_epoch_change()) {
            return;
        }
        let result = if self.inner.onchain_state().is_key_rotation_epoch(epoch) {
            self.setup_key_rotation(epoch)
        } else {
            self.setup_initial_dkg(epoch)
        };
        match result {
            Ok(()) => info!(
                "sync_if_stale: restored the MpcManager for epoch {epoch}; a reconfiguration \
                 that did not complete had left it on {pinned:?}"
            ),
            Err(e) => error!(
                "sync_if_stale: failed to restore the MpcManager for epoch {epoch} (left on \
                 {pinned:?} by a reconfiguration that did not complete): {e}"
            ),
        }
    }

    async fn sync_if_stale(&self) {
        if self.is_awaiting_genesis() || !self.inner.is_in_current_committee() {
            return;
        }
        let epoch = self.inner.onchain_state().epoch();
        if self.inner.signing_manager_for(epoch).is_some() {
            self.restore_current_manager(epoch);
            return;
        }
        let _guard = match self.reconciling.try_lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let epoch = self.inner.onchain_state().epoch();
        if self.inner.signing_manager_for(epoch).is_some() {
            return;
        }
        info!("sync_if_stale: rebuilding SigningManager for epoch {epoch}");
        let output = match self.recover_mpc_state().await {
            Ok(output) => output,
            Err(e) => {
                if let Some(p) = self.get_pending_epoch_change() {
                    info!(
                        "sync_if_stale: recover_mpc_state for epoch {epoch} superseded by \
                         pending reconfig to {p} ({e})"
                    );
                    return;
                }
                error!("sync_if_stale: recover_mpc_state failed for epoch {epoch}: {e}");
                self.re_register_keys_if_lost().await;
                return;
            }
        };
        match self.recover_presigning_state(&output).await {
            Ok(PresigRecovery::Installed) => {
                info!("sync_if_stale: recovered epoch {epoch} via certs path");
            }
            Ok(PresigRecovery::MissingBatch {
                epoch: walk_epoch,
                batch_index,
                batch_start,
            }) => {
                self.repair_missing_batch(walk_epoch, batch_index, batch_start)
                    .await;
                return;
            }
            Err(certs_err) => {
                if let Some(p) = self.get_pending_epoch_change() {
                    info!(
                        "sync_if_stale: recovery for epoch {epoch} superseded by pending \
                         reconfig to {p} ({certs_err})"
                    );
                    return;
                }
                let num_consumed = self
                    .inner
                    .onchain_state()
                    .state()
                    .hashi()
                    .num_consumed_presigs;
                if num_consumed > 0 {
                    error!(
                        "sync_if_stale: recovery failed for epoch {epoch} at cursor \
                         {num_consumed} ({certs_err}); retrying on the next tick (no genesis fallback)"
                    );
                    return;
                }
                info!(
                    "sync_if_stale: certs path failed for epoch {epoch} ({certs_err}), \
                     falling back to protocol"
                );
                if let Err(e) = self.prepare_signing(epoch, &output).await {
                    error!("sync_if_stale: protocol fallback failed for epoch {epoch}: {e}");
                    return;
                }
                info!("sync_if_stale: recovered epoch {epoch} via protocol path");
            }
        }
        let _ = self.key_ready_tx.send(Some(output.public_key));
    }

    async fn repair_missing_batch(&self, epoch: u64, batch_index: u32, batch_start: u64) {
        let metrics = &self.inner.metrics;
        let repair_total = &metrics.mpc_presig_batch_repair_total;
        let skip = |outcome: &str| repair_total.with_label_values(&[outcome]).inc();
        let now = tokio::time::Instant::now;
        let rearm_soon = || {
            *self.next_batch_repair.lock().unwrap() =
                Some((epoch, batch_index, now() + RETRY_INTERVAL))
        };
        if self.inner.onchain_state().epoch() != epoch {
            skip("epoch_moved");
            return;
        }
        {
            let mut next = self.next_batch_repair.lock().unwrap();
            if repair_rate_limited(*next, epoch, batch_index, now()) {
                skip("rate_limited");
                return;
            }
            *next = Some((epoch, batch_index, now() + REPAIR_MIN_INTERVAL));
        }
        let certs = match tob_certificates(
            self.inner.onchain_state(),
            epoch,
            Some(batch_index),
            move_types::ProtocolType::NonceGeneration,
        ) {
            Ok(certs) => certs,
            Err(e) => {
                skip("read_failed");
                rearm_soon();
                warn!(
                    "repair_missing_batch: cert read failed for epoch {epoch} batch \
                     {batch_index}: {e}"
                );
                return;
            }
        };

        let address = match self.inner.config.validator_address() {
            Ok(address) => address,
            Err(e) => {
                skip("no_address");
                error!("repair_missing_batch: no validator address: {e}");
                return;
            }
        };
        if certs.iter().any(|(dealer, _)| *dealer == address) {
            skip("already_dealt");
            warn!(
                "repair_missing_batch: epoch {epoch} batch {batch_index} already carries our \
                 cert and is still below floor; no withdrawal signing"
            );
            return;
        }

        let Some(mpc_manager) = self.inner.mpc_manager() else {
            skip("no_manager");
            error!("repair_missing_batch: no MpcManager for epoch {epoch} batch {batch_index}");
            return;
        };
        {
            let mgr = mpc_manager.read().unwrap();
            if let Err(e) = mgr.ensure_manager_epoch(epoch) {
                skip("manager_epoch");
                rearm_soon();
                warn!("repair_missing_batch: {e}");
                return;
            }
            if mgr.this_node_deals_nothing() {
                skip("no_weight");
                warn!(
                    "repair_missing_batch: epoch {epoch} batch {batch_index} is below floor and \
                     this node has nothing to deal into it; no withdrawal signing"
                );
                return;
            }
        }
        if let Err(e) = self.bail_if_reconfig_pending() {
            skip("reconfig_pending");
            rearm_soon();
            info!("repair_missing_batch: {e}");
            return;
        }
        let signer = match self.inner.config.operator_private_key() {
            Ok(signer) => signer,
            Err(e) => {
                skip("no_signer");
                error!("repair_missing_batch: no operator key: {e}");
                return;
            }
        };
        warn!(
            "repair_missing_batch: epoch {epoch} batch {batch_index} below floor at {batch_start} \
             with {} cert(s), cursor has drawn from it; dealing into it, no withdrawal \
             signing",
            certs.len(),
        );
        let onchain_state = self.inner.onchain_state().clone();
        let p2p_channel =
            RpcP2PChannel::new(onchain_state.clone(), epoch, MPC_LABEL_NONCE_GENERATION);
        let mut tob_channel = SuiTobSessionChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            Some(batch_index),
            move_types::ProtocolType::NonceGeneration,
            signer,
        )
        .with_idle_timeout(NONCE_RECEIVE_IDLE_TIMEOUT);
        repair_total.with_label_values(&["attempted"]).inc();
        let started = now();
        let round = MpcManager::run_nonce_dealer_phase(
            &mpc_manager,
            batch_index,
            &p2p_channel,
            &mut tob_channel,
            metrics,
        );
        tokio::pin!(round);
        let mut heartbeat = tokio::time::interval(REPAIR_HEARTBEAT_TICK);
        loop {
            tokio::select! {
                () = &mut round => break,
                _ = heartbeat.tick() => metrics.task_heartbeat("mpc_service"),
            }
        }
        *self.next_batch_repair.lock().unwrap() =
            Some((epoch, batch_index, now() + REPAIR_MIN_INTERVAL));
        info!(
            "repair_missing_batch: epoch {epoch} batch {batch_index} round returned after {:?}",
            started.elapsed(),
        );
    }

    async fn re_register_keys_if_lost(&self) {
        let committee = self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .current_committee()
            .cloned();
        let Some(committee) = committee else { return };
        let Ok(me) = self.inner.config.validator_address() else {
            return;
        };
        if !self.inner.committee_key_lost(&committee, me) {
            return;
        }
        self.inner.metrics.mpc_committee_key_lost_total.inc();
        let mut target = match self.inner.next_reconfig_epoch().await {
            Ok(target) => target,
            Err(e) => {
                warn!("cannot determine next reconfig epoch for key re-registration: {e}");
                return;
            }
        };
        for _ in 0..MAX_KEY_REREGISTRATION_BUMPS {
            if self
                .replacement_keys_target_epoch
                .lock()
                .unwrap()
                .is_some_and(|recorded| recorded >= target)
            {
                return;
            }
            warn!(
                "no DB encryption or signing key matches the current committee record; \
                 registering fresh keys for epoch {target} so the node rejoins at that reconfig"
            );
            let landed_at = match self.inner.prepare_and_register_keys(target).await {
                Ok(landed_at) => landed_at,
                Err(e) => {
                    warn!(
                        "failed to register replacement keys for epoch {target}: {e}; will retry"
                    );
                    return;
                }
            };
            // The snapshot check below reads the mirror, so the mirror must
            // first reflect the registration that just landed: a lagging
            // view could show the epoch-`target` committee as not yet
            // snapshotted when it was in fact already frozen without the
            // replacement keys, ending the bump loop one epoch short.
            if let Some(landed_at) = landed_at {
                const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
                if tokio::time::timeout(
                    VISIBILITY_TIMEOUT,
                    self.inner.onchain_state().wait_until_checkpoint(landed_at),
                )
                .await
                .is_err()
                {
                    warn!(
                        "mirror did not reach the key-registration checkpoint {landed_at} within \
                         {VISIBILITY_TIMEOUT:?}; re-verifying next tick"
                    );
                    return;
                }
            }
            let frozen = self
                .inner
                .onchain_state()
                .state()
                .hashi()
                .committees
                .committees()
                .get(&target)
                .cloned();
            match frozen {
                Some(frozen) if self.inner.committee_key_lost(&frozen, me) => {
                    self.inner.metrics.mpc_key_reregistration_bumps_total.inc();
                    info!(
                        "epoch {target} committee already snapshotted without replacement keys; \
                         re-targeting {}",
                        target + 1
                    );
                    target += 1;
                }
                Some(frozen) => {
                    if frozen.members().iter().any(|m| m.validator_address() == me) {
                        info!("replacement keys frozen into the epoch {target} committee");
                    } else {
                        warn!(
                            "not a member of the epoch {target} committee; replacement keys \
                             registered for a future committee"
                        );
                    }
                    *self.replacement_keys_target_epoch.lock().unwrap() = Some(target);
                    return;
                }
                None => {
                    info!(
                        "replacement keys registered; the epoch {target} committee is not yet \
                         snapshotted and will include them"
                    );
                    *self.replacement_keys_target_epoch.lock().unwrap() = Some(target);
                    return;
                }
            }
        }
        warn!(
            "replacement keys still excluded after {MAX_KEY_REREGISTRATION_BUMPS} registration \
             attempts; will retry next tick"
        );
    }

    async fn refill_presignatures(&self, batch_index: u32) -> anyhow::Result<()> {
        let epoch = self.inner.onchain_state().epoch();
        let signing_manager = self
            .inner
            .signing_manager_for(epoch)
            .ok_or_else(|| anyhow::anyhow!("SigningManager not available for epoch {epoch}"))?;
        // Refill requests arrive via a coalescing channel that outlives
        // manager rebuilds and epoch changes, so a replayed value can name a
        // batch that is already installed, already staged, or not contiguous
        // with the installed range. Only the immediately-next batch is
        // actionable; anything else is skipped before spending generation
        // work, and the trigger paths re-request the right index on demand.
        let expected = signing_manager.batch_index() + 1;
        if batch_index != expected {
            info!(
                "Skipping presignature refill for batch {batch_index}: \
                 the next installable batch is {expected}"
            );
            return Ok(());
        }
        if signing_manager.prefetched_batch_index() == Some(batch_index) {
            info!(
                "Skipping presignature refill for batch {batch_index}: \
                 it is already staged for installation"
            );
            return Ok(());
        }
        let (_, presignatures, batch_size_per_weight) =
            self.generate_presignatures(epoch, batch_index).await?;
        if self.inner.onchain_state().epoch() != epoch {
            return Err(anyhow::anyhow!("Epoch changed during presignature refill"));
        }
        signing_manager.set_next_batch(
            batch_index,
            presignatures,
            self.identity_inputs(epoch, batch_size_per_weight),
        );
        Ok(())
    }

    async fn fetch_final_nonce_certs(
        onchain_state: &crate::onchain::OnchainState,
        mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
        epoch: u64,
        batch_index: u32,
        wait_for_floor: bool,
        metrics: &crate::metrics::Metrics,
    ) -> anyhow::Result<(
        VerifiedNonceCerts<move_types::StampedDealerSubmissionV1>,
        Option<u64>,
    )> {
        let mut wait_deadline = tokio::time::Instant::now() + NONCE_RECEIVE_IDLE_TIMEOUT;
        let overall_deadline = tokio::time::Instant::now() + NONCE_WAIT_TOTAL_BUDGET;
        let mut best_weight = 0u32;
        let mut cutoff_confirmed: Option<u64> = None;
        let mut adjudicated = HashMap::new();
        let bail_if_superseded = || -> anyhow::Result<()> {
            let (onchain_epoch, pending) = {
                let state = onchain_state.state();
                let committees = &state.hashi().committees;
                (committees.epoch(), committees.pending_epoch_change())
            };
            anyhow::ensure!(
                !crate::communication::sui_tob::tob_wait_superseded(
                    move_types::ProtocolType::NonceGeneration,
                    epoch,
                    onchain_epoch,
                    pending,
                ),
                "nonce cert wait for epoch {epoch} batch {batch_index} superseded \
                 (onchain epoch {onchain_epoch}, pending epoch change {pending:?})"
            );
            Ok(())
        };
        loop {
            bail_if_superseded()?;
            let certs = match onchain_state.tob_certs(
                epoch,
                Some(batch_index),
                move_types::ProtocolType::NonceGeneration,
            ) {
                Ok(certs) => certs.map(|(_, certs)| certs).unwrap_or_default(),
                Err(e) if crate::onchain::is_inconsistent_listing(&e) => {
                    if tokio::time::Instant::now() >= wait_deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(NONCE_WINDOW_WAIT_POLL).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let certs = MpcManager::verified_nonce_certs(
                mpc_manager,
                epoch,
                certs,
                batch_index,
                &mut adjudicated,
                metrics,
            )
            .await;
            bail_if_superseded()?;
            let (floor_reached, cutoff_ms, window_ms, weight) = {
                let mgr = mpc_manager.read().unwrap();
                let window = mgr.window_certified_nonce_dealers(&certs).1;
                (
                    window.floor_reached(),
                    window.cutoff_ms(),
                    mgr.mpc_config.nonce_accumulation_window_ms,
                    window.weight(),
                )
            };
            if weight > best_weight {
                best_weight = weight;
                wait_deadline = (tokio::time::Instant::now() + NONCE_RECEIVE_IDLE_TIMEOUT)
                    .min(overall_deadline);
            }
            if wait_for_floor && !floor_reached {
                if tokio::time::Instant::now() >= wait_deadline {
                    metrics.mpc_nonce_fetch_floor_unreached_total.inc();
                    anyhow::bail!(
                        "nonce certs never reached the floor for epoch {epoch} batch {batch_index}"
                    );
                }
                tokio::time::sleep(NONCE_WINDOW_WAIT_POLL).await;
                continue;
            }
            // The certs above came from the mirror, so the settling
            // condition is the mirror's own clock: once it has applied
            // everything through a checkpoint stamped past the cutoff,
            // every submission at or before the cutoff is either in the
            // read we just took or in the re-read the loop does next.
            let Some(cutoff_ms) = cutoff_ms else {
                return Ok((certs, None));
            };
            if cutoff_confirmed == Some(cutoff_ms) {
                return Ok((certs, Some(cutoff_ms)));
            }
            if tokio::time::Instant::now() >= wait_deadline {
                metrics.mpc_nonce_cutoff_unsettled_total.inc();
                anyhow::bail!(
                    "nonce cert cutoff never settled for epoch {epoch} batch {batch_index} \
                     (last confirmed {cutoff_confirmed:?}, now {cutoff_ms})"
                );
            }
            let deadline = (Duration::from_millis(window_ms) + NONCE_WINDOW_WAIT_SLACK)
                .min(overall_deadline.saturating_duration_since(tokio::time::Instant::now()));
            if tokio::time::timeout(
                deadline,
                onchain_state.wait_mirror_past_timestamp_ms(cutoff_ms),
            )
            .await
            .is_err()
            {
                metrics.mpc_nonce_window_cutoff_unreached_total.inc();
                warn!(
                    "fetch_final_nonce_certs: the mirror never advanced past window cutoff \
                     {cutoff_ms} for epoch {epoch} batch {batch_index} after {deadline:?} \
                     (stalled chain clock or a lagging mirror); failing this batch"
                );
                anyhow::bail!("nonce window did not close for epoch {epoch} batch {batch_index}");
            }
            if cutoff_confirmed.is_some() {
                tokio::time::sleep(NONCE_WINDOW_WAIT_POLL).await;
            }
            cutoff_confirmed = Some(cutoff_ms);
        }
    }

    async fn recover_presignatures_from_certs(
        &self,
        mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
        epoch: u64,
        batch_index: u32,
        batch_size_per_weight: u16,
        params: Parameters,
    ) -> anyhow::Result<Presignatures> {
        let onchain_state = self.inner.onchain_state().clone();
        let p2p_channel = RpcP2PChannel::new(
            self.inner.onchain_state().clone(),
            epoch,
            MPC_LABEL_NONCE_GENERATION,
        );
        let (certs, settled_cutoff_ms) = Self::fetch_final_nonce_certs(
            &onchain_state,
            mpc_manager,
            epoch,
            batch_index,
            false,
            &self.inner.metrics,
        )
        .await?;
        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "No nonce gen certificates on TOB for epoch {epoch} batch {batch_index}"
            ));
        }
        let (outputs, served_weight) = {
            let avid_certs = nonce_certificates(&certs, epoch, batch_index);
            let admitted = mpc_manager
                .read()
                .unwrap()
                .avid_admitted_nonce_dealers(&avid_certs, settled_cutoff_ms)?;
            if !admitted.floor_reached() {
                return Err(admitted
                    .below_floor_error(batch_index, &self.inner.metrics)
                    .into());
            }
            let outcome = MpcManager::run_avid_nonce_party_phase(
                mpc_manager,
                batch_index,
                &p2p_channel,
                &admitted,
                Some((onchain_state.clone(), epoch)),
                &self.inner.metrics,
            )
            .await
            .map_err(|e| anyhow::anyhow!("AVID nonce recovery from certs failed: {e}"))?;
            if outcome.local_skips > 0 {
                self.inner.metrics.mpc_nonce_local_skip_batches_total.inc();
                anyhow::bail!(
                    "AVID nonce recovery for epoch {epoch} batch {batch_index} skipped {} \
                     dealer(s) for node-local reasons; cannot rebuild the original batch",
                    outcome.local_skips,
                );
            }
            (outcome.outputs, admitted.weight)
        };
        if outputs.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid nonce outputs after reconstruction for epoch {epoch} batch {batch_index}"
            ));
        }
        let dealer_count = outputs.len();
        let presignatures = Presignatures::new(
            outputs,
            batch_size_per_weight,
            params,
            USE_LEGACY_PRESIG_DERIVATION,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        let metrics = &self.inner.metrics;
        let served_implies = presig_count(served_weight as usize, params, batch_size_per_weight);
        if presignatures.len() != served_implies {
            metrics.mpc_nonce_size_mismatch_total.inc();
            anyhow::bail!(
                "nonce batch {batch_index} for epoch {epoch} rebuilt from certs: built {} \
                 presigs but the admitted certs size to {served_implies} (weight \
                 {served_weight}); refusing to install",
                presignatures.len(),
            );
        }
        metrics.mpc_nonce_batch_index.set(batch_index as i64);
        metrics.mpc_nonce_batch_dealers.set(dealer_count as i64);
        Ok(presignatures)
    }

    async fn try_submit_start_reconfig(&self, sui_epoch: u64) {
        if let Some(pending) = self.get_pending_epoch_change() {
            if !reconfig_window_closed(sui_epoch, pending) {
                return;
            }
            // The pending reconfiguration overran its window, so the chain
            // will not let it complete; abort it (any node may) so the
            // replacement can form in the new epoch.
            self.abort_stale_reconfig(pending).await;
            if self.get_pending_epoch_change().is_some() {
                return;
            }
        }
        let hashi_epoch = self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .epoch();
        if hashi_epoch >= sui_epoch {
            return;
        }
        if self.is_awaiting_genesis() {
            // Pre-genesis (where an aborted genesis DKG lands) there is no
            // committee to serve, so block in the same retry-until-pending
            // loop startup uses rather than give up after a few attempts and
            // leave the replacement to the next Sui epoch boundary or a
            // restart.
            self.try_submit_genesis_reconfig().await;
            return;
        }
        if let Err(e) = self.inner.prepare_and_register_keys(sui_epoch).await {
            warn!(
                "Failed to prepare/register encryption+signing keys for epoch {sui_epoch}: {e}; \
                 will retry on next trigger"
            );
        }
        for attempt in 1..=MAX_PROTOCOL_ATTEMPTS {
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor.execute_start_reconfig().await
            };
            match result.await {
                Ok(()) => {
                    return;
                }
                Err(e) => {
                    warn!("start_reconfig attempt {attempt}/{MAX_PROTOCOL_ATTEMPTS} failed: {e:#}");
                    if attempt < MAX_PROTOCOL_ATTEMPTS {
                        // Poll for pending epoch change while waiting, so we can
                        // return early if another node submitted start_reconfig.
                        let polls = (RETRY_INTERVAL.as_millis()
                            / START_RECONFIG_POLL_INTERVAL.as_millis())
                            as u32;
                        for _ in 0..polls {
                            if self.get_pending_epoch_change().is_some() {
                                return;
                            }
                            tokio::time::sleep(START_RECONFIG_POLL_INTERVAL).await;
                        }
                    }
                }
            }
        }
    }

    #[tracing::instrument(level = "info", skip_all, fields(target_epoch))]
    async fn handle_reconfig(&self, target_epoch: u64) {
        let run_dkg = self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .mpc_public_key()
            .is_empty();
        let protocol_label = if run_dkg {
            MPC_LABEL_DKG
        } else {
            MPC_LABEL_KEY_ROTATION
        };
        if !self.reconfig_target_pending(target_epoch) {
            info!(
                "handle_reconfig: epoch {target_epoch} no longer pending (or past its Sui epoch \
                 window) at entry, aborting before start",
            );
            return;
        }
        if let Err(e) = self.inner.verify_bitcoin_chain_id() {
            error!("refusing to participate in reconfig for epoch {target_epoch}: {e}");
            self.sleep_if_still_pending(target_epoch).await;
            return;
        }
        let metrics = &self.inner.metrics;
        let _reconfig_timer = metrics
            .mpc_reconfig_total_duration_seconds
            .with_label_values(&[protocol_label])
            .start_timer();
        info!("handle_reconfig: epoch={target_epoch}, run_dkg={run_dkg}, entering retry loop",);
        let output = loop {
            if !self.reconfig_target_pending(target_epoch) {
                info!(
                    "handle_reconfig: epoch {target_epoch} no longer pending or past its Sui \
                     epoch window, aborting"
                );
                return;
            }
            let in_committee = self.inner.is_in_committee_for(target_epoch);
            let needs_fresh_manager = match self.inner.mpc_manager() {
                None => true,
                Some(mgr) => {
                    let mgr = mgr.read().unwrap();
                    mgr.mpc_config.epoch != target_epoch
                        || mgr.is_committee_member() != in_committee
                }
            };
            if needs_fresh_manager {
                let setup_result = if run_dkg {
                    self.setup_initial_dkg(target_epoch)
                } else {
                    self.setup_key_rotation(target_epoch)
                };
                if let Err(e) = setup_result {
                    error!(
                        "Failed to set up MPC manager for epoch {}: {e}, retrying...",
                        target_epoch
                    );
                    self.sleep_if_still_pending(target_epoch).await;
                    continue;
                }
            }
            let _timer = metrics
                .mpc_total_duration_seconds
                .with_label_values(&[protocol_label])
                .start_timer();
            let result = if run_dkg {
                self.run_dkg(target_epoch).await
            } else {
                self.run_key_rotation(target_epoch).await
            };
            drop(_timer);
            match result {
                Ok(ReconfigOutcome::Output(output)) => break output,
                Ok(outcome) => {
                    let reason = outcome.label();
                    if matches!(outcome, ReconfigOutcome::NoShares) {
                        warn!(
                            "handle_reconfig: epoch {target_epoch} produced no output: this node \
                             holds no previous-epoch shares to reshare"
                        );
                    } else {
                        info!(
                            "handle_reconfig: epoch {target_epoch} produced no output for this \
                             node ({reason}); waiting out the pending window"
                        );
                    }
                    metrics
                        .mpc_reconfig_no_output_total
                        .with_label_values(&[protocol_label, reason])
                        .inc();
                    _reconfig_timer.stop_and_discard();
                    while self.reconfig_target_pending(target_epoch) {
                        metrics.task_heartbeat("mpc_service");
                        self.sleep_if_still_pending(target_epoch).await;
                    }
                    let backup = match outcome {
                        ReconfigOutcome::NoRole => Backup::Skip,
                        ReconfigOutcome::Output(_)
                        | ReconfigOutcome::Dealt
                        | ReconfigOutcome::NotNeeded
                        | ReconfigOutcome::NoShares => Backup::Write,
                    };
                    self.post_reconfig_housekeeping(target_epoch, false, backup)
                        .await;
                    return;
                }
                Err(e) => {
                    error!(
                        "MPC protocol for epoch {} failed: {e}, retrying...",
                        target_epoch
                    );
                    self.sleep_if_still_pending(target_epoch).await;
                }
            }
        };
        if !self.reconfig_target_live(target_epoch) {
            info!("handle_reconfig: epoch {target_epoch} aborted after protocol completion");
            return;
        }
        let _ = self.key_ready_tx.send(Some(output.public_key));
        info!("MPC key ready for epoch {target_epoch}, submitting end_reconfig");
        let _end_reconfig_timer = metrics
            .mpc_end_reconfig_duration_seconds
            .with_label_values(&[protocol_label])
            .start_timer();
        let mut end_reconfig_confirmed = false;
        loop {
            // Pending cleared: activated by another node (signing setup
            // below) or aborted (nothing to do). Checked before the window
            // so a completion that landed in the window's last moments is
            // not mistaken for an overrun.
            if self.get_pending_epoch_change() != Some(target_epoch) {
                break;
            }
            if self.reconfig_window_closed(target_epoch) {
                info!(
                    "handle_reconfig: epoch {target_epoch} overran its Sui epoch window before \
                     end_reconfig landed; it can only be aborted now"
                );
                _end_reconfig_timer.stop_and_discard();
                _reconfig_timer.stop_and_discard();
                return;
            }
            match self.submit_end_reconfig(target_epoch, &output).await {
                Ok(()) => {
                    end_reconfig_confirmed = true;
                    break;
                }
                Err(e) => match classify_reconfig_submission_error(&e) {
                    ReconfigSubmissionErrorKind::NonMoveAbort => {
                        warn!(
                            "submit_end_reconfig for epoch {} failed: {e:#}, retrying...",
                            target_epoch
                        );
                        self.sleep_if_still_pending(target_epoch).await;
                    }
                    ReconfigSubmissionErrorKind::ReconfigTargetDead => {
                        info!(
                            "handle_reconfig: epoch {target_epoch} can no longer complete \
                             (aborted, or past its Sui epoch window); giving up on it: {e:#}"
                        );
                        _end_reconfig_timer.stop_and_discard();
                        _reconfig_timer.stop_and_discard();
                        // The chain knows the target is dead before the
                        // mirror does. Until the mirror catches up the outer
                        // loop still sees it pending and would re-enter here
                        // immediately, re-collecting signatures and
                        // submitting another doomed transaction each pass.
                        self.sleep_if_still_pending(target_epoch).await;
                        return;
                    }
                    ReconfigSubmissionErrorKind::NonRetryableMoveAbort
                    | ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted
                    | ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted => {
                        let msg = format!(
                            "submit_end_reconfig for epoch {target_epoch} failed with non-retryable error: {e:#}"
                        );
                        error!("{msg}");
                        panic!("{msg}");
                    }
                },
            }
        }
        drop(_end_reconfig_timer);
        let next_epoch = target_epoch + 1;
        if let Err(e) = self.inner.prepare_and_register_keys(next_epoch).await {
            warn!(
                "Failed to prepare/register encryption+signing keys for epoch {next_epoch}: {e}; \
                 will retry at next trigger"
            );
        }
        info!("end_reconfig complete for epoch {target_epoch}, running prepare_signing");
        self.post_reconfig_housekeeping(target_epoch, end_reconfig_confirmed, Backup::Write)
            .await;
        if !self.reconfig_target_live(target_epoch) {
            info!(
                "handle_reconfig: epoch {target_epoch} no longer pending nor current; \
                 skipping signing setup"
            );
            return;
        }
        let _prepare_signing_timer = metrics
            .mpc_prepare_signing_duration_seconds
            .with_label_values(&[protocol_label])
            .start_timer();
        for attempt in 1..=MAX_PROTOCOL_ATTEMPTS {
            match self.prepare_signing(target_epoch, &output).await {
                Ok(()) => break,
                Err(e) => {
                    error!(
                        "prepare_signing attempt {attempt}/{MAX_PROTOCOL_ATTEMPTS} \
                         for epoch {target_epoch}: {e}"
                    );
                    if attempt < MAX_PROTOCOL_ATTEMPTS {
                        tokio::time::sleep(RETRY_INTERVAL).await;
                    } else {
                        error!(
                            "All prepare_signing attempts exhausted for epoch {target_epoch}. \
                             Node cannot sign until next recovery trigger."
                        );
                    }
                }
            }
        }
        drop(_prepare_signing_timer);
        drop(_reconfig_timer);
    }

    /// Compact the database so rows tombstoned by pruning are actually unlinked.
    ///
    /// Awaited deliberately before `prepare_signing` refills the presig pool:
    /// the keyspaces are at their emptiest right after the prune, so the merge
    /// writes almost nothing.
    async fn run_major_compaction(&self, epoch: u64) {
        let db = self.inner.db.clone();
        let started = std::time::Instant::now();
        let compaction = match tokio::task::spawn_blocking(move || db.major_compact()).await {
            Ok(compaction) => compaction,
            Err(e) => {
                error!("major compaction for epoch {epoch} panicked: {e}");
                return;
            }
        };
        for keyspace in compaction.keyspaces {
            self.inner.metrics.record_major_compaction(&keyspace);
            match &keyspace.error {
                Some(e) => error!("compacting {} failed: {e}", keyspace.name),
                None => info!(
                    "compacted {} in {:?}: {} -> {} live bytes",
                    keyspace.name, keyspace.elapsed, keyspace.before, keyspace.after,
                ),
            }
        }
        // The unlink rotation is what actually releases the disk, so its
        // failure fails the run even when every keyspace compacted cleanly.
        match &compaction.unlink_error {
            Some(e) => {
                self.inner.metrics.record_major_compaction_unlink_failure();
                error!(
                    "major compaction for epoch {epoch} failed after {:?}: \
                     retired tables were not unlinked, the space is still held: {e}",
                    started.elapsed()
                );
            }
            None => info!(
                "major compaction for epoch {epoch} finished in {:?}",
                started.elapsed()
            ),
        }
    }

    fn setup_initial_dkg(&self, target_epoch: u64) -> anyhow::Result<()> {
        let dkg_manager = self
            .inner
            .create_mpc_manager(target_epoch, ProtocolType::Dkg)?;
        self.inner.set_mpc_manager(dkg_manager);
        Ok(())
    }

    fn setup_key_rotation(&self, target_epoch: u64) -> anyhow::Result<()> {
        let rotation_manager = self
            .inner
            .create_mpc_manager(target_epoch, ProtocolType::KeyRotation)?;
        self.inner.set_mpc_manager(rotation_manager);
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(target_epoch))]
    async fn run_key_rotation(&self, target_epoch: u64) -> anyhow::Result<ReconfigOutcome> {
        let onchain_state = self.inner.onchain_state().clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized for key rotation"))?;
        let previous_epoch = mpc_manager.read().unwrap().previous_epoch;
        let onchain_mpc_key = hex::encode(onchain_state.mpc_public_key());
        let onchain_epoch = onchain_state.epoch();
        info!(
            "run_key_rotation: target_epoch={target_epoch}, previous_epoch={previous_epoch}, \
             onchain_epoch={onchain_epoch}, onchain_mpc_key={onchain_mpc_key}",
        );
        let role = {
            let mgr = mpc_manager.read().unwrap();
            if mgr.is_committee_member() {
                RotationRole::DealerAndParty
            } else if mgr.is_previous_committee_member() {
                RotationRole::DealerOnly
            } else {
                info!(
                    "run_key_rotation: in neither the epoch {target_epoch} committee nor its \
                     predecessor, no role in this rotation"
                );
                return Ok(ReconfigOutcome::NoRole);
            }
        };
        let previous_certs = key_generation_certificates(&onchain_state, previous_epoch)
            .map_err(|e| anyhow::anyhow!("Failed to read previous certificates: {e}"))?;
        let previous_certs: Vec<CertificateV1> =
            previous_certs.into_iter().map(|(_, cert)| cert).collect();
        let fetched = previous_certs.len();
        let previous_certs =
            verify_fetched_certificates(&mpc_manager, previous_certs, &self.inner.metrics).await;
        info!(
            "run_key_rotation: {} of {fetched} certs verified for previous_epoch={previous_epoch}",
            previous_certs.len(),
        );
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel =
            RpcP2PChannel::new(onchain_state.clone(), target_epoch, MPC_LABEL_KEY_ROTATION);
        let mut tob_channel = SuiTobSessionChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            None,
            move_types::ProtocolType::KeyRotation,
            signer,
        )
        .with_idle_timeout(RECONFIG_RECEIVE_IDLE_TIMEOUT);
        let output = MpcManager::run_key_rotation(
            &mpc_manager,
            &previous_certs,
            &p2p_channel,
            &mut tob_channel,
            &self.inner.metrics,
            role,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Key rotation failed: {e}"))?;
        Ok(output)
    }

    async fn submit_end_reconfig(&self, epoch: u64, output: &MpcOutput) -> anyhow::Result<()> {
        let mpc_public_key =
            bcs::to_bytes(&output.public_key).expect("public key serialization should succeed");
        let target_committee = self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .committees()
            .get(&epoch)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no committee found for epoch {}", epoch))?;
        let message = ReconfigCompletionMessage {
            epoch,
            mpc_public_key: mpc_public_key.clone(),
        };
        let my_address = self.inner.config.validator_address()?;
        let signing_key =
            self.inner
                .find_signing_key_for_committee(&target_committee, my_address, epoch)?;
        let my_sig = signing_key.sign(
            self.inner.config.hashi_ids().hashi_object_id,
            epoch,
            my_address,
            &message,
        );
        self.inner
            .store_reconfig_signature(epoch, my_sig.signature().as_bytes().to_vec());
        let cert = loop {
            if !self.reconfig_target_pending(epoch) {
                return Err(anyhow::anyhow!(
                    "epoch {epoch} no longer pending or past its Sui epoch window"
                ));
            }
            match self
                .collect_reconfig_signatures(epoch, &mpc_public_key, &target_committee)
                .await
            {
                Ok(cert) => break cert,
                Err(e) => {
                    warn!(
                        "Signature collection for epoch {} failed: {e}, retrying...",
                        epoch
                    );
                    self.sleep_if_still_pending(epoch).await;
                }
            }
        };
        let mut committee_handoff_cert = self.collect_committee_handoff_if_needed(epoch).await?;
        loop {
            if !self.reconfig_target_pending(epoch) {
                return Err(anyhow::anyhow!(
                    "epoch {epoch} no longer pending or past its Sui epoch window"
                ));
            }
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor
                    .execute_end_reconfig(
                        &mpc_public_key,
                        cert.committee_signature(),
                        committee_handoff_cert.as_ref(),
                    )
                    .await
            };
            match result.await {
                Ok(()) => return Ok(()),
                Err(e) => match classify_reconfig_submission_error(&e) {
                    ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted => {
                        warn!(
                            "end_reconfig submission for epoch {epoch} found reconfig already completed; waiting for the watcher to observe it: {e:#}"
                        );
                        self.wait_for_pending_clear_visibility(epoch).await;
                        if self.get_pending_epoch_change() != Some(epoch) {
                            return Ok(());
                        }
                        warn!(
                            "end_reconfig for epoch {epoch} is complete on chain, but the watcher still reports it pending after the visibility wait; retrying"
                        );
                        continue;
                    }
                    ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted => {
                        if committee_handoff_cert.take().is_some() {
                            warn!(
                                "end_reconfig submission for epoch {epoch} found handoff already submitted; retrying without the handoff call: {e:#}"
                            );
                            continue;
                        }
                        Err(e).with_context(|| {
                            format!(
                                "end_reconfig submission for epoch {epoch} failed because a handoff was already submitted, but this transaction did not submit one"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::NonRetryableMoveAbort => {
                        Err(e).with_context(|| {
                            format!(
                                "end_reconfig submission for epoch {epoch} failed with non-retryable error"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::ReconfigTargetDead => {
                        Err(e).with_context(|| {
                            format!(
                                "end_reconfig submission for epoch {epoch} found the target dead: \
                                 aborted, or past its Sui epoch window"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::NonMoveAbort => {
                        warn!(
                            "end_reconfig submission for epoch {} failed: {e:#}, retrying...",
                            epoch
                        );
                        self.sleep_if_still_pending(epoch).await;
                    }
                },
            }
        }
    }

    async fn collect_committee_handoff_if_needed(
        &self,
        epoch: u64,
    ) -> anyhow::Result<Option<CommitteeSignature>> {
        let from_epoch = self.inner.onchain_state().epoch();
        let requires_committee_handoff = !self
            .inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .mpc_public_key()
            .is_empty();
        if !requires_committee_handoff {
            return Ok(None);
        }

        let committee_handoff = loop {
            if !self.reconfig_target_pending(epoch) {
                return Err(anyhow::anyhow!(
                    "epoch {epoch} no longer pending or past its Sui epoch window"
                ));
            }
            match crate::leader::LeaderService::collect_committee_transition_signatures(
                &self.inner,
                from_epoch,
            )
            .await
            {
                Ok(handoff) => break handoff,
                Err(e) => {
                    warn!(
                        from_epoch,
                        "Committee handoff signature collection failed: {e:#}, retrying..."
                    );
                    self.sleep_if_still_pending(epoch).await;
                }
            }
        };
        Ok(Some(committee_handoff.into_parts().0))
    }

    async fn collect_reconfig_signatures(
        &self,
        epoch: u64,
        mpc_public_key: &[u8],
        committee: &Committee,
    ) -> anyhow::Result<hashi_types::committee::SignedMessage<ReconfigCompletionMessage>> {
        let message = ReconfigCompletionMessage {
            epoch,
            mpc_public_key: mpc_public_key.to_vec(),
        };
        let my_address = self.inner.config.validator_address()?;
        let my_sig_bytes = self
            .inner
            .get_reconfig_signature(epoch)
            .expect("own signature must be stored before collecting");
        let my_sig =
            BLS12381Signature::from_bytes(&my_sig_bytes).expect("stored signature must be valid");
        let mut aggregator = BlsSignatureAggregator::new(
            self.inner.config.hashi_ids().hashi_object_id,
            committee,
            message.clone(),
        );
        aggregator
            .add_signature_from(my_address, my_sig)
            .map_err(|e| anyhow::anyhow!("failed to add own signature: {e}"))?;
        let required_weight = certificate_threshold(committee.total_weight());
        while aggregator.weight() < required_weight {
            if !self.reconfig_target_pending(epoch) {
                return Err(anyhow::anyhow!(
                    "epoch {epoch} no longer pending (or past its Sui epoch window) during \
                     signature collection"
                ));
            }
            let other_members: Vec<_> = committee
                .members()
                .iter()
                .filter(|m| m.validator_address() != my_address)
                .collect();
            let futures = other_members.iter().map(|member| {
                let address = member.validator_address();
                async move {
                    let result = tokio::time::timeout(RPC_TIMEOUT, async {
                        let client = self
                            .inner
                            .onchain_state()
                            .state()
                            .hashi()
                            .committees
                            .client(&address)
                            .ok_or_else(|| anyhow::anyhow!("client not found for {}", address))?;
                        client
                            .get_reconfig_completion_signature(epoch)
                            .await
                            .map_err(|e| anyhow::anyhow!("RPC failed: {e}"))
                    })
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("RPC timed out")));
                    (
                        address,
                        result.and_then(|opt| {
                            opt.ok_or_else(|| anyhow::anyhow!("signature not ready"))
                        }),
                    )
                }
            });
            let results = join_all(futures).await;
            for (address, result) in results {
                if let Ok(sig_bytes) = result {
                    match BLS12381Signature::from_bytes(&sig_bytes) {
                        Ok(sig) => {
                            if let Err(e) = aggregator.add_signature_from(address, sig) {
                                info!("Signature from {} rejected: {e}", address);
                            }
                        }
                        Err(e) => {
                            info!("Invalid signature bytes from {}: {e}", address);
                        }
                    }
                }
            }
            if aggregator.weight() < required_weight {
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
        aggregator
            .finish()
            .map_err(|e| anyhow::anyhow!("failed to finalize certificate: {e}"))
    }
}

/// TODO(IOP-528): Fold into fastcrypto.
pub(crate) fn presig_count(
    total_weight: usize,
    params: Parameters,
    batch_size_per_weight: u16,
) -> usize {
    let consumed = params.t as usize - 1;
    total_weight.saturating_sub(consumed) * batch_size_per_weight as usize
}

pub(crate) async fn verify_fetched_certificates(
    mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
    certs: Vec<CertificateV1>,
    metrics: &Metrics,
) -> Vec<VerifiedCertificateV1> {
    let mgr = Arc::clone(mpc_manager);
    let (verified, rejected) = spawn_blocking(move || {
        let mgr = mgr.read().unwrap();
        let mut verified = Vec::with_capacity(certs.len());
        let mut rejected: Vec<(&'static str, &'static str)> = Vec::new();
        for cert in certs {
            let label = cert.protocol_label();
            match mgr.verify_certificate(cert.clone()) {
                Ok(cert) => verified.push(cert),
                Err(e) => {
                    warn!(
                        "dropping unverifiable TOB certificate from {:?}: {e}",
                        cert.dealer_address()
                    );
                    rejected.push((label, mgr.certificate_rejection_reason(&cert)));
                }
            }
        }
        (verified, rejected)
    })
    .await;
    for (protocol, reason) in rejected {
        metrics
            .mpc_certs_rejected_total
            .with_label_values(&[protocol, reason])
            .inc();
    }
    verified
}

/// Live, boundary sizing and replay admit the same dealers only if they
/// convert the served certs identically.
fn nonce_certificates(
    certs: &VerifiedNonceCerts<move_types::StampedDealerSubmissionV1>,
    epoch: u64,
    batch_index: u32,
) -> VerifiedNonceCerts<CertificateV1> {
    certs.filter_map(|dealer, stamped| {
        let cert = stamped.to_dealer_certificate(epoch).ok()?;
        Some((
            *dealer,
            CertificateV1::NonceGeneration {
                batch_index,
                cert,
                timestamp_ms: stamped.timestamp_ms,
            },
        ))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconfigSubmissionErrorKind {
    NonMoveAbort,
    NonRetryableMoveAbort,
    CommitteeHandoffAlreadySubmitted,
    EndReconfigAlreadyCompleted,
    /// The target can no longer complete: it was aborted, or Sui's epoch
    /// moved past it and only an abort can resolve it now. Give up on it
    /// without claiming success (no prune, no signing setup).
    ReconfigTargetDead,
}

/// How an `abort_reconfig` submission failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbortSubmissionErrorKind {
    /// Nothing to abort any more: another node aborted it first, or it
    /// completed inside its window after all.
    AlreadyResolved,
    /// The chain still considers the pending epoch current.
    StillCurrent,
    Other,
}

fn classify_abort_submission_error(err: &anyhow::Error) -> AbortSubmissionErrorKind {
    let Some(error) = crate::sui_tx_executor::transaction_execution_error(err) else {
        return AbortSubmissionErrorKind::Other;
    };
    classify_abort_execution_error(error)
}

fn classify_abort_execution_error(error: &ExecutionError) -> AbortSubmissionErrorKind {
    if error
        .kind
        .and_then(|kind| ExecutionErrorKind::try_from(kind).ok())
        != Some(ExecutionErrorKind::MoveAbort)
    {
        return AbortSubmissionErrorKind::Other;
    }
    let Some(abort) = error.abort_opt() else {
        return AbortSubmissionErrorKind::Other;
    };
    let abort_constant_name = abort
        .clever_error
        .as_ref()
        .and_then(|clever| clever.constant_name.as_deref());
    match (abort.location().module_opt(), abort_constant_name) {
        (Some("reconfig"), Some(RECONFIG_E_NOT_RECONFIGURING | RECONFIG_E_WRONG_EPOCH)) => {
            AbortSubmissionErrorKind::AlreadyResolved
        }
        (Some("committee_set"), Some(COMMITTEE_SET_E_PENDING_EPOCH_STILL_CURRENT)) => {
            AbortSubmissionErrorKind::StillCurrent
        }
        _ => AbortSubmissionErrorKind::Other,
    }
}

fn classify_reconfig_submission_error(err: &anyhow::Error) -> ReconfigSubmissionErrorKind {
    let Some(error) = crate::sui_tx_executor::transaction_execution_error(err) else {
        return ReconfigSubmissionErrorKind::NonMoveAbort;
    };
    classify_reconfig_execution_error(error)
}

fn classify_reconfig_execution_error(error: &ExecutionError) -> ReconfigSubmissionErrorKind {
    if error
        .kind
        .and_then(|kind| ExecutionErrorKind::try_from(kind).ok())
        != Some(ExecutionErrorKind::MoveAbort)
    {
        return ReconfigSubmissionErrorKind::NonMoveAbort;
    }

    let Some(abort) = error.abort_opt() else {
        return ReconfigSubmissionErrorKind::NonRetryableMoveAbort;
    };
    let location = abort.location();

    let abort_constant_name = abort
        .clever_error
        .as_ref()
        .and_then(|clever| clever.constant_name.as_deref());
    match (
        location.module_opt(),
        location.function_name_opt(),
        abort_constant_name,
    ) {
        (Some("committee_set"), Some("set_pending_committee_handoff_cert"), _) => {
            ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted
        }
        // `ENotReconfiguring` and the window check live in a private helper
        // shared by `submit_committee_handoff` and `end_reconfig`, while the
        // entries raise the already-completed and wrong-epoch aborts
        // themselves, so the location varies; the constant carries the
        // meaning.
        (Some("reconfig"), _, Some(RECONFIG_E_ALREADY_COMPLETED)) => {
            ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted
        }
        (
            Some("reconfig"),
            _,
            Some(RECONFIG_E_NOT_RECONFIGURING | RECONFIG_E_WINDOW_CLOSED | RECONFIG_E_WRONG_EPOCH),
        ) => ReconfigSubmissionErrorKind::ReconfigTargetDead,
        _ => ReconfigSubmissionErrorKind::NonRetryableMoveAbort,
    }
}

#[cfg(test)]
mod presig_count_tests {
    use super::Parameters;
    use super::presig_count;

    #[test]
    fn matches_height_times_batch_width() {
        let params = Parameters { t: 3, f: 1 };
        // height = W - (t - 1)
        assert_eq!(presig_count(5, params, 2), (5 - 2) * 2);
        assert_eq!(presig_count(3, params, 7), 7);
        assert_eq!(presig_count(10, params, 4), (10 - 2) * 4);
    }

    #[test]
    fn saturates_below_floor_without_underflow() {
        let params = Parameters { t: 3, f: 1 };
        assert_eq!(presig_count(1, params, 2), 0);
        assert_eq!(presig_count(0, params, 5), 0);
    }

    #[test]
    fn matches_fastcrypto_presignature_count() {
        use fastcrypto::groups::GroupElement;
        use fastcrypto::groups::Scalar;
        use fastcrypto_tbls::threshold_schnorr::S;
        use fastcrypto_tbls::threshold_schnorr::batch_avss;
        use fastcrypto_tbls::types::ShareIndex;

        use super::G;
        use super::Presignatures;
        use super::USE_LEGACY_PRESIG_DERIVATION;

        let mut rng = rand::thread_rng();
        let params = Parameters { t: 3, f: 1 };
        let batch_size_per_weight = 2u16;
        let total_weight = 5usize;
        let index = ShareIndex::new(1).unwrap();
        let outputs: Vec<batch_avss::ReceiverOutput> = (0..total_weight)
            .map(|_| batch_avss::ReceiverOutput {
                my_shares: batch_avss::SharesForNode {
                    shares: vec![batch_avss::ShareBatch {
                        index,
                        batch: (0..batch_size_per_weight)
                            .map(|_| S::rand(&mut rng))
                            .collect(),
                        blinding_share: S::zero(),
                    }],
                },
                public_keys: (0..batch_size_per_weight)
                    .map(|_| G::generator() * S::rand(&mut rng))
                    .collect(),
            })
            .collect();

        let expected = presig_count(total_weight, params, batch_size_per_weight);
        assert_eq!(
            Presignatures::new(
                outputs,
                batch_size_per_weight,
                params,
                USE_LEGACY_PRESIG_DERIVATION
            )
            .unwrap()
            .len(),
            expected
        );
        assert_ne!(
            expected,
            (total_weight - params.f as usize) * batch_size_per_weight as usize
        );
    }
}

pub(crate) fn build_pruning_references(
    committee_set: &crate::onchain::types::CommitteeSet,
    target_epoch: u64,
) -> crate::db::PruningReferences {
    let mut referenced = crate::db::PruningReferences::default();
    let previous = committee_set.previous_committee_for_target(target_epoch);
    let preceding = committee_set.committees().range(..target_epoch).next_back();
    for committee in committee_set
        .committees()
        .get(&target_epoch)
        .into_iter()
        .chain(previous.map(|(_, committee)| committee))
        .chain(preceding.map(|(_, committee)| committee))
    {
        for member in committee.members() {
            referenced.add_member_pubkeys(member.encryption_public_key(), member.public_key());
        }
    }
    for (epoch, _) in previous.into_iter().chain(preceding.map(|(e, c)| (*e, c))) {
        referenced.add_committee_epoch(epoch);
    }
    for member_info in committee_set.members().values() {
        referenced.add_pending_registration(
            member_info.next_epoch_encryption_public_key(),
            member_info.next_epoch_public_key(),
        );
    }
    referenced
}

#[cfg(test)]
mod repair_gate_tests {
    use super::repair_rate_limited;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn only_the_same_epoch_and_batch_before_the_deadline_is_limited() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(900);
        assert!(repair_rate_limited(Some((7, 3, deadline)), 7, 3, now));
        assert!(!repair_rate_limited(Some((7, 3, now)), 7, 3, now));
        assert!(!repair_rate_limited(Some((7, 4, deadline)), 7, 3, now));
        assert!(!repair_rate_limited(Some((8, 3, deadline)), 7, 3, now));
        assert!(!repair_rate_limited(None, 7, 3, now));
    }
}

#[cfg(test)]
mod walk_step_tests {
    use super::WalkStep;
    use super::walk_step;

    #[test]
    fn missing_only_once_the_cursor_has_drawn_from_the_batch() {
        assert_eq!(walk_step(None, 0, 400), WalkStep::Missing);
        assert_eq!(walk_step(None, 300, 400), WalkStep::Missing);
        assert_eq!(walk_step(None, 400, 400), WalkStep::Stop);
        assert_eq!(walk_step(None, 500, 400), WalkStep::Stop);
        assert_eq!(walk_step(None, 0, 0), WalkStep::Stop);
    }

    #[test]
    fn a_sized_batch_is_the_last_one_when_it_holds_the_cursor() {
        assert_eq!(walk_step(Some(100), 0, 400), WalkStep::Continue(100));
        assert_eq!(walk_step(Some(100), 300, 400), WalkStep::Continue(100));
        assert_eq!(walk_step(Some(200), 300, 400), WalkStep::Last(200));
        assert_eq!(walk_step(Some(1080), 0, 400), WalkStep::Last(1080));
    }
}

/// Whether `target_epoch` is still worth acting on after the protocol ran:
/// pending, or already the current epoch (another node's `end_reconfig`
/// activated it). "Current" needs a committee to exist for it: before
/// genesis the epoch is 0 with no committee, and the genesis committee on a
/// fresh network is pinned to Sui epoch 0 too, so an aborted genesis DKG
/// would otherwise look activated.
fn reconfig_target_live(
    pending: Option<u64>,
    current_epoch: u64,
    current_committee_exists: bool,
    target_epoch: u64,
) -> bool {
    pending == Some(target_epoch) || (current_epoch == target_epoch && current_committee_exists)
}

/// `start_reconfig` pins the pending committee to Sui's epoch, and the chain
/// refuses to complete it once Sui's epoch has moved on. `latest_sui_epoch`
/// is the watcher's checkpoint view, which can lag the chain but never lead
/// it, so a closed window here is closed on chain too.
fn reconfig_window_closed(latest_sui_epoch: u64, target_epoch: u64) -> bool {
    latest_sui_epoch > target_epoch
}

/// Whether the `MpcManager` must be rebuilt for `current_epoch`: it is on
/// some other epoch (or missing) and no reconfiguration is pending. While one
/// is pending the manager belongs to its target, which `handle_reconfig`
/// owns and replaces itself.
fn manager_needs_restore(pinned: Option<u64>, current_epoch: u64, pending: Option<u64>) -> bool {
    pending.is_none() && pinned != Some(current_epoch)
}

/// Pending on chain and inside its Sui epoch window.
fn reconfig_target_pending(pending: Option<u64>, latest_sui_epoch: u64, target_epoch: u64) -> bool {
    pending == Some(target_epoch) && !reconfig_window_closed(latest_sui_epoch, target_epoch)
}

#[cfg(test)]
mod pruning_reference_tests {
    use super::build_pruning_references;
    use crate::db::Database;
    use crate::onchain::types::CommitteeSet;
    use crate::onchain::types::MemberInfo;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use std::collections::BTreeMap;
    use sui_sdk_types::Address;

    #[test]
    fn previous_committee_survives_a_gap_while_a_change_is_pending() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();
        let address = Address::new([1u8; 32]);
        let mut committees = BTreeMap::new();
        for epoch in [500u64, 520] {
            let enc = EncryptionPrivateKey::new(&mut rand::thread_rng());
            let enc_pub = enc.public_key();
            let bls = Bls12381PrivateKey::generate(&mut rand::thread_rng());
            db.store_encryption_key(epoch, &enc).unwrap();
            db.store_signing_key(epoch, &bls).unwrap();
            committees.insert(
                epoch,
                Committee::new(
                    vec![CommitteeMember::new(address, bls.public_key(), enc_pub, 1)],
                    epoch,
                    0,
                    5_000,
                ),
            );
        }
        let mut set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        set.set_epoch(520)
            .set_pending_epoch_change(Some(521))
            .set_committees(committees)
            .set_members(BTreeMap::<Address, MemberInfo>::new());
        db.prune_messages_below(520, &build_pruning_references(&set, 520))
            .unwrap();
        assert!(
            db.get_encryption_key(500).unwrap().is_some(),
            "the real predecessor must stay pinned even when `previous_committee_for_target` \
             names the target itself"
        );
    }

    #[test]
    fn committees_older_than_the_predecessor_stop_being_pinned() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();
        let address = Address::new([1u8; 32]);

        let mut committees = BTreeMap::new();
        for epoch in [10u64, 20, 30, 40] {
            let enc = EncryptionPrivateKey::new(&mut rand::thread_rng());
            let enc_pub = enc.public_key();
            let bls = Bls12381PrivateKey::generate(&mut rand::thread_rng());
            db.store_encryption_key(epoch, &enc).unwrap();
            db.store_signing_key(epoch, &bls).unwrap();
            committees.insert(
                epoch,
                Committee::new(
                    vec![CommitteeMember::new(address, bls.public_key(), enc_pub, 1)],
                    epoch,
                    0,
                    5_000,
                ),
            );
        }

        let mut set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        set.set_epoch(30)
            .set_pending_epoch_change(None)
            .set_committees(committees)
            .set_members(BTreeMap::<Address, MemberInfo>::new());

        db.prune_messages_below(40, &build_pruning_references(&set, 40))
            .unwrap();

        for epoch in [40u64, 30] {
            assert!(
                db.get_encryption_key(epoch).unwrap().is_some(),
                "epoch {epoch} is the target or its predecessor and must stay pinned"
            );
        }
        for epoch in [10u64, 20] {
            assert!(
                db.get_encryption_key(epoch).unwrap().is_none(),
                "epoch {epoch} is older than the predecessor and must no longer be pinned"
            );
            assert!(
                db.get_signing_key(epoch).unwrap().is_none(),
                "epoch {epoch} signing key rides the same reference set"
            );
        }
    }
}

#[cfg(test)]
mod reconfig_submission_classifier_tests {
    use sui_rpc::proto::sui::rpc::v2::CleverError;
    use sui_rpc::proto::sui::rpc::v2::ExecutionError;
    use sui_rpc::proto::sui::rpc::v2::MoveAbort;
    use sui_rpc::proto::sui::rpc::v2::MoveLocation;
    use sui_rpc::proto::sui::rpc::v2::execution_error::ErrorDetails;
    use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;

    use super::AbortSubmissionErrorKind;
    use super::ReconfigSubmissionErrorKind;
    use super::classify_abort_execution_error;
    use super::classify_reconfig_execution_error;

    /// A Move abort raised in `module::function`, with the clever-error
    /// constant name the fullnode attaches for `#[error]` constants.
    fn move_abort(module: &str, function: &str, constant: Option<&str>) -> ExecutionError {
        let mut location = MoveLocation::default();
        location.module = Some(module.to_string());
        location.function_name = Some(function.to_string());
        let mut abort = MoveAbort::default();
        abort.abort_code = Some(1);
        abort.location = Some(location);
        abort.clever_error = constant.map(|name| {
            let mut clever = CleverError::default();
            clever.constant_name = Some(name.to_string());
            clever
        });
        let mut error = ExecutionError::default();
        error.kind = Some(ExecutionErrorKind::MoveAbort as i32);
        error.error_details = Some(ErrorDetails::Abort(abort));
        error
    }

    #[test]
    fn a_won_end_reconfig_race_is_reported_as_completed() {
        // Each completion entry raises this itself.
        for function in ["end_reconfig", "submit_committee_handoff"] {
            let error = move_abort("reconfig", function, Some("EReconfigAlreadyCompleted"));
            assert_eq!(
                classify_reconfig_execution_error(&error),
                ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted,
                "{function}"
            );
        }
    }

    #[test]
    fn an_aborted_or_overrun_target_is_dead_not_completed() {
        // The first two are raised by the private helper both entries share;
        // each entry raises the wrong-epoch abort itself.
        for (function, constant) in [
            ("pending_epoch_in_window", "ENotReconfiguring"),
            ("pending_epoch_in_window", "EReconfigWindowClosed"),
            ("end_reconfig", "EWrongReconfigEpoch"),
            ("submit_committee_handoff", "EWrongReconfigEpoch"),
        ] {
            let error = move_abort("reconfig", function, Some(constant));
            assert_eq!(
                classify_reconfig_execution_error(&error),
                ReconfigSubmissionErrorKind::ReconfigTargetDead,
                "{constant}"
            );
        }
    }

    #[test]
    fn other_failures_keep_their_existing_classification() {
        let handoff = move_abort("committee_set", "set_pending_committee_handoff_cert", None);
        assert_eq!(
            classify_reconfig_execution_error(&handoff),
            ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted
        );
        let other = move_abort(
            "reconfig",
            "submit_committee_handoff",
            Some("EInitialReconfig"),
        );
        assert_eq!(
            classify_reconfig_execution_error(&other),
            ReconfigSubmissionErrorKind::NonRetryableMoveAbort
        );
        let mut not_an_abort = ExecutionError::default();
        not_an_abort.kind = Some(ExecutionErrorKind::InsufficientGas as i32);
        assert_eq!(
            classify_reconfig_execution_error(&not_an_abort),
            ReconfigSubmissionErrorKind::NonMoveAbort
        );
    }

    #[test]
    fn a_lost_abort_race_is_already_resolved() {
        for constant in ["ENotReconfiguring", "EWrongReconfigEpoch"] {
            let error = move_abort("reconfig", "abort_reconfig", Some(constant));
            assert_eq!(
                classify_abort_execution_error(&error),
                AbortSubmissionErrorKind::AlreadyResolved,
                "{constant}"
            );
        }
    }

    #[test]
    fn an_abort_inside_the_window_is_still_current() {
        let error = move_abort(
            "committee_set",
            "abort_reconfig",
            Some("EPendingEpochStillCurrent"),
        );
        assert_eq!(
            classify_abort_execution_error(&error),
            AbortSubmissionErrorKind::StillCurrent
        );
        let other = move_abort(
            "versioning",
            "assert_version_enabled",
            Some("EVersionDisabled"),
        );
        assert_eq!(
            classify_abort_execution_error(&other),
            AbortSubmissionErrorKind::Other
        );
    }
}

#[cfg(test)]
mod reconfig_target_tests {
    use super::reconfig_target_live;
    use super::reconfig_target_pending;
    use super::reconfig_window_closed;

    #[test]
    fn live_while_pending_or_current_only() {
        assert!(reconfig_target_live(Some(6), 5, true, 6));
        assert!(reconfig_target_live(None, 6, true, 6));
        assert!(!reconfig_target_live(None, 5, true, 6));
        assert!(!reconfig_target_live(Some(7), 5, true, 6));
        assert!(!reconfig_target_live(None, 7, true, 6));
    }

    #[test]
    fn an_aborted_genesis_at_sui_epoch_zero_is_not_live() {
        // Genesis pending: epoch 0 with the pending epoch-0 committee already
        // inserted by start_reconfig, so the current committee exists.
        assert!(reconfig_target_live(Some(0), 0, true, 0));
        // Aborted genesis: the epoch-0 committee was removed, back to
        // pre-genesis.
        assert!(!reconfig_target_live(None, 0, false, 0));
        // Activated genesis: the committee for epoch 0 now exists.
        assert!(reconfig_target_live(None, 0, true, 0));
    }

    #[test]
    fn the_window_closes_once_a_later_sui_epoch_is_seen() {
        assert!(!reconfig_window_closed(6, 6));
        assert!(reconfig_window_closed(7, 6));
        // A lagging checkpoint view never closes the window early.
        assert!(!reconfig_window_closed(5, 6));
        assert!(!reconfig_window_closed(0, 6));
    }

    #[test]
    fn pending_means_pending_and_inside_the_window() {
        assert!(reconfig_target_pending(Some(6), 6, 6));
        assert!(reconfig_target_pending(Some(6), 5, 6));
        assert!(!reconfig_target_pending(Some(6), 7, 6));
        assert!(!reconfig_target_pending(None, 6, 6));
        assert!(!reconfig_target_pending(Some(7), 6, 6));
    }
}

#[cfg(test)]
mod manager_restore_tests {
    use super::manager_needs_restore;

    #[test]
    fn a_manager_left_on_a_dead_target_is_restored() {
        // The rotation to 7 was aborted; the node still serves epoch 6.
        assert!(manager_needs_restore(Some(7), 6, None));
        // A missing manager is just as unusable for refill.
        assert!(manager_needs_restore(None, 6, None));
    }

    #[test]
    fn a_manager_on_the_current_epoch_is_left_alone() {
        assert!(!manager_needs_restore(Some(6), 6, None));
    }

    #[test]
    fn nothing_is_touched_while_a_reconfiguration_is_pending() {
        // The target's manager belongs to handle_reconfig.
        assert!(!manager_needs_restore(Some(7), 6, Some(7)));
        // Even one on a stale epoch waits: handle_reconfig replaces it.
        assert!(!manager_needs_restore(Some(5), 6, Some(7)));
    }
}
