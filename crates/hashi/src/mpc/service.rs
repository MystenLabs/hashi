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
use std::collections::HashSet;
use sui_futures::service::Service;
use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;
use tokio::sync::watch;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::communication::PrefetchedTobChannel;
use crate::communication::SuiTobChannel;
use crate::communication::fetch_certificates;
use crate::communication::fetch_key_generation_certificates;
use crate::constants::PRESIG_REFILL_DIVISOR;
use crate::metrics::MPC_LABEL_DKG;
use crate::metrics::MPC_LABEL_KEY_ROTATION;
use crate::metrics::MPC_LABEL_NONCE_GENERATION;
use crate::mpc::MpcManager;
use crate::mpc::MpcOutput;
use crate::mpc::SigningManager;
use crate::mpc::rpc::RpcP2PChannel;
use crate::mpc::types::CertificateV1;
use crate::mpc::types::MpcOutputRecoveryOutcome;
use crate::mpc::types::NonceGenerationProtocol;
use crate::mpc::types::ProtocolType;
use crate::onchain::Notification;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types;
use hashi_types::move_types::ReconfigCompletionMessage;

const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROTOCOL_ATTEMPTS: u32 = 3;
const START_RECONFIG_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MPC_RECONFIG_TIMEOUT: Duration = Duration::from_secs(600);
const RECONCILE_TICK: Duration = Duration::from_secs(15);
/// Move `hashi::reconfig::ENotReconfiguring`, matched by its clever-error
/// constant name (the `#[error]` abort code encodes a source line, so the
/// numeric code is not stable).
const RECONFIG_E_NOT_RECONFIGURING: &str = "ENotReconfiguring";

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
    backup_handle: crate::backup::BackupHandle,
    replacement_keys_target_epoch: Mutex<Option<u64>>,
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
        if let Some(epoch) = pending {
            info!("Entering handle_reconfig for epoch {epoch}");
            self.handle_reconfig(epoch).await;
        } else if self.is_awaiting_genesis() {
            // No committee has been formed yet (epoch 0, no committee for epoch 0).
            // Wait for enough validators to register then trigger genesis reconfig.
            info!("No initial committee yet; waiting for enough validators to register...");
            self.try_submit_genesis_reconfig().await;
        } else if self.inner.is_in_current_committee() {
            loop {
                if let Some(epoch) = self.get_pending_epoch_change() {
                    self.handle_reconfig(epoch).await;
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
        let mut notifications = self.inner.onchain_state().subscribe();
        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();
        let mut reconcile_tick = tokio::time::interval(RECONCILE_TICK);
        reconcile_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // Check for pending reconfig before blocking on `recv()`.
            if let Some(epoch) = self.get_pending_epoch_change() {
                self.handle_reconfig(epoch).await;
                continue;
            }
            tokio::select! {
                notification = notifications.recv() => {
                    match notification {
                        Ok(notification) => match notification {
                            Notification::StartReconfig(epoch) => {
                                self.handle_reconfig(epoch).await;
                            }
                            Notification::SuiEpochChanged(sui_epoch) => {
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
                    for attempt in 1..=MAX_PROTOCOL_ATTEMPTS {
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
            }
        }
    }

    async fn sleep_if_still_pending(&self, epoch: u64) {
        if self.get_pending_epoch_change() == Some(epoch) {
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }

    fn get_pending_epoch_change(&self) -> Option<u64> {
        self.inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .pending_epoch_change()
    }

    /// Returns true if no committee has ever been formed (genesis state).
    fn is_awaiting_genesis(&self) -> bool {
        let state = self.inner.onchain_state().state();
        let committees = &state.hashi().committees;
        committees.epoch() == 0 && committees.current_committee().is_none()
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
        let certs = fetch_key_generation_certificates(&onchain_state, epoch)
            .await
            .map_err(|e| {
                anyhow::anyhow!("failed to fetch reconfig certs for epoch {epoch}: {e}")
            })?;
        let is_key_rotation = matches!(certs.first(), Some((_, CertificateV1::Rotation(_))));
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
            fetch_certificates(&onchain_state, epoch, None, move_types::ProtocolType::Dkg)
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch DKG certs for epoch {epoch}: {e}"))?
                .into_iter()
                .map(|(_, cert)| cert)
                .collect();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized for DKG recovery"))?;
        match MpcManager::reconstruct_current_dkg_output(&mpc_manager, &certs, onchain_mpc_key) {
            MpcOutputRecoveryOutcome::Recovered(output) => {
                info!(
                    "recover_current_dkg: recovered current epoch {epoch} from local DKG \
                     messages (no peers)"
                );
                Ok(output)
            }
            MpcOutputRecoveryOutcome::NotApplicable => self.run_dkg(epoch).await,
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
        let current_certs: Vec<CertificateV1> = fetch_certificates(
            &onchain_state,
            epoch,
            None,
            move_types::ProtocolType::KeyRotation,
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch rotation certs for epoch {epoch}: {e}"))?
        .into_iter()
        .map(|(_, cert)| cert)
        .collect();
        let previous_certs: Vec<CertificateV1> =
            fetch_key_generation_certificates(&onchain_state, previous_epoch)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to fetch certs for previous epoch {previous_epoch}: {e}"
                    )
                })?
                .into_iter()
                .map(|(_, cert)| cert)
                .collect();
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
            MpcOutputRecoveryOutcome::NotApplicable => self.run_key_rotation(epoch).await,
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
    async fn run_dkg(&self, target_epoch: u64) -> anyhow::Result<MpcOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .expect("MpcManager must be set before run_dkg");
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), target_epoch, MPC_LABEL_DKG);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            None,
            move_types::ProtocolType::Dkg,
            signer,
        );
        let output = MpcManager::run_dkg(
            &mpc_manager,
            &p2p_channel,
            &mut tob_channel,
            &self.inner.metrics,
        )
        .await
        .map_err(|e| anyhow::anyhow!("DKG failed: {e}"))?;
        Ok(output)
    }

    async fn generate_presignatures(
        &self,
        epoch: u64,
        batch_index: u32,
    ) -> anyhow::Result<(Committee, Presignatures)> {
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
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel =
            RpcP2PChannel::new(onchain_state.clone(), epoch, MPC_LABEL_NONCE_GENERATION);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            Some(batch_index),
            move_types::ProtocolType::NonceGeneration,
            signer,
        );
        let metrics = &self.inner.metrics;
        let _timer = metrics
            .mpc_total_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let nonce_result = MpcManager::run_nonce_generation(
            &mpc_manager,
            batch_index,
            &p2p_channel,
            &mut tob_channel,
            metrics,
        )
        .await;
        drop(_timer);
        let nonce_outputs =
            nonce_result.map_err(|e| anyhow::anyhow!("Nonce generation failed: {e}"))?;
        let (batch_size_per_weight, params, use_legacy) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                Parameters {
                    t: mgr.mpc_config.threshold,
                    f: mgr.mpc_config.max_faulty,
                },
                mgr.mpc_config.presignature_derivation_version.use_legacy(),
            )
        };
        let _timer = metrics
            .mpc_presig_conversion_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let presignatures =
            Presignatures::new(nonce_outputs, batch_size_per_weight, params, use_legacy)
                .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        drop(_timer);
        Ok((committee, presignatures))
    }

    async fn prepare_signing(&self, epoch: u64, output: &MpcOutput) -> anyhow::Result<()> {
        let (committee, presignatures) = self.generate_presignatures(epoch, 0).await?;
        let address = self.inner.config.validator_address()?;
        let signing_manager = SigningManager::new(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            presignatures,
            0, // batch_index
            0, // batch_start_index
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
        );
        self.inner.store_signing_manager(signing_manager);
        Ok(())
    }

    async fn recover_presigning_state(&self, output: &MpcOutput) -> anyhow::Result<()> {
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
            for txn in hashi.withdrawal_queue.withdrawal_txns().values() {
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
        let (batch_size_per_weight, params, use_legacy, protocol, floor) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                Parameters {
                    t: mgr.mpc_config.threshold,
                    f: mgr.mpc_config.max_faulty,
                },
                mgr.mpc_config.presignature_derivation_version.use_legacy(),
                mgr.mpc_config.nonce_generation_protocol,
                mgr.required_nonce_weight(),
            )
        };
        let mut boundaries: Vec<(u32, u64, usize)> = Vec::new();
        let mut batch_start = 0u64;
        let mut batch_index = 0u32;
        loop {
            let size = self
                .nonce_batch_size_from_certs(
                    &mpc_manager,
                    epoch,
                    batch_index,
                    protocol,
                    params,
                    use_legacy,
                    batch_size_per_weight,
                    floor,
                )
                .await?;
            let Some(size) = size else {
                anyhow::ensure!(
                    batch_start >= num_consumed,
                    "nonce batch {batch_index} at start {batch_start} read sub-floor below cursor \
                     {num_consumed} — partial cert fetch",
                );
                break;
            };
            boundaries.push((batch_index, batch_start, size));
            if num_consumed < batch_start + size as u64 {
                break;
            }
            batch_start += size as u64;
            batch_index += 1;
        }
        anyhow::ensure!(
            !boundaries.is_empty(),
            "no certified nonce batches to recover for epoch {epoch} at cursor {num_consumed}",
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
        let signing_manager = SigningManager::new_recovered(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            retained,
            num_consumed,
            &pending,
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
        )?;
        self.inner.store_signing_manager(signing_manager);
        info!(
            "Recovered presigning state: {retained_count} of {} batch(es) retained from \
             first_pending_batch={first_pending}, recovered_end={recovered_end}, \
             num_consumed_presigs={num_consumed}, pending={}",
            boundaries.len(),
            pending.len(),
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn nonce_batch_size_from_certs(
        &self,
        mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
        epoch: u64,
        batch_index: u32,
        protocol: NonceGenerationProtocol,
        params: Parameters,
        use_legacy: bool,
        batch_size_per_weight: u16,
        floor: u32,
    ) -> anyhow::Result<Option<usize>> {
        let onchain_state = self.inner.onchain_state().clone();
        let weight = match protocol {
            NonceGenerationProtocol::Vanilla => {
                let Some(certs) = onchain_state
                    .fetch_certs(
                        epoch,
                        Some(batch_index),
                        move_types::ProtocolType::NonceGeneration,
                    )
                    .await?
                else {
                    return Ok(None);
                };
                let certs = MpcManager::verified_nonce_certs(mpc_manager, epoch, certs).await;
                certified_nonce_weight(mpc_manager, &certs)
            }
            NonceGenerationProtocol::Avid => {
                let certs = fetch_certificates(
                    &onchain_state,
                    epoch,
                    Some(batch_index),
                    move_types::ProtocolType::NonceGeneration,
                )
                .await?;
                if certs.is_empty() {
                    return Ok(None);
                }
                let certs = MpcManager::verified_nonce_certs(mpc_manager, epoch, certs).await;
                certified_nonce_weight(mpc_manager, &certs)
            }
        };
        if weight < floor {
            return Ok(None);
        }
        Ok(Some(presig_count(
            weight as usize,
            params,
            use_legacy,
            batch_size_per_weight,
        )))
    }

    async fn sync_if_stale(&self) {
        if self.is_awaiting_genesis() || !self.inner.is_in_current_committee() {
            return;
        }
        let epoch = self.inner.onchain_state().epoch();
        if self.inner.signing_manager_for(epoch).is_some() {
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
                error!("sync_if_stale: recover_mpc_state failed for epoch {epoch}: {e}");
                self.re_register_keys_if_lost().await;
                return;
            }
        };
        match self.recover_presigning_state(&output).await {
            Ok(()) => {
                info!("sync_if_stale: recovered epoch {epoch} via certs path");
            }
            Err(certs_err) => {
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
        let target = match self.inner.next_reconfig_epoch().await {
            Ok(target) => target,
            Err(e) => {
                warn!("cannot determine next reconfig epoch for key re-registration: {e}");
                return;
            }
        };
        let target = {
            let state = self.inner.onchain_state().state();
            let committees = &state.hashi().committees;
            match committees.pending_epoch_change() {
                Some(p)
                    if p == target
                        && committees
                            .committees()
                            .get(&p)
                            .is_some_and(|c| self.inner.committee_key_lost(c, me)) =>
                {
                    p + 1
                }
                _ => target,
            }
        };
        if *self.replacement_keys_target_epoch.lock().unwrap() == Some(target) {
            return;
        }
        warn!(
            "no DB encryption or signing key matches the current committee record; \
             registering fresh keys for epoch {target} so the node rejoins at that reconfig"
        );
        match self.inner.prepare_and_register_keys(target).await {
            Ok(()) => {
                info!("replacement keys in place for epoch {target}");
                *self.replacement_keys_target_epoch.lock().unwrap() = Some(target);
            }
            Err(e) => {
                warn!("failed to register replacement keys for epoch {target}: {e}; will retry");
            }
        }
    }

    async fn refill_presignatures(&self, batch_index: u32) -> anyhow::Result<()> {
        let epoch = self.inner.onchain_state().epoch();
        let signing_manager = self
            .inner
            .signing_manager_for(epoch)
            .ok_or_else(|| anyhow::anyhow!("SigningManager not available for epoch {epoch}"))?;
        let (_, presignatures) = self.generate_presignatures(epoch, batch_index).await?;
        if self.inner.onchain_state().epoch() != epoch {
            return Err(anyhow::anyhow!("Epoch changed during presignature refill"));
        }
        signing_manager.set_next_batch(presignatures);
        Ok(())
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
        let (protocol, use_legacy, floor) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.mpc_config.nonce_generation_protocol,
                mgr.mpc_config.presignature_derivation_version.use_legacy(),
                mgr.required_nonce_weight(),
            )
        };
        let expected_from = |weight: u32| -> anyhow::Result<usize> {
            anyhow::ensure!(
                weight >= floor,
                "nonce batch {batch_index} for epoch {epoch} refetched below floor \
                 ({weight} < {floor}); certificate set shrank during recovery",
            );
            Ok(presig_count(
                weight as usize,
                params,
                use_legacy,
                batch_size_per_weight,
            ))
        };
        let (outputs, expected_size) = match protocol {
            NonceGenerationProtocol::Vanilla => {
                let certs = onchain_state
                    .fetch_certs(
                        epoch,
                        Some(batch_index),
                        move_types::ProtocolType::NonceGeneration,
                    )
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "No nonce gen certificates on TOB for epoch {epoch} batch {batch_index}"
                        )
                    })?;
                let certs = MpcManager::verified_nonce_certs(mpc_manager, epoch, certs).await;
                let expected_size = expected_from(certified_nonce_weight(mpc_manager, &certs))?;
                let outputs = MpcManager::reconstruct_presignatures_with_complaint_recovery(
                    mpc_manager,
                    epoch,
                    batch_index,
                    &certs,
                    &p2p_channel,
                )
                .await?;
                (outputs, Some(expected_size))
            }
            NonceGenerationProtocol::Avid => {
                let certs = fetch_certificates(
                    &onchain_state,
                    epoch,
                    Some(batch_index),
                    move_types::ProtocolType::NonceGeneration,
                )
                .await?;
                if certs.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No nonce gen certificates on TOB for epoch {epoch} batch {batch_index}"
                    ));
                }
                let certs = MpcManager::verified_nonce_certs(mpc_manager, epoch, certs).await;
                let expected_size = expected_from(certified_nonce_weight(mpc_manager, &certs))?;
                let mut prefetched = PrefetchedTobChannel::new(certs);
                let outputs = MpcManager::run_nonce_generation(
                    mpc_manager,
                    batch_index,
                    &p2p_channel,
                    &mut prefetched,
                    &self.inner.metrics,
                )
                .await
                .map_err(|e| anyhow::anyhow!("AVID nonce recovery from certs failed: {e}"))?;
                (outputs, Some(expected_size))
            }
        };
        if outputs.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid nonce outputs after reconstruction for epoch {epoch} batch {batch_index}"
            ));
        }
        let presignatures = Presignatures::new(outputs, batch_size_per_weight, params, use_legacy)
            .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        if let Some(expected) = expected_size {
            anyhow::ensure!(
                presignatures.len() == expected,
                "Reconstructed nonce batch {batch_index} for epoch {epoch} has {} presigs but \
                 certificates imply {expected}; message-incomplete reconstruction",
                presignatures.len(),
            );
        }
        Ok(presignatures)
    }

    async fn try_submit_start_reconfig(&self, sui_epoch: u64) {
        if self.get_pending_epoch_change().is_some() {
            return;
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
                    warn!("start_reconfig attempt {attempt}/{MAX_PROTOCOL_ATTEMPTS} failed: {e}");
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
        if self.get_pending_epoch_change() != Some(target_epoch) {
            info!(
                "handle_reconfig: epoch {target_epoch} no longer pending at entry, aborting before start",
            );
            return;
        }
        // A pending epoch change implies the launch (finish_publish) has
        // happened, so the on-chain bitcoin_chain_id exists now even if this
        // node booted pre-launch and the startup check was skipped. Refuse
        // to participate on mismatch — signing for the wrong Bitcoin network
        // must not happen; the caller re-enters while the epoch change is
        // pending, surfacing the error every RETRY_INTERVAL until an
        // operator fixes the config.
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
            if self.get_pending_epoch_change() != Some(target_epoch) {
                info!("handle_reconfig: epoch {target_epoch} no longer pending, aborting",);
                return;
            }
            let needs_fresh_manager = match self.inner.mpc_manager() {
                None => true,
                Some(mgr) => mgr.read().unwrap().mpc_config.epoch != target_epoch,
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
                tokio::time::timeout(MPC_RECONFIG_TIMEOUT, self.run_dkg(target_epoch))
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!(
                            "DKG timed out after {MPC_RECONFIG_TIMEOUT:?}"
                        ))
                    })
            } else {
                tokio::time::timeout(MPC_RECONFIG_TIMEOUT, self.run_key_rotation(target_epoch))
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!(
                            "Key rotation timed out after {MPC_RECONFIG_TIMEOUT:?}"
                        ))
                    })
            };
            drop(_timer);
            match result {
                Ok(output) => break output,
                Err(e) => {
                    error!(
                        "MPC protocol for epoch {} failed: {e}, retrying...",
                        target_epoch
                    );
                    self.sleep_if_still_pending(target_epoch).await;
                }
            }
        };
        let _ = self.key_ready_tx.send(Some(output.public_key));
        info!("MPC key ready for epoch {target_epoch}, submitting end_reconfig");
        let _end_reconfig_timer = metrics
            .mpc_end_reconfig_duration_seconds
            .with_label_values(&[protocol_label])
            .start_timer();
        loop {
            if self.get_pending_epoch_change() != Some(target_epoch) {
                break;
            }
            match self.submit_end_reconfig(target_epoch, &output).await {
                Ok(()) => break,
                Err(e) => match classify_reconfig_submission_error(&e) {
                    ReconfigSubmissionErrorKind::NonMoveAbort => {
                        warn!(
                            "submit_end_reconfig for epoch {} failed: {e}, retrying...",
                            target_epoch
                        );
                        self.sleep_if_still_pending(target_epoch).await;
                    }
                    ReconfigSubmissionErrorKind::NonRetryableMoveAbort
                    | ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted
                    | ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted => {
                        let msg = format!(
                            "submit_end_reconfig for epoch {target_epoch} failed with non-retryable error: {e}"
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
        self.backup_handle.backup_after_epoch_change(target_epoch);
        info!("end_reconfig complete for epoch {target_epoch}, running prepare_signing");
        let pruning_references = {
            let state = self.inner.onchain_state().state();
            let committee_set = &state.hashi().committees;
            let mut referenced = crate::db::PruningReferences::default();
            for committee in committee_set.committees().values() {
                for member in committee.members() {
                    referenced
                        .add_member_pubkeys(member.encryption_public_key(), member.public_key());
                }
            }
            for member_info in committee_set.members().values() {
                referenced.add_pending_registration(
                    member_info.next_epoch_encryption_public_key(),
                    member_info.next_epoch_public_key(),
                );
            }
            if let Some((prev_epoch, _)) = committee_set.previous_committee_for_target(target_epoch)
            {
                referenced.add_committee_epoch(prev_epoch);
            }
            referenced
        };
        if let Err(e) = self
            .inner
            .db
            .prune_messages_below(target_epoch, &pruning_references)
        {
            error!("Failed to prune old MPC messages below epoch {target_epoch}: {e}");
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
    async fn run_key_rotation(&self, target_epoch: u64) -> anyhow::Result<MpcOutput> {
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
        let previous_certs = fetch_key_generation_certificates(&onchain_state, previous_epoch)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch previous certificates: {e}"))?;
        let previous_certs: Vec<CertificateV1> =
            previous_certs.into_iter().map(|(_, cert)| cert).collect();
        info!(
            "run_key_rotation: fetched {} certs for previous_epoch={previous_epoch}",
            previous_certs.len(),
        );
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel =
            RpcP2PChannel::new(onchain_state.clone(), target_epoch, MPC_LABEL_KEY_ROTATION);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            None,
            move_types::ProtocolType::KeyRotation,
            signer,
        );
        let output = MpcManager::run_key_rotation(
            &mpc_manager,
            &previous_certs,
            &p2p_channel,
            &mut tob_channel,
            &self.inner.metrics,
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
        let my_sig = signing_key.sign(epoch, my_address, &message);
        self.inner
            .store_reconfig_signature(epoch, my_sig.signature().as_bytes().to_vec());
        let cert = loop {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!("epoch {} no longer pending", epoch));
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
        self.submit_committee_handoff_if_needed(epoch).await?;
        loop {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!("epoch {} no longer pending", epoch));
            }
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor
                    .execute_end_reconfig(&mpc_public_key, cert.committee_signature())
                    .await
            };
            match result.await {
                Ok(()) => return Ok(()),
                Err(e) => match classify_reconfig_submission_error(&e) {
                    ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted => {
                        warn!(
                            "end_reconfig submission for epoch {epoch} found reconfig already completed; rescraping on-chain state: {e}"
                        );
                        self.inner.onchain_state().rescrape().await?;
                        if self.get_pending_epoch_change() != Some(epoch) {
                            return Ok(());
                        }
                        Err(e).with_context(|| {
                            format!(
                                "end_reconfig submission for epoch {epoch} failed with ENotReconfiguring, but epoch is still pending after rescrape"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::NonRetryableMoveAbort
                    | ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted => {
                        Err(e).with_context(|| {
                            format!(
                                "end_reconfig submission for epoch {epoch} failed with non-retryable error"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::NonMoveAbort => {
                        warn!(
                            "end_reconfig submission for epoch {} failed: {e}, retrying...",
                            epoch
                        );
                        self.sleep_if_still_pending(epoch).await;
                    }
                },
            }
        }
    }

    async fn submit_committee_handoff_if_needed(&self, epoch: u64) -> anyhow::Result<()> {
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
            return Ok(());
        }

        let committee_handoff = loop {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!("epoch {} no longer pending", epoch));
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
                        "Committee handoff signature collection failed: {e}, retrying..."
                    );
                    self.sleep_if_still_pending(epoch).await;
                }
            }
        };
        loop {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!("epoch {} no longer pending", epoch));
            }
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor
                    .execute_submit_committee_handoff(committee_handoff.committee_signature())
                    .await
            };
            match result.await {
                Ok(()) => return Ok(()),
                Err(e) => match classify_reconfig_submission_error(&e) {
                    ReconfigSubmissionErrorKind::CommitteeHandoffAlreadySubmitted => {
                        warn!(
                            "submit_committee_handoff submission for epoch {epoch} found handoff already submitted: {e}"
                        );
                        return Ok(());
                    }
                    ReconfigSubmissionErrorKind::NonRetryableMoveAbort
                    | ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted => {
                        Err(e).with_context(|| {
                            format!(
                                "submit_committee_handoff submission for epoch {epoch} failed with non-retryable error"
                            )
                        })?;
                    }
                    ReconfigSubmissionErrorKind::NonMoveAbort => {
                        warn!(
                            "submit_committee_handoff submission for epoch {} failed: {e}, retrying...",
                            epoch
                        );
                        self.sleep_if_still_pending(epoch).await;
                    }
                },
            }
        }
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
        let mut aggregator = BlsSignatureAggregator::new(committee, message.clone());
        aggregator
            .add_signature_from(my_address, my_sig)
            .map_err(|e| anyhow::anyhow!("failed to add own signature: {e}"))?;
        let required_weight = certificate_threshold(committee.total_weight());
        while aggregator.weight() < required_weight {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!(
                    "epoch {epoch} no longer pending during signature collection"
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
    use_legacy: bool,
    batch_size_per_weight: u16,
) -> usize {
    let consumed = if use_legacy {
        params.f as usize
    } else {
        params.t as usize - 1
    };
    total_weight.saturating_sub(consumed) * batch_size_per_weight as usize
}

fn certified_nonce_weight<T>(
    mpc_manager: &Arc<std::sync::RwLock<MpcManager>>,
    certs: &[(sui_sdk_types::Address, T)],
) -> u32 {
    mpc_manager
        .read()
        .unwrap()
        .certified_nonce_dealers_from_certs(certs)
        .1
}

enum ReconfigSubmissionErrorKind {
    NonMoveAbort,
    NonRetryableMoveAbort,
    CommitteeHandoffAlreadySubmitted,
    EndReconfigAlreadyCompleted,
}

fn classify_reconfig_submission_error(err: &anyhow::Error) -> ReconfigSubmissionErrorKind {
    let Some(tx_err) = err.downcast_ref::<crate::sui_tx_executor::TransactionExecutionError>()
    else {
        return ReconfigSubmissionErrorKind::NonMoveAbort;
    };

    let Some(error) = tx_err.status().error_opt() else {
        return ReconfigSubmissionErrorKind::NonMoveAbort;
    };
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
        (Some("reconfig"), Some("end_reconfig"), Some(RECONFIG_E_NOT_RECONFIGURING)) => {
            ReconfigSubmissionErrorKind::EndReconfigAlreadyCompleted
        }
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
        assert_eq!(presig_count(5, params, false, 2), (5 - 2) * 2);
        assert_eq!(presig_count(3, params, false, 7), 7);
        // height = W - f
        assert_eq!(presig_count(5, params, true, 2), (5 - 1) * 2);
        assert_eq!(presig_count(10, params, true, 4), (10 - 1) * 4);
    }

    #[test]
    fn saturates_below_floor_without_underflow() {
        let params = Parameters { t: 3, f: 1 };
        assert_eq!(presig_count(1, params, false, 2), 0);
        assert_eq!(presig_count(0, params, true, 5), 0);
    }
}
