//! MPC (Multi-Party Computation) Service

use std::sync::Arc;
use std::time::Duration;

use fastcrypto::traits::ToFromBytes;
use futures::future::join_all;
use sui_futures::service::Service;
use tokio::sync::watch;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::communication::SuiTobChannel;
use crate::communication::fetch_certificates;
use crate::constants::PRESIG_REFILL_DIVISOR;
use crate::mpc::DkgOutput;
use crate::mpc::MpcManager;
use crate::mpc::SigningManager;
use crate::mpc::rpc::RpcP2PChannel;
use crate::mpc::types::CertificateV1;
use crate::mpc::types::ProtocolType;
use crate::onchain::Notification;
use crate::onchain::OnchainState;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types::ReconfigCompletionMessage;

const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const START_RECONFIG_MAX_ATTEMPTS: u32 = 3;
const START_RECONFIG_POLL_INTERVAL: Duration = Duration::from_millis(500);

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
                panic!("Key ready channel closed unexpectedly");
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
}

impl MpcService {
    pub fn new(hashi: Arc<Hashi>) -> (Self, MpcHandle) {
        let (key_ready_tx, key_ready_rx) = watch::channel(None);
        let (refill_tx, refill_rx) = watch::channel(0u32);
        let service = Self {
            inner: hashi,
            key_ready_tx,
            refill_tx: Arc::new(refill_tx),
            refill_rx,
        };
        let handle = MpcHandle { key_ready_rx };
        (service, handle)
    }

    /// Start the MPC service and return a `Service` for lifecycle management.
    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    async fn run(mut self) {
        if let Some(epoch) = self.get_pending_epoch_change() {
            self.handle_reconfig(epoch).await;
        } else if self.inner.is_in_current_committee() {
            loop {
                // TODO: Store DKG public key on-chain, and read it from there if it already exists.
                // Note that restart is already supported in `MpcManager`, so the latter is not strictly necessary despite more direct.
                match self.recover_mpc_state().await {
                    Ok(output) => {
                        let epoch = self.inner.onchain_state().epoch();
                        if let Err(e) = self.recover_presigning_state(&output) {
                            error!(
                                "Presigning recovery from DB failed: {e}, falling back to fresh nonce generation"
                            );
                            if let Err(e) = self.prepare_signing(epoch, &output).await {
                                error!("Failed to init signing after DKG recovery: {e}");
                            }
                        }
                        let _ = self.key_ready_tx.send(Some(output.public_key));
                        break;
                    }
                    Err(e) => {
                        error!("MPC state recovery failed: {e:?}");
                    }
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        } else {
            info!("Node is not in the current committee, waiting for reconfig notification...");
        }
        let mut notifications = self.inner.onchain_state().subscribe();
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
                Ok(()) = self.refill_rx.changed() => {
                    let next_batch = *self.refill_rx.borrow();
                    if let Err(e) = self.refill_presignatures(next_batch).await {
                        // TODO: Failed refill can desynchronize this node's presignature
                        // index from peers. Recovery requires presig state sync with peers.
                        error!("Presignature refill failed: {e}");
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

    async fn recover_mpc_state(&self) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let epoch = onchain_state.epoch();
        let protocol_type = onchain_state
            .fetch_certs(epoch, None)
            .await?
            .map(|(pt, _)| pt);
        match protocol_type {
            Some(hashi_types::move_types::ProtocolType::KeyRotation) => {
                self.setup_key_rotation(epoch)?;
                self.run_key_rotation(epoch).await
            }
            _ => self.run_dkg().await,
        }
    }

    async fn run_dkg(&self) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let (epoch, committee) = get_epoch_and_committee(&onchain_state)?;
        let mpc_manager = self
            .inner
            .mpc_manager()
            .expect("MpcManager must be set before run_dkg");
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            None,
            signer,
            committee,
        );
        let output = MpcManager::run(&mpc_manager, &p2p_channel, &mut tob_channel)
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
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            Some(batch_index),
            signer,
            committee.clone(),
        );
        let nonce_outputs = MpcManager::run_nonce_generation(
            &mpc_manager,
            batch_index,
            &p2p_channel,
            &mut tob_channel,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Nonce generation failed: {e}"))?;
        let (batch_size_per_weight, f) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                mgr.dkg_config.max_faulty as usize,
            )
        };
        let presignatures = Presignatures::new(nonce_outputs, batch_size_per_weight, f)
            .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        Ok((committee, presignatures))
    }

    async fn prepare_signing(&self, epoch: u64, output: &DkgOutput) -> anyhow::Result<()> {
        let (committee, presignatures) = self.generate_presignatures(epoch, 0).await?;
        let address = self.inner.config.validator_address()?;
        let signing_manager = SigningManager::new(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            presignatures,
            0,
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
        );
        self.inner.set_or_init_signing_manager(signing_manager);
        Ok(())
    }

    fn recover_presigning_state(&self, output: &DkgOutput) -> anyhow::Result<()> {
        let state = self.inner.onchain_state().state();
        let hashi = state.hashi();
        let num_consumed = hashi.withdrawal_queue.num_consumed_presigs();
        let epoch = hashi.committees.epoch();
        let committee = hashi
            .committees
            .committees()
            .get(&epoch)
            .ok_or_else(|| anyhow::anyhow!("No committee found for epoch {epoch}"))?
            .clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized"))?;
        let (batch_size_per_weight, f) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.batch_size_per_weight,
                mgr.dkg_config.max_faulty as usize,
            )
        };
        // Reconstruct batch 0 to determine the actual batch size.
        let batch_0_outputs = mpc_manager.read().unwrap().reconstruct_presignatures(0)?;
        if batch_0_outputs.is_empty() {
            return Err(anyhow::anyhow!("No persisted nonce messages for batch 0"));
        }
        let batch_0_presigs = Presignatures::new(batch_0_outputs, batch_size_per_weight, f)
            .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?;
        let batch_size = batch_0_presigs.len();
        let batch_index = (num_consumed / batch_size as u64) as u32;
        let index_in_batch = (num_consumed % batch_size as u64) as usize;
        let presignatures = if batch_index == 0 {
            batch_0_presigs
        } else {
            let nonce_outputs = mpc_manager
                .read()
                .unwrap()
                .reconstruct_presignatures(batch_index)?;
            if nonce_outputs.is_empty() {
                return Err(anyhow::anyhow!(
                    "No persisted nonce messages for batch {batch_index}"
                ));
            }
            Presignatures::new(nonce_outputs, batch_size_per_weight, f)
                .map_err(|e| anyhow::anyhow!("Failed to create presignatures: {e}"))?
        };
        let address = self.inner.config.validator_address()?;
        let mut signing_manager = SigningManager::new(
            address,
            committee,
            output.threshold,
            output.key_shares.clone(),
            output.public_key,
            presignatures,
            batch_index,
            PRESIG_REFILL_DIVISOR,
            self.refill_tx.clone(),
        );
        signing_manager.skip_consumed_presigs(index_in_batch);
        self.inner.set_or_init_signing_manager(signing_manager);
        info!(
            "Recovered presigning state: batch_index={batch_index}, \
             skipped {index_in_batch}/{batch_size} presignatures \
             (num_consumed_presigs={num_consumed})"
        );
        Ok(())
    }

    async fn refill_presignatures(&self, batch_index: u32) -> anyhow::Result<()> {
        let epoch = self.inner.onchain_state().epoch();
        let (_, presignatures) = self.generate_presignatures(epoch, batch_index).await?;
        if self.inner.onchain_state().epoch() != epoch {
            return Err(anyhow::anyhow!("Epoch changed during presignature refill"));
        }
        let signing_manager = self.inner.signing_manager();
        signing_manager
            .write()
            .unwrap()
            .set_next_batch(presignatures);
        Ok(())
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
        for attempt in 1..=START_RECONFIG_MAX_ATTEMPTS {
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
                    warn!(
                        "start_reconfig attempt {attempt}/{START_RECONFIG_MAX_ATTEMPTS} failed: {e}"
                    );
                    if attempt < START_RECONFIG_MAX_ATTEMPTS {
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

    async fn handle_reconfig(&self, target_epoch: u64) {
        // Create the MpcManager once before the retry loop so retries reuse
        // the same manager (and its accumulated messages) instead of generating
        // fresh random dealer messages that conflict with previously sent ones.
        if let Err(e) = self.setup_key_rotation(target_epoch) {
            error!(
                "Failed to set up key rotation for epoch {}: {e}",
                target_epoch
            );
            return;
        }
        let output = loop {
            if self.get_pending_epoch_change() != Some(target_epoch) {
                return;
            }
            match self.run_key_rotation(target_epoch).await {
                Ok(output) => break output,
                Err(e) => {
                    error!(
                        "Key rotation to epoch {} failed: {e}, retrying...",
                        target_epoch
                    );
                    self.sleep_if_still_pending(target_epoch).await;
                }
            }
        };
        let _ = self.key_ready_tx.send(Some(output.public_key));
        loop {
            if self.get_pending_epoch_change() != Some(target_epoch) {
                break;
            }
            match self.submit_end_reconfig(target_epoch, &output).await {
                Ok(()) => break,
                Err(e) => {
                    error!(
                        "submit_end_reconfig for epoch {} failed: {e}, retrying...",
                        target_epoch
                    );
                    self.sleep_if_still_pending(target_epoch).await;
                }
            }
        }
        if let Err(e) = self.prepare_signing(target_epoch, &output).await {
            // TODO: Node has valid key but no presignatures, can't sign.
            // Recovery requires presig state sync with peers.
            error!("Failed to init signing after key rotation to epoch {target_epoch}: {e}");
        }
    }

    fn setup_key_rotation(&self, target_epoch: u64) -> anyhow::Result<()> {
        let rotation_manager = self
            .inner
            .create_mpc_manager(target_epoch, ProtocolType::KeyRotation)?;
        self.inner.set_mpc_manager(rotation_manager);
        Ok(())
    }

    async fn run_key_rotation(&self, target_epoch: u64) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let target_committee = onchain_state
            .state()
            .hashi()
            .committees
            .committees()
            .get(&target_epoch)
            .ok_or_else(|| anyhow::anyhow!("No committee found for epoch {}", target_epoch))?
            .clone();
        let mpc_manager = self
            .inner
            .mpc_manager()
            .ok_or_else(|| anyhow::anyhow!("MpcManager not initialized for key rotation"))?;
        let source_epoch = mpc_manager.read().unwrap().source_epoch;
        let source_committee = onchain_state
            .state()
            .hashi()
            .committees
            .committees()
            .get(&source_epoch)
            .ok_or_else(|| anyhow::anyhow!("No committee for source epoch {source_epoch}"))?
            .clone();
        let previous_certs =
            fetch_certificates(&onchain_state, source_epoch, None, &source_committee)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch previous certificates: {e}"))?;
        let previous_certs: Vec<CertificateV1> =
            previous_certs.into_iter().map(|(_, cert)| cert).collect();
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), target_epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            None,
            signer,
            target_committee,
        );
        let output = MpcManager::run_key_rotation(
            &mpc_manager,
            &previous_certs,
            &p2p_channel,
            &mut tob_channel,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Key rotation failed: {e}"))?;
        Ok(output)
    }

    async fn submit_end_reconfig(&self, epoch: u64, output: &DkgOutput) -> anyhow::Result<()> {
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
        let signing_key = self
            .inner
            .config
            .protocol_private_key()
            .ok_or_else(|| anyhow::anyhow!("no protocol_private_key configured"))?;
        let my_address = self.inner.config.validator_address()?;
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
        loop {
            if self.get_pending_epoch_change() != Some(epoch) {
                return Err(anyhow::anyhow!("epoch {} no longer pending", epoch));
            }
            let result = async {
                let mut executor =
                    crate::sui_tx_executor::SuiTxExecutor::from_hashi(self.inner.clone())?;
                executor
                    .execute_end_reconfig(
                        &mpc_public_key,
                        cert.signature_bytes(),
                        cert.signers_bitmap_bytes(),
                    )
                    .await
            };
            match result.await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        "end_reconfig submission for epoch {} failed: {e}, retrying...",
                        epoch
                    );
                    self.sleep_if_still_pending(epoch).await;
                }
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
                    (address, result)
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

fn get_epoch_and_committee(onchain_state: &OnchainState) -> anyhow::Result<(u64, Committee)> {
    let state = onchain_state.state();
    let epoch = state.hashi().committees.epoch();
    let committee = state
        .hashi()
        .committees
        .current_committee()
        .ok_or_else(|| anyhow::anyhow!("No current committee"))?
        .clone();
    Ok((epoch, committee))
}
