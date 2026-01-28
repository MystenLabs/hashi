//! MPC (Multi-Party Computation) Service

use std::sync::Arc;
use std::time::Duration;

use fastcrypto::traits::ToFromBytes;
use futures::future::join_all;
use tokio::sync::watch;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::communication::SuiTobChannel;
use crate::communication::fetch_certificates;
use crate::dkg::DkgManager;
use crate::dkg::DkgOutput;
use crate::dkg::rpc::RpcP2PChannel;
use crate::dkg::types::CertificateV1;
use crate::dkg::types::ProtocolType;
use crate::onchain::Notification;
use crate::onchain::OnchainState;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types::ReconfigCompletionMessage;

const RETRY_INTERVAL: Duration = Duration::from_secs(10);

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
}

impl MpcService {
    pub fn new(hashi: Arc<Hashi>) -> (Self, MpcHandle) {
        let (key_ready_tx, key_ready_rx) = watch::channel(None);
        let service = Self {
            inner: hashi,
            key_ready_tx,
        };
        let handle = MpcHandle { key_ready_rx };
        (service, handle)
    }

    pub async fn start(self) {
        if let Some(epoch) = self.get_pending_epoch_change() {
            self.handle_reconfig(epoch).await;
        } else {
            loop {
                // TODO: Store DKG public key on-chain, and read it from there if it already exists.
                // Note that restart is already supported in `DkgManager`, so the latter is not strictly necessary despite more direct.
                match self.run_dkg().await {
                    Ok(output) => {
                        let _ = self.key_ready_tx.send(Some(output.public_key));
                        break;
                    }
                    Err(e) => {
                        error!("DKG failed: {e:?}");
                    }
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
        let mut notifications = self.inner.onchain_state().subscribe();
        while let Ok(notification) = notifications.recv().await {
            if let Notification::StartReconfig(epoch) = notification {
                self.handle_reconfig(epoch).await;
            }
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

    async fn run_dkg(&self) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let (epoch, committee) = get_epoch_and_committee(&onchain_state)?;
        let dkg_manager = self.inner.dkg_manager();
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            signer,
            committee,
        );
        let output = DkgManager::run(&dkg_manager, &p2p_channel, &mut tob_channel)
            .await
            .map_err(|e| anyhow::anyhow!("DKG failed: {e}"))?;
        Ok(output)
    }

    async fn handle_reconfig(&self, target_epoch: u64) {
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
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        };
        let _ = self.key_ready_tx.send(Some(output.public_key));
        loop {
            if self.get_pending_epoch_change() != Some(target_epoch) {
                return;
            }
            match self.submit_end_reconfig(target_epoch, &output).await {
                Ok(()) => {
                    return;
                }
                Err(e) => {
                    error!(
                        "submit_end_reconfig for epoch {} failed: {e}, retrying...",
                        target_epoch
                    );
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        }
    }

    async fn run_key_rotation(&self, target_epoch: u64) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let previous_certs = self.fetch_previous_certificates().await?;
        let target_committee = onchain_state
            .state()
            .hashi()
            .committees
            .committees()
            .get(&target_epoch)
            .ok_or_else(|| anyhow::anyhow!("No committee found for epoch {}", target_epoch))?
            .clone();
        let rotation_manager = self
            .inner
            .create_dkg_manager(target_epoch, ProtocolType::KeyRotation)?;
        self.inner.set_dkg_manager(rotation_manager);
        let dkg_manager = self.inner.dkg_manager();
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), target_epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            target_epoch,
            signer,
            target_committee,
        );
        let output = DkgManager::run_key_rotation(
            &dkg_manager,
            &previous_certs,
            &p2p_channel,
            &mut tob_channel,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Key rotation failed: {e}"))?;
        Ok(output)
    }

    async fn fetch_previous_certificates(&self) -> anyhow::Result<Vec<CertificateV1>> {
        let onchain_state = self.inner.onchain_state().clone();
        let source_epoch = onchain_state.state().hashi().committees.epoch();
        let source_committee = onchain_state
            .state()
            .hashi()
            .committees
            .current_committee()
            .ok_or_else(|| anyhow::anyhow!("No source committee"))?
            .clone();
        let certs = fetch_certificates(&onchain_state, source_epoch, &source_committee)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch certificates: {e}"))?;
        Ok(certs.into_iter().map(|(_, cert)| cert).collect())
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
                    tokio::time::sleep(RETRY_INTERVAL).await;
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
                    tokio::time::sleep(RETRY_INTERVAL).await;
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
                    let result: anyhow::Result<Vec<u8>> = async {
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
                    }
                    .await;
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
