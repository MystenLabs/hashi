//! MPC (Multi-Party Computation) Service

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::error;

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
use hashi_types::committee::Committee;

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
        loop {
            if self.get_pending_epoch_change() != Some(target_epoch) {
                return;
            }
            match self.run_key_rotation(target_epoch).await {
                Ok(output) => {
                    let _ = self.key_ready_tx.send(Some(output.public_key));
                    self.submit_end_reconfig(target_epoch, &output).await;
                    return;
                }
                Err(e) => {
                    error!(
                        "Key rotation to epoch {} failed: {e}, retrying...",
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

    async fn submit_end_reconfig(&self, _epoch: u64, _output: &DkgOutput) {
        todo!("Generate completion cert and submit on-chain")
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
