//! MPC (Multi-Party Computation) Service

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;
use tracing::error;

use crate::Hashi;
use crate::communication::SuiTobChannel;
use crate::dkg::DkgManager;
use crate::dkg::DkgOutput;
use crate::dkg::rpc::RpcP2PChannel;
use crate::onchain::OnchainState;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::committee::Committee;

const DKG_RETRY_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct MpcHandle {
    dkg_completion_rx: watch::Receiver<Option<G>>,
}

impl std::fmt::Debug for MpcHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcHandle").finish_non_exhaustive()
    }
}

impl MpcHandle {
    pub async fn wait_for_dkg_completion(&self) -> G {
        let mut rx = self.dkg_completion_rx.clone();
        loop {
            {
                let value = rx.borrow();
                if let Some(pk) = value.as_ref() {
                    return *pk;
                }
            }
            if rx.changed().await.is_err() {
                panic!("DKG completion channel closed before DKG completed");
            }
        }
    }

    pub fn dkg_completed(&self) -> Option<G> {
        *self.dkg_completion_rx.borrow()
    }
}

pub struct MpcService {
    inner: Arc<Hashi>,
    dkg_manager: Arc<Mutex<DkgManager>>,
    dkg_completion_tx: watch::Sender<Option<G>>,
}

impl MpcService {
    pub fn new(hashi: Arc<Hashi>, dkg_manager: Arc<Mutex<DkgManager>>) -> (Self, MpcHandle) {
        let (dkg_completion_tx, dkg_completion_rx) = watch::channel(None);
        let service = Self {
            inner: hashi,
            dkg_manager,
            dkg_completion_tx,
        };
        let handle = MpcHandle { dkg_completion_rx };
        (service, handle)
    }

    pub async fn start(self) {
        loop {
            // TODO: Store DKG public key on-chain, and read it from there if it already exists.
            // Note that restart is already supported in `DkgManager`, so the latter is not strictly necessary despite more direct.
            match self.run_dkg().await {
                Ok(output) => {
                    let _ = self.dkg_completion_tx.send(Some(output.public_key));
                    return;
                }
                Err(e) => {
                    error!("DKG failed: {e:?}");
                }
            }
            tokio::time::sleep(DKG_RETRY_INTERVAL).await;
        }
    }

    async fn run_dkg(&self) -> anyhow::Result<DkgOutput> {
        let onchain_state = self.inner.onchain_state().clone();
        let (epoch, committee) = get_epoch_and_committee(&onchain_state)?;
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(
            self.inner.config.hashi_ids(),
            onchain_state,
            epoch,
            signer,
            committee,
        );
        let output = DkgManager::run(&self.dkg_manager, &p2p_channel, &mut tob_channel)
            .await
            .map_err(|e| anyhow::anyhow!("DKG failed: {e}"))?;
        Ok(output)
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
