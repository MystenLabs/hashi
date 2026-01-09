//! MPC (Multi-Party Computation) Service

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::watch;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::committee::BlsSignatureAggregator;
use crate::communication::OrderedBroadcastChannel;
use crate::communication::P2PChannel;
use crate::communication::SuiTobChannel;
use crate::communication::with_timeout_and_retry;
use crate::dkg::DealerPhaseData;
use crate::dkg::DkgManager;
use crate::dkg::DkgOutput;
use crate::dkg::rpc::RpcP2PChannel;
use crate::dkg::types::Certificate;
use fastcrypto_tbls::threshold_schnorr::G;

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
        debug!("MpcService: starting");
        // Wait for all nodes' RPC services to be ready before starting DKG.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match self.run_dkg().await {
            Ok(output) => {
                debug!(
                    "MpcService: DKG completed successfully. Public key: {:?}",
                    output.public_key
                );
                let _ = self.dkg_completion_tx.send(Some(output.public_key));
            }
            Err(e) => error!("MpcService: DKG failed: {e:?}"),
        }
    }

    async fn run_dkg(&self) -> anyhow::Result<DkgOutput> {
        let validator_address = self.inner.config.validator_address()?;
        debug!(%validator_address, "Starting DKG");
        let onchain_state = self.inner.onchain_state().clone();
        let (epoch, committee) = {
            let state = onchain_state.state();
            let epoch = state.hashi().committees.epoch();
            let committee = state
                .hashi()
                .committees
                .current_committee()
                .ok_or_else(|| anyhow::anyhow!("No current committee"))?
                .clone();
            (epoch, committee)
        };
        debug!(
            %validator_address,
            epoch,
            committee_size = committee.members().len(),
            "DKG configuration"
        );
        let signer = self.inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(onchain_state, epoch, signer, committee);
        let threshold = {
            let mgr = self.dkg_manager.lock().unwrap();
            mgr.threshold()
        };
        if tob_channel.existing_certificate_weight() < threshold as u32 {
            debug!(%validator_address, "Running dealer phase");
            if let Err(e) = self.run_as_dealer(&p2p_channel, &mut tob_channel).await {
                warn!(%validator_address, %e, "Dealer phase failed");
            }
        } else {
            debug!(%validator_address, "Skipping dealer phase - enough certificates already exist");
        }
        debug!(%validator_address, "Running party phase");
        let output = self.run_as_party(&mut tob_channel).await?;
        debug!(%validator_address, "DKG completed");
        Ok(output)
    }

    // TODO: Migrate non-happy path features from DkgManager::run_as_dealer().
    async fn run_as_dealer(
        &self,
        p2p_channel: &RpcP2PChannel,
        tob_channel: &mut SuiTobChannel,
    ) -> anyhow::Result<()> {
        let mut rng = StdRng::from_entropy();
        let dealer_data: DealerPhaseData = {
            let mut mgr = self.dkg_manager.lock().unwrap();
            mgr.prepare_dealer_phase(&mut rng)?
        };
        let mut aggregator =
            BlsSignatureAggregator::new(&dealer_data.committee, dealer_data.mpc_message);
        aggregator
            .add_signature_from_bytes(
                dealer_data.my_address,
                dealer_data.my_signature,
                &dealer_data.inner_bytes,
            )
            .expect("first signature should always be valid");
        debug!(
            recipients = dealer_data.recipients.len(),
            "Sending to recipients"
        );
        for recipient in &dealer_data.recipients {
            match p2p_channel
                .send_dkg_message(recipient, &dealer_data.request)
                .await
            {
                Ok(response) => {
                    if let Err(e) = aggregator.add_signature_from_bytes(
                        *recipient,
                        response.signature,
                        &dealer_data.inner_bytes,
                    ) {
                        info!(%recipient, %e, "Invalid signature");
                    }
                }
                Err(e) => info!(%recipient, %e, "Failed to send message"),
            }
        }
        debug!(
            weight = aggregator.weight(),
            required = dealer_data.required_weight,
            "Checking signature weight"
        );
        if aggregator.weight() >= dealer_data.required_weight as u64 {
            let cert = aggregator
                .finish_unchecked()
                .expect("signatures should always be valid");
            debug!("Publishing certificate");
            with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to publish certificate: {e}"))?;
        }
        Ok(())
    }

    // TODO: Migrate non-happy path features from DkgManager::run_as_party().
    async fn run_as_party(&self, tob_channel: &mut SuiTobChannel) -> anyhow::Result<DkgOutput> {
        let threshold = {
            let mgr = self.dkg_manager.lock().unwrap();
            mgr.threshold()
        };
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= threshold as u32 {
                break;
            }
            let cert: Certificate = tob_channel
                .receive()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to receive certificate: {e}"))?;
            let weight_opt = {
                let mut mgr = self.dkg_manager.lock().unwrap();
                mgr.process_party_certificate(&cert, &mut certified_dealers)?
            };
            if let Some(weight) = weight_opt {
                dealer_weight_sum += weight as u32;
                info!(
                    weight_sum = dealer_weight_sum,
                    threshold, "Processed certificate"
                );
            }
        }
        let output = {
            let mgr = self.dkg_manager.lock().unwrap();
            mgr.finalize_dkg()?
        };
        Ok(output)
    }
}
