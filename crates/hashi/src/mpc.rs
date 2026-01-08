//! MPC (Multi-Party Computation) Service

use std::collections::HashSet;
use std::sync::Arc;

use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Mutex;
use sui_sdk_types::Address;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
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
use crate::dkg::types::ComplainRequest;
use crate::dkg::types::ComplainResponse;
use crate::dkg::types::DkgError;
use crate::dkg::types::RetrieveMessageRequest;
use crate::dkg::types::RetrieveMessageResponse;
use crate::dkg::types::SendMessageRequest;
use crate::dkg::types::SendMessageResponse;
use fastcrypto_tbls::threshold_schnorr::G;

pub enum MpcRequest {
    SendMessage {
        sender: Address,
        epoch: u64,
        request: SendMessageRequest,
        reply: oneshot::Sender<Result<SendMessageResponse, DkgError>>,
    },
    RetrieveMessage {
        epoch: u64,
        request: RetrieveMessageRequest,
        reply: oneshot::Sender<Result<RetrieveMessageResponse, DkgError>>,
    },
    Complain {
        epoch: u64,
        request: ComplainRequest,
        reply: oneshot::Sender<Result<ComplainResponse, DkgError>>,
    },
}

#[derive(Clone)]
pub struct MpcHandle {
    tx: mpsc::Sender<MpcRequest>,
    dkg_completion_rx: watch::Receiver<Option<G>>,
}

impl std::fmt::Debug for MpcHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcHandle").finish_non_exhaustive()
    }
}

impl MpcHandle {
    pub async fn send_message(
        &self,
        sender: Address,
        epoch: u64,
        request: SendMessageRequest,
    ) -> Result<SendMessageResponse, DkgError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(MpcRequest::SendMessage {
                sender,
                epoch,
                request,
                reply: reply_tx,
            })
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService channel closed".into()))?;
        reply_rx
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService reply channel closed".into()))?
    }

    pub async fn retrieve_message(
        &self,
        epoch: u64,
        request: RetrieveMessageRequest,
    ) -> Result<RetrieveMessageResponse, DkgError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(MpcRequest::RetrieveMessage {
                epoch,
                request,
                reply: reply_tx,
            })
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService channel closed".into()))?;
        reply_rx
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService reply channel closed".into()))?
    }

    pub async fn complain(
        &self,
        epoch: u64,
        request: ComplainRequest,
    ) -> Result<ComplainResponse, DkgError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(MpcRequest::Complain {
                epoch,
                request,
                reply: reply_tx,
            })
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService channel closed".into()))?;
        reply_rx
            .await
            .map_err(|_| DkgError::ProtocolFailed("MpcService reply channel closed".into()))?
    }

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
    rx: mpsc::Receiver<MpcRequest>,
    dkg_completion_tx: watch::Sender<Option<G>>,
}

impl MpcService {
    pub fn new(hashi: Arc<Hashi>, dkg_manager: DkgManager) -> (Self, MpcHandle) {
        let (tx, rx) = mpsc::channel(100);
        let (dkg_completion_tx, dkg_completion_rx) = watch::channel(None);
        let service = Self {
            inner: hashi,
            dkg_manager: Arc::new(Mutex::new(dkg_manager)),
            rx,
            dkg_completion_tx,
        };
        let handle = MpcHandle {
            tx,
            dkg_completion_rx,
        };
        (service, handle)
    }

    pub async fn start(self) {
        debug!("MpcService: starting");
        // Wait for all nodes' RPC services to be ready before starting DKG.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let dkg_manager = self.dkg_manager.clone();
        let inner = self.inner.clone();
        let dkg_completion_tx = self.dkg_completion_tx.clone();
        let request_processor = {
            let dkg_manager = self.dkg_manager.clone();
            tokio::spawn(async move {
                Self::process_requests(dkg_manager, self.rx).await;
            })
        };
        match Self::run_dkg(&inner, &dkg_manager, &dkg_completion_tx).await {
            Ok(output) => {
                debug!(
                    "MpcService: DKG completed successfully. Public key: {:?}",
                    output.public_key
                );
                let _ = dkg_completion_tx.send(Some(output.public_key));
            }
            Err(e) => error!("MpcService: DKG failed: {e:?}"),
        }
        let _ = request_processor.await;
    }

    async fn process_requests(
        dkg_manager: Arc<Mutex<DkgManager>>,
        mut rx: mpsc::Receiver<MpcRequest>,
    ) {
        while let Some(request) = rx.recv().await {
            match request {
                MpcRequest::SendMessage {
                    sender,
                    epoch,
                    request,
                    reply,
                } => {
                    let result = {
                        let mut mgr = dkg_manager.lock().unwrap();
                        Self::validate_epoch(&mgr, epoch)
                            .and_then(|()| mgr.handle_send_message_request(sender, &request))
                    };
                    let _ = reply.send(result);
                }
                MpcRequest::RetrieveMessage {
                    epoch,
                    request,
                    reply,
                } => {
                    let result = {
                        let mgr = dkg_manager.lock().unwrap();
                        Self::validate_epoch(&mgr, epoch)
                            .and_then(|()| mgr.handle_retrieve_message_request(&request))
                    };
                    let _ = reply.send(result);
                }
                MpcRequest::Complain {
                    epoch,
                    request,
                    reply,
                } => {
                    let result = {
                        let mut mgr = dkg_manager.lock().unwrap();
                        Self::validate_epoch(&mgr, epoch)
                            .and_then(|()| mgr.handle_complain_request(&request))
                    };
                    let _ = reply.send(result);
                }
            }
        }
        info!("MpcService request channel closed");
    }

    fn validate_epoch(dkg_manager: &DkgManager, epoch: u64) -> Result<(), DkgError> {
        let expected = dkg_manager.dkg_config.epoch;
        if epoch != expected {
            return Err(DkgError::InvalidConfig(format!(
                "epoch mismatch: expected {expected}, got {epoch}"
            )));
        }
        Ok(())
    }

    async fn run_dkg(
        inner: &Arc<Hashi>,
        dkg_manager: &Arc<Mutex<DkgManager>>,
        _dkg_completion_tx: &watch::Sender<Option<G>>,
    ) -> anyhow::Result<DkgOutput> {
        let validator_address = inner.config.validator_address()?;
        debug!(%validator_address, "Starting DKG");
        let onchain_state = inner.onchain_state().clone();
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
        let signer = inner.config.operator_private_key()?;
        let p2p_channel = RpcP2PChannel::new(onchain_state.clone(), epoch);
        let mut tob_channel = SuiTobChannel::new(onchain_state, epoch, signer, committee);
        debug!(%validator_address, "Running dealer phase");
        if let Err(e) = Self::run_as_dealer(dkg_manager, &p2p_channel, &mut tob_channel).await {
            warn!(%validator_address, %e, "Dealer phase failed");
        }
        debug!(%validator_address, "Running party phase");
        let output = Self::run_as_party(dkg_manager, &mut tob_channel).await?;
        debug!(%validator_address, "DKG completed");
        Ok(output)
    }

    // TODO: Migrate non-happy path features from DkgManager::run_as_dealer().
    async fn run_as_dealer(
        dkg_manager: &Arc<Mutex<DkgManager>>,
        p2p_channel: &RpcP2PChannel,
        tob_channel: &mut SuiTobChannel,
    ) -> anyhow::Result<()> {
        let mut rng = StdRng::from_entropy();
        let dealer_data: DealerPhaseData = {
            let mut mgr = dkg_manager.lock().unwrap();
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
    async fn run_as_party(
        dkg_manager: &Arc<Mutex<DkgManager>>,
        tob_channel: &mut SuiTobChannel,
    ) -> anyhow::Result<DkgOutput> {
        let threshold = {
            let mgr = dkg_manager.lock().unwrap();
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
                let mut mgr = dkg_manager.lock().unwrap();
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
            let mgr = dkg_manager.lock().unwrap();
            mgr.finalize_dkg()?
        };
        Ok(output)
    }
}
