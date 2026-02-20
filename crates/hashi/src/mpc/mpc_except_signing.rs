use crate::communication::OrderedBroadcastChannel;
use crate::communication::P2PChannel;
use crate::communication::send_to_many;
use crate::communication::with_timeout_and_retry;
use crate::constants::SUI_MAINNET_CHAIN_ID;
use crate::constants::SUI_TESTNET_CHAIN_ID;
use crate::mpc::types::CertificateV1;
pub use crate::mpc::types::ComplainRequest;
pub use crate::mpc::types::ComplaintResponses;
pub use crate::mpc::types::ComplaintsToProcessKey;
use crate::mpc::types::DealerCertificate;
pub use crate::mpc::types::DealerFlowData;
use crate::mpc::types::DealerMessagesHash;
pub use crate::mpc::types::DealerOutputsKey;
use crate::mpc::types::DkgConfig;
pub use crate::mpc::types::DkgOutput;
pub use crate::mpc::types::EncryptionGroupElement;
pub use crate::mpc::types::GetPublicDkgOutputRequest;
pub use crate::mpc::types::GetPublicDkgOutputResponse;
pub use crate::mpc::types::MessageHash;
pub use crate::mpc::types::Messages;
pub use crate::mpc::types::MpcError;
pub use crate::mpc::types::MpcResult;
pub use crate::mpc::types::ProtocolType;
pub use crate::mpc::types::PublicDkgOutput;
pub use crate::mpc::types::RetrieveMessagesRequest;
pub use crate::mpc::types::RetrieveMessagesResponse;
use crate::mpc::types::RotationComplainContext;
use crate::mpc::types::RotationMessages;
pub use crate::mpc::types::SendMessagesRequest;
pub use crate::mpc::types::SendMessagesResponse;
pub use crate::mpc::types::SessionId;
use crate::onchain::types::CommitteeSet;
use crate::storage::PublicMessagesStore;
use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::HashToGroupElement;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::ecies_v1::PublicKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::IndexedValue;
use fastcrypto_tbls::types::ShareIndex;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::MemberSignature;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::RwLock;
use sui_sdk_types::Address;

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";
const EXPECT_THRESHOLD_VALIDATED: &str = "Threshold already validated";
const EXPECT_THRESHOLD_MET: &str = "Already checked earlier that threshold is met";
const EXPECT_SERIALIZATION_SUCCESS: &str = "Serialization should always succeed";

// DKG protocol
// 1) A dealer sends out a message to all parties containing the encrypted shares and the public keys of the nonces.
// 2) Each party verifies the message and returns a signature. Once sufficient valid signatures are received from the parties, the dealer sends a certificate to Sui (TOB).
// 3) Once sufficient valid certificates are received, a party completes the protocol locally by aggregating the shares from the dealers.
pub struct MpcManager {
    // Immutable during the epoch
    pub party_id: PartyId,
    pub address: Address,
    pub dkg_config: DkgConfig,
    pub session_id: SessionId,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub signing_key: Bls12381PrivateKey,
    pub committee: Committee,
    pub previous_committee: Option<Committee>,
    pub previous_nodes: Option<Nodes<EncryptionGroupElement>>,
    pub previous_threshold: Option<u16>,
    /// Used to reconstruct source session IDs during certificate reconstruction.
    chain_id: String,
    /// The epoch from which to read previous messages during reconstruction.
    pub source_epoch: u64,
    previous_output: Option<DkgOutput>,
    pub batch_size_per_weight: u16,

    // Mutable during the epoch
    pub dealer_outputs: HashMap<DealerOutputsKey, avss::PartialOutput>,
    pub dealer_messages: HashMap<Address, Messages>,
    pub message_responses: HashMap<Address, SendMessagesResponse>,
    pub complaints_to_process: HashMap<ComplaintsToProcessKey, complaint::Complaint>,
    pub complaint_responses: HashMap<Address, ComplaintResponses>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
    /// Must be `BTreeMap` so that all nodes iterate outputs in
    /// the same deterministic order when constructing `Presignatures`.
    pub dealer_nonce_outputs: BTreeMap<Address, batch_avss::ReceiverOutput>,
}

impl MpcManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        committee_set: &CommitteeSet,
        session_id: SessionId,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        signing_key: Bls12381PrivateKey,
        public_message_store: Box<dyn PublicMessagesStore>,
        allowed_delta: u16,
        chain_id: &str,
        weight_divisor: Option<u16>,
        batch_size_per_weight: u16,
    ) -> MpcResult<Self> {
        if weight_divisor.is_some() {
            assert!(
                chain_id != SUI_MAINNET_CHAIN_ID && chain_id != SUI_TESTNET_CHAIN_ID,
                "weight_divisor must not be set on mainnet or testnet"
            );
        }
        let weight_divisor = weight_divisor.unwrap_or(1);
        let epoch = committee_set
            .pending_epoch_change()
            .unwrap_or_else(|| committee_set.epoch());
        let committee = committee_set
            .committees()
            .get(&epoch)
            .ok_or_else(|| MpcError::InvalidConfig(format!("no committee for epoch {epoch}")))?
            .clone();
        // TODO: Pass t and f as arguments instead of computing them
        let (nodes, threshold) = build_reduced_nodes(&committee, allowed_delta, weight_divisor)?;
        let total_weight = nodes.total_weight();
        let max_faulty = ((total_weight - threshold) / 2).min(threshold.saturating_sub(1));
        let dkg_config = DkgConfig::new(epoch, nodes, threshold, max_faulty)?;
        let party_id = committee
            .index_of(&address)
            .expect("address not in committee") as u16;
        let (source_epoch, previous_committee) = if committee_set.pending_epoch_change().is_some() {
            // Live reconfig
            let source = committee_set.epoch();
            (source, committee_set.committees().get(&source).cloned())
        } else {
            match epoch.checked_sub(1).and_then(|prev| {
                committee_set
                    .committees()
                    .get(&prev)
                    .cloned()
                    .map(|c| (prev, c))
            }) {
                // Rotation recovery
                Some((prev, committee)) => (prev, Some(committee)),
                // Initial DKG
                None => (committee_set.epoch(), None),
            }
        };
        let (previous_nodes, previous_threshold) = match previous_committee.as_ref() {
            Some(prev_committee) => {
                let (nodes, threshold) =
                    build_reduced_nodes(prev_committee, allowed_delta, weight_divisor)?;
                (Some(nodes), Some(threshold))
            }
            None => (None, None),
        };
        let mut manager = Self {
            party_id,
            address,
            dkg_config,
            session_id,
            encryption_key,
            signing_key,
            committee,
            previous_committee,
            previous_nodes,
            previous_threshold,
            dealer_outputs: HashMap::new(),
            dealer_messages: HashMap::new(),
            message_responses: HashMap::new(),
            complaints_to_process: HashMap::new(),
            complaint_responses: HashMap::new(),
            public_messages_store: public_message_store,
            chain_id: chain_id.to_string(),
            source_epoch,
            previous_output: None,
            batch_size_per_weight,
            dealer_nonce_outputs: BTreeMap::new(),
        };
        manager.load_stored_messages()?;
        Ok(manager)
    }

    pub fn handle_send_messages_request(
        &mut self,
        sender: Address,
        request: &SendMessagesRequest,
    ) -> MpcResult<SendMessagesResponse> {
        if let Some(existing_messages) = self.dealer_messages.get(&sender) {
            let existing_hash = compute_messages_hash(existing_messages);
            let incoming_hash = compute_messages_hash(&request.messages);
            if existing_hash != incoming_hash {
                return Err(MpcError::InvalidMessage {
                    sender,
                    reason: "Dealer sent different messages".to_string(),
                });
            }
            if let Some(response) = self.message_responses.get(&sender) {
                return Ok(response.clone());
            }
            return Err(MpcError::InvalidMessage {
                sender,
                reason: "Message previously rejected due to invalid shares".to_string(),
            });
        }
        let signature = match &request.messages {
            Messages::Dkg(msg) => {
                self.store_dkg_message(sender, msg)?;
                self.try_sign_dkg_message(sender, &request.messages)?
            }
            Messages::Rotation(msgs) => {
                let previous = self
                    .previous_output
                    .clone()
                    .ok_or_else(|| MpcError::ProtocolFailed("Rotation not started".into()))?;
                self.store_rotation_messages(sender, msgs)?;
                self.try_sign_rotation_messages(&previous, sender, &request.messages)?
            }
            Messages::NonceGeneration { .. } => {
                self.store_nonce_message(sender, &request.messages);
                self.try_sign_nonce_message(sender, &request.messages)?
            }
        };
        let response = SendMessagesResponse { signature };
        self.message_responses.insert(sender, response.clone());
        Ok(response)
    }

    pub fn handle_retrieve_messages_request(
        &self,
        request: &RetrieveMessagesRequest,
    ) -> MpcResult<RetrieveMessagesResponse> {
        let messages = self
            .dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| MpcError::NotFound(format!("Messages for dealer {:?}", request.dealer)))?
            .clone();
        Ok(RetrieveMessagesResponse { messages })
    }

    pub fn handle_complain_request(
        &mut self,
        request: &ComplainRequest,
    ) -> MpcResult<ComplaintResponses> {
        // It is safe to return a response from cache since we already know that dealer was malicious.
        if let Some(cached_response) = self.complaint_responses.get(&request.dealer) {
            return Ok(cached_response.clone());
        }
        let messages = self
            .dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No message from dealer".into()))?;
        let responses = match messages {
            Messages::Dkg(message) => {
                let partial_output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Dkg(request.dealer))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed("No output for complained dealer".into())
                    })?;
                let session_id = self.session_id.dealer_session_id(&request.dealer);
                let receiver = avss::Receiver::new(
                    self.dkg_config.nodes.clone(),
                    self.party_id,
                    self.dkg_config.threshold,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                );
                let complaint_response =
                    receiver.handle_complaint(message, &request.complaint, partial_output)?;
                ComplaintResponses::Dkg(complaint_response)
            }
            Messages::Rotation(rotation_messages) => {
                let previous_output = self.previous_output.as_ref().ok_or_else(|| {
                    MpcError::ProtocolFailed("No previous DKG output for rotation".into())
                })?;
                let complained_share_index = request.share_index.ok_or_else(|| {
                    MpcError::ProtocolFailed("Rotation complaint requires share_index".into())
                })?;
                let complained_message = rotation_messages
                    .get(&complained_share_index)
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation message for complained share_index {}",
                            complained_share_index
                        ))
                    })?;
                let complained_output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Rotation(complained_share_index))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed("No output for complained share".into())
                    })?;
                let commitment = previous_output
                    .commitments
                    .get(&complained_share_index)
                    .copied();
                let session_id = self
                    .session_id
                    .rotation_session_id(&request.dealer, complained_share_index);
                let receiver = avss::Receiver::new(
                    self.dkg_config.nodes.clone(),
                    self.party_id,
                    self.dkg_config.threshold,
                    session_id.to_vec(),
                    commitment,
                    self.encryption_key.clone(),
                );
                let complained_response = receiver.handle_complaint(
                    complained_message,
                    &request.complaint,
                    complained_output,
                )?;
                let mut responses = BTreeMap::new();
                for &share_index in rotation_messages.keys() {
                    let response = if share_index == complained_share_index {
                        complained_response.clone()
                    } else if let Some(output) = self
                        .dealer_outputs
                        .get(&DealerOutputsKey::Rotation(share_index))
                    {
                        complaint::ComplaintResponse::new(self.party_id, output.my_shares.clone())
                    } else {
                        continue;
                    };
                    responses.insert(share_index, response);
                }
                ComplaintResponses::Rotation(responses)
            }
            Messages::NonceGeneration {
                batch_index,
                message,
            } => {
                let nonce_output =
                    self.dealer_nonce_outputs
                        .get(&request.dealer)
                        .ok_or_else(|| {
                            MpcError::ProtocolFailed("No nonce output for complained dealer".into())
                        })?;
                let receiver = self.create_nonce_receiver(request.dealer, *batch_index)?;
                let complaint_response =
                    receiver.handle_complaint(message, &request.complaint, nonce_output)?;
                ComplaintResponses::NonceGeneration(complaint_response)
            }
        };
        self.complaint_responses
            .insert(request.dealer, responses.clone());
        Ok(responses)
    }

    pub fn handle_get_public_dkg_output_request(
        &self,
        request: &GetPublicDkgOutputRequest,
    ) -> MpcResult<GetPublicDkgOutputResponse> {
        let previous_epoch = self
            .dkg_config
            .epoch
            .checked_sub(1)
            .ok_or_else(|| MpcError::InvalidConfig("no previous epoch exists".to_string()))?;
        if request.epoch != previous_epoch {
            return Err(MpcError::NotFound(format!(
                "no DKG output for epoch {} (current epoch is {})",
                request.epoch, self.dkg_config.epoch
            )));
        }
        let output = self.previous_output.as_ref().ok_or_else(|| {
            MpcError::NotFound(format!(
                "DKG output for epoch {} not yet available",
                request.epoch
            ))
        })?;
        Ok(GetPublicDkgOutputResponse {
            output: PublicDkgOutput::from_dkg_output(output),
        })
    }

    // TODO: Consider making dealer and party flows concurrent
    pub async fn run(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<DkgOutput> {
        let threshold = {
            let mgr = mpc_manager.read().unwrap();
            mgr.dkg_config.threshold
        };
        if tob_channel.existing_certificate_weight() < threshold as u32
            && let Err(e) = Self::run_as_dealer(mpc_manager, p2p_channel, tob_channel).await
        {
            tracing::error!("Dealer phase failed: {}. Continuing as party only.", e);
        }
        Self::run_as_party(mpc_manager, p2p_channel, tob_channel).await
    }

    pub async fn run_key_rotation(
        mpc_manager: &Arc<RwLock<Self>>,
        previous_certificates: &[CertificateV1],
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<DkgOutput> {
        let (previous, is_member_of_previous_committee) =
            Self::prepare_previous_output(mpc_manager, previous_certificates, p2p_channel).await?;
        {
            let mut mgr = mpc_manager.write().unwrap();
            mgr.previous_output = Some(previous.clone());
            // Clear DKG entries inserted by reconstruct_from_dkg_certificates.
            // Without this, handle_send_messages_request rejects incoming
            // rotation messages due to hash mismatch with stale DKG entries.
            mgr.dealer_messages.clear();
            mgr.dealer_outputs.clear();
            mgr.complaints_to_process.clear();
            mgr.message_responses.clear();
            mgr.complaint_responses.clear();
            // Reload rotation messages from DB for restart recovery.
            // For live rotation this is a no-op (no messages stored yet).
            // For restart, this restores rotation messages that were
            // loaded in the constructor but wiped by the clear above.
            for (dealer, message) in mgr
                .public_messages_store
                .list_all_rotation_messages()
                .map_err(|e| MpcError::StorageError(e.to_string()))?
            {
                mgr.dealer_messages.insert(dealer, message);
            }
        }
        if is_member_of_previous_committee {
            // TODO(Optimization): Skip dealer phase if enough rotation certificates already exist.
            if let Err(e) = Self::run_key_rotation_as_dealer(
                mpc_manager,
                &previous,
                p2p_channel,
                ordered_broadcast_channel,
            )
            .await
            {
                tracing::error!(
                    "Rotation dealer phase failed: {}. Continuing as party only.",
                    e
                );
            }
        }
        Self::run_key_rotation_as_party(
            mpc_manager,
            &previous,
            p2p_channel,
            ordered_broadcast_channel,
        )
        .await
    }

    pub async fn run_nonce_generation(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<Vec<batch_avss::ReceiverOutput>> {
        // Clear stale state from previous batch.
        {
            let mut mgr = mpc_manager.write().unwrap();
            mgr.dealer_nonce_outputs.clear();
            mgr.dealer_messages.clear();
            mgr.dealer_outputs.clear();
            mgr.complaints_to_process.clear();
            mgr.message_responses.clear();
            mgr.complaint_responses.clear();
        }
        if let Err(e) =
            Self::run_as_nonce_dealer(mpc_manager, batch_index, p2p_channel, tob_channel).await
        {
            tracing::error!(
                "Nonce dealer phase failed: {}. Continuing as party only.",
                e
            );
        }
        // Clear nonce outputs accumulated by the RPC handler during the dealer
        // phase. The handler's `try_sign_nonce_message` stores outputs for
        // whichever dealer messages arrived, which is non-deterministic across
        // nodes. The party phase below re-derives outputs from certified on-chain
        // certificates, ensuring all nodes use the same deterministic set.
        {
            let mut mgr = mpc_manager.write().unwrap();
            mgr.dealer_nonce_outputs.clear();
        }
        Self::run_as_nonce_party(mpc_manager, p2p_channel, tob_channel).await?;
        let mut mgr = mpc_manager.write().unwrap();
        Ok(std::mem::take(&mut mgr.dealer_nonce_outputs)
            .into_values()
            .collect())
    }

    async fn run_as_dealer(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<()> {
        // TODO(Optimization): Skip dealer phase if certificate is already on TOB
        let dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_dealer_flow(&mut rng)
            })
            .await?
        };
        let mut aggregator =
            BlsSignatureAggregator::new(&dealer_data.committee, dealer_data.messages_hash.clone());
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    if let Err(e) = aggregator.add_signature_from(addr, response.signature) {
                        tracing::info!("Invalid signature from {:?}: {}", addr, e);
                    }
                }
                Err(e) => tracing::info!("Failed to send message to {:?}: {}", addr, e),
            }
        }
        if aggregator.weight() >= dealer_data.required_weight as u64 {
            let dkg_cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            let cert = CertificateV1::Dkg(dkg_cert);
            with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    async fn run_as_party(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<DkgOutput> {
        let threshold = {
            let mgr = mpc_manager.read().unwrap();
            mgr.dkg_config.threshold
        };
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= threshold as u32 {
                break;
            }
            let cert = tob_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            let CertificateV1::Dkg(dkg_cert) = cert else {
                continue;
            };
            let message = dkg_cert.message();
            let dealer = message.dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            {
                let mgr = Arc::clone(mpc_manager);
                let cert = dkg_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                if let Err(e) = verified {
                    tracing::info!("Invalid certificate signature from {:?}: {}", &dealer, e);
                    continue;
                }
            }
            let needs_retrieval = {
                let mgr = mpc_manager.read().unwrap();
                match mgr.dealer_messages.get(&dealer) {
                    None => true,
                    Some(stored_msg) => compute_messages_hash(stored_msg) != message.messages_hash,
                }
            };
            if needs_retrieval {
                tracing::info!(
                    "Certificate from dealer {:?} received but message missing or hash mismatch, retrieving from signers",
                    &dealer
                );
                Self::retrieve_dealer_message(mpc_manager, message, &dkg_cert, p2p_channel)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to retrieve message from any signer for dealer {:?}: {}. Certificate exists but message unavailable from all signers.",
                            &dealer,
                            e
                        );
                        e
                    })?;
            }
            let has_complaint = {
                let mgr = Arc::clone(mpc_manager);
                spawn_blocking(move || {
                    let mut mgr = mgr.write().unwrap();
                    if !mgr
                        .dealer_outputs
                        .contains_key(&DealerOutputsKey::Dkg(dealer))
                        && !mgr
                            .complaints_to_process
                            .contains_key(&ComplaintsToProcessKey::Dkg(dealer))
                    {
                        mgr.process_certified_dkg_message(dealer)?;
                    }
                    Ok::<_, MpcError>(
                        mgr.complaints_to_process
                            .contains_key(&ComplaintsToProcessKey::Dkg(dealer)),
                    )
                })
                .await?
            };
            if has_complaint {
                let signers = {
                    let mgr = mpc_manager.read().unwrap();
                    dkg_cert
                        .signers(&mgr.committee)
                        .expect("certificate verified above")
                };
                Self::recover_shares_via_complaint(mpc_manager, &dealer, signers, p2p_channel)
                    .await?;
            }
            let dealer_weight = {
                let mgr = mpc_manager.read().unwrap();
                if !mgr
                    .dealer_outputs
                    .contains_key(&DealerOutputsKey::Dkg(dealer))
                {
                    tracing::warn!("No dealer output for {:?} after processing", dealer);
                    continue;
                }
                // Use the reduced weights (after `Nodes::new_reduced`), not the original committee weights.
                let party_id = mgr
                    .committee
                    .index_of(&dealer)
                    .expect("dealer must be in committee") as u16;
                mgr.dkg_config
                    .nodes
                    .weight_of(party_id)
                    .map_err(|_| MpcError::ProtocolFailed("Missing dealer weight".to_string()))?
            };
            dealer_weight_sum += dealer_weight as u32;
            certified_dealers.insert(dealer);
        }
        let output = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mgr = mgr.read().unwrap();
                mgr.complete_dkg(certified_dealers.into_iter())
            })
            .await?
        };
        Ok(output)
    }

    async fn run_key_rotation_as_dealer(
        mpc_manager: &Arc<RwLock<Self>>,
        previous: &DkgOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<()> {
        // TODO(Optimization): Skip dealer phase if certificate is already on TOB
        let dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            let previous = previous.clone();
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_rotation_dealer_flow(&previous, &mut rng)
            })
            .await?
        };
        let mut aggregator =
            BlsSignatureAggregator::new(&dealer_data.committee, dealer_data.messages_hash.clone());
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    if let Err(e) = aggregator.add_signature_from(addr, response.signature.clone())
                    {
                        tracing::info!("Invalid rotation signature from {:?}: {}", addr, e);
                    }
                }
                Err(e) => {
                    tracing::info!("Failed to send rotation messages to {:?}: {}", addr, e)
                }
            }
        }
        if aggregator.weight() >= dealer_data.required_weight as u64 {
            let rotation_cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            let cert = CertificateV1::Rotation(rotation_cert);
            with_timeout_and_retry(|| ordered_broadcast_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    async fn run_key_rotation_as_party(
        mpc_manager: &Arc<RwLock<Self>>,
        previous: &DkgOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<DkgOutput> {
        let mut certified_share_indices: Vec<ShareIndex> = {
            let mgr = mpc_manager.read().unwrap();
            mgr.dealer_outputs
                .keys()
                .filter_map(|k| match k {
                    DealerOutputsKey::Rotation(idx) => Some(*idx),
                    DealerOutputsKey::Dkg(_) => None,
                })
                .collect()
        };
        let mut certified_dealers = HashSet::new();
        loop {
            if certified_share_indices.len() >= previous.threshold as usize {
                break;
            }
            let cert = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            let CertificateV1::Rotation(rotation_cert) = cert else {
                continue;
            };
            let message = rotation_cert.message();
            let dealer = message.dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            {
                let mgr = Arc::clone(mpc_manager);
                let cert = rotation_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                if let Err(e) = verified {
                    tracing::info!(
                        "Invalid rotation certificate signature from {:?}: {}",
                        &dealer,
                        e
                    );
                    continue;
                }
            }
            let dealer_share_indices = {
                let mgr = mpc_manager.read().unwrap();
                let previous_nodes = mgr.previous_nodes.as_ref().ok_or_else(|| {
                    MpcError::InvalidConfig("Key rotation requires previous nodes".into())
                })?;
                let previous_committee = mgr.previous_committee.as_ref().ok_or_else(|| {
                    MpcError::InvalidConfig("Key rotation requires previous committee".into())
                })?;
                let dealer_party_id = previous_committee.index_of(&dealer).ok_or_else(|| {
                    MpcError::InvalidMessage {
                        sender: dealer,
                        reason: "Dealer not in previous committee".into(),
                    }
                })? as u16;
                previous_nodes.share_ids_of(dealer_party_id).map_err(|_| {
                    MpcError::InvalidMessage {
                        sender: dealer,
                        reason: "Dealer has no shares in previous committee".into(),
                    }
                })?
            };
            let needs_retrieval = {
                let mgr = mpc_manager.read().unwrap();
                match mgr.dealer_messages.get(&dealer) {
                    None => true,
                    Some(stored_msgs) => {
                        compute_messages_hash(stored_msgs) != message.messages_hash
                    }
                }
            };
            if needs_retrieval {
                tracing::info!(
                    "Rotation messages from dealer {:?} not available or hash mismatch, retrieving from signers",
                    dealer
                );
                Self::retrieve_rotation_messages(mpc_manager, message, &rotation_cert, p2p_channel)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to retrieve rotation messages for dealer {:?}: {}",
                            dealer,
                            e
                        );
                        e
                    })?;
            }
            {
                let mgr = Arc::clone(mpc_manager);
                let previous = previous.clone();
                let share_indices = dealer_share_indices.clone();
                spawn_blocking(move || {
                    let mut mgr = mgr.write().unwrap();
                    if share_indices.iter().any(|idx| {
                        !mgr.dealer_outputs
                            .contains_key(&DealerOutputsKey::Rotation(*idx))
                            && !mgr
                                .complaints_to_process
                                .contains_key(&ComplaintsToProcessKey::Rotation(dealer, *idx))
                    }) {
                        mgr.process_certified_rotation_message(&dealer, &previous)?;
                    }
                    Ok::<_, MpcError>(())
                })
                .await?;
            }
            let signers = {
                let mgr = mpc_manager.read().unwrap();
                rotation_cert
                    .signers(&mgr.committee)
                    .expect("certificate verified above")
            };
            Self::recover_rotation_shares_via_complaints(
                mpc_manager,
                &dealer,
                previous,
                signers,
                p2p_channel,
            )
            .await?;
            // Only add indices not already tracked (avoids duplicates when
            // the dealer phase already stored outputs for this node's own shares).
            for idx in dealer_share_indices {
                if !certified_share_indices.contains(&idx) {
                    certified_share_indices.push(idx);
                }
            }
            certified_dealers.insert(dealer);
        }
        let output = {
            let mgr = Arc::clone(mpc_manager);
            let previous = previous.clone();
            spawn_blocking(move || {
                let mut mgr = mgr.write().unwrap();
                mgr.complete_key_rotation(&previous, &certified_share_indices)
            })
            .await?
        };
        Ok(output)
    }

    async fn run_as_nonce_dealer(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<()> {
        let dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_nonce_dealer_flow(batch_index, &mut rng)
            })
            .await?
        };
        let mut aggregator =
            BlsSignatureAggregator::new(&dealer_data.committee, dealer_data.messages_hash.clone());
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    if let Err(e) = aggregator.add_signature_from(addr, response.signature) {
                        tracing::info!("Invalid signature from {:?}: {}", addr, e);
                    }
                }
                Err(e) => tracing::info!("Failed to send nonce message to {:?}: {}", addr, e),
            }
        }
        if aggregator.weight() >= dealer_data.required_weight as u64 {
            let nonce_cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            let cert = CertificateV1::NonceGeneration {
                batch_index,
                cert: nonce_cert,
            };
            with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    async fn run_as_nonce_party(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<()> {
        let required_weight = {
            let mgr = mpc_manager.read().unwrap();
            2 * mgr.dkg_config.max_faulty + 1
        };
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= required_weight as u32 {
                break;
            }
            let cert = tob_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            let CertificateV1::NonceGeneration {
                cert: nonce_cert, ..
            } = cert
            else {
                continue;
            };
            let message = nonce_cert.message();
            let dealer = message.dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            {
                let mgr = Arc::clone(mpc_manager);
                let cert = nonce_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                if let Err(e) = verified {
                    tracing::info!(
                        "Invalid nonce certificate signature from {:?}: {}",
                        &dealer,
                        e
                    );
                    continue;
                }
            }
            let needs_retrieval = {
                let mgr = mpc_manager.read().unwrap();
                match mgr.dealer_messages.get(&dealer) {
                    None => true,
                    Some(stored_msg) => compute_messages_hash(stored_msg) != message.messages_hash,
                }
            };
            if needs_retrieval {
                tracing::info!(
                    "Nonce certificate from dealer {:?} received but message missing or hash mismatch, retrieving from signers",
                    &dealer
                );
                Self::retrieve_nonce_message(mpc_manager, message, &nonce_cert, p2p_channel)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to retrieve nonce message from any signer for dealer {:?}: {}",
                            &dealer,
                            e
                        );
                        e
                    })?;
            }
            let has_complaint = {
                let mgr = Arc::clone(mpc_manager);
                spawn_blocking(move || {
                    let mut mgr = mgr.write().unwrap();
                    if !mgr.dealer_nonce_outputs.contains_key(&dealer)
                        && !mgr
                            .complaints_to_process
                            .contains_key(&ComplaintsToProcessKey::NonceGeneration(dealer))
                    {
                        mgr.process_certified_nonce_message(dealer)?;
                    }
                    Ok::<_, MpcError>(
                        mgr.complaints_to_process
                            .contains_key(&ComplaintsToProcessKey::NonceGeneration(dealer)),
                    )
                })
                .await?
            };
            if has_complaint {
                let signers = {
                    let mgr = mpc_manager.read().unwrap();
                    nonce_cert
                        .signers(&mgr.committee)
                        .expect("certificate verified above")
                };
                Self::recover_nonce_shares_via_complaint(
                    mpc_manager,
                    &dealer,
                    signers,
                    p2p_channel,
                )
                .await?;
            }
            let dealer_weight = {
                let mgr = mpc_manager.read().unwrap();
                if !mgr.dealer_nonce_outputs.contains_key(&dealer) {
                    tracing::warn!("No nonce output for {:?} after processing", dealer);
                    continue;
                }
                let party_id = mgr
                    .committee
                    .index_of(&dealer)
                    .expect("dealer must be in committee") as u16;
                mgr.dkg_config
                    .nodes
                    .weight_of(party_id)
                    .map_err(|_| MpcError::ProtocolFailed("Missing dealer weight".to_string()))?
            };
            dealer_weight_sum += dealer_weight as u32;
            certified_dealers.insert(dealer);
        }
        Ok(())
    }

    fn create_dealer_message(
        &self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> avss::Message {
        let dealer_session_id = self.session_id.dealer_session_id(&self.address);
        let dealer = avss::Dealer::new(
            None,
            self.dkg_config.nodes.clone(),
            self.dkg_config.threshold,
            self.dkg_config.max_faulty,
            dealer_session_id.to_vec(),
        )
        .expect("checked threshold above");
        dealer.create_message(rng)
    }

    fn store_dkg_message(&mut self, dealer: Address, message: &avss::Message) -> MpcResult<()> {
        self.dealer_messages
            .insert(dealer, Messages::Dkg(message.clone()));
        self.public_messages_store
            .store_dealer_message(&dealer, message)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn store_rotation_messages(
        &mut self,
        dealer: Address,
        messages: &RotationMessages,
    ) -> MpcResult<()> {
        self.dealer_messages
            .insert(dealer, Messages::Rotation(messages.clone()));
        self.public_messages_store
            .store_rotation_messages(&dealer, messages)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn store_nonce_message(&mut self, dealer: Address, messages: &Messages) {
        // TODO: Persist nonce messages to DB for restart recovery.
        self.dealer_messages.insert(dealer, messages.clone());
    }

    fn try_sign_dkg_message(
        &mut self,
        dealer: Address,
        messages: &Messages,
    ) -> MpcResult<BLS12381Signature> {
        let message = match messages {
            Messages::Dkg(msg) => msg,
            Messages::Rotation(_) | Messages::NonceGeneration { .. } => {
                panic!("try_sign_dkg_message called with non-DKG messages")
            }
        };
        let dealer_session_id = self.session_id.dealer_session_id(&dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None, // commitment: None for initial DKG
            self.encryption_key.clone(),
        );
        let result = receiver.process_message(message)?;
        match result {
            avss::ProcessedMessage::Valid(output) => {
                self.dealer_outputs
                    .insert(DealerOutputsKey::Dkg(dealer), output);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer,
                    messages_hash: compute_messages_hash(messages),
                };
                let signature =
                    self.signing_key
                        .sign(self.dkg_config.epoch, self.address, &dkg_message);
                Ok(signature.signature().clone())
            }
            avss::ProcessedMessage::Complaint(_) => Err(MpcError::InvalidMessage {
                sender: dealer,
                reason: "Invalid shares".to_string(),
            }),
        }
    }

    fn create_nonce_receiver(
        &self,
        dealer: Address,
        batch_index: u32,
    ) -> MpcResult<batch_avss::Receiver> {
        let dealer_party_id =
            self.committee
                .index_of(&dealer)
                .ok_or_else(|| MpcError::InvalidMessage {
                    sender: dealer,
                    reason: "Dealer not in committee".into(),
                })? as u16;
        let dealer_session_id = SessionId::nonce_dealer_session_id(
            &self.chain_id,
            self.dkg_config.epoch,
            batch_index,
            &dealer,
        );
        batch_avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            dealer_party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            self.encryption_key.clone(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn create_nonce_dealer_message(
        &self,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<Messages> {
        let dealer_sid = SessionId::nonce_dealer_session_id(
            &self.chain_id,
            self.dkg_config.epoch,
            batch_index,
            &self.address,
        );
        let dealer = batch_avss::Dealer::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            self.dkg_config.max_faulty,
            dealer_sid.to_vec(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        let message = dealer
            .create_message(rng)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        Ok(Messages::NonceGeneration {
            batch_index,
            message,
        })
    }

    fn try_sign_nonce_message(
        &mut self,
        dealer: Address,
        messages: &Messages,
    ) -> MpcResult<BLS12381Signature> {
        let (batch_index, message) = match messages {
            Messages::NonceGeneration {
                batch_index,
                message,
            } => (*batch_index, message),
            Messages::Dkg(_) | Messages::Rotation(_) => {
                panic!("try_sign_nonce_message called with non-nonce messages")
            }
        };
        let receiver = self.create_nonce_receiver(dealer, batch_index)?;
        let result = receiver.process_message(message)?;
        match result {
            batch_avss::ProcessedMessage::Valid(output) => {
                self.dealer_nonce_outputs.insert(dealer, output);
                let nonce_message = DealerMessagesHash {
                    dealer_address: dealer,
                    messages_hash: compute_messages_hash(messages),
                };
                let signature =
                    self.signing_key
                        .sign(self.dkg_config.epoch, self.address, &nonce_message);
                Ok(signature.signature().clone())
            }
            batch_avss::ProcessedMessage::Complaint(_) => Err(MpcError::InvalidMessage {
                sender: dealer,
                reason: "Invalid nonce shares".to_string(),
            }),
        }
    }

    fn process_certified_dkg_message(&mut self, dealer: Address) -> MpcResult<()> {
        let output_key = DealerOutputsKey::Dkg(dealer);
        let complaint_key = ComplaintsToProcessKey::Dkg(dealer);
        let message = match self
            .dealer_messages
            .get(&dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No message for dealer".into()))?
        {
            Messages::Dkg(msg) => msg.clone(),
            Messages::Rotation(_) | Messages::NonceGeneration { .. } => {
                panic!("process_certified_dkg_message called with non-DKG messages")
            }
        };
        let session_id = self.session_id.dealer_session_id(&dealer).to_vec();
        self.process_and_store_message(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            session_id,
            &message,
            None,
            output_key,
            complaint_key,
        )
    }

    fn process_certified_nonce_message(&mut self, dealer: Address) -> MpcResult<()> {
        let (batch_index, message) = match self
            .dealer_messages
            .get(&dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No message for dealer".into()))?
        {
            Messages::NonceGeneration {
                batch_index,
                message,
            } => (*batch_index, message.clone()),
            Messages::Dkg(_) | Messages::Rotation(_) => {
                panic!("process_certified_nonce_message called with non-nonce messages")
            }
        };
        let dealer_party_id =
            self.committee
                .index_of(&dealer)
                .ok_or_else(|| MpcError::InvalidMessage {
                    sender: dealer,
                    reason: "Dealer not in committee".into(),
                })? as u16;
        let dealer_sid = SessionId::nonce_dealer_session_id(
            &self.chain_id,
            self.dkg_config.epoch,
            batch_index,
            &dealer,
        );
        let receiver = batch_avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            dealer_party_id,
            self.dkg_config.threshold,
            dealer_sid.to_vec(),
            self.encryption_key.clone(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        match receiver.process_message(&message)? {
            batch_avss::ProcessedMessage::Valid(output) => {
                self.dealer_nonce_outputs.insert(dealer, output);
            }
            batch_avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints_to_process
                    .insert(ComplaintsToProcessKey::NonceGeneration(dealer), complaint);
            }
        }
        Ok(())
    }

    fn process_certified_rotation_message(
        &mut self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
    ) -> MpcResult<()> {
        let rotation_messages = match self
            .dealer_messages
            .get(dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No rotation messages for dealer".into()))?
        {
            Messages::Rotation(msgs) => msgs.clone(),
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("process_certified_rotation_message called with non-rotation messages")
            }
        };
        for (share_index, message) in rotation_messages {
            let output_key = DealerOutputsKey::Rotation(share_index);
            let complaint_key = ComplaintsToProcessKey::Rotation(*dealer, share_index);
            if self.dealer_outputs.contains_key(&output_key)
                || self.complaints_to_process.contains_key(&complaint_key)
            {
                continue;
            }
            let session_id = self
                .session_id
                .rotation_session_id(dealer, share_index)
                .to_vec();
            let commitment = previous_dkg_output.commitments.get(&share_index).copied();
            self.process_and_store_message(
                self.dkg_config.nodes.clone(),
                self.party_id,
                self.dkg_config.threshold,
                session_id,
                &message,
                commitment,
                output_key,
                complaint_key,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_and_store_message(
        &mut self,
        nodes: Nodes<EncryptionGroupElement>,
        party_id: u16,
        threshold: u16,
        session_id: Vec<u8>,
        message: &avss::Message,
        commitment: Option<G>,
        output_key: DealerOutputsKey,
        complaint_key: ComplaintsToProcessKey,
    ) -> MpcResult<()> {
        let receiver = avss::Receiver::new(
            nodes,
            party_id,
            threshold,
            session_id,
            commitment,
            self.encryption_key.clone(),
        );
        match receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => {
                self.dealer_outputs.insert(output_key, output);
            }
            avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints_to_process.insert(complaint_key, complaint);
            }
        }
        Ok(())
    }

    fn complete_dkg(
        &self,
        certified_dealers: impl Iterator<Item = Address>,
    ) -> MpcResult<DkgOutput> {
        let threshold = self.dkg_config.threshold;
        let outputs: HashMap<PartyId, avss::PartialOutput> = certified_dealers
            .map(|dealer| {
                let dealer_party_id = self
                    .committee
                    .index_of(&dealer)
                    .expect("certified dealer must be committee member")
                    as u16;
                let output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Dkg(dealer))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No dealer output found for dealer: {:?}.",
                            dealer
                        ))
                    })?
                    .clone();
                Ok((dealer_party_id, output))
            })
            .collect::<Result<_, MpcError>>()?;
        let combined_output =
            avss::ReceiverOutput::complete_dkg(threshold, &self.dkg_config.nodes, outputs)
                .expect(EXPECT_THRESHOLD_MET);
        Ok(DkgOutput {
            public_key: combined_output.vk,
            key_shares: combined_output.my_shares,
            commitments: combined_output
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold,
        })
    }

    async fn retrieve_dealer_message(
        mpc_manager: &Arc<RwLock<Self>>,
        message: &DealerMessagesHash,
        certificate: &DealerCertificate,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (request, signers) = {
            let mgr = mpc_manager.read().unwrap();
            if certificate
                .is_signer(&mgr.address, &mgr.committee)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?
            {
                tracing::error!(
                    "Self in certificate signers but message not available for dealer {:?}.",
                    message.dealer_address
                );
                return Err(MpcError::ProtocolFailed(
                    "Self in certificate signers but message not available".to_string(),
                ));
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
            };
            let signers = certificate
                .signers(&mgr.committee)
                .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?;
            (request, signers)
        };
        // TODO: Implement gradual escalation strategy for better network efficiency:
        // - Round 1: Call 1-2 random signers, wait ~2s
        // - Round 2: Call 2-3 more signers, wait ~2s
        // - and so on
        for signer in signers {
            match p2p_channel.retrieve_messages(&signer, &request).await {
                Ok(response) => {
                    if compute_messages_hash(&response.messages) == message.messages_hash {
                        let Messages::Dkg(msg) = &response.messages else {
                            unreachable!(
                                "Hash matched DKG certificate but got {:?}",
                                std::mem::discriminant(&response.messages)
                            );
                        };
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.store_dkg_message(message.dealer_address, msg)?;
                        return Ok(());
                    }
                    tracing::info!(
                        "Message hash mismatch from signer {:?} for dealer {:?}",
                        signer,
                        message.dealer_address
                    );
                }
                Err(e) => {
                    tracing::info!("Failed to retrieve message from signer {:?}: {}", signer, e);
                }
            }
        }
        Err(MpcError::PairwiseCommunicationError(format!(
            "Could not retrieve message for dealer {:?} from any signer",
            message.dealer_address
        )))
    }

    async fn retrieve_nonce_message(
        mpc_manager: &Arc<RwLock<Self>>,
        message: &DealerMessagesHash,
        certificate: &DealerCertificate,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (request, signers) = {
            let mgr = mpc_manager.read().unwrap();
            if certificate
                .is_signer(&mgr.address, &mgr.committee)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?
            {
                tracing::error!(
                    "Self in certificate signers but nonce message not available for dealer {:?}.",
                    message.dealer_address
                );
                return Err(MpcError::ProtocolFailed(
                    "Self in certificate signers but nonce message not available".to_string(),
                ));
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
            };
            let signers = certificate
                .signers(&mgr.committee)
                .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?;
            (request, signers)
        };
        for signer in signers {
            match p2p_channel.retrieve_messages(&signer, &request).await {
                Ok(response) => {
                    if compute_messages_hash(&response.messages) == message.messages_hash {
                        let Messages::NonceGeneration { .. } = &response.messages else {
                            unreachable!(
                                "Hash matched nonce certificate but got {:?}",
                                std::mem::discriminant(&response.messages)
                            );
                        };
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.store_nonce_message(message.dealer_address, &response.messages);
                        return Ok(());
                    }
                    tracing::info!(
                        "Message hash mismatch from signer {:?} for nonce dealer {:?}",
                        signer,
                        message.dealer_address
                    );
                }
                Err(e) => {
                    tracing::info!(
                        "Failed to retrieve nonce message from signer {:?}: {}",
                        signer,
                        e
                    );
                }
            }
        }
        Err(MpcError::PairwiseCommunicationError(format!(
            "Could not retrieve nonce message for dealer {:?} from any signer",
            message.dealer_address
        )))
    }

    fn prepare_dealer_flow(
        &mut self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.dealer_messages.get(&self.address) {
            Some(msgs @ Messages::Dkg(_)) => msgs.clone(),
            _ => {
                let msg = self.create_dealer_message(rng);
                self.store_dkg_message(self.address, &msg)?;
                Messages::Dkg(msg)
            }
        };
        let signature = self.try_sign_dkg_message(self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn prepare_rotation_dealer_flow(
        &mut self,
        previous: &DkgOutput,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.dealer_messages.get(&self.address) {
            Some(msgs @ Messages::Rotation(_)) => msgs.clone(),
            _ => {
                let msgs = self.create_rotation_messages(previous, rng);
                self.store_rotation_messages(self.address, &msgs)?;
                Messages::Rotation(msgs)
            }
        };
        let signature = self.try_sign_rotation_messages(previous, self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn prepare_nonce_dealer_flow(
        &mut self,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.dealer_messages.get(&self.address) {
            Some(msgs @ Messages::NonceGeneration { .. }) => msgs.clone(),
            _ => {
                let msgs = self.create_nonce_dealer_message(batch_index, rng)?;
                self.store_nonce_message(self.address, &msgs);
                msgs
            }
        };
        let signature = self.try_sign_nonce_message(self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn build_dealer_flow_data(
        &self,
        messages: Messages,
        signature: BLS12381Signature,
    ) -> DealerFlowData {
        let my_signature = MemberSignature::new(self.dkg_config.epoch, self.address, signature);
        let messages_hash = DealerMessagesHash {
            dealer_address: self.address,
            messages_hash: compute_messages_hash(&messages),
        };
        let recipients: Vec<_> = self
            .committee
            .members()
            .iter()
            .map(|m| m.validator_address())
            .filter(|addr| *addr != self.address)
            .collect();
        let required_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        let request = SendMessagesRequest { messages };
        DealerFlowData {
            request,
            recipients,
            messages_hash,
            my_signature,
            required_weight,
            committee: self.committee.clone(),
        }
    }

    async fn retrieve_rotation_messages(
        mpc_manager: &Arc<RwLock<Self>>,
        message: &DealerMessagesHash,
        certificate: &DealerCertificate,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (request, signers) = {
            let mgr = mpc_manager.read().unwrap();
            if certificate
                .is_signer(&mgr.address, &mgr.committee)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?
            {
                tracing::error!(
                    "Self in certificate signers but rotation messages not available for dealer {:?}.",
                    message.dealer_address
                );
                return Err(MpcError::ProtocolFailed(
                    "Self in certificate signers but rotation messages not available".to_string(),
                ));
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
            };
            let signers = certificate.signers(&mgr.committee).map_err(|_| {
                MpcError::ProtocolFailed(
                    "Certificate does not match the current epoch or committee".to_string(),
                )
            })?;
            (request, signers)
        };
        for signer in signers {
            match p2p_channel.retrieve_messages(&signer, &request).await {
                Ok(response) => {
                    if compute_messages_hash(&response.messages) == message.messages_hash {
                        let Messages::Rotation(msgs) = &response.messages else {
                            tracing::info!(
                                "Hash matched rotation certificate but got DKG message from {:?}",
                                signer
                            );
                            continue;
                        };
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.store_rotation_messages(message.dealer_address, msgs)?;
                        return Ok(());
                    }
                    tracing::info!(
                        "Message hash mismatch from signer {:?} for dealer {:?}",
                        signer,
                        message.dealer_address
                    );
                }
                Err(e) => {
                    tracing::info!(
                        "Failed to retrieve rotation messages from {:?}: {}",
                        signer,
                        e
                    );
                }
            }
        }
        Err(MpcError::PairwiseCommunicationError(
            "Failed to retrieve rotation messages from any signer".to_string(),
        ))
    }

    async fn recover_shares_via_complaint(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: &Address,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (complaint_request, receiver, message) = {
            let mgr = mpc_manager.read().unwrap();
            let complaint = mgr
                .complaints_to_process
                .get(&ComplaintsToProcessKey::Dkg(*dealer))
                .ok_or_else(|| MpcError::ProtocolFailed("No complaint for dealer".into()))?;
            let complaint_request = ComplainRequest {
                dealer: *dealer,
                share_index: None,
                complaint: complaint.clone(),
            };
            let dealer_session_id = mgr.session_id.dealer_session_id(dealer);
            let receiver = avss::Receiver::new(
                mgr.dkg_config.nodes.clone(),
                mgr.party_id,
                mgr.dkg_config.threshold,
                dealer_session_id.to_vec(),
                None,
                mgr.encryption_key.clone(),
            );
            let messages = mgr
                .dealer_messages
                .get(dealer)
                .expect("cannot have complaint without message");
            let message = match messages {
                Messages::Dkg(msg) => msg.clone(),
                Messages::Rotation(_) | Messages::NonceGeneration { .. } => {
                    panic!("Expected DKG message in recover_shares_via_complaint");
                }
            };
            (complaint_request, receiver, message)
        };
        let receiver = Arc::new(receiver);
        let mut responses = Vec::new();
        for signer in signers {
            let response =
                match with_timeout_and_retry(|| p2p_channel.complain(&signer, &complaint_request))
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::info!("Complaint to {:?} failed: {}", signer, e);
                        continue;
                    }
                };
            let complaint_response = match response {
                ComplaintResponses::Dkg(resp) => resp,
                ComplaintResponses::Rotation(_) | ComplaintResponses::NonceGeneration(_) => {
                    tracing::info!("Unexpected non-DKG response in DKG complaint recovery");
                    continue;
                }
            };
            responses.push(complaint_response);
            let result = {
                let receiver = Arc::clone(&receiver);
                let message = message.clone();
                let responses = responses.clone();
                spawn_blocking(move || receiver.recover(&message, responses)).await
            };
            match result {
                Ok(partial_output) => {
                    let mut mgr = mpc_manager.write().unwrap();
                    mgr.dealer_outputs
                        .insert(DealerOutputsKey::Dkg(*dealer), partial_output);
                    mgr.complaints_to_process
                        .remove(&ComplaintsToProcessKey::Dkg(*dealer));
                    return Ok(());
                }
                Err(FastCryptoError::InputTooShort(_)) => {
                    continue;
                }
                Err(e) => {
                    let error_msg = format!("Share recovery failed for dealer {:?}: {}", dealer, e);
                    tracing::error!("{}", error_msg);
                    return Err(MpcError::CryptoError(error_msg));
                }
            }
        }
        Err(MpcError::ProtocolFailed(format!(
            "Not enough valid complaint responses for dealer {:?}",
            dealer
        )))
    }

    async fn recover_nonce_shares_via_complaint(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: &Address,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (complaint_request, receiver, message) = {
            let mgr = mpc_manager.read().unwrap();
            let complaint = mgr
                .complaints_to_process
                .get(&ComplaintsToProcessKey::NonceGeneration(*dealer))
                .ok_or_else(|| MpcError::ProtocolFailed("No nonce complaint for dealer".into()))?;
            let complaint_request = ComplainRequest {
                dealer: *dealer,
                share_index: None,
                complaint: complaint.clone(),
            };
            let (batch_index, message) = match mgr
                .dealer_messages
                .get(dealer)
                .expect("cannot have complaint without message")
            {
                Messages::NonceGeneration {
                    batch_index,
                    message,
                } => (*batch_index, message.clone()),
                Messages::Dkg(_) | Messages::Rotation(_) => {
                    panic!("Expected nonce message in recover_nonce_shares_via_complaint");
                }
            };
            let dealer_party_id = mgr
                .committee
                .index_of(dealer)
                .expect("dealer must be in committee") as u16;
            let dealer_sid = SessionId::nonce_dealer_session_id(
                &mgr.chain_id,
                mgr.dkg_config.epoch,
                batch_index,
                dealer,
            );
            let receiver = batch_avss::Receiver::new(
                mgr.dkg_config.nodes.clone(),
                mgr.party_id,
                dealer_party_id,
                mgr.dkg_config.threshold,
                dealer_sid.to_vec(),
                mgr.encryption_key.clone(),
                mgr.batch_size_per_weight,
            )
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
            (complaint_request, receiver, message)
        };
        let receiver = Arc::new(receiver);
        let mut responses = Vec::new();
        for signer in signers {
            let response =
                match with_timeout_and_retry(|| p2p_channel.complain(&signer, &complaint_request))
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::info!("Nonce complaint to {:?} failed: {}", signer, e);
                        continue;
                    }
                };
            let complaint_response = match response {
                ComplaintResponses::NonceGeneration(resp) => resp,
                ComplaintResponses::Dkg(_) | ComplaintResponses::Rotation(_) => {
                    tracing::info!("Unexpected non-nonce response in nonce complaint recovery");
                    continue;
                }
            };
            responses.push(complaint_response);
            let result = {
                let receiver = Arc::clone(&receiver);
                let message = message.clone();
                let responses = responses.clone();
                spawn_blocking(move || receiver.recover(&message, responses)).await
            };
            match result {
                Ok(output) => {
                    let mut mgr = mpc_manager.write().unwrap();
                    mgr.dealer_nonce_outputs.insert(*dealer, output);
                    mgr.complaints_to_process
                        .remove(&ComplaintsToProcessKey::NonceGeneration(*dealer));
                    return Ok(());
                }
                Err(FastCryptoError::InputTooShort(_)) => {
                    continue;
                }
                Err(e) => {
                    let error_msg =
                        format!("Nonce share recovery failed for dealer {:?}: {}", dealer, e);
                    tracing::error!("{}", error_msg);
                    return Err(MpcError::CryptoError(error_msg));
                }
            }
        }
        Err(MpcError::ProtocolFailed(format!(
            "Not enough valid nonce complaint responses for dealer {:?}",
            dealer
        )))
    }

    async fn recover_rotation_shares_via_complaints(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (request, recovery_contexts) = {
            let mgr = mpc_manager.read().unwrap();
            let Some(RotationComplainContext {
                request,
                recovery_contexts,
            }) = mgr.prepare_rotation_complain_request(dealer, previous_dkg_output)?
            else {
                return Ok(());
            };
            (request, recovery_contexts)
        };
        // Wrap receivers in Arc for use in `spawn_blocking` across loop iterations.
        let recovery_contexts: HashMap<ShareIndex, (Arc<avss::Receiver>, avss::Message)> =
            recovery_contexts
                .into_iter()
                .map(|(idx, (r, m))| (idx, (Arc::new(r), m)))
                .collect();
        let mut all_responses: HashMap<
            ShareIndex,
            Vec<complaint::ComplaintResponse<avss::SharesForNode>>,
        > = HashMap::new();
        let mut pending_shares: HashSet<ShareIndex> = HashSet::new();
        for &share_index in recovery_contexts.keys() {
            all_responses.insert(share_index, Vec::new());
            pending_shares.insert(share_index);
        }
        for signer in &signers {
            if pending_shares.is_empty() {
                break;
            }
            match p2p_channel.complain(signer, &request).await {
                Ok(response) => {
                    let rotation_responses = match response {
                        ComplaintResponses::Rotation(resps) => resps,
                        ComplaintResponses::Dkg(_) | ComplaintResponses::NonceGeneration(_) => {
                            tracing::info!(
                                "Unexpected non-rotation response in rotation complaint recovery"
                            );
                            continue;
                        }
                    };
                    for (share_index, share_response) in rotation_responses {
                        if let Some(responses) = all_responses.get_mut(&share_index) {
                            responses.push(share_response);
                        }
                    }
                    for share_index in pending_shares.clone() {
                        let responses = all_responses.get(&share_index).unwrap();
                        let (receiver, message) = recovery_contexts.get(&share_index).unwrap();
                        let result = {
                            let receiver = Arc::clone(receiver);
                            let message = message.clone();
                            let responses = responses.clone();
                            spawn_blocking(move || receiver.recover(&message, responses)).await
                        };
                        match result {
                            Ok(partial_output) => {
                                let mut mgr = mpc_manager.write().unwrap();
                                mgr.dealer_outputs.insert(
                                    DealerOutputsKey::Rotation(share_index),
                                    partial_output,
                                );
                                mgr.complaints_to_process.remove(
                                    &ComplaintsToProcessKey::Rotation(*dealer, share_index),
                                );
                                drop(mgr);
                                pending_shares.remove(&share_index);
                            }
                            Err(FastCryptoError::InputTooShort(_)) => {
                                continue;
                            }
                            Err(e) => {
                                let error_msg = format!(
                                    "Share recovery failed for dealer {:?} with share {}: {}",
                                    dealer, share_index, e
                                );
                                tracing::error!("{}", error_msg);
                                return Err(MpcError::CryptoError(error_msg));
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::info!(
                        "Failed to get rotation complaint response from {}: {}",
                        signer,
                        e
                    );
                }
            }
        }
        if !pending_shares.is_empty() {
            tracing::info!(
                "Could not recover all shares for dealer {:?}: missing {:?}",
                dealer,
                pending_shares
            );
        }
        Ok(())
    }

    fn load_stored_messages(&mut self) -> MpcResult<()> {
        for (dealer, message) in self
            .public_messages_store
            .list_all_dealer_messages()
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            self.dealer_messages.insert(dealer, message);
        }
        for (dealer, message) in self
            .public_messages_store
            .list_all_rotation_messages()
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            self.dealer_messages.insert(dealer, message);
        }
        Ok(())
    }

    fn prepare_rotation_complain_request(
        &self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
    ) -> MpcResult<Option<RotationComplainContext>> {
        let messages = self
            .dealer_messages
            .get(dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No rotation messages for dealer".into()))?;
        let rotation_messages = match messages {
            Messages::Rotation(msgs) => msgs,
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("prepare_rotation_complain_request called with non-rotation messages")
            }
        };
        let complained_shares: Vec<(ShareIndex, complaint::Complaint)> = self
            .complaints_to_process
            .iter()
            .filter_map(|(key, complaint)| match key {
                ComplaintsToProcessKey::Rotation(d, share_index) if d == dealer => {
                    Some((*share_index, complaint.clone()))
                }
                _ => None,
            })
            .collect();
        if complained_shares.is_empty() {
            return Ok(None);
        }
        let mut recovery_contexts: HashMap<ShareIndex, (avss::Receiver, avss::Message)> =
            HashMap::new();
        for (share_index, _complaint) in &complained_shares {
            let session_id = self.session_id.rotation_session_id(dealer, *share_index);
            let commitment = previous_dkg_output.commitments.get(share_index).copied();
            let receiver = avss::Receiver::new(
                self.dkg_config.nodes.clone(),
                self.party_id,
                self.dkg_config.threshold,
                session_id.to_vec(),
                commitment,
                self.encryption_key.clone(),
            );
            let message = rotation_messages
                .get(share_index)
                .ok_or_else(|| {
                    MpcError::ProtocolFailed(format!(
                        "No rotation message for share index {}",
                        share_index
                    ))
                })?
                .clone();
            recovery_contexts.insert(*share_index, (receiver, message));
        }
        let (first_share_index, first_complaint) = complained_shares.first().unwrap();
        let request = ComplainRequest {
            dealer: *dealer,
            share_index: Some(*first_share_index),
            complaint: first_complaint.clone(),
        };
        Ok(Some(RotationComplainContext {
            request,
            recovery_contexts,
        }))
    }

    fn create_rotation_messages(
        &self,
        previous_dkg_output: &DkgOutput,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> RotationMessages {
        previous_dkg_output
            .key_shares
            .shares
            .iter()
            .map(|share| {
                let sid = self
                    .session_id
                    .rotation_session_id(&self.address, share.index);
                let dealer = avss::Dealer::new(
                    Some(share.value),
                    self.dkg_config.nodes.clone(),
                    self.dkg_config.threshold,
                    self.dkg_config.max_faulty,
                    sid.to_vec(),
                )
                .expect(EXPECT_THRESHOLD_VALIDATED);
                let message = dealer.create_message(rng);
                (share.index, message)
            })
            .collect()
    }

    fn try_sign_rotation_messages(
        &mut self,
        previous_dkg_output: &DkgOutput,
        dealer: Address,
        messages: &Messages,
    ) -> MpcResult<BLS12381Signature> {
        let rotation_messages = match messages {
            Messages::Rotation(msgs) => msgs,
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("try_sign_rotation_messages called with non-rotation messages")
            }
        };
        let previous_committee = self.previous_committee.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("Key rotation requires previous committee".into())
        })?;
        let previous_nodes = self.previous_nodes.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("Key rotation requires previous nodes".into())
        })?;
        let dealer_party_id =
            previous_committee
                .index_of(&dealer)
                .ok_or_else(|| MpcError::InvalidMessage {
                    sender: dealer,
                    reason: "Dealer not in previous committee".into(),
                })? as u16;
        let dealer_share_indices: HashSet<_> = previous_nodes
            .share_ids_of(dealer_party_id)
            .map_err(|_| MpcError::InvalidMessage {
                sender: dealer,
                reason: "Dealer has no shares in previous committee".into(),
            })?
            .into_iter()
            .collect();
        let mut outputs = Vec::with_capacity(rotation_messages.len());
        for (&share_index, message) in rotation_messages {
            if !dealer_share_indices.contains(&share_index) {
                return Err(MpcError::InvalidMessage {
                    sender: dealer,
                    reason: format!("Share index {} does not belong to dealer", share_index),
                });
            }
            if self
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Rotation(share_index))
            {
                return Err(MpcError::InvalidMessage {
                    sender: dealer,
                    reason: format!("Share index {} already processed", share_index),
                });
            }
            let session_id = self.session_id.rotation_session_id(&dealer, share_index);
            let commitment = previous_dkg_output.commitments.get(&share_index).copied();
            let receiver = avss::Receiver::new(
                self.dkg_config.nodes.clone(),
                self.party_id,
                self.dkg_config.threshold,
                session_id.to_vec(),
                commitment,
                self.encryption_key.clone(),
            );
            match receiver.process_message(message)? {
                avss::ProcessedMessage::Valid(output) => {
                    outputs.push((DealerOutputsKey::Rotation(share_index), output));
                }
                avss::ProcessedMessage::Complaint(_) => {
                    return Err(MpcError::InvalidMessage {
                        sender: dealer,
                        reason: format!("Invalid rotation share for index {}", share_index),
                    });
                }
            }
        }
        self.dealer_outputs.extend(outputs);
        let messages_hash = compute_messages_hash(messages);
        let rotation_message = DealerMessagesHash {
            dealer_address: dealer,
            messages_hash,
        };
        let signature =
            self.signing_key
                .sign(self.dkg_config.epoch, self.address, &rotation_message);
        Ok(signature.signature().clone())
    }

    fn complete_key_rotation(
        &mut self,
        previous_dkg_output: &DkgOutput,
        certified_share_indices: &[ShareIndex],
    ) -> MpcResult<DkgOutput> {
        let threshold = previous_dkg_output.threshold;
        let indexed_outputs: Vec<IndexedValue<avss::PartialOutput>> = certified_share_indices
            .iter()
            .take(threshold as usize)
            .map(|&share_index| {
                let output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Rotation(share_index))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation output found for share index: {}",
                            share_index
                        ))
                    })?;
                Ok(IndexedValue {
                    index: share_index,
                    value: output.clone(),
                })
            })
            .collect::<Result<_, MpcError>>()?;
        let combined = avss::ReceiverOutput::complete_key_rotation(
            threshold,
            self.party_id,
            &self.dkg_config.nodes,
            &indexed_outputs,
        )
        .expect(EXPECT_THRESHOLD_MET);
        if combined.vk != previous_dkg_output.public_key {
            return Err(MpcError::ProtocolFailed(
                "Key rotation produced different public key".into(),
            ));
        }
        Ok(DkgOutput {
            public_key: combined.vk,
            key_shares: combined.my_shares,
            commitments: combined
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: self.dkg_config.threshold,
        })
    }

    fn reconstruct_previous_output(
        &mut self,
        certificates: &[CertificateV1],
    ) -> MpcResult<DkgOutput> {
        match certificates.first() {
            Some(CertificateV1::Dkg(_)) | None => {
                self.reconstruct_from_dkg_certificates(certificates)
            }
            Some(CertificateV1::Rotation(_)) => {
                let previous_threshold = self.previous_threshold.ok_or_else(|| {
                    MpcError::InvalidConfig("Key rotation requires previous threshold".into())
                })?;
                self.reconstruct_from_rotation_certificates(certificates, previous_threshold)
            }
            Some(CertificateV1::NonceGeneration { .. }) => {
                todo!("Reconstruct previous output from nonce generation certificates")
            }
        }
    }

    fn reconstruct_from_dkg_certificates(
        &mut self,
        certificates: &[CertificateV1],
    ) -> MpcResult<DkgOutput> {
        let previous_committee = self.previous_committee.clone().ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous committee".into())
        })?;
        let previous_nodes = self.previous_nodes.clone().ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous nodes".into())
        })?;
        let previous_threshold = self.previous_threshold.ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous threshold".into())
        })?;
        let previous_party_id = previous_committee.index_of(&self.address).ok_or_else(|| {
            MpcError::InvalidConfig("This node is not in the previous committee".into())
        })? as u16;
        let source_session_id =
            SessionId::new(&self.chain_id, self.source_epoch, &ProtocolType::Dkg);
        let mut certified_dealers = HashMap::new();
        for cert in certificates {
            let CertificateV1::Dkg(dkg_cert) = cert else {
                return Err(MpcError::InvalidCertificate(
                    "Mixed certificate types: expected all DKG certificates".into(),
                ));
            };
            let msg = dkg_cert.message();
            let dealer_address = msg.dealer_address;
            let source_epoch = self.source_epoch;
            let message = self
                .public_messages_store
                .get_dealer_message(source_epoch, &dealer_address)
                .map_err(|e| MpcError::StorageError(e.to_string()))?
                .ok_or_else(|| {
                    MpcError::StorageError(format!(
                        "DKG message not found for dealer: {:?}",
                        dealer_address
                    ))
                })?;
            let messages = Messages::Dkg(message.clone());
            let actual_hash = compute_messages_hash(&messages);
            if actual_hash != msg.messages_hash {
                return Err(MpcError::ProtocolFailed(format!(
                    "Message hash mismatch for dealer {:?}: stored message does not match certificate",
                    dealer_address
                )));
            }
            self.dealer_messages.insert(dealer_address, messages);
            let session_id = source_session_id
                .dealer_session_id(&dealer_address)
                .to_vec();
            self.process_and_store_message(
                previous_nodes.clone(),
                previous_party_id,
                previous_threshold,
                session_id,
                &message,
                None,
                DealerOutputsKey::Dkg(dealer_address),
                ComplaintsToProcessKey::Dkg(dealer_address),
            )?;
            certified_dealers.insert(dealer_address, cert.clone());
        }
        // Unlike normal flow which accumulates until threshold in a loop, reconstruction
        // receives all certificates at once. Check threshold for better error handling.
        let total_weight: u16 = certified_dealers
            .keys()
            .map(|dealer| {
                let party_id = previous_committee
                    .index_of(dealer)
                    .expect("certified dealer must be in previous committee")
                    as u16;
                previous_nodes
                    .weight_of(party_id)
                    .expect("party_id must be valid")
            })
            .sum();
        if total_weight < previous_threshold {
            return Err(MpcError::NotEnoughApprovals {
                needed: previous_threshold as usize,
                got: total_weight as usize,
            });
        }
        let outputs: HashMap<PartyId, avss::PartialOutput> = certified_dealers
            .into_keys()
            .map(|dealer| {
                let dealer_party_id = previous_committee
                    .index_of(&dealer)
                    .expect("certified dealer must be in previous committee")
                    as u16;
                let output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Dkg(dealer))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No dealer output found for dealer: {:?}.",
                            dealer
                        ))
                    })?
                    .clone();
                Ok((dealer_party_id, output))
            })
            .collect::<Result<_, MpcError>>()?;
        let combined_output =
            avss::ReceiverOutput::complete_dkg(previous_threshold, &previous_nodes, outputs)
                .expect(EXPECT_THRESHOLD_MET);
        Ok(DkgOutput {
            public_key: combined_output.vk,
            key_shares: combined_output.my_shares,
            commitments: combined_output
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: previous_threshold,
        })
    }

    fn reconstruct_from_rotation_certificates(
        &mut self,
        certificates: &[CertificateV1],
        previous_threshold: u16,
    ) -> MpcResult<DkgOutput> {
        let previous_nodes = self.previous_nodes.clone().ok_or_else(|| {
            MpcError::InvalidConfig("Rotation reconstruction requires previous nodes".into())
        })?;
        let previous_committee = self.previous_committee.clone().ok_or_else(|| {
            MpcError::InvalidConfig("Rotation reconstruction requires previous committee".into())
        })?;
        let previous_party_id = previous_committee.index_of(&self.address).ok_or_else(|| {
            MpcError::InvalidConfig("This node is not in the previous committee".into())
        })? as u16;
        let source_session_id = SessionId::new(
            &self.chain_id,
            self.source_epoch,
            &ProtocolType::KeyRotation,
        );
        // Each dealer only rotates their own shares from the previous epoch, so share indices
        // are unique across dealers (no duplicates in `certified_share_indices`).
        let mut certified_share_indices = Vec::new();
        for cert in certificates {
            let CertificateV1::Rotation(rotation_cert) = cert else {
                return Err(MpcError::InvalidCertificate(
                    "Mixed certificate types: expected all Rotation certificates".into(),
                ));
            };
            let msg = rotation_cert.message();
            let dealer_address = msg.dealer_address;
            let source_epoch = self.source_epoch;
            let rotation_msgs = self
                .public_messages_store
                .get_rotation_messages(source_epoch, &dealer_address)
                .map_err(|e| MpcError::StorageError(e.to_string()))?
                .ok_or_else(|| {
                    MpcError::StorageError(format!(
                        "Rotation messages not found for dealer: {:?}",
                        dealer_address
                    ))
                })?;
            let messages = Messages::Rotation(rotation_msgs.clone());
            let actual_hash = compute_messages_hash(&messages);
            if actual_hash != msg.messages_hash {
                return Err(MpcError::ProtocolFailed(format!(
                    "Message hash mismatch for dealer {:?}: stored message does not match certificate",
                    dealer_address
                )));
            }
            self.dealer_messages.insert(dealer_address, messages);
            for (share_index, message) in rotation_msgs {
                let session_id = source_session_id
                    .rotation_session_id(&dealer_address, share_index)
                    .to_vec();
                let output_key = DealerOutputsKey::Rotation(share_index);
                let complaint_key = ComplaintsToProcessKey::Rotation(dealer_address, share_index);
                // Pass None for commitment. Re-verification would be redundant since we trust the certificates.
                self.process_and_store_message(
                    previous_nodes.clone(),
                    previous_party_id,
                    previous_threshold,
                    session_id,
                    &message,
                    None,
                    output_key,
                    complaint_key,
                )?;
                certified_share_indices.push(share_index);
            }
        }
        // Unlike normal flow which accumulates until threshold in a loop, reconstruction
        // receives all certificates at once. Check threshold for better error handling.
        if certified_share_indices.len() < previous_threshold as usize {
            return Err(MpcError::NotEnoughApprovals {
                needed: previous_threshold as usize,
                got: certified_share_indices.len(),
            });
        }
        let indexed_outputs: Vec<IndexedValue<avss::PartialOutput>> = certified_share_indices
            .iter()
            .take(previous_threshold as usize)
            .map(|&share_index| {
                let output = self
                    .dealer_outputs
                    .get(&DealerOutputsKey::Rotation(share_index))
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation output found for share index: {}",
                            share_index
                        ))
                    })?;
                Ok(IndexedValue {
                    index: share_index,
                    value: output.clone(),
                })
            })
            .collect::<Result<_, MpcError>>()?;
        let combined = avss::ReceiverOutput::complete_key_rotation(
            previous_threshold,
            previous_party_id,
            &previous_nodes,
            &indexed_outputs,
        )
        .expect(EXPECT_THRESHOLD_MET);
        Ok(DkgOutput {
            public_key: combined.vk,
            key_shares: combined.my_shares,
            commitments: combined
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: previous_threshold,
        })
    }

    pub async fn fetch_public_dkg_output_from_quorum(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        previous_committee_threshold: u64,
    ) -> MpcResult<PublicDkgOutput> {
        let (previous_committee, epoch) = {
            let mgr = mpc_manager.read().unwrap();
            let previous_committee = mgr
                .previous_committee
                .clone()
                .expect("key rotation requires previous committee");
            let epoch = mgr
                .dkg_config
                .epoch
                .checked_sub(1)
                .expect("key rotation requires epoch > 0");
            (previous_committee, epoch)
        };
        let request = GetPublicDkgOutputRequest { epoch };
        let mut futures: FuturesUnordered<_> = previous_committee
            .members()
            .iter()
            .map(|member| {
                let addr = member.validator_address();
                let weight = member.weight();
                let req = request.clone();
                async move {
                    let result = p2p_channel.get_public_dkg_output(&addr, &req).await;
                    (addr, weight, result)
                }
            })
            .collect();
        let mut responses: HashMap<[u8; 32], (PublicDkgOutput, u64)> = HashMap::new();
        while let Some((addr, weight, result)) = futures.next().await {
            match result {
                Ok(response) => {
                    let hash = hash_public_dkg_output(&response.output);
                    let (output, weight_sum) = responses
                        .entry(hash)
                        .or_insert((response.output.clone(), 0));
                    *weight_sum += weight;
                    if *weight_sum >= previous_committee_threshold {
                        return Ok(output.clone());
                    }
                }
                Err(e) => {
                    tracing::info!("Failed to get public DKG output from {}: {}", addr, e);
                }
            }
        }
        let max_weight = responses.values().map(|(_, w)| *w).max().unwrap_or(0);
        Err(MpcError::NotEnoughApprovals {
            needed: (previous_committee_threshold + 1) as usize,
            got: max_weight as usize,
        })
    }

    async fn prepare_previous_output(
        mpc_manager: &Arc<RwLock<Self>>,
        previous_certificates: &[CertificateV1],
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<(DkgOutput, bool)> {
        let (is_member_of_previous_committee, threshold_opt) = {
            let mgr = mpc_manager.read().unwrap();
            let is_member = mgr
                .previous_committee
                .as_ref()
                .and_then(|c| c.index_of(&mgr.address))
                .is_some();
            (is_member, mgr.previous_threshold)
        };
        let previous = if is_member_of_previous_committee {
            let mgr = Arc::clone(mpc_manager);
            let certs = previous_certificates.to_vec();
            spawn_blocking(move || {
                let mut mgr = mgr.write().unwrap();
                mgr.reconstruct_previous_output(&certs)
            })
            .await?
        } else {
            let threshold = threshold_opt.ok_or_else(|| {
                MpcError::InvalidConfig("Key rotation requires previous threshold".into())
            })?;
            let public_output = Self::fetch_public_dkg_output_from_quorum(
                mpc_manager,
                p2p_channel,
                threshold as u64,
            )
            .await?;
            DkgOutput {
                public_key: public_output.public_key,
                key_shares: avss::SharesForNode { shares: vec![] },
                commitments: public_output.commitments,
                threshold,
            }
        };
        Ok((previous, is_member_of_previous_committee))
    }
}

pub fn fallback_encryption_public_key() -> PublicKey<EncryptionGroupElement> {
    static FALLBACK_ENCRYPTION_PK: LazyLock<PublicKey<EncryptionGroupElement>> =
        LazyLock::new(|| PublicKey::from(EncryptionGroupElement::hash_to_group_element(b"hashi")));
    FALLBACK_ENCRYPTION_PK.clone()
}

fn compute_messages_hash(messages: &Messages) -> MessageHash {
    let bytes = bcs::to_bytes(messages).expect(EXPECT_SERIALIZATION_SUCCESS);
    MessageHash::from(Blake2b256::digest(&bytes).digest)
}

fn compute_bft_threshold(total_weight: u16) -> MpcResult<u16> {
    if total_weight == 0 {
        return Err(MpcError::InvalidConfig(
            "committee has zero total weight".into(),
        ));
    }
    Ok((total_weight - 1) / 3 + 1)
}

fn build_reduced_nodes(
    committee: &Committee,
    allowed_delta: u16,
    test_weight_divisor: u16,
) -> MpcResult<(Nodes<EncryptionGroupElement>, u16)> {
    let nodes_vec: Vec<Node<EncryptionGroupElement>> = committee
        .members()
        .iter()
        .enumerate()
        .map(|(index, member)| Node {
            id: index as u16,
            pk: member.encryption_public_key().to_owned(),
            weight: (member.weight() as u16 / test_weight_divisor).max(1),
        })
        .collect();
    let total_weight: u16 = nodes_vec.iter().map(|n| n.weight).sum();
    let threshold = compute_bft_threshold(total_weight)?;
    Nodes::new_reduced(nodes_vec, threshold, allowed_delta, 1)
        .map_err(|e| MpcError::CryptoError(e.to_string()))
}

fn hash_public_dkg_output(output: &PublicDkgOutput) -> [u8; 32] {
    let bytes = bcs::to_bytes(output).expect(EXPECT_SERIALIZATION_SUCCESS);
    Blake2b256::digest(&bytes).digest
}

pub(crate) async fn spawn_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("spawn_blocking task panicked")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::ChannelResult;
    use crate::mpc::types::GetPartialSignaturesRequest;
    use crate::mpc::types::GetPartialSignaturesResponse;
    use crate::mpc::types::ProtocolType;
    use crate::mpc::types::RotationMessages;
    use crate::onchain::types::MemberInfo;
    use fastcrypto::encoding::Encoding;
    use fastcrypto::encoding::Hex;
    use fastcrypto::groups::Scalar;
    use fastcrypto::random_oracle::RandomOracle;
    use fastcrypto_tbls::ecies_v1::MultiRecipientEncryption;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPublicKey;
    use hashi_types::committee::MemberSignature;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    /// Use 0 for allowed_delta in tests to disable weight reduction.
    const TEST_ALLOWED_DELTA: u16 = 0;
    /// Use 1 for test_weight_divisor in unit tests (they already use small weights).
    const TEST_WEIGHT_DIVISOR: u16 = 1;
    const TEST_CHAIN_ID: &str = "testchain";
    const TEST_BATCH_SIZE_PER_WEIGHT: u16 = 50;

    struct MockPublicMessagesStore;

    impl PublicMessagesStore for MockPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            _dealer: &Address,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_dealer_message(
            &self,
            _epoch: u64,
            _dealer: &Address,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(None)
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(vec![])
        }

        fn store_rotation_messages(
            &mut self,
            _dealer: &Address,
            _messages: &RotationMessages,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_rotation_messages(
            &self,
            _epoch: u64,
            _dealer: &Address,
        ) -> anyhow::Result<Option<RotationMessages>> {
            Ok(None)
        }

        fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(vec![])
        }
    }

    fn receive_dealer_messages(
        manager: &mut MpcManager,
        messages: &Messages,
        dealer: Address,
    ) -> MpcResult<MemberSignature> {
        let Messages::Dkg(msg) = messages else {
            panic!("receive_dealer_messages called with rotation messages");
        };
        manager.store_dkg_message(dealer, msg)?;
        let sig = manager.try_sign_dkg_message(dealer, messages)?;
        Ok(MemberSignature::new(
            manager.dkg_config.epoch,
            manager.address,
            sig,
        ))
    }
    struct TestSetup {
        pub committee_set: CommitteeSet,
        pub encryption_keys: Vec<PrivateKey<EncryptionGroupElement>>,
        pub signing_keys: Vec<Bls12381PrivateKey>,
    }

    impl TestSetup {
        fn new(num_validators: usize) -> Self {
            let mut rng = rand::thread_rng();

            let encryption_keys: Vec<_> = (0..num_validators)
                .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
                .collect();

            let signing_keys: Vec<_> = (0..num_validators)
                .map(|_| Bls12381PrivateKey::generate(&mut rng))
                .collect();

            let epoch = 100u64;

            // Build MemberInfo for each validator
            let member_infos: BTreeMap<Address, MemberInfo> = (0..num_validators)
                .map(|i| {
                    let addr = Address::new([i as u8; 32]);
                    let next_epoch_encryption_public_key =
                        Some(PublicKey::from_private_key(&encryption_keys[i]));
                    let member_info = MemberInfo {
                        validator_address: addr,
                        operator_address: addr,
                        next_epoch_public_key: signing_keys[i].public_key(),
                        https_address: None,
                        tls_public_key: None,
                        next_epoch_encryption_public_key,
                    };
                    (addr, member_info)
                })
                .collect();

            // Build Committee
            let members: Vec<_> = (0..num_validators)
                .map(|i| {
                    let addr = Address::new([i as u8; 32]);
                    CommitteeMember::new(
                        addr,
                        signing_keys[i].public_key(),
                        EncryptionPublicKey::from_private_key(&encryption_keys[i]),
                        1,
                    )
                })
                .collect();
            let committee = Committee::new(members.clone(), epoch);
            // Also create a previous committee for key rotation tests
            let previous_committee = Committee::new(members, epoch - 1);

            let mut committees = BTreeMap::new();
            committees.insert(epoch - 1, previous_committee);
            committees.insert(epoch, committee);

            let mut committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
            committee_set
                .set_epoch(epoch)
                .set_members(member_infos)
                .set_committees(committees);

            Self {
                committee_set,
                encryption_keys,
                signing_keys,
            }
        }

        fn with_weights(weights: &[u16]) -> Self {
            let mut rng = rand::thread_rng();
            let num_validators = weights.len();

            let encryption_keys: Vec<_> = (0..num_validators)
                .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
                .collect();

            let signing_keys: Vec<_> = (0..num_validators)
                .map(|_| Bls12381PrivateKey::generate(&mut rng))
                .collect();

            let epoch = 100u64;

            // Build MemberInfo for each validator
            let member_infos: BTreeMap<Address, MemberInfo> = (0..num_validators)
                .map(|i| {
                    let addr = Address::new([i as u8; 32]);
                    let next_epoch_encryption_public_key =
                        Some(PublicKey::from_private_key(&encryption_keys[i]));
                    let member_info = MemberInfo {
                        validator_address: addr,
                        operator_address: addr,
                        next_epoch_public_key: signing_keys[i].public_key(),
                        https_address: None,
                        tls_public_key: None,
                        next_epoch_encryption_public_key,
                    };
                    (addr, member_info)
                })
                .collect();

            // Build Committee with custom weights
            let members: Vec<_> = (0..num_validators)
                .map(|i| {
                    let addr = Address::new([i as u8; 32]);
                    let encryption_public_key = PublicKey::from_private_key(&encryption_keys[i]);
                    CommitteeMember::new(
                        addr,
                        signing_keys[i].public_key(),
                        encryption_public_key,
                        weights[i].into(),
                    )
                })
                .collect();
            let committee = Committee::new(members.clone(), epoch);
            // Also create a previous committee for key rotation tests
            let previous_committee = Committee::new(members, epoch - 1);

            let mut committees = BTreeMap::new();
            committees.insert(epoch - 1, previous_committee);
            committees.insert(epoch, committee);

            let mut committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
            committee_set
                .set_epoch(epoch)
                .set_members(member_infos)
                .set_committees(committees);

            Self {
                committee_set,
                encryption_keys,
                signing_keys,
            }
        }

        fn create_manager(&self, validator_index: usize) -> MpcManager {
            self.create_manager_with_store(validator_index, Box::new(MockPublicMessagesStore))
        }

        fn create_manager_with_store(
            &self,
            validator_index: usize,
            store: Box<dyn PublicMessagesStore>,
        ) -> MpcManager {
            let address = Address::new([validator_index as u8; 32]);
            let session_id = SessionId::new(
                TEST_CHAIN_ID,
                self.committee_set.epoch(),
                &ProtocolType::Dkg,
            );
            MpcManager::new(
                address,
                &self.committee_set,
                session_id,
                self.encryption_keys[validator_index].clone(),
                self.signing_keys[validator_index].clone(),
                store,
                TEST_ALLOWED_DELTA,
                TEST_CHAIN_ID,
                None,
                TEST_BATCH_SIZE_PER_WEIGHT,
            )
            .unwrap()
        }

        fn address(&self, validator_index: usize) -> Address {
            Address::new([validator_index as u8; 32])
        }

        fn session_id(&self) -> SessionId {
            SessionId::new(
                TEST_CHAIN_ID,
                self.committee_set.epoch(),
                &ProtocolType::Dkg,
            )
        }

        fn committee(&self) -> &Committee {
            self.committee_set.current_committee().unwrap()
        }

        fn num_validators(&self) -> usize {
            self.encryption_keys.len()
        }

        fn create_dealer_with_message(
            &self,
            validator_index: usize,
            rng: &mut impl fastcrypto::traits::AllowedRng,
        ) -> MpcManager {
            let mut manager = self.create_manager(validator_index);
            let dealer_message = manager.create_dealer_message(rng);
            let address = self.address(validator_index);
            let messages = Messages::Dkg(dealer_message);
            receive_dealer_messages(&mut manager, &messages, address).unwrap();
            manager
        }

        fn epoch(&self) -> u64 {
            self.committee_set.epoch()
        }

        fn dkg_config(&self) -> DkgConfig {
            self.create_manager(0).dkg_config.clone()
        }
    }

    fn create_test_certificate(
        committee: &Committee,
        dealer_messages: &Messages,
        dealer_address: Address,
        signatures: Vec<MemberSignature>,
    ) -> MpcResult<DealerCertificate> {
        let messages_hash = compute_messages_hash(dealer_messages);
        let dkg_message = DealerMessagesHash {
            dealer_address,
            messages_hash,
        };
        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);
        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn create_rotation_test_certificate(
        committee: &Committee,
        rotation_messages: &Messages,
        dealer_address: Address,
        signatures: Vec<MemberSignature>,
    ) -> MpcResult<DealerCertificate> {
        let messages_hash = compute_messages_hash(rotation_messages);
        let rotation_message = DealerMessagesHash {
            dealer_address,
            messages_hash,
        };
        let mut aggregator = BlsSignatureAggregator::new(committee, rotation_message);
        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    struct MockP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, MpcManager>>>,
        current_sender: Address,
    }

    impl MockP2PChannel {
        fn new(managers: HashMap<Address, MpcManager>, current_sender: Address) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for MockP2PChannel {
        async fn send_messages(
            &self,
            recipient: &Address,
            request: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_messages_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_messages(
            &self,
            party: &Address,
            request: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            let managers = self.managers.lock().unwrap();
            let manager = managers.get(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_retrieve_messages_request(request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn complain(
            &self,
            party: &Address,
            request: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager.handle_complain_request(request).map_err(|e| {
                crate::communication::ChannelError::RequestFailed(format!("Handler failed: {}", e))
            })?;
            Ok(response)
        }

        async fn get_public_dkg_output(
            &self,
            party: &Address,
            request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            let managers = self.managers.lock().unwrap();
            let manager = managers.get(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_get_public_dkg_output_request(request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("MockP2PChannel does not implement get_partial_signatures")
        }
    }

    struct MockOrderedBroadcastChannel {
        certificates: std::sync::Mutex<std::collections::VecDeque<CertificateV1>>,
        published: std::sync::Mutex<Vec<CertificateV1>>,
        /// Override for existing_certificate_weight().
        /// If set, returns this value instead of the pending message count.
        override_existing_weight: Option<u32>,
        /// If set, publish() will fail with this error message.
        fail_on_publish: Option<String>,
    }

    impl MockOrderedBroadcastChannel {
        fn new(certificates: Vec<CertificateV1>) -> Self {
            Self {
                certificates: std::sync::Mutex::new(certificates.into()),
                published: std::sync::Mutex::new(Vec::new()),
                override_existing_weight: None,
                fail_on_publish: None,
            }
        }

        fn with_override_weight(mut self, weight: u32) -> Self {
            self.override_existing_weight = Some(weight);
            self
        }

        fn with_fail_on_publish(mut self, error_message: &str) -> Self {
            self.fail_on_publish = Some(error_message.to_string());
            self
        }

        fn published_count(&self) -> usize {
            self.published.lock().unwrap().len()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(self.certificates.lock().unwrap().len())
        }
    }

    #[async_trait::async_trait]
    impl OrderedBroadcastChannel<CertificateV1> for MockOrderedBroadcastChannel {
        async fn publish(&self, message: CertificateV1) -> ChannelResult<()> {
            if let Some(ref error_msg) = self.fail_on_publish {
                return Err(crate::communication::ChannelError::RequestFailed(
                    error_msg.clone(),
                ));
            }
            self.published.lock().unwrap().push(message.clone());
            // Also add to certificates so it's available for receive
            self.certificates.lock().unwrap().push_back(message);
            Ok(())
        }

        async fn receive(&mut self) -> ChannelResult<CertificateV1> {
            self.certificates
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| {
                    crate::communication::ChannelError::RequestFailed(
                        "No more certificates".to_string(),
                    )
                })
        }

        fn existing_certificate_weight(&self) -> u32 {
            // Use override if set, otherwise approximate with pending certificate count.
            self.override_existing_weight
                .unwrap_or_else(|| self.certificates.lock().unwrap().len() as u32)
        }
    }

    fn create_manager_with_valid_keys(
        validator_index: usize,
        num_validators: usize,
    ) -> (MpcManager, TestSetup) {
        let setup = TestSetup::new(num_validators);
        let manager = setup.create_manager(validator_index);
        (manager, setup)
    }

    struct FailingP2PChannel {
        error_message: String,
    }

    #[async_trait::async_trait]
    impl P2PChannel for FailingP2PChannel {
        async fn send_messages(
            &self,
            _recipient: &Address,
            _request: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn retrieve_messages(
            &self,
            _party: &Address,
            _request: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("FailingP2PChannel does not implement get_partial_signatures")
        }
    }

    struct SucceedingP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, MpcManager>>>,
        current_sender: Address,
    }

    impl SucceedingP2PChannel {
        fn new(managers: HashMap<Address, MpcManager>, current_sender: Address) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for SucceedingP2PChannel {
        async fn send_messages(
            &self,
            recipient: &Address,
            request: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_messages_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_messages(
            &self,
            _party: &Address,
            _request: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!("SucceedingP2PChannel does not implement retrieve_messages")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            unimplemented!("SucceedingP2PChannel does not implement complain")
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("SucceedingP2PChannel does not implement get_public_dkg_output")
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("SucceedingP2PChannel does not implement get_partial_signatures")
        }
    }

    struct PartiallyFailingP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, MpcManager>>>,
        current_sender: Address,
        /// Recipients that always fail (even on retry)
        failed_recipients: std::sync::Arc<std::sync::Mutex<HashSet<Address>>>,
        max_failures: usize,
    }

    impl PartiallyFailingP2PChannel {
        fn new(
            managers: HashMap<Address, MpcManager>,
            current_sender: Address,
            max_failures: usize,
        ) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
                failed_recipients: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                max_failures,
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for PartiallyFailingP2PChannel {
        async fn send_messages(
            &self,
            recipient: &Address,
            request: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            let mut failed = self.failed_recipients.lock().unwrap();
            // If this recipient already failed, keep failing (even on retry)
            if failed.contains(recipient) {
                return Err(crate::communication::ChannelError::RequestFailed(
                    "network error".to_string(),
                ));
            }
            // If we haven't reached max failures, mark this recipient as failed
            if failed.len() < self.max_failures {
                failed.insert(*recipient);
                return Err(crate::communication::ChannelError::RequestFailed(
                    "network error".to_string(),
                ));
            }
            drop(failed); // Release the lock before calling manager
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_messages_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_messages(
            &self,
            _party: &Address,
            _request: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement retrieve_messages")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            unimplemented!("PartiallyFailingP2PChannel does not implement complain")
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement get_public_dkg_output")
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement get_partial_signatures")
        }
    }

    /// P2P channel that returns pre-collected complaint responses.
    /// Useful for testing scenarios where responses are prepared ahead of time.
    struct PreCollectedP2PChannel {
        responses: std::sync::Mutex<HashMap<Address, ComplaintResponses>>,
    }

    impl PreCollectedP2PChannel {
        fn new(responses: HashMap<Address, ComplaintResponses>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for PreCollectedP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement send_messages")
        }

        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement retrieve_messages")
        }

        async fn complain(
            &self,
            party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            self.responses
                .lock()
                .unwrap()
                .get(party)
                .cloned()
                .ok_or_else(|| {
                    crate::communication::ChannelError::RequestFailed("No response".into())
                })
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement get_public_dkg_output")
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement get_partial_signatures")
        }
    }

    struct FailingOrderedBroadcastChannel {
        error_message: String,
        fail_on_publish: bool,
        fail_on_receive: bool,
    }

    #[async_trait::async_trait]
    impl OrderedBroadcastChannel<CertificateV1> for FailingOrderedBroadcastChannel {
        async fn publish(&self, _message: CertificateV1) -> ChannelResult<()> {
            if self.fail_on_publish {
                Err(crate::communication::ChannelError::RequestFailed(
                    self.error_message.clone(),
                ))
            } else {
                Ok(())
            }
        }

        async fn receive(&mut self) -> ChannelResult<CertificateV1> {
            if self.fail_on_receive {
                Err(crate::communication::ChannelError::RequestFailed(
                    self.error_message.clone(),
                ))
            } else {
                unreachable!()
            }
        }
    }

    #[test]
    fn test_mpc_manager_new_from_committee_set() {
        let setup = TestSetup::new(5);

        let encryption_key = setup.encryption_keys[0].clone();
        let signing_key = setup.signing_keys[0].clone();
        let address = setup.address(0);
        let session_id = setup.session_id();

        let manager = MpcManager::new(
            address,
            &setup.committee_set,
            session_id,
            encryption_key,
            signing_key,
            Box::new(MockPublicMessagesStore),
            TEST_ALLOWED_DELTA,
            TEST_CHAIN_ID,
            None,
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .expect("Should create manager from CommitteeSet");

        // Verify party_id is assigned based on canonical ordering
        assert_eq!(manager.party_id, 0);
        assert_eq!(manager.address, address);

        // Verify DkgConfig was built correctly
        assert_eq!(manager.dkg_config.epoch, setup.epoch());
        assert_eq!(manager.dkg_config.nodes.num_nodes(), 5);
        assert_eq!(manager.committee.members().len(), 5);
    }

    #[test]
    fn test_mpc_manager_new_fails_if_no_committee_for_epoch() {
        let mut rng = rand::thread_rng();

        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();
        let signing_keys: Vec<_> = (0..5)
            .map(|_| Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let epoch = 100u64;

        let members: BTreeMap<Address, MemberInfo> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let member_info = MemberInfo {
                    validator_address: addr,
                    operator_address: addr,
                    next_epoch_public_key: signing_keys[i].public_key(),
                    https_address: None,
                    tls_public_key: None,
                    next_epoch_encryption_public_key: Some(PublicKey::from_private_key(
                        &encryption_keys[i],
                    )),
                };
                (addr, member_info)
            })
            .collect();

        // Empty committees map - no committee for the epoch
        let mut committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        committee_set
            .set_epoch(epoch)
            .set_members(members)
            .set_committees(BTreeMap::new()); // Empty!

        let session_id = SessionId::new("test", epoch, &ProtocolType::Dkg);
        let result = MpcManager::new(
            Address::new([0; 32]),
            &committee_set,
            session_id,
            encryption_keys[0].clone(),
            signing_keys[0].clone(),
            Box::new(MockPublicMessagesStore),
            TEST_ALLOWED_DELTA,
            "test",
            None,
            TEST_BATCH_SIZE_PER_WEIGHT,
        );

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Should fail with no committee for epoch"),
        };
        assert!(
            err.to_string().contains("no committee for epoch"),
            "Error should mention missing committee"
        );
    }

    #[test]
    fn test_mpc_manager_new_with_weighted_committee() {
        let setup = TestSetup::with_weights(&[1, 2, 3, 4, 5]); // total = 15

        let manager = setup.create_manager(0);

        // With total_weight=15: max_faulty = (15-1)/3 = 4, threshold = 5
        assert_eq!(manager.dkg_config.threshold, 5);
        assert_eq!(manager.dkg_config.max_faulty, 4);
    }

    #[test]
    fn test_mpc_manager_new_party_id_follows_canonical_order() {
        let setup = TestSetup::new(5);

        // Create managers for all validators and verify their party_ids
        for i in 0..5 {
            let manager = setup.create_manager(i);

            assert_eq!(
                manager.party_id, i as u16,
                "Party ID should match canonical order index for validator {}",
                i
            );

            // Verify the address maps to this party_id via committee
            let expected_party_id = manager.committee.index_of(&setup.address(i));
            assert_eq!(
                expected_party_id,
                Some(i),
                "committee.index_of should map correctly for validator {}",
                i
            );
        }
    }

    struct InMemoryPublicMessagesStore {
        stored: HashMap<Address, avss::Message>,
        rotation_stored: HashMap<Address, RotationMessages>,
    }

    impl InMemoryPublicMessagesStore {
        fn new() -> Self {
            Self {
                stored: HashMap::new(),
                rotation_stored: HashMap::new(),
            }
        }
    }

    impl PublicMessagesStore for InMemoryPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            dealer: &Address,
            message: &avss::Message,
        ) -> anyhow::Result<()> {
            self.stored.insert(*dealer, message.clone());
            Ok(())
        }

        fn get_dealer_message(
            &self,
            _epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(self.stored.get(dealer).cloned())
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(self
                .stored
                .iter()
                .map(|(k, v)| (*k, Messages::Dkg(v.clone())))
                .collect())
        }

        fn store_rotation_messages(
            &mut self,
            dealer: &Address,
            messages: &RotationMessages,
        ) -> anyhow::Result<()> {
            self.rotation_stored.insert(*dealer, messages.clone());
            Ok(())
        }

        fn get_rotation_messages(
            &self,
            _epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<RotationMessages>> {
            Ok(self.rotation_stored.get(dealer).cloned())
        }

        fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(self
                .rotation_stored
                .iter()
                .map(|(k, v)| (*k, Messages::Rotation(v.clone())))
                .collect())
        }
    }

    struct FailingPublicMessagesStore;

    impl PublicMessagesStore for FailingPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            _dealer: &Address,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn get_dealer_message(
            &self,
            _epoch: u64,
            _dealer: &Address,
        ) -> anyhow::Result<Option<avss::Message>> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(vec![])
        }

        fn store_rotation_messages(
            &mut self,
            _dealer: &Address,
            _messages: &RotationMessages,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn get_rotation_messages(
            &self,
            _epoch: u64,
            _dealer: &Address,
        ) -> anyhow::Result<Option<RotationMessages>> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_dealer_receiver_flow() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 0)
        let dealer_manager = setup.create_manager(0);
        let message = dealer_manager.create_dealer_message(&mut rng);
        let dealer_address = dealer_manager.address;
        // Wrap with dealer's share index (party 0 = share index 1)
        let messages = Messages::Dkg(message);

        // Create receiver (party 1) with custom storage
        let storage = InMemoryPublicMessagesStore::new();
        let mut receiver_manager = setup.create_manager_with_store(1, Box::new(storage));

        // Receiver processes the dealer's message
        let signature =
            receive_dealer_messages(&mut receiver_manager, &messages, dealer_address).unwrap();

        // Verify signature format
        assert_eq!(signature.address(), &receiver_manager.address);

        // Verify receiver output was stored (keyed by dealer address for DKG)
        assert!(
            receiver_manager
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_address))
        );

        // Verify dealer message was stored in memory for signature recovery
        assert!(
            receiver_manager
                .dealer_messages
                .contains_key(&dealer_address)
        );

        // Verify dealer message was persisted to storage
        let stored = receiver_manager
            .public_messages_store
            .list_all_dealer_messages()
            .unwrap();
        assert!(
            stored.iter().any(|(d, _)| d == &dealer_address),
            "Dealer message should be persisted to storage"
        );
    }

    #[test]
    fn test_receive_dealer_message_storage_failure() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(4); // Need at least 4 validators for threshold

        // Create dealer (party 0)
        let dealer_manager = setup.create_manager(0);
        let message = dealer_manager.create_dealer_message(&mut rng);
        let dealer_address = dealer_manager.address;
        let messages = Messages::Dkg(message);

        // Create receiver with failing storage
        let mut receiver_manager =
            setup.create_manager_with_store(1, Box::new(FailingPublicMessagesStore));

        // Receiver processes the dealer's message - should fail due to storage error
        let result = receive_dealer_messages(&mut receiver_manager, &messages, dealer_address);

        // Verify operation fails with storage error
        assert!(result.is_err(), "Should fail when storage fails");
        match result {
            Err(MpcError::StorageError(msg)) => {
                assert!(
                    msg.contains("Storage failure"),
                    "Error should mention storage failure"
                );
            }
            _ => panic!("Expected StorageError, got {:?}", result),
        }
    }

    #[test]
    fn test_complete_dkg_success() {
        let mut rng = rand::thread_rng();

        // Use different weights: [3, 2, 4, 1, 2] (total = 12)
        // threshold = (12 - 1) / 3 + 1 = 4
        let weights = [3, 2, 4, 1, 2];
        let setup = TestSetup::with_weights(&weights);

        // Using validators 0, 1, 4 as dealers
        let dealer_indices = [0usize, 1, 4];
        let dealer_managers: Vec<_> = dealer_indices
            .iter()
            .map(|&i| setup.create_manager(i))
            .collect();

        // Create receiver (party 2 with weight=4 - will receive 4 shares!)
        let mut receiver_manager = setup.create_manager(2);

        // Each dealer creates a message and wraps it
        let dealer_messages: Vec<Messages> = dealer_managers
            .iter()
            .map(|dm| {
                let message = dm.create_dealer_message(&mut rng);
                Messages::Dkg(message)
            })
            .collect();

        // Receiver processes all dealer messages and creates certificates
        let certified_dealers = dealer_messages
            .iter()
            .enumerate()
            .map(|(i, messages)| {
                let dealer_address = dealer_managers[i].address;
                // Receiver processes the messages
                let _sig = receive_dealer_messages(&mut receiver_manager, messages, dealer_address);
                dealer_address
            })
            .collect::<Vec<_>>();

        let dkg_output = receiver_manager
            .complete_dkg(certified_dealers.into_iter())
            .unwrap();

        // Verify output structure
        // Receiver has weight=4, so should receive 4 shares
        assert_eq!(dkg_output.key_shares.shares.len(), 4);
        assert!(!dkg_output.commitments.is_empty());
    }

    #[test]
    fn test_complete_dkg_missing_dealer_output() {
        let setup = TestSetup::new(5);

        // Create a receiver manager (will not receive dealer messages)
        let receiver_manager = setup.create_manager(0);

        // Create dealers
        let dealer_addr0 = setup.address(1);
        let dealer_addr1 = setup.address(2);

        let certified_dealers = vec![dealer_addr0, dealer_addr1];

        let result = receiver_manager.complete_dkg(certified_dealers.into_iter());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No dealer output found for dealer")
        );
    }

    #[tokio::test]
    async fn test_run_dkg() {
        let mut rng = rand::thread_rng();
        let weights: [u16; 5] = [1, 1, 1, 2, 2];
        let num_validators = weights.len();
        let setup = TestSetup::with_weights(&weights);

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();

        // Phase 1: Pre-create all dealer messages and wrap them
        let dealer_messages: Vec<Messages> = managers
            .iter()
            .map(|mgr| {
                let message = mgr.create_dealer_message(&mut rng);
                Messages::Dkg(message)
            })
            .collect();

        // Phase 2: Pre-compute all signatures and certificates
        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // Collect signatures from all validators
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::Dkg(cert));
        }

        // Phase 3: Test run_as_dealer() and run_as_party() for validator 0 with mocked channels
        // Remove validator 0 from managers (it will call run_dkg)
        let mut test_manager = managers.remove(0);
        let threshold = test_manager.dkg_config.threshold;

        // Create mock P2P channel with remaining managers (validators 1-4)
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));

        // Pre-populate validator 0's manager with dealer outputs from all validators (including itself)
        for (j, messages) in dealer_messages.iter().enumerate() {
            receive_dealer_messages(&mut test_manager, messages, setup.address(j)).unwrap();
        }

        // Create mock ordered broadcast channel with certificates from dealers 1-4
        // (exclude dealer 0 since run_as_dealer() will create its own certificate)
        let other_certificates: Vec<_> = certificates.iter().skip(1).cloned().collect();
        let other_certificates_len = other_certificates.len();
        let mut mock_tob = MockOrderedBroadcastChannel::new(other_certificates);

        let test_manager = Arc::new(RwLock::new(test_manager));

        // Call run_as_dealer() and run_as_party() for validator 0
        MpcManager::run_as_dealer(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();
        let output = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify validator 0 received the correct number of key shares based on its weight
        assert_eq!(
            output.key_shares.shares.len(),
            weights[0] as usize,
            "Validator 0 should receive shares equal to its weight"
        );

        // Verify the output has commitments (one per weight unit across all validators)
        let total_weight: u16 = weights.iter().sum();
        assert_eq!(
            output.commitments.len(),
            total_weight as usize,
            "Should have commitments equal to total weight"
        );

        // Verify all certificates were consumed from the TOB channel (only threshold needed)
        assert_eq!(
            mock_tob.pending_messages(),
            Some(other_certificates_len - threshold as usize),
            "TOB should have consumed exactly threshold certificates"
        );

        // Verify that other validators (in the mock P2P channel) received and processed validator 0's dealer message
        let other_managers = mock_p2p.managers.lock().unwrap();
        // DKG: outputs keyed by dealer address
        let validator0_address = setup.address(0);
        for j in 1..num_validators {
            let addr_j = setup.address(j);
            let other_mgr = other_managers.get(&addr_j).unwrap();
            assert!(
                other_mgr
                    .dealer_outputs
                    .contains_key(&DealerOutputsKey::Dkg(validator0_address)),
                "Validator {} should have dealer output from validator 0",
                j
            );
        }
    }

    #[tokio::test]
    async fn test_run_dkg_with_complaint_recovery() {
        let mut rng = rand::thread_rng();
        let weights: [u16; 5] = [1, 1, 1, 2, 2];
        let num_validators = weights.len();
        let setup = TestSetup::with_weights(&weights);
        let cheating_dealer_idx = 3; // weight=2
        let test_party_idx = 0; // weight=1, victim of cheating

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();

        // Phase 1: Create dealer messages. Dealer 3 creates a cheating message targeting party 0.
        let dealer_messages: Vec<Messages> = (0..num_validators)
            .map(|i| {
                if i == cheating_dealer_idx {
                    Messages::Dkg(create_cheating_message(
                        &setup,
                        i,
                        test_party_idx as u16,
                        &mut rng,
                    ))
                } else {
                    Messages::Dkg(managers[i].create_dealer_message(&mut rng))
                }
            })
            .collect();

        // Phase 2: Collect signatures and create certificates.
        // Validator 0 cannot sign cheating dealer 3's message (corrupt shares → complaint),
        // but validators 1-4 can (their shares are fine).
        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            let mut signatures = Vec::new();
            for (mgr_idx, manager) in managers.iter_mut().enumerate() {
                if dealer_idx == cheating_dealer_idx && mgr_idx == test_party_idx {
                    // Validator 0 can't sign the cheating message — just store it
                    let Messages::Dkg(msg) = messages else {
                        unreachable!()
                    };
                    manager.store_dkg_message(dealer_addr, msg).unwrap();
                    continue;
                }
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::Dkg(cert));
        }

        // Phase 3: Test run_as_dealer() and run_as_party() for validator 0
        let test_manager = managers.remove(0);

        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(test_party_idx));

        // TOB: certificates from dealers 1-4 (dealer 0's cert is created by run_as_dealer)
        let other_certificates: Vec<_> = certificates.iter().skip(1).cloned().collect();
        let mut mock_tob = MockOrderedBroadcastChannel::new(other_certificates);

        let test_manager = Arc::new(RwLock::new(test_manager));

        MpcManager::run_as_dealer(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();
        let output = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify output is valid despite cheating dealer
        assert_eq!(
            output.key_shares.shares.len(),
            weights[test_party_idx] as usize,
        );
        let total_weight: u16 = weights.iter().sum();
        assert_eq!(output.commitments.len(), total_weight as usize);

        // Verify complaint was resolved: output recovered, complaint removed
        let mgr = test_manager.read().unwrap();
        let cheating_addr = setup.address(cheating_dealer_idx);
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(cheating_addr)),
            "Should have recovered output for cheating dealer"
        );
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(cheating_addr)),
            "Complaint should be removed after recovery"
        );
    }

    /// Test setup for run() tests. Creates managers and certificates.
    struct RunTestSetup {
        test_manager: Arc<RwLock<MpcManager>>,
        mock_p2p: MockP2PChannel,
        certificates: Vec<CertificateV1>,
    }

    fn setup_run_test() -> RunTestSetup {
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let setup = TestSetup::new(num_validators);

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();

        // Create dealer messages for validators 1-4 only (not validator 0)
        // Validator 0 will create its own message when run() is called
        // Each dealer's message is wrapped with their share_index = party_id + 1
        let dealer_messages: Vec<_> = managers
            .iter()
            .enumerate()
            .skip(1) // Skip validator 0
            .map(|(_, mgr)| Messages::Dkg(mgr.create_dealer_message(&mut rng)))
            .collect();

        // Create certificates for dealers 1-4
        let mut certificates = Vec::new();
        for (idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_idx = idx + 1; // Dealers 1-4
            let dealer_addr = setup.address(dealer_idx);

            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::Dkg(cert));
        }

        // Extract test_manager (validator 0)
        let test_manager = Arc::new(RwLock::new(managers.remove(0)));

        // Create mock P2P with remaining managers
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));

        RunTestSetup {
            test_manager,
            mock_p2p,
            certificates,
        }
    }

    #[tokio::test]
    async fn test_run_triggers_dealer_phase() {
        let setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // Override weight to 0 so dealer phase runs, but provide enough certs for party to complete
        let mut mock_tob =
            MockOrderedBroadcastChannel::new(setup.certificates).with_override_weight(0);

        let output = MpcManager::run(&setup.test_manager, &setup.mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify dealer published a certificate
        assert!(
            mock_tob.published_count() > 0,
            "Dealer should have published when existing_weight < threshold"
        );

        // Verify DKG completed successfully
        assert_eq!(output.key_shares.shares.len(), 1);
    }

    #[tokio::test]
    async fn test_run_skips_dealer_phase() {
        let setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // With 4 certificates and threshold = 2, existing_weight = 4 >= 2, dealer skips
        let mut mock_tob = MockOrderedBroadcastChannel::new(setup.certificates);

        let output = MpcManager::run(&setup.test_manager, &setup.mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify dealer did NOT publish (skipped)
        assert_eq!(
            mock_tob.published_count(),
            0,
            "Dealer should be skipped when existing_weight >= threshold"
        );

        // Verify DKG completed successfully
        assert_eq!(output.key_shares.shares.len(), 1);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_run_dealer_failure_party_still_executes() {
        let setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // Override weight to 0 so dealer phase runs, but make publish fail
        let mut mock_tob = MockOrderedBroadcastChannel::new(setup.certificates)
            .with_override_weight(0)
            .with_fail_on_publish("simulated publish failure");

        let output = MpcManager::run(&setup.test_manager, &setup.mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify DKG completed successfully (party phase executed despite dealer failure)
        assert_eq!(output.key_shares.shares.len(), 1);

        // Verify warning was logged
        assert!(logs_contain("Dealer phase failed"));
        assert!(logs_contain("simulated publish failure"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_success() {
        let num_validators = 5;
        let setup = TestSetup::new(num_validators);

        // Create manager for validator 0
        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        // Create managers for other validators
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| (setup.address(i), setup.create_manager(i)))
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Call run_as_dealer()
        let result = MpcManager::run_as_dealer(&test_manager, &mock_p2p, &mut mock_tob).await;

        // Verify success
        assert!(result.is_ok());

        // Verify own dealer output is stored
        // DKG: outputs keyed by dealer address
        let validator0_address = setup.address(0);
        assert!(
            test_manager
                .read()
                .unwrap()
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(validator0_address))
        );

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let addr = setup.address(i);
            let other_mgr = other_managers.get(&addr).unwrap();
            assert!(
                other_mgr
                    .dealer_outputs
                    .contains_key(&DealerOutputsKey::Dkg(validator0_address)),
                "Validator {} should have dealer output from validator 0",
                i
            );
        }

        // `test_run_dkg()` verifies end-to-end that TOB publishing works
    }

    #[tokio::test]
    async fn test_run_as_party_success() {
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let setup = TestSetup::new(num_validators);

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();
        let threshold = managers[0].dkg_config.threshold;

        // Pre-create dealer messages and certificates for threshold validators
        // Each dealer's message is wrapped with their share_index = party_id + 1
        let dealer_messages: Vec<_> = managers
            .iter()
            .enumerate()
            .take(threshold as usize)
            .map(|(_, mgr)| Messages::Dkg(mgr.create_dealer_message(&mut rng)))
            .collect();

        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::Dkg(cert));
        }

        // Create mock TOB with threshold certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates.clone());

        // Call run_as_party() for validator 0
        let test_manager = Arc::new(RwLock::new(managers.remove(0)));
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let output = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify output structure
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), num_validators); // total weight = 5

        // Verify TOB consumed exactly threshold certificates
        assert_eq!(mock_tob.pending_messages(), Some(0));
    }

    #[tokio::test]
    async fn test_run_as_party_recovers_shares_via_complaint() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer 0 with normal message
        let dealer_0_addr = setup.address(0);
        let dealer_0_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer_0_message = dealer_0_mgr
            .dealer_messages
            .get(&dealer_0_addr)
            .unwrap()
            .clone();
        let dealer_0_message_hash = compute_messages_hash(&dealer_0_message);
        let dealer_0_dkg_message = DealerMessagesHash {
            dealer_address: dealer_0_addr,
            messages_hash: dealer_0_message_hash,
        };

        // Create dealer 1 with cheating message (corrupts party 2's shares)
        let dealer_1_addr = setup.address(1);
        let dealer_1_msg = create_cheating_message(&setup, 1, 2, &mut rng);
        let dealer_1_message = Messages::Dkg(dealer_1_msg.clone());
        let dealer_1_message_hash = compute_messages_hash(&dealer_1_message);
        let dealer_1_dkg_message = DealerMessagesHash {
            dealer_address: dealer_1_addr,
            messages_hash: dealer_1_message_hash,
        };

        // Create party 2 manager (will have complaint for dealer 1)
        let party_addr = setup.address(2);
        let mut party_manager = setup.create_manager(2);

        // Party 2 successfully processes dealer 0's message
        receive_dealer_messages(&mut party_manager, &dealer_0_message, dealer_0_addr).unwrap();

        // Party 2 stores dealer 1's cheating message and creates complaint during processing
        party_manager
            .store_dkg_message(dealer_1_addr, &dealer_1_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_1_addr)
            .unwrap();
        // DKG: complaints keyed by dealer address
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_1_addr))
        );

        // Create other parties who can successfully process dealer 1's message
        let mut other_managers = HashMap::new();
        for party_id in [0usize, 1, 3, 4] {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            // They successfully process dealer 1's cheating message
            receive_dealer_messages(&mut mgr, &dealer_1_message, dealer_1_addr).unwrap();
            other_managers.insert(addr, mgr);
        }

        let epoch = setup.epoch();
        // Create certificates with signers (excluding party 2 who has complaint)
        let cert_0 = create_certificate_with_signers(
            setup.committee(),
            dealer_0_addr,
            &dealer_0_message,
            [0usize, 1, 3]
                .iter()
                .map(|i| {
                    let addr = setup.address(*i);
                    setup.signing_keys[*i].sign(epoch, addr, &dealer_0_dkg_message)
                })
                .collect(),
        )
        .unwrap();

        let cert_1 = create_certificate_with_signers(
            setup.committee(),
            dealer_1_addr,
            &dealer_1_message,
            [0usize, 1, 3]
                .iter()
                .map(|i| {
                    let addr = setup.address(*i);
                    setup.signing_keys[*i].sign(epoch, addr, &dealer_1_dkg_message)
                })
                .collect(),
        )
        .unwrap();

        let certificates = vec![CertificateV1::Dkg(cert_0), CertificateV1::Dkg(cert_1)];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);
        let mock_p2p = MockP2PChannel::new(other_managers, party_addr);

        // Verify complaint exists before run_as_party
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_1_addr))
        );

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Run as party - should recover shares via complaint
        let output = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify complaint was resolved
        // DKG: complaints keyed by dealer address
        let mgr = party_manager.read().unwrap();
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_1_addr)),
            "Complaint should be cleared after successful recovery"
        );
        // DKG: outputs keyed by dealer address
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_1_addr)),
            "Dealer output should exist for dealer 1 after recovery"
        );

        // Verify output is valid
        assert_eq!(output.key_shares.shares.len(), 1);
        assert_eq!(output.commitments.len(), 5);
    }

    #[tokio::test]
    async fn test_run_as_party_recovers_from_hash_mismatch() {
        // Test that run_as_party() recovers when stored message hash doesn't match certificate hash
        // by retrieving the correct message from certificate signers
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        // BFT threshold = (total_weight - 1) / 3 + 1 = (5-1)/3 + 1 = 2
        let threshold = setup.dkg_config().threshold as usize;

        // Create all managers
        let mut managers: Vec<_> = (0..setup.num_validators())
            .map(|i| setup.create_manager(i))
            .collect();

        // Create threshold valid certificates + some invalid ones
        // Each dealer's message is wrapped with their share_index = party_id + 1
        let dealer_messages: Vec<_> = managers
            .iter()
            .enumerate()
            .take(threshold)
            .map(|(_, mgr)| Messages::Dkg(mgr.create_dealer_message(&mut rng)))
            .collect();

        let mut valid_certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            valid_certificates.push(CertificateV1::Dkg(cert));
        }

        // Create certificate that will fail validation due to hash mismatch
        // (test_manager processes a DIFFERENT message than what's in the cert)
        // Dealer 3 has share_index = 4
        let invalid_dealer_msg = Messages::Dkg(managers[3].create_dealer_message(&mut rng));
        let different_dealer_msg = Messages::Dkg(managers[3].create_dealer_message(&mut rng));
        let dealer_addr_3 = setup.address(3);

        // test_manager processes the DIFFERENT message
        receive_dealer_messages(&mut managers[0], &different_dealer_msg, dealer_addr_3).unwrap();
        // Other managers process the actual message (for cert creation)
        for manager in managers.iter_mut().skip(1) {
            receive_dealer_messages(manager, &invalid_dealer_msg, dealer_addr_3).unwrap();
        }

        // Create certificate for invalid_dealer_msg (but test_manager has different_dealer_msg stored)
        let invalid_signatures: Vec<_> = managers
            .iter()
            .skip(1) // Skip test_manager who has wrong message
            .map(|mgr| {
                let messages_hash = compute_messages_hash(&invalid_dealer_msg);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer_addr_3,
                    messages_hash,
                };
                setup.signing_keys[mgr.party_id as usize].sign(
                    setup.epoch(),
                    mgr.address,
                    &dkg_message,
                )
            })
            .collect();

        let invalid_cert = create_test_certificate(
            setup.committee(),
            &invalid_dealer_msg,
            dealer_addr_3,
            invalid_signatures,
        )
        .unwrap();

        // Mix valid and invalid certificates in TOB
        // Order: valid[0], invalid (will be recovered), valid[1], ...
        // With threshold=2, we need accumulated weight >= 2 from unique dealers
        let mut all_certificates = vec![
            valid_certificates[0].clone(),
            CertificateV1::Dkg(invalid_cert), // hash mismatch - will be recovered from P2P
        ];
        // Add remaining valid certificates if any
        for cert in valid_certificates.iter().skip(1) {
            all_certificates.push(cert.clone());
        }

        let num_certs = all_certificates.len();
        let mut mock_tob = MockOrderedBroadcastChannel::new(all_certificates);

        // Call run_as_party() for validator 0
        let test_manager = Arc::new(RwLock::new(managers.remove(0)));
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let output = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify success: the mismatched certificate's message was retrieved and processed
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), setup.num_validators()); // total weight = 5

        // TOB should have consumed at least threshold certificates
        let remaining = mock_tob.pending_messages().unwrap();
        assert!(
            remaining < num_certs,
            "TOB should have consumed at least {} certificates, remaining: {}",
            threshold,
            remaining
        );
    }

    #[tokio::test]
    async fn test_run_as_party_requires_different_dealers() {
        // Test that having t certificates from a single dealer is not sufficient
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create all managers
        let mut managers: Vec<_> = (0..setup.num_validators())
            .map(|i| setup.create_manager(i))
            .collect();

        // Create dealer messages from 2 dealers
        // Each dealer's message is wrapped with their share_index = party_id + 1
        let dealer_messages: Vec<_> = managers
            .iter()
            .enumerate()
            .take(2)
            .map(|(_, mgr)| Messages::Dkg(mgr.create_dealer_message(&mut rng)))
            .collect();

        // Create certificates
        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_messages(manager, messages, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::Dkg(cert));
        }

        // Mock TOB delivers: dealer 0 cert, dealer 0 cert again (duplicate), then dealer 1 cert
        // Total of 3 messages, but only 2 unique dealers
        let tob_messages = vec![
            certificates[0].clone(), // From dealer 0
            certificates[0].clone(), // From dealer 0 again (duplicate)
            certificates[1].clone(), // From dealer 1
        ];
        let mut mock_tob = MockOrderedBroadcastChannel::new(tob_messages);

        // Call run_as_party() for validator 2
        let test_manager = Arc::new(RwLock::new(managers.remove(2)));
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| {
                let addr_idx = if idx < 2 { idx } else { idx + 1 };
                (setup.address(addr_idx), mgr)
            })
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(2));
        let output = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify it correctly waited for 2 different dealers
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), setup.num_validators()); // total weight = 5

        // Verify TOB consumed all 3 messages (not just the first 2)
        assert_eq!(mock_tob.pending_messages(), Some(0));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_run_as_dealer_p2p_send_error() {
        let (test_manager, _) = create_manager_with_valid_keys(0, 5);
        let test_manager = Arc::new(RwLock::new(test_manager));

        let failing_p2p = FailingP2PChannel {
            error_message: "network error".to_string(),
        };
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let result = MpcManager::run_as_dealer(&test_manager, &failing_p2p, &mut mock_tob).await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        assert!(logs_contain("Failed to send message"));
        assert!(logs_contain("network error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_tob_publish_error() {
        let setup = TestSetup::new(5);

        // Create test manager (validator 0)
        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        // Create managers for validators 1-4 to respond with valid signatures
        let other_managers: HashMap<_, _> = (1..setup.num_validators())
            .map(|i| {
                let addr = setup.address(i);
                let manager = setup.create_manager(i);
                (addr, manager)
            })
            .collect();

        let succeeding_p2p = SucceedingP2PChannel::new(other_managers, setup.address(0));

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "consensus error".to_string(),
            fail_on_publish: true,
            fail_on_receive: false,
        };

        let result =
            MpcManager::run_as_dealer(&test_manager, &succeeding_p2p, &mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(ERR_PUBLISH_CERT_FAILED));
        assert!(err.to_string().contains("consensus error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_partial_failures_still_collects_enough() {
        // Use 7 validators so we have more room for failures
        // threshold=4, max_faulty=1, required_sigs=5
        // Dealer sends to 6 others, fail 1, succeed 5
        let setup = TestSetup::new(7);

        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        let other_managers: HashMap<_, _> = (1..setup.num_validators())
            .map(|i| {
                let addr = setup.address(i);
                let manager = setup.create_manager(i);
                (addr, manager)
            })
            .collect();

        let partially_failing_p2p = PartiallyFailingP2PChannel::new(
            other_managers,
            setup.address(0),
            1, // Fail 1 out of 6, get 5 signatures
        );

        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let result =
            MpcManager::run_as_dealer(&test_manager, &partially_failing_p2p, &mut mock_tob).await;

        assert!(result.is_ok());
        // Verify that a certificate was published
        assert_eq!(mock_tob.published_count(), 1);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_run_as_dealer_partial_failures_insufficient_signatures() {
        let setup = TestSetup::new(5);

        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        let other_managers: HashMap<_, _> = (1..setup.num_validators())
            .map(|i| {
                let addr = setup.address(i);
                let manager = setup.create_manager(i);
                (addr, manager)
            })
            .collect();

        // Fail too many validators - fail 3 out of 4, only 1 succeeds
        let partially_failing_p2p =
            PartiallyFailingP2PChannel::new(other_managers, setup.address(0), 3);

        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let result =
            MpcManager::run_as_dealer(&test_manager, &partially_failing_p2p, &mut mock_tob).await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        // Verify logging occurred for the 3 failures
        assert!(logs_contain("Failed to send message"));
    }
    #[tokio::test]
    async fn test_run_as_dealer_includes_own_signature() {
        let setup = TestSetup::new(5);

        // Create manager for validator 0 (the dealer)
        let dealer_addr = setup.address(0);
        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        // Create managers for other validators
        let other_managers: HashMap<_, _> = (1..setup.num_validators())
            .map(|i| {
                let addr = setup.address(i);
                let manager = setup.create_manager(i);
                (addr, manager)
            })
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, dealer_addr);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Run as dealer
        let result = MpcManager::run_as_dealer(&test_manager, &mock_p2p, &mut mock_tob).await;

        assert!(result.is_ok());

        // Verify a certificate was published
        assert_eq!(mock_tob.published_count(), 1);

        // Extract the certificate
        let published = mock_tob.published.lock().unwrap();
        let cert = &published[0];

        // Get the list of signers from the certificate
        let signers = cert
            .signers(setup.committee())
            .expect("Failed to get signers from certificate");

        // Verify the dealer's own signature is included
        assert!(
            signers.contains(&dealer_addr),
            "Dealer's own signature must be included in the certificate"
        );

        // Verify we have the expected number of distinct signers
        let signers_set: std::collections::HashSet<_> = signers.iter().collect();
        assert_eq!(
            signers_set.len(),
            signers.len(),
            "All signatures should be from distinct validators"
        );
    }

    #[tokio::test]
    async fn test_run_as_party_tob_receive_error() {
        let setup = TestSetup::new(5);
        let test_manager = Arc::new(RwLock::new(setup.create_manager(0)));

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "receive timeout".to_string(),
            fail_on_publish: false,
            fail_on_receive: true,
        };

        let mock_p2p = MockP2PChannel::new(HashMap::new(), setup.address(0));
        let result = MpcManager::run_as_party(&test_manager, &mock_p2p, &mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::BroadcastError(_)));
        assert!(err.to_string().contains("receive timeout"));
    }
    //
    struct WeightBasedTestSetup {
        setup: TestSetup,
        dealer_messages: Vec<(Address, Messages)>,
        certificates: Vec<CertificateV1>,
    }

    //
    fn setup_weight_based_test(
        weights: Vec<u16>,
        _threshold: u16,
        num_dealers: Option<usize>,
    ) -> WeightBasedTestSetup {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::with_weights(&weights);

        // Create dealer managers (either all validators or specified subset)
        let dealer_count = num_dealers.unwrap_or(setup.num_validators());
        let dealer_managers: Vec<_> = (0..dealer_count).map(|i| setup.create_manager(i)).collect();

        // Generate dealer messages once and store them
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|manager| {
                let message = manager.create_dealer_message(&mut rng);
                let messages = Messages::Dkg(message);
                (manager.address, messages)
            })
            .collect();

        // Create certificates from the stored messages
        let certificates: Vec<_> = dealer_messages
            .iter()
            .map(|(dealer_addr, messages)| {
                create_weight_based_test_certificate(&setup, dealer_addr, messages)
            })
            .collect();

        WeightBasedTestSetup {
            setup,
            dealer_messages,
            certificates,
        }
    }

    // Create a test certificate with minimal valid signatures for weight-based tests
    fn create_weight_based_test_certificate(
        setup: &TestSetup,
        dealer_addr: &Address,
        messages: &Messages,
    ) -> CertificateV1 {
        let messages_hash = compute_messages_hash(messages);
        let dkg_message = DealerMessagesHash {
            dealer_address: *dealer_addr,
            messages_hash,
        };

        let config = setup.dkg_config();
        let committee = setup.committee();
        let mut aggregator =
            hashi_types::committee::BlsSignatureAggregator::new(committee, dkg_message.clone());

        // Add signatures from validators until we meet the required weight
        let dkg_required = config.threshold;
        let mut weight_sum = 0u16;

        for i in 0..setup.num_validators() {
            let signer_addr = setup.address(i);
            let signature = setup.signing_keys[i].sign(setup.epoch(), signer_addr, &dkg_message);
            aggregator.add_signature(signature).unwrap();
            weight_sum += config
                .nodes
                .iter()
                .find(|n| n.id == i as u16)
                .map(|n| n.weight)
                .unwrap_or(1);

            if weight_sum >= dkg_required {
                break;
            }
        }

        CertificateV1::Dkg(aggregator.finish().unwrap())
    }

    // Helper to create and setup a party manager for testing
    async fn setup_party_and_run(
        test_setup: &WeightBasedTestSetup,
        party_index: usize,
    ) -> (MpcResult<DkgOutput>, MockOrderedBroadcastChannel) {
        let party_addr = test_setup.setup.address(party_index);

        let mut party_manager = test_setup.setup.create_manager(party_index);

        // Pre-process the dealer messages so validation passes
        for (dealer_addr, messages) in &test_setup.dealer_messages {
            let _ = receive_dealer_messages(&mut party_manager, messages, *dealer_addr);
        }

        // Create mock TOB with certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(test_setup.certificates.clone());

        // Run party collection
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);
        let party_manager = Arc::new(RwLock::new(party_manager));
        let result = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob).await;

        (result, mock_tob)
    }

    #[tokio::test]
    async fn test_run_as_party_weight_based_collection() {
        // Test that run_as_party stops collecting when dealer_weight_sum >= threshold
        // Use weights [1, 1, 1, 2, 2] (total = 7)
        // With threshold=3, we need dealers with total weight >= 3
        // This ensures we get exactly 3 dealers (1+1+1=3) to satisfy both weight and AVSS requirements
        let weights = vec![1, 1, 1, 2, 2];
        let test_setup = setup_weight_based_test(weights.clone(), 3, None);
        let (result, mock_tob) = setup_party_and_run(&test_setup, 0).await;

        assert!(result.is_ok());

        // Key verification: Check how many certificates were consumed
        // BTreeMap ordering of addresses: [0,0,0,...], [1,1,1,...], [2,2,2,...], etc
        // Weights: addr0=1, addr1=1, addr2=1, addr3=2, addr4=2
        // Should consume addr0 (weight 1) + addr1 (weight 1) + addr2 (weight 1) = total weight 3 >= threshold
        let remaining = mock_tob.pending_messages().unwrap();
        assert_eq!(
            remaining, 2,
            "Should consume exactly 3 certificates to reach weight threshold of 3"
        );

        // Verify the output
        let output = result.unwrap();
        assert_eq!(output.key_shares.shares.len(), weights[0] as usize); // Party 0 has weight 1
    }

    #[tokio::test]
    async fn test_run_as_party_sufficient_combined_weight() {
        // Test that dealers with sufficient combined weight can complete DKG
        // Use weights [4, 1, 1, 1, 1] (total = 8)
        // Create only 2 dealers (validator 0 with weight 4, validator 1 with weight 1)
        // Combined weight: 4 + 1 = 5 >= threshold 3
        let test_setup = setup_weight_based_test(vec![4, 1, 1, 1, 1], 3, Some(2));
        let (result, _mock_tob) = setup_party_and_run(&test_setup, 2).await;

        // Should succeed: complete_dkg() validates that dealer weights sum >= threshold
        // which is satisfied (5 >= 3)
        assert!(
            result.is_ok(),
            "Expected success with sufficient dealer weight, got: {:?}",
            result.unwrap_err()
        );
    }

    #[tokio::test]
    async fn test_run_as_party_exact_weight_threshold() {
        // Test edge case where accumulated weight exactly equals threshold
        // Use weights [1, 1, 1, 1, 1] (all equal), total_weight=5
        // BFT threshold = (total_weight - 1) / 3 + 1 = (5-1)/3 + 1 = 1 + 1 = 2
        // So we need exactly 2 dealers (weight 1+1 = 2) to reach threshold
        let test_setup = setup_weight_based_test(vec![1, 1, 1, 1, 1], 2, None);
        let (result, mock_tob) = setup_party_and_run(&test_setup, 0).await;

        assert!(result.is_ok());

        // Should consume exactly 2 certificates (weight 1+1 = 2 = threshold)
        let remaining = mock_tob.pending_messages().unwrap();
        assert_eq!(
            remaining, 3,
            "Should consume exactly 2 certificates to reach threshold"
        );
    }

    #[tokio::test]
    async fn test_run_as_party_with_reduced_weights() {
        let weights = vec![2500, 2500, 2500, 2500];
        let test_setup = setup_weight_based_test(weights.clone(), 0, None); // threshold computed automatically

        let manager = test_setup.setup.create_manager(0);
        let original_weight: u16 = test_setup
            .setup
            .committee()
            .weight_of(&manager.address)
            .unwrap() as u16;
        let reduced_weight = manager
            .dkg_config
            .nodes
            .weight_of(manager.party_id)
            .unwrap();

        assert_ne!(
            original_weight, reduced_weight,
            "Test requires weights to be reduced by Nodes::new_reduced. \
             Original: {}, Reduced: {}. If equal, this test won't catch the bug.",
            original_weight, reduced_weight
        );

        let (result, _mock_tob) = setup_party_and_run(&test_setup, 0).await;

        assert!(
            result.is_ok(),
            "run_as_party should succeed when using correct reduced weights. \
             Failure indicates weight tracking uses committee weights instead of \
             dkg_config.nodes weights. Error: {:?}",
            result.unwrap_err()
        );
    }

    #[tokio::test]
    async fn test_run_as_party_skips_duplicate_dealers() {
        // Test that run_as_party skips duplicate certificates from the same dealer without validation

        // Setup with normal weights
        let weights = vec![1, 1, 1, 2, 2];
        let threshold = 3;
        let test_setup = setup_weight_based_test(weights.clone(), threshold, None);

        // Create certificates but duplicate some dealers
        // We'll create: dealer0, dealer0 (duplicate), dealer1, dealer1 (duplicate), dealer2, dealer3
        let modified_certificates = vec![
            test_setup.certificates[0].clone(), // dealer 0
            test_setup.certificates[0].clone(), // dealer 0 duplicate
            test_setup.certificates[1].clone(), // dealer 1
            test_setup.certificates[1].clone(), // dealer 1 duplicate
            test_setup.certificates[2].clone(), // dealer 2
            test_setup.certificates[3].clone(), // dealer 3
        ];

        // Now we have 6 certificates but only 4 unique dealers
        assert_eq!(modified_certificates.len(), 6);

        // Create party manager
        let party_addr = test_setup.setup.address(0);
        let mut party_manager = test_setup.setup.create_manager(0);

        // Pre-process the dealer messages
        for (dealer_addr, messages) in &test_setup.dealer_messages {
            let _ = receive_dealer_messages(&mut party_manager, messages, *dealer_addr);
        }

        // Create mock TOB with the modified certificates (including duplicates)
        let mut mock_tob = MockOrderedBroadcastChannel::new(modified_certificates);

        // Run party collection
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);
        let party_manager = Arc::new(RwLock::new(party_manager));
        let result = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob).await;
        assert!(result.is_ok());

        // Verify behavior:
        // Should process: dealer0 (weight 1), skip dealer0 duplicate,
        //                dealer1 (weight 1), skip dealer1 duplicate,
        //                dealer2 (weight 1) - now we have weight 3 >= threshold
        // Should NOT process: dealer3 (since we already have enough weight)
        let remaining = mock_tob.pending_messages().unwrap();

        // We started with 6 certificates
        // Consumed: dealer0, dealer0_dup (skipped), dealer1, dealer1_dup (skipped), dealer2
        // That's 5 certificates consumed (including skipped ones), 1 remaining
        assert_eq!(
            remaining, 1,
            "Should have 1 certificate remaining (dealer3)"
        );
    }

    #[tokio::test]
    async fn test_run_as_party_retrieves_missing_dealer_messages() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create 3 dealers with their messages
        let dealer1_addr = setup.address(0);
        let dealer1_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer2_addr = setup.address(1);
        let dealer2_mgr = setup.create_dealer_with_message(1, &mut rng);

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let party_addr = setup.address(3);
        let party_manager = setup.create_manager(3);

        // Get the dealer messages for certificate creation
        let msg1 = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();
        let msg2 = dealer2_mgr
            .dealer_messages
            .get(&dealer2_addr)
            .unwrap()
            .clone();

        let epoch = setup.epoch();
        // Create signatures for certificates
        let signatures_1: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let messages_hash = compute_messages_hash(&msg1);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer1_addr,
                    messages_hash,
                };
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let signatures_2: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let messages_hash = compute_messages_hash(&msg2);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer2_addr,
                    messages_hash,
                };
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        // Create certificates using the test helper
        let cert1 =
            create_test_certificate(setup.committee(), &msg1, dealer1_addr, signatures_1).unwrap();
        let cert2 =
            create_test_certificate(setup.committee(), &msg2, dealer2_addr, signatures_2).unwrap();

        // Create mock P2P channel with dealers that have messages
        let mut dealers = HashMap::new();
        dealers.insert(dealer1_addr, dealer1_mgr);
        dealers.insert(dealer2_addr, dealer2_mgr);
        let mock_p2p = MockP2PChannel::new(dealers, party_addr);

        // Create mock TOB with certificates - threshold is 2, so we need 2 dealers
        let certificates = vec![CertificateV1::Dkg(cert1), CertificateV1::Dkg(cert2)];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        // Verify party doesn't have any dealer messages yet
        assert!(party_manager.dealer_messages.is_empty());

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Run as party - should retrieve missing messages via P2P
        let result = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob).await;

        assert!(result.is_ok());
        let mgr = party_manager.read().unwrap();
        assert!(mgr.dealer_messages.contains_key(&dealer1_addr));
        assert!(mgr.dealer_messages.contains_key(&dealer2_addr));
        // DKG: outputs keyed by dealer address
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer1_addr))
        );
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer2_addr))
        );
    }

    #[tokio::test]
    async fn test_run_as_party_aborts_on_retrieval_failure() {
        // Tests that run_as_party aborts with error when message retrieval fails
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create 3 dealers with their messages
        let dealer1_addr = setup.address(0);
        let dealer1_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer2_addr = setup.address(1);
        let _dealer2_mgr = setup.create_dealer_with_message(1, &mut rng);
        let dealer3_addr = setup.address(2);
        let dealer3_mgr = setup.create_dealer_with_message(2, &mut rng);

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let party_addr = setup.address(3);
        let party_manager = setup.create_manager(3);

        // Get the dealer messages for certificate creation
        let msg1 = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();
        let msg2 = _dealer2_mgr
            .dealer_messages
            .get(&dealer2_addr)
            .unwrap()
            .clone();
        let msg3 = dealer3_mgr
            .dealer_messages
            .get(&dealer3_addr)
            .unwrap()
            .clone();

        let epoch = setup.epoch();
        // Helper to create signatures
        let create_sigs = |dealer_addr: Address, msgs: &Messages| -> Vec<MemberSignature> {
            (0..3)
                .map(|i| {
                    let addr = setup.address(i);
                    let messages_hash = compute_messages_hash(msgs);
                    let dkg_message = DealerMessagesHash {
                        dealer_address: dealer_addr,
                        messages_hash,
                    };
                    setup.signing_keys[i].sign(epoch, addr, &dkg_message)
                })
                .collect()
        };

        // Create certificates for all three dealers
        let cert1 = create_test_certificate(
            setup.committee(),
            &msg1,
            dealer1_addr,
            create_sigs(dealer1_addr, &msg1),
        )
        .unwrap();
        let cert2 = create_test_certificate(
            setup.committee(),
            &msg2,
            dealer2_addr,
            create_sigs(dealer2_addr, &msg2),
        )
        .unwrap();
        let cert3 = create_test_certificate(
            setup.committee(),
            &msg3,
            dealer3_addr,
            create_sigs(dealer3_addr, &msg3),
        )
        .unwrap();

        // Create mock P2P channel with only dealer1 and dealer3 (dealer2 is missing)
        // So retrieval of dealer2's message will fail
        let mut dealers = HashMap::new();
        dealers.insert(dealer1_addr, dealer1_mgr);
        dealers.insert(dealer3_addr, dealer3_mgr);
        let mock_p2p = MockP2PChannel::new(dealers, party_addr);

        // Create mock TOB with all three certificates
        let certificates = vec![
            CertificateV1::Dkg(cert1),
            CertificateV1::Dkg(cert2),
            CertificateV1::Dkg(cert3),
        ];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Run as party - should process dealer1 successfully, then ABORT on dealer2 retrieval failure
        let result = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob).await;

        // Should fail with PairwiseCommunicationError (could not retrieve message from any signer)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::PairwiseCommunicationError(_)));

        // Verify party has dealer1 message (processed before failure)
        let mgr = party_manager.read().unwrap();
        assert!(mgr.dealer_messages.contains_key(&dealer1_addr));
        // But NOT dealer2 or dealer3 (aborted before processing these)
        assert!(!mgr.dealer_messages.contains_key(&dealer2_addr));
        assert!(!mgr.dealer_messages.contains_key(&dealer3_addr));
    }

    #[tokio::test]
    async fn test_run_as_party_aborts_on_failed_recovery() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer 0 with a message - recovery will fail
        let dealer0_addr = setup.address(0);
        let dealer0_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer0_message = dealer0_mgr
            .dealer_messages
            .get(&dealer0_addr)
            .unwrap()
            .clone();
        let dealer0_message_hash = compute_messages_hash(&dealer0_message);
        let dealer0_dkg_message = DealerMessagesHash {
            dealer_address: dealer0_addr,
            messages_hash: dealer0_message_hash,
        };

        // Create dealer 1 - would be processed if we continued
        let dealer1_addr = setup.address(1);
        let dealer1_mgr = setup.create_dealer_with_message(1, &mut rng);
        let dealer1_message = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();
        let dealer1_message_hash = compute_messages_hash(&dealer1_message);
        let dealer1_dkg_message = DealerMessagesHash {
            dealer_address: dealer1_addr,
            messages_hash: dealer1_message_hash,
        };

        // Create party manager (validator 4)
        let party_addr = setup.address(4);
        let mut party_manager = setup.create_manager(4);

        // Setup complaint for dealer 0 (recovery will fail - no responders in P2P)
        let complaint = create_complaint_for_dealer(&setup, &dealer0_message, 4, 0, &mut rng);
        setup_party_with_complaint(
            &mut party_manager,
            &dealer0_addr,
            &dealer0_message,
            complaint,
        );

        let epoch = setup.epoch();
        // Create certificates with signers (excluding party 2 who has complaint)
        let cert0 = create_certificate_with_signers(
            setup.committee(),
            dealer0_addr,
            &dealer0_message,
            [0usize, 1, 3]
                .iter()
                .map(|i| {
                    let addr = setup.address(*i);
                    setup.signing_keys[*i].sign(epoch, addr, &dealer0_dkg_message)
                })
                .collect(),
        )
        .unwrap();
        let cert1 = create_certificate_with_signers(
            setup.committee(),
            dealer1_addr,
            &dealer1_message,
            [0usize, 1, 3]
                .iter()
                .map(|i| {
                    let addr = setup.address(*i);
                    setup.signing_keys[*i].sign(epoch, addr, &dealer1_dkg_message)
                })
                .collect(),
        )
        .unwrap();

        // Create mock P2P with no responders (recovery will fail)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Create mock TOB with both certificates
        let certificates = vec![CertificateV1::Dkg(cert0), CertificateV1::Dkg(cert1)];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Run as party - should ABORT on dealer0 recovery failure
        // With retry logic, failed signers are skipped, so we get ProtocolFailed
        let result = MpcManager::run_as_party(&party_manager, &mock_p2p, &mut mock_tob).await;

        // Should fail with ProtocolFailed (all signers failed, not enough responses)
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, MpcError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );

        // Verify dealer1 was NOT processed (aborted before reaching it)
        let mgr = party_manager.read().unwrap();
        // DKG: outputs keyed by dealer address
        assert!(
            !mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer1_addr)),
            "Dealer1 should NOT be processed - aborted before reaching it"
        );

        // Dealer0 should NOT be in dealer_outputs (recovery failed, DKG aborted)
        assert!(
            !mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer0_addr)),
            "Dealer0 should NOT have output - recovery failed and aborted"
        );

        // Complaint for dealer0 should still be present (wasn't removed due to failure)
        assert!(
            mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer0_addr)),
            "Complaint should remain after recovery failure"
        );
    }

    #[tokio::test]
    async fn test_handle_send_messages_request() {
        // Test that handle_send_messages_request works with the new request/response types
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 1) with its encryption key
        let dealer_address = setup.address(1);
        let dealer_manager = setup.create_manager(1);

        // Create receiver (party 0) with its encryption key
        let receiver_address = setup.address(0);
        let mut receiver_manager = setup.create_manager(0);

        // Dealer creates a message and wrap it for the request
        let dealer_message = dealer_manager.create_dealer_message(&mut rng);
        let dealer_messages = Messages::Dkg(dealer_message);

        // Create a request as if dealer sent it to receiver
        let request = SendMessagesRequest {
            messages: dealer_messages.clone(),
        };

        // Receiver handles the request
        let response = receiver_manager
            .handle_send_messages_request(dealer_address, &request)
            .unwrap();

        // Verify we got a valid BLS signature (non-empty)
        assert!(!response.signature.as_ref().is_empty());
        let _ = receiver_address; // suppress unused warning
    }

    #[tokio::test]
    async fn test_handle_retrieve_messages_request_success() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 0)
        let dealer_address = setup.address(0);
        let mut dealer_manager = setup.create_manager(0);

        // Dealer creates and processes its own message (stores in dealer_messages)
        let dealer_message = dealer_manager.create_dealer_message(&mut rng);
        let dealer_messages = Messages::Dkg(dealer_message);
        receive_dealer_messages(&mut dealer_manager, &dealer_messages, dealer_address).unwrap();

        // Party requests the dealer's message
        let request = RetrieveMessagesRequest {
            dealer: dealer_address,
        };
        let response = dealer_manager
            .handle_retrieve_messages_request(&request)
            .unwrap();

        let expected_hash = compute_messages_hash(&dealer_messages);
        let received_hash = compute_messages_hash(&response.messages);
        assert_eq!(received_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_handle_retrieve_messages_request_message_not_available() {
        let setup = TestSetup::new(5);

        // Create dealer (party 0) but don't create/process any message
        let dealer_address = setup.address(0);
        let dealer_manager = setup.create_manager(0);

        // Party requests the dealer's message
        let request = RetrieveMessagesRequest {
            dealer: dealer_address,
        };
        let result = dealer_manager.handle_retrieve_messages_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::NotFound(_)));
        assert!(err.to_string().contains("Messages for dealer"));
    }

    #[test]
    fn test_handle_complain_request_no_message_from_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let (dealer_address, _dealer_message, complaint) =
            create_dealer_message_and_complaint(&setup, &mut rng);

        // Create manager (party 1) without any dealer messages
        let mut manager = setup.create_manager(1);

        // For DKG, share_index is None (dealer has only one share)
        let request = ComplainRequest {
            dealer: dealer_address,
            share_index: None,
            complaint,
        };

        // Manager has no message from this dealer
        let result = manager.handle_complain_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No message from dealer"));
    }

    #[test]
    fn test_handle_complain_request_no_shares_for_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let (dealer_address, dealer_messages, complaint) =
            create_dealer_message_and_complaint(&setup, &mut rng);

        // Create manager that has the message but NOT dealer_output
        let mut manager = setup.create_manager(1);

        // Manually insert without processing (so no dealer_output)
        manager
            .dealer_messages
            .insert(dealer_address, dealer_messages);

        // For DKG, share_index is None (dealer has only one share)
        let request = ComplainRequest {
            dealer: dealer_address,
            share_index: None,
            complaint,
        };

        // Manager has message but no output for the share
        let result = manager.handle_complain_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        // DKG error message uses "dealer" not "share"
        assert!(err.to_string().contains("No output for complained dealer"));
    }

    #[test]
    fn test_handle_complain_request_caches_response() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create a cheating dealer message with corrupted shares for party 1
        let cheating_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Party 1 processes the corrupted message and gets a complaint
        let config = setup.dkg_config();
        let session_id = setup.session_id();
        let dealer_session_id = session_id.dealer_session_id(&dealer_addr);
        let receiver1 = avss::Receiver::new(
            config.nodes.clone(),
            1,
            config.threshold,
            dealer_session_id.to_vec(),
            None,
            setup.encryption_keys[1].clone(),
        );

        let Messages::Dkg(inner_msg) = &cheating_message else {
            unreachable!()
        };
        let result = receiver1.process_message(inner_msg);
        let complaint = match result {
            Ok(avss::ProcessedMessage::Complaint(c)) => c,
            Ok(_) => panic!("Expected complaint but got valid shares"),
            Err(e) => panic!("Processing failed with error: {:?}", e),
        };

        // Party 2 processes the SAME cheating message
        // Party 2's shares are valid (not corrupted) so it gets valid output
        let mut party2_manager = setup.create_manager(2);

        // Set up party 2 with the cheating message
        receive_dealer_messages(&mut party2_manager, &cheating_message, dealer_addr).unwrap();

        // For DKG, share_index is None (dealer has only one share)
        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: None,
            complaint: complaint.clone(),
        };

        // First call - should compute and cache
        let response1 = party2_manager.handle_complain_request(&request).unwrap();

        // Verify cache contains the response
        assert_eq!(party2_manager.complaint_responses.len(), 1);
        assert!(
            party2_manager
                .complaint_responses
                .contains_key(&dealer_addr)
        );

        // Second call - should return cached response
        let response2 = party2_manager.handle_complain_request(&request).unwrap();

        // Verify responses are identical
        assert_eq!(
            bcs::to_bytes(&response1).unwrap(),
            bcs::to_bytes(&response2).unwrap(),
            "Second call should return cached response"
        );

        // Cache size should still be 1
        assert_eq!(party2_manager.complaint_responses.len(), 1);
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_succeeds_with_exact_threshold() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let cheating_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        let Messages::Dkg(inner_msg) = &cheating_message else {
            unreachable!()
        };
        party_manager
            .store_dkg_message(dealer_addr, inner_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_addr)
            .unwrap();
        // DKG: complaints keyed by dealer address
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr))
        );

        // Create exactly threshold (2) parties that can respond
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_messages(&mut mgr, &cheating_message, dealer_addr).unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers.iter().map(|(addr, _)| *addr).collect();

        let managers_map: HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Recover with exactly threshold signers
        // Tests incremental recovery: receiver.recover() returns InputTooShort after first response,
        // continues to collect second response, then succeeds
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            signer_addresses,
            &mock_p2p,
        )
        .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed: {:?}",
            result.err()
        );
        let mgr = party_manager.read().unwrap();
        // DKG: outputs keyed by dealer address
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_addr))
        );
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr)),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_skips_failed_signers() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let cheating_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        let Messages::Dkg(inner_msg) = &cheating_message else {
            unreachable!()
        };
        party_manager
            .store_dkg_message(dealer_addr, inner_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_addr)
            .unwrap();
        // DKG: complaints keyed by dealer address
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr))
        );

        // Create 2 parties that can respond (threshold is 2)
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_messages(&mut mgr, &cheating_message, dealer_addr).unwrap();
            other_managers.push((addr, mgr));
        }

        // Add a non-existent signer that will fail
        let failing_signer = Address::new([99; 32]);

        // Signer list: [failing_signer, valid_signer1, valid_signer2]
        // The first signer fails, but recovery should still succeed with the remaining two
        let mut signer_addresses = vec![failing_signer];
        signer_addresses.extend(other_managers.iter().map(|(addr, _)| *addr));

        let managers_map: HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Recovery should succeed despite first signer failing
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            signer_addresses,
            &mock_p2p,
        )
        .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed despite failed signer: {:?}",
            result.err()
        );
        let mgr = party_manager.read().unwrap();
        // DKG: outputs keyed by dealer address
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_addr))
        );
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr)),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_complaint_for_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create manager without any complaints
        let party_addr = setup.address(1);
        let party_manager = setup.create_manager(1);

        // Create a dealer address that has no complaint
        let dealer_addr = setup.address(0);
        let dealer_manager = setup.create_dealer_with_message(0, &mut rng);

        let dealer_message = dealer_manager.dealer_messages.get(&dealer_addr).unwrap();
        let messages_hash = compute_messages_hash(dealer_message);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };

        // Create a minimal certificate
        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_addr,
            dealer_message,
            vec![setup.signing_keys[1].sign(setup.epoch(), party_addr, &dkg_message)],
        )
        .unwrap();

        // Create empty mock P2P channel
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        let signers = cert.signers(&party_manager.committee).unwrap();
        let party_manager = Arc::new(RwLock::new(party_manager));

        // Call recover_shares_via_complaint - should fail because no complaint exists
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            signers,
            &mock_p2p,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No complaint for dealer"));
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_p2p_failure() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer with a message
        let dealer_addr = setup.address(0);
        let dealer_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer_message = dealer_mgr
            .dealer_messages
            .get(&dealer_addr)
            .unwrap()
            .clone();

        // Create party manager with a complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);

        // Create and setup complaint for dealer
        let complaint = create_complaint_for_dealer(&setup, &dealer_message, 1, 0, &mut rng);
        setup_party_with_complaint(&mut party_manager, &dealer_addr, &dealer_message, complaint);

        // Create certificate with a signer that doesn't exist in mock P2P
        let signer_addresses = vec![Address::new([99; 32])]; // This validator doesn't exist

        // Create empty mock P2P channel (no responders)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Call recover_shares_via_complaint - should fail because P2P call fails
        // With retry logic, failed signers are skipped (continue), so we get ProtocolFailed
        // instead of BroadcastError
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            signer_addresses,
            &mock_p2p,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, MpcError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );
        assert!(err.to_string().contains("Not enough valid"));
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_insufficient_signers() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let cheating_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        let Messages::Dkg(inner_msg) = &cheating_message else {
            unreachable!()
        };
        party_manager
            .store_dkg_message(dealer_addr, inner_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_addr)
            .unwrap();
        // DKG: complaints keyed by dealer address
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr))
        );

        // Create only 1 other party that can respond (threshold is 2, so insufficient)
        let mut other_managers = vec![];
        for party_id in 2..3 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_messages(&mut mgr, &cheating_message, dealer_addr).unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers.iter().map(|(addr, _)| *addr).collect();

        let managers_map: HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Attempt recovery with insufficient signers
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            signer_addresses,
            &mock_p2p,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, MpcError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );
        assert!(
            err.to_string().contains("Not enough valid"),
            "Error message should indicate insufficient responses, got: {}",
            err
        );
    }

    #[tokio::test]
    #[should_panic(expected = "cannot have complaint without message")]
    async fn test_recover_shares_via_complaint_no_dealer_message() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let cheating_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        let Messages::Dkg(inner_msg) = &cheating_message else {
            unreachable!()
        };
        party_manager
            .store_dkg_message(dealer_addr, inner_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_addr)
            .unwrap();
        // DKG: complaints keyed by dealer address
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr))
        );

        // Remove the dealer message to simulate the edge case
        party_manager.dealer_messages.remove(&dealer_addr);

        // Create mock P2P (empty is fine since we should fail before contacting anyone)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Try to recover - should fail because dealer message is missing
        let _ = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            vec![Address::new([2; 32])],
            &mock_p2p,
        )
        .await;
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_crypto_error() {
        // This test triggers a genuine crypto error by providing complaint responses
        // from parties whose IDs are not in the receiver's nodes configuration.
        // When receiver.recover() calls total_weight_of() with invalid party IDs,
        // it returns a FastCryptoError that gets wrapped as CryptoError.

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let dealer_message = Messages::Dkg(create_cheating_message(&setup, 0, 1, &mut rng));

        // Create responders 3 and 4 who successfully process the dealer message
        let addr3 = setup.address(3);
        let mut mgr3 = setup.create_manager(3);
        receive_dealer_messages(&mut mgr3, &dealer_message, dealer_addr).unwrap();

        let addr4 = setup.address(4);
        let mut mgr4 = setup.create_manager(4);
        receive_dealer_messages(&mut mgr4, &dealer_message, dealer_addr).unwrap();

        // Party 1 complains
        let mut party_manager = setup.create_manager(1);
        let Messages::Dkg(inner_msg) = &dealer_message else {
            unreachable!()
        };
        party_manager
            .store_dkg_message(dealer_addr, inner_msg)
            .unwrap();
        party_manager
            .process_certified_dkg_message(dealer_addr)
            .unwrap();

        // Pre-collect complaint responses from parties 3 and 4
        // DKG: complaints keyed by dealer address
        let complaint = party_manager
            .complaints_to_process
            .get(&ComplaintsToProcessKey::Dkg(dealer_addr))
            .unwrap()
            .clone();
        // For DKG, share_index is None (dealer has only one share)
        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: None,
            complaint,
        };

        let resp3 = mgr3.handle_complain_request(&request).unwrap();
        let resp4 = mgr4.handle_complain_request(&request).unwrap();

        let responses = std::collections::HashMap::from([(addr3, resp3), (addr4, resp4)]);

        // Modify party_manager's config to exclude parties 3 and 4
        // This makes their responses invalid (party IDs not in the nodes list)
        let config = setup.dkg_config();
        let smaller_nodes = fastcrypto_tbls::nodes::Nodes::new(
            config
                .nodes
                .iter()
                .filter(|node| node.id < 3)
                .cloned()
                .collect(),
        )
        .unwrap();
        party_manager.dkg_config.nodes = smaller_nodes;

        let p2p = PreCollectedP2PChannel::new(responses);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Attempt recovery - parties 3 and 4 are not in the modified config
        let result = MpcManager::recover_shares_via_complaint(
            &party_manager,
            &dealer_addr,
            vec![addr3, addr4],
            &p2p,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, MpcError::CryptoError(_)),
            "Expected CryptoError, got: {:?}",
            err
        );
    }
    #[tokio::test]
    async fn test_retrieve_dealer_message_success() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 0) with its message
        let dealer_address = setup.address(0);
        let dealer_manager = setup.create_dealer_with_message(0, &mut rng);

        // Create party (party 1) that will request the message
        let party_address = setup.address(1);
        let party_manager = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_manager.dealer_messages.get(&dealer_address).unwrap();

        // Create DkgMessage and validator signatures
        let messages_hash = compute_messages_hash(dealer_message);
        let dkg_message = DealerMessagesHash {
            dealer_address,
            messages_hash,
        };

        // Dealer signs its own message
        let dealer_signature =
            setup.signing_keys[0].sign(setup.epoch(), dealer_address, &dkg_message);

        // Create certificate with dealer's signature
        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_address,
            dealer_message,
            vec![dealer_signature],
        )
        .unwrap();

        // Create mock P2P channel with the dealer (who also signed the cert)
        let mut dealers = HashMap::new();
        dealers.insert(dealer_address, dealer_manager);
        let mock_p2p = MockP2PChannel::new(dealers, party_address);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Party requests dealer's share from certificate signers
        let result =
            MpcManager::retrieve_dealer_message(&party_manager, &dkg_message, &cert, &mock_p2p)
                .await;

        assert!(result.is_ok());
        let mgr = party_manager.read().unwrap();
        assert!(mgr.dealer_messages.contains_key(&dealer_address));
        // Message is stored but not yet processed (that happens during run_as_party)
        // DKG: outputs keyed by dealer address
        assert!(
            !mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_address))
        );
        drop(mgr);

        // Process the message to verify it's valid
        party_manager
            .write()
            .unwrap()
            .process_certified_dkg_message(dealer_address)
            .unwrap();
        assert!(
            party_manager
                .read()
                .unwrap()
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_address))
        );
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_retries_multiple_signers() {
        // Tests that retrieve_dealer_message retries with next signer if first fails
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer with message (validator 0)
        let dealer_addr = setup.address(0);
        let dealer_mgr = setup.create_dealer_with_message(0, &mut rng);

        // Create party that will request (validator 2)
        let party_addr = setup.address(2);
        let party_mgr = setup.create_manager(2);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let messages_hash = compute_messages_hash(dealer_message);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };

        // Create certificate with two signers: validator 1 (not in P2P) and dealer (validator 0)
        // Validator 1 signs first, then validator 0
        let validator_1_addr = setup.address(1);
        let validator_1_signature =
            setup.signing_keys[1].sign(setup.epoch(), validator_1_addr, &dkg_message);
        let dealer_signature = setup.signing_keys[0].sign(setup.epoch(), dealer_addr, &dkg_message);

        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_addr,
            dealer_message,
            vec![validator_1_signature, dealer_signature],
        )
        .unwrap();

        // MockP2PChannel: only include dealer (validator 1 not included)
        let mut managers = HashMap::new();
        managers.insert(dealer_addr, dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        let party_mgr = Arc::new(RwLock::new(party_mgr));

        // Should succeed by trying validator 1 (fails), then dealer (succeeds)
        let result =
            MpcManager::retrieve_dealer_message(&party_mgr, &dkg_message, &cert, &mock_p2p).await;

        assert!(result.is_ok());
        assert!(
            party_mgr
                .read()
                .unwrap()
                .dealer_messages
                .contains_key(&dealer_addr)
        );
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_aborts_when_self_in_signers() {
        // Tests that retrieve_dealer_message aborts with error when requesting party is in signer list
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let setup = TestSetup::new(5);

        // Create dealer with message (validator 0)
        let dealer_addr = setup.address(0);
        let dealer_mgr = setup.create_dealer_with_message(0, &mut rng);

        // Create party that will request (party 1)
        let party_addr = setup.address(1);
        let party_mgr = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let messages_hash = compute_messages_hash(dealer_message);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };

        // Create certificate with signers including the requesting party
        // This is an invalid state - party shouldn't be retrieving a message it signed for
        let party_signature = setup.signing_keys[1].sign(setup.epoch(), party_addr, &dkg_message);
        let dealer_signature = setup.signing_keys[0].sign(setup.epoch(), dealer_addr, &dkg_message);

        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_addr,
            dealer_message,
            vec![party_signature, dealer_signature],
        )
        .unwrap();

        // MockP2PChannel: include dealer
        let mut managers = HashMap::new();
        managers.insert(dealer_addr, dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        let party_mgr = Arc::new(RwLock::new(party_mgr));

        // Should abort with ProtocolFailed error due to invariant violation
        let result =
            MpcManager::retrieve_dealer_message(&party_mgr, &dkg_message, &cert, &mock_p2p).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(
            err.to_string()
                .contains("Self in certificate signers but message not available")
        );
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_all_signers_fail() {
        // Tests that retrieve_dealer_message returns error when all signers fail
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer with message (validator 0)
        let dealer_addr = setup.address(0);
        let dealer_mgr = setup.create_dealer_with_message(0, &mut rng);

        // Create party that will request (validator 1)
        let party_addr = setup.address(1);
        let party_mgr = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let messages_hash = compute_messages_hash(dealer_message);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };

        // Create certificate with signers 2 and 3 (both will be offline in P2P)
        let signer_2_addr = setup.address(2);
        let signer_3_addr = setup.address(3);
        let signer_2_signature =
            setup.signing_keys[2].sign(setup.epoch(), signer_2_addr, &dkg_message);
        let signer_3_signature =
            setup.signing_keys[3].sign(setup.epoch(), signer_3_addr, &dkg_message);

        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_addr,
            dealer_message,
            vec![signer_2_signature, signer_3_signature],
        )
        .unwrap();

        // MockP2PChannel: empty (no signers available)
        let managers = HashMap::new();
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        let party_mgr = Arc::new(RwLock::new(party_mgr));

        // Should fail because all signers are offline
        let result =
            MpcManager::retrieve_dealer_message(&party_mgr, &dkg_message, &cert, &mock_p2p).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::PairwiseCommunicationError(_)));
        assert!(err.to_string().contains("Could not retrieve"));
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_rejects_wrong_hash() {
        // Tests that retrieve_dealer_message validates hash and rejects messages with wrong hash
        // Simulates Byzantine signer returning wrong message
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer A with message MA
        let dealer_a_addr = setup.address(0);
        let dealer_a_mgr = setup.create_dealer_with_message(0, &mut rng);
        let message_a = dealer_a_mgr
            .dealer_messages
            .get(&dealer_a_addr)
            .unwrap()
            .clone();

        // Create dealer B with different message MB
        let dealer_b_addr = setup.address(1);
        let dealer_b_mgr = setup.create_dealer_with_message(1, &mut rng);
        let message_b = dealer_b_mgr
            .dealer_messages
            .get(&dealer_b_addr)
            .unwrap()
            .clone();

        // Create party that will request
        let party_addr = setup.address(2);
        let party_mgr = setup.create_manager(2);

        // Create Byzantine signer that has WRONG message stored for dealer A
        // (It has dealer B's message stored under dealer A's key.)
        let byzantine_signer_addr = Address::new([3; 32]);
        let mut byzantine_signer = setup.create_manager(3);
        // Byzantine: store dealer B's message under dealer A's address
        byzantine_signer
            .dealer_messages
            .insert(dealer_a_addr, message_b.clone());

        // Create DkgMessage for dealer A
        let message_hash_a = compute_messages_hash(&message_a);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_a_addr,
            messages_hash: message_hash_a,
        };

        // Create valid certificate for dealer A with correct hash, signed by Byzantine signer and dealer A
        let byzantine_signature =
            setup.signing_keys[3].sign(setup.epoch(), byzantine_signer_addr, &dkg_message);
        let dealer_a_signature =
            setup.signing_keys[0].sign(setup.epoch(), dealer_a_addr, &dkg_message);

        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_a_addr,
            &message_a,
            vec![byzantine_signature, dealer_a_signature],
        )
        .unwrap();

        // MockP2PChannel: has Byzantine signer and real dealer A
        let mut managers = HashMap::new();
        managers.insert(byzantine_signer_addr, byzantine_signer);
        managers.insert(dealer_a_addr, dealer_a_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        let party_mgr = Arc::new(RwLock::new(party_mgr));

        // Party requests dealer A's message
        // 1. Tries Byzantine signer first -> returns message B
        // 2. Computes hash(message B) != hash(message A) -> rejects, continues
        // 3. Tries real dealer A -> returns message A -> hash matches -> success
        let result =
            MpcManager::retrieve_dealer_message(&party_mgr, &dkg_message, &cert, &mock_p2p).await;

        assert!(result.is_ok());
        // Should have dealer A's correct message (from second signer)
        assert!(
            party_mgr
                .read()
                .unwrap()
                .dealer_messages
                .contains_key(&dealer_a_addr)
        );
    }
    fn create_certificate_with_signers(
        committee: &Committee,
        dealer_address: Address,
        messages: &Messages,
        signatures: Vec<MemberSignature>,
    ) -> MpcResult<DealerCertificate> {
        let messages_hash = compute_messages_hash(messages);
        let dkg_message = DealerMessagesHash {
            dealer_address,
            messages_hash,
        };

        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);

        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn create_complaint_for_dealer(
        setup: &TestSetup,
        dealer_messages: &Messages,
        party_id: u16,
        dealer_index: usize,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> complaint::Complaint {
        // Get the DKG message
        let dealer_message = match dealer_messages {
            Messages::Dkg(msg) => msg,
            Messages::Rotation(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected DKG message in create_valid_complaint")
            }
        };
        let config = setup.dkg_config();
        let session_id = setup.session_id();
        let dealer_address = setup.address(dealer_index);
        let dealer_session_id = session_id.dealer_session_id(&dealer_address);
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(rng);
        let receiver = avss::Receiver::new(
            config.nodes.clone(),
            party_id,
            config.threshold,
            dealer_session_id.to_vec(),
            None,
            wrong_key,
        );
        match receiver.process_message(dealer_message).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint with wrong key"),
        }
    }

    /// Create a cheating dealer message with corrupted shares for one party.
    fn create_cheating_message(
        setup: &TestSetup,
        dealer_index: usize,
        corrupt_party_id: u16,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> avss::Message {
        use fastcrypto::groups::secp256k1::ProjectivePoint;
        type S = <ProjectivePoint as fastcrypto::groups::GroupElement>::ScalarType;

        let config = setup.dkg_config();
        let session_id = setup.session_id();
        let dealer_address = setup.address(dealer_index);
        let dealer_session_id = session_id.dealer_session_id(&dealer_address);

        // Create polynomial
        let secret = S::rand(rng);
        let polynomial = Poly::<S>::rand_fixed_c0(config.threshold - 1, secret, rng);
        let commitment = polynomial.commit::<ProjectivePoint>();

        // Evaluate and serialize shares for each node
        let mut pk_and_msgs: Vec<_> = config
            .nodes
            .iter()
            .map(|node| {
                let share_ids = config.nodes.share_ids_of(node.id).unwrap();
                let shares: Vec<_> = share_ids
                    .into_iter()
                    .map(|index| polynomial.eval(index))
                    .collect();
                let shares_bytes = bcs::to_bytes(&shares).unwrap();
                (node.pk.clone(), shares_bytes)
            })
            .collect();

        // Corrupt the plaintext shares for the target party
        if corrupt_party_id < pk_and_msgs.len() as u16 {
            let idx = corrupt_party_id as usize;
            if pk_and_msgs[idx].1.len() > 7 {
                pk_and_msgs[idx].1[7] ^= 1; // Flip one bit
            }
        }

        // Encrypt the shares
        let random_oracle =
            RandomOracle::new(&Hex::encode(dealer_session_id.to_vec())).extend("encryption");
        let corrupted_ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &random_oracle, rng);

        // Create an honest message to use as a template
        let dealer = avss::Dealer::new(
            Some(secret), // Use same secret so commitment matches
            config.nodes.clone(),
            config.threshold,
            config.max_faulty,
            dealer_session_id.to_vec(),
        )
        .unwrap();
        let template_message = dealer.create_message(rng);

        // Serialize our corrupted components to construct the Message
        let ciphertext_bytes = bcs::to_bytes(&corrupted_ciphertext).unwrap();
        let commitment_bytes = bcs::to_bytes(&commitment).unwrap();

        // Manually construct the serialized Message (ciphertext, then commitment)
        let mut combined = Vec::new();
        combined.extend_from_slice(&ciphertext_bytes);
        combined.extend_from_slice(&commitment_bytes);

        bcs::from_bytes::<avss::Message>(&combined).unwrap_or(template_message)
    }

    /// Creates a cheating rotation message where the encrypted share for `corrupt_party_id` is corrupted.
    /// This allows `corrupt_party_id` to generate a valid complaint using their correct key.
    fn create_cheating_rotation_message(
        setup: &TestSetup,
        session_id: &SessionId,
        dealer_address: &Address,
        share_value: fastcrypto::groups::secp256k1::Scalar,
        share_index: ShareIndex,
        corrupt_party_id: u16,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (ShareIndex, avss::Message) {
        use fastcrypto::groups::secp256k1::ProjectivePoint;
        type S = <ProjectivePoint as fastcrypto::groups::GroupElement>::ScalarType;

        let config = setup.dkg_config();
        let rotation_session_id = session_id.rotation_session_id(dealer_address, share_index);

        // Create polynomial with the share value as secret
        let polynomial = Poly::<S>::rand_fixed_c0(config.threshold - 1, share_value, rng);
        let commitment = polynomial.commit::<ProjectivePoint>();

        // Evaluate and serialize shares for each node
        let mut pk_and_msgs: Vec<_> = config
            .nodes
            .iter()
            .map(|node| {
                let share_ids = config.nodes.share_ids_of(node.id).unwrap();
                let shares: Vec<_> = share_ids
                    .into_iter()
                    .map(|index| polynomial.eval(index))
                    .collect();
                let shares_bytes = bcs::to_bytes(&shares).unwrap();
                (node.pk.clone(), shares_bytes)
            })
            .collect();

        // Corrupt the plaintext shares for the target party
        if corrupt_party_id < pk_and_msgs.len() as u16 {
            let idx = corrupt_party_id as usize;
            if pk_and_msgs[idx].1.len() > 7 {
                pk_and_msgs[idx].1[7] ^= 1; // Flip one bit
            }
        }

        // Encrypt the shares
        let random_oracle =
            RandomOracle::new(&Hex::encode(rotation_session_id.to_vec())).extend("encryption");
        let corrupted_ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &random_oracle, rng);

        // Create an honest message to use as a template
        let dealer = avss::Dealer::new(
            Some(share_value),
            config.nodes.clone(),
            config.threshold,
            config.max_faulty,
            rotation_session_id.to_vec(),
        )
        .unwrap();
        let template_message = dealer.create_message(rng);

        // Serialize our corrupted components to construct the Message
        let ciphertext_bytes = bcs::to_bytes(&corrupted_ciphertext).unwrap();
        let commitment_bytes = bcs::to_bytes(&commitment).unwrap();

        // Manually construct the serialized Message (ciphertext, then commitment)
        let mut combined = Vec::new();
        combined.extend_from_slice(&ciphertext_bytes);
        combined.extend_from_slice(&commitment_bytes);

        let message = bcs::from_bytes::<avss::Message>(&combined).unwrap_or(template_message);

        (share_index, message)
    }

    fn create_dealer_message_and_complaint(
        setup: &TestSetup,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (Address, Messages, complaint::Complaint) {
        let dealer_address = setup.address(0);
        let dealer_manager = setup.create_manager(0);
        let dealer_message = Messages::Dkg(dealer_manager.create_dealer_message(rng));
        // Create complaint from party 1 using wrong encryption key
        let complaint = create_complaint_for_dealer(setup, &dealer_message, 1, 0, rng);
        (dealer_address, dealer_message, complaint)
    }

    fn setup_party_with_complaint(
        party_manager: &mut MpcManager,
        dealer_address: &Address,
        dealer_messages: &Messages,
        complaint: complaint::Complaint,
    ) {
        // DKG: complaints keyed by dealer address
        party_manager
            .complaints_to_process
            .insert(ComplaintsToProcessKey::Dkg(*dealer_address), complaint);
        party_manager
            .dealer_messages
            .insert(*dealer_address, dealer_messages.clone());
    }

    fn create_handle_send_message_test_setup(
        _rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (TestSetup, Address, MpcManager, Address, MpcManager) {
        let setup = TestSetup::new(5);
        let dealer_address = setup.address(1);
        let dealer_manager = setup.create_manager(1);
        let receiver_address = setup.address(0);
        let receiver_manager = setup.create_manager(0);
        (
            setup,
            dealer_address,
            dealer_manager,
            receiver_address,
            receiver_manager,
        )
    }

    #[tokio::test]
    async fn test_handle_send_messages_request_idempotent() {
        // Test that same request returns cached response (idempotent)
        let mut rng = rand::thread_rng();
        let (_setup, dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_message_test_setup(&mut rng);

        let dealer_message = dealer_manager.create_dealer_message(&mut rng);
        let dealer_messages = Messages::Dkg(dealer_message);
        let request = SendMessagesRequest {
            messages: dealer_messages.clone(),
        };

        // First request
        let response1 = receiver_manager
            .handle_send_messages_request(dealer_address, &request)
            .unwrap();

        // Second request with same messages - should return cached response
        let response2 = receiver_manager
            .handle_send_messages_request(dealer_address, &request)
            .unwrap();

        // Responses should be identical (same signature bytes)
        assert_eq!(response1.signature, response2.signature);
    }

    #[tokio::test]
    async fn test_handle_send_messages_request_equivocation() {
        // Test that different message from same dealer triggers error
        let mut rng = rand::thread_rng();
        let (_setup, dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_message_test_setup(&mut rng);

        // First message from dealer
        let dealer_message1 = dealer_manager.create_dealer_message(&mut rng);
        let dealer_messages1 = Messages::Dkg(dealer_message1);
        let request1 = SendMessagesRequest {
            messages: dealer_messages1.clone(),
        };

        // Process first request successfully
        let response1 = receiver_manager
            .handle_send_messages_request(dealer_address, &request1)
            .unwrap();
        // Verify we got a valid BLS signature (non-empty)
        assert!(!response1.signature.as_ref().is_empty());

        // Second DIFFERENT message from same dealer (equivocation)
        let dealer_message2 = dealer_manager.create_dealer_message(&mut rng);
        let dealer_messages2 = Messages::Dkg(dealer_message2);
        let request2 = SendMessagesRequest {
            messages: dealer_messages2.clone(),
        };

        // Should return error
        let result = receiver_manager.handle_send_messages_request(dealer_address, &request2);
        assert!(result.is_err());

        match result.unwrap_err() {
            MpcError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_address);
                assert!(reason.contains("different messages"));
            }
            _ => panic!("Expected InvalidMessage error"),
        }
    }

    #[tokio::test]
    async fn test_handle_send_messages_request_invalid_shares_no_panic_on_retry() {
        // Second RPC call with invalid shares should not panic.

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 1)
        let dealer_addr = setup.address(1);

        // Create a cheating message with corrupted shares for party 0
        let cheating_message = Messages::Dkg(create_cheating_message(
            &setup, 1, // dealer_index
            0, // Corrupt shares for party 0 (receiver)
            &mut rng,
        ));

        // Create receiver (party 0)
        let mut receiver_manager = setup.create_manager(0);

        let request = SendMessagesRequest {
            messages: cheating_message.clone(),
        };

        // First call: message is invalid, should return error
        let result1 = receiver_manager.handle_send_messages_request(dealer_addr, &request);
        assert!(result1.is_err(), "Invalid shares should return error");
        match result1.unwrap_err() {
            MpcError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_addr);
                assert!(reason.contains("Invalid shares"));
            }
            _ => panic!("Expected InvalidMessage error"),
        }

        // Second call: same message - should return error with "previously rejected" message
        let result2 = receiver_manager.handle_send_messages_request(dealer_addr, &request);
        assert!(result2.is_err(), "Second call should also return error");
        match result2.unwrap_err() {
            MpcError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_addr);
                assert!(
                    reason.contains("previously rejected"),
                    "Second call should indicate message was previously rejected, got: {}",
                    reason
                );
            }
            _ => panic!("Expected InvalidMessage error"),
        }

        // Verify message was stored (for later retrieval)
        assert!(
            receiver_manager.dealer_messages.contains_key(&dealer_addr),
            "Message should be stored even if invalid"
        );

        // Verify no response was cached (since we returned error)
        assert!(
            !receiver_manager
                .message_responses
                .contains_key(&dealer_addr),
            "Response should not be cached for invalid shares"
        );

        // Verify receiver can still serve the message via RetrieveMessagesRequest
        let retrieve_request = RetrieveMessagesRequest {
            dealer: dealer_addr,
        };
        let retrieve_response = receiver_manager
            .handle_retrieve_messages_request(&retrieve_request)
            .unwrap();
        assert_eq!(
            compute_messages_hash(&retrieve_response.messages),
            compute_messages_hash(&cheating_message),
            "Stored message should be retrievable"
        );
    }

    #[tokio::test]
    async fn test_retrieve_stores_invalid_message_for_later_complaint() {
        // retrieve_dealer_message should store without validation

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 1)
        let dealer_addr = setup.address(1);

        // Create a cheating message with corrupted shares for party 0
        let cheating_message = Messages::Dkg(create_cheating_message(
            &setup, 1, // dealer_index
            0, // Corrupt shares for party 0 (receiver)
            &mut rng,
        ));

        // Parties 2, 3, 4 can validate this message (shares are valid for them)
        // and will sign the certificate
        let mut signers = Vec::new();
        for i in 2..5usize {
            let addr = setup.address(i);
            let mut mgr = setup.create_manager(i);
            let sig = receive_dealer_messages(&mut mgr, &cheating_message, dealer_addr).unwrap();
            signers.push((addr, mgr, sig));
        }

        // Create certificate signed by parties 2, 3, 4
        let messages_hash = compute_messages_hash(&cheating_message);
        let dkg_message = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };
        let committee = setup.committee();
        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);
        for (_, _, sig) in &signers {
            aggregator.add_signature(sig.clone()).unwrap();
        }
        let certificate = aggregator.finish().unwrap();

        // Party 0 doesn't have the message yet (simulating it wasn't received via SendMessage)
        let receiver_addr = setup.address(0);
        let receiver_manager = setup.create_manager(0);

        // Create P2P channel with signers who have the message
        let other_managers: HashMap<Address, MpcManager> = signers
            .into_iter()
            .map(|(addr, mgr, _)| (addr, mgr))
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, receiver_addr);

        let receiver_manager = Arc::new(RwLock::new(receiver_manager));

        // Retrieve message - should succeed even though shares are invalid for party 0
        let dkg_dealer_hash = DealerMessagesHash {
            dealer_address: dealer_addr,
            messages_hash,
        };
        let result = MpcManager::retrieve_dealer_message(
            &receiver_manager,
            &dkg_dealer_hash,
            &certificate,
            &mock_p2p,
        )
        .await;

        assert!(
            result.is_ok(),
            "retrieve_dealer_message should succeed for invalid shares. Error: {:?}",
            result.err()
        );

        // Verify message was stored
        {
            let mgr = receiver_manager.read().unwrap();
            assert!(
                mgr.dealer_messages.contains_key(&dealer_addr),
                "Invalid message should be stored for later complaint processing"
            );
        }

        // Now process the message - should create a complaint
        receiver_manager
            .write()
            .unwrap()
            .process_certified_dkg_message(dealer_addr)
            .unwrap();

        let mgr = receiver_manager.read().unwrap();
        // DKG: complaints and outputs keyed by dealer address
        assert!(
            mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Dkg(dealer_addr)),
            "Processing invalid message should create complaint"
        );
        assert!(
            !mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer_addr)),
            "Invalid message should not create dealer output"
        );
    }

    /// A store that tracks calls to store_dealer_message.
    struct TrackingPublicMessagesStore {
        stored: HashMap<Address, avss::Message>,
        rotation_stored: HashMap<Address, RotationMessages>,
        store_count: Arc<AtomicUsize>,
    }

    impl TrackingPublicMessagesStore {
        fn new(store_count: Arc<AtomicUsize>) -> Self {
            Self {
                stored: HashMap::new(),
                rotation_stored: HashMap::new(),
                store_count,
            }
        }

        /// Pre-populate without incrementing counter (simulates data from before restart)
        fn pre_populate(&mut self, dealer: Address, message: avss::Message) {
            self.stored.insert(dealer, message);
        }
    }

    impl PublicMessagesStore for TrackingPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            dealer: &Address,
            message: &avss::Message,
        ) -> anyhow::Result<()> {
            self.store_count.fetch_add(1, Ordering::SeqCst);
            self.stored.insert(*dealer, message.clone());
            Ok(())
        }

        fn get_dealer_message(
            &self,
            _epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(self.stored.get(dealer).cloned())
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(self
                .stored
                .iter()
                .map(|(k, v)| (*k, Messages::Dkg(v.clone())))
                .collect())
        }

        fn store_rotation_messages(
            &mut self,
            dealer: &Address,
            messages: &RotationMessages,
        ) -> anyhow::Result<()> {
            self.rotation_stored.insert(*dealer, messages.clone());
            Ok(())
        }

        fn get_rotation_messages(
            &self,
            _epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<RotationMessages>> {
            Ok(self.rotation_stored.get(dealer).cloned())
        }

        fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            Ok(self
                .rotation_stored
                .iter()
                .map(|(k, v)| (*k, Messages::Rotation(v.clone())))
                .collect())
        }
    }

    /// A P2P channel that tracks retrieve_message calls.
    struct TrackingP2PChannel {
        inner: MockP2PChannel,
        retrieve_count: Arc<AtomicUsize>,
    }

    impl TrackingP2PChannel {
        fn new(inner: MockP2PChannel, retrieve_count: Arc<AtomicUsize>) -> Self {
            Self {
                inner,
                retrieve_count,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for TrackingP2PChannel {
        async fn send_messages(
            &self,
            recipient: &Address,
            request: &SendMessagesRequest,
        ) -> crate::communication::ChannelResult<SendMessagesResponse> {
            self.inner.send_messages(recipient, request).await
        }

        async fn retrieve_messages(
            &self,
            party: &Address,
            request: &RetrieveMessagesRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessagesResponse> {
            self.retrieve_count.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve_messages(party, request).await
        }

        async fn complain(
            &self,
            party: &Address,
            request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplaintResponses> {
            self.inner.complain(party, request).await
        }

        async fn get_public_dkg_output(
            &self,
            party: &Address,
            request: &GetPublicDkgOutputRequest,
        ) -> crate::communication::ChannelResult<GetPublicDkgOutputResponse> {
            self.inner.get_public_dkg_output(party, request).await
        }

        async fn get_partial_signatures(
            &self,
            _party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> crate::communication::ChannelResult<GetPartialSignaturesResponse> {
            unimplemented!("TrackingP2PChannel does not implement get_partial_signatures")
        }
    }

    #[tokio::test]
    async fn test_restart_dealer_reuses_stored_message() {
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let setup = TestSetup::new(num_validators);

        // Simulate pre-restart: dealer 0 created and stored a message
        let original_dealer = setup.create_manager(0);
        let dealer_address = original_dealer.address;
        let original_message = original_dealer.create_dealer_message(&mut rng);
        let original_hash = compute_messages_hash(&Messages::Dkg(original_message.clone()));

        // Create tracking store with pre-populated message (simulating persistence)
        let store_count = Arc::new(AtomicUsize::new(0));
        let mut store = TrackingPublicMessagesStore::new(store_count.clone());
        store.pre_populate(dealer_address, original_message);

        // Simulate restart: create manager for same party with stored message
        let restarted_manager = setup.create_manager_with_store(0, Box::new(store));

        // Verify message was loaded (storage returns raw message, loaded as Messages::Dkg)
        assert_eq!(restarted_manager.address, dealer_address);
        let loaded = restarted_manager
            .dealer_messages
            .get(&dealer_address)
            .unwrap();
        assert_eq!(compute_messages_hash(loaded), original_hash);

        // Create other managers for P2P
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| (setup.address(i), setup.create_manager(i)))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, dealer_address);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let restarted_manager = Arc::new(RwLock::new(restarted_manager));

        // Run run_as_dealer - should reuse stored message
        let result = MpcManager::run_as_dealer(&restarted_manager, &mock_p2p, &mut mock_tob).await;
        assert!(result.is_ok());

        // Verify store_dealer_message was NOT called (message already existed)
        assert_eq!(
            store_count.load(Ordering::SeqCst),
            0,
            "store_dealer_message should not be called when message already exists"
        );

        // Verify the message in dealer_messages still has the same hash
        let final_message = restarted_manager
            .read()
            .unwrap()
            .dealer_messages
            .get(&dealer_address)
            .unwrap()
            .clone();
        assert_eq!(
            compute_messages_hash(&final_message),
            original_hash,
            "run_as_dealer should use the pre-stored message, not create a new one"
        );
    }

    #[tokio::test]
    async fn test_restart_party_uses_stored_messages_without_retrieval() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealers with messages (simulating what happened before restart)
        let dealer1_addr = setup.address(0);
        let dealer1_mgr = setup.create_dealer_with_message(0, &mut rng);
        let dealer2_addr = setup.address(1);
        let dealer2_mgr = setup.create_dealer_with_message(1, &mut rng);

        // Extract raw avss::Message from Messages::Dkg for storage
        let msg1 = match dealer1_mgr.dealer_messages.get(&dealer1_addr).unwrap() {
            Messages::Dkg(m) => m.clone(),
            _ => panic!("expected DKG message"),
        };
        let msg2 = match dealer2_mgr.dealer_messages.get(&dealer2_addr).unwrap() {
            Messages::Dkg(m) => m.clone(),
            _ => panic!("expected DKG message"),
        };

        // Create tracking store with pre-populated messages (simulating restart)
        let store_count = Arc::new(AtomicUsize::new(0));
        let mut store = TrackingPublicMessagesStore::new(store_count.clone());
        store.pre_populate(dealer1_addr, msg1.clone());
        store.pre_populate(dealer2_addr, msg2.clone());

        // Create party (validator 3) with pre-stored messages
        let party_addr = setup.address(3);
        let party_manager = setup.create_manager_with_store(3, Box::new(store));

        // Verify messages were loaded on construction
        assert!(
            party_manager.dealer_messages.contains_key(&dealer1_addr),
            "dealer1 message should be loaded"
        );
        assert!(
            party_manager.dealer_messages.contains_key(&dealer2_addr),
            "dealer2 message should be loaded"
        );

        // Wrap messages for certificate creation (storage stores raw, but certs need wrapped)
        let msg1_wrapped = Messages::Dkg(msg1);
        let msg2_wrapped = Messages::Dkg(msg2);

        // Create certificates
        let epoch = setup.epoch();
        let signatures_1: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let messages_hash = compute_messages_hash(&msg1_wrapped);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer1_addr,
                    messages_hash,
                };
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let signatures_2: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let messages_hash = compute_messages_hash(&msg2_wrapped);
                let dkg_message = DealerMessagesHash {
                    dealer_address: dealer2_addr,
                    messages_hash,
                };
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let cert1 =
            create_test_certificate(setup.committee(), &msg1_wrapped, dealer1_addr, signatures_1)
                .unwrap();
        let cert2 =
            create_test_certificate(setup.committee(), &msg2_wrapped, dealer2_addr, signatures_2)
                .unwrap();

        // Create tracking P2P channel to verify retrieve_message is NOT called
        let retrieve_count = Arc::new(AtomicUsize::new(0));
        let mut dealers = HashMap::new();
        dealers.insert(dealer1_addr, dealer1_mgr);
        dealers.insert(dealer2_addr, dealer2_mgr);
        let inner_p2p = MockP2PChannel::new(dealers, party_addr);
        let tracking_p2p = TrackingP2PChannel::new(inner_p2p, retrieve_count.clone());

        // Create mock TOB with certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(vec![
            CertificateV1::Dkg(cert1),
            CertificateV1::Dkg(cert2),
        ]);

        let party_manager = Arc::new(RwLock::new(party_manager));

        // Run as party
        let result = MpcManager::run_as_party(&party_manager, &tracking_p2p, &mut mock_tob).await;
        assert!(result.is_ok());

        // Verify retrieve_message was NOT called (messages were already in memory)
        assert_eq!(
            retrieve_count.load(Ordering::SeqCst),
            0,
            "retrieve_message should not be called when messages are pre-stored"
        );

        // Verify dealer outputs were created from stored messages
        // DKG: outputs keyed by dealer address
        let mgr = party_manager.read().unwrap();
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer1_addr)),
            "dealer1 output should be created"
        );
        assert!(
            mgr.dealer_outputs
                .contains_key(&DealerOutputsKey::Dkg(dealer2_addr)),
            "dealer2 output should be created"
        );
    }

    /// For rotation tests that provides a completed DKG setup.
    struct RotationTestSetup {
        setup: TestSetup,
        certificates: HashMap<Address, CertificateV1>,
        dealer_messages: Vec<Messages>,
        dealer_indices: Vec<usize>,
    }

    impl RotationTestSetup {
        /// Creates a rotation test setup with weighted validators and completed DKG.
        /// Uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4).
        /// Dealers are validators 0, 1, 4 (total weight = 7 >= threshold).
        fn new() -> Self {
            let mut rng = rand::thread_rng();
            let weights = [3, 2, 4, 1, 2];
            let setup = TestSetup::with_weights(&weights);

            let dealer_indices = vec![0usize, 1, 4];
            let mut dealer_managers: Vec<_> = dealer_indices
                .iter()
                .map(|&i| setup.create_manager(i))
                .collect();

            // Each dealer creates a message and wraps it
            let dealer_messages: Vec<_> = dealer_managers
                .iter()
                .map(|dm| {
                    let message = dm.create_dealer_message(&mut rng);
                    Messages::Dkg(message)
                })
                .collect();

            // Create certificates by collecting signatures
            let mut certificates = HashMap::new();
            for (i, messages) in dealer_messages.iter().enumerate() {
                let dealer_address = dealer_managers[i].address;

                let validator_signatures = vec![
                    receive_dealer_messages(&mut dealer_managers[0], messages, dealer_address)
                        .unwrap(),
                    receive_dealer_messages(&mut dealer_managers[1], messages, dealer_address)
                        .unwrap(),
                ];

                let cert = create_test_certificate(
                    setup.committee(),
                    messages,
                    dealer_address,
                    validator_signatures,
                )
                .unwrap();

                certificates.insert(dealer_address, CertificateV1::Dkg(cert));
            }

            Self {
                setup,
                certificates,
                dealer_messages,
                dealer_indices,
            }
        }

        fn certificates(&self) -> Vec<CertificateV1> {
            self.certificates.values().cloned().collect()
        }

        /// Sets previous_committee, previous_nodes, and previous_threshold on a
        /// DKG manager so it can be used for rotation tests. In production, these
        /// are set by MpcManager::new when pending_epoch_change is set.
        fn prepare_for_rotation(&self, manager: &mut MpcManager) {
            let previous_committee = self.setup.committee_set.previous_committee().cloned();
            if let Some(ref prev) = previous_committee {
                let (nodes, threshold) =
                    build_reduced_nodes(prev, TEST_ALLOWED_DELTA, TEST_WEIGHT_DIVISOR).unwrap();
                manager.previous_nodes = Some(nodes);
                manager.previous_threshold = Some(threshold);
            }
            manager.previous_committee = previous_committee;
        }

        /// Creates a manager that has completed DKG and is ready for rotation.
        fn create_receiver_with_completed_dkg(
            &self,
            receiver_index: usize,
        ) -> (MpcManager, DkgOutput) {
            let mut receiver_manager = self.setup.create_manager(receiver_index);

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_messages(&mut receiver_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = receiver_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Clear state to prepare for rotation (new committee formation)
            receiver_manager.dealer_messages.clear();
            receiver_manager.dealer_outputs.clear();
            receiver_manager.complaints_to_process.clear();
            receiver_manager.message_responses.clear();
            self.prepare_for_rotation(&mut receiver_manager);

            (receiver_manager, dkg_output)
        }

        /// Creates a manager with InMemoryPublicMessagesStore and completed DKG.
        /// The store contains all dealer messages for later reconstruction.
        /// The manager is ready for rotation (outputs cleared after DKG completion).
        fn create_receiver_with_memory_store(
            &self,
            receiver_index: usize,
        ) -> (MpcManager, DkgOutput) {
            let mut receiver_manager = self.setup.create_manager_with_store(
                receiver_index,
                Box::new(InMemoryPublicMessagesStore::new()),
            );

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_messages(&mut receiver_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = receiver_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Clear state to prepare for rotation (new committee formation)
            receiver_manager.dealer_messages.clear();
            receiver_manager.dealer_outputs.clear();
            receiver_manager.complaints_to_process.clear();
            receiver_manager.message_responses.clear();
            self.prepare_for_rotation(&mut receiver_manager);

            (receiver_manager, dkg_output)
        }

        /// Creates a rotation dealer that has completed DKG and generates rotation messages.
        /// The manager is ready for rotation (outputs cleared after DKG completion).
        fn create_rotation_dealer(&self, dealer_index: usize) -> (MpcManager, DkgOutput, Messages) {
            let mut rng = rand::thread_rng();
            let mut dealer_manager = self.setup.create_manager(dealer_index);

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_messages(&mut dealer_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = dealer_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Clear state to prepare for rotation (new committee formation)
            dealer_manager.dealer_messages.clear();
            dealer_manager.dealer_outputs.clear();
            dealer_manager.complaints_to_process.clear();
            dealer_manager.message_responses.clear();
            self.prepare_for_rotation(&mut dealer_manager);

            // Create rotation messages and store for reuse
            let msgs = dealer_manager.create_rotation_messages(&dkg_output, &mut rng);
            let rotation_messages = Messages::Rotation(msgs);
            let dealer_address = self.setup.address(dealer_index);
            dealer_manager
                .dealer_messages
                .insert(dealer_address, rotation_messages.clone());

            (dealer_manager, dkg_output, rotation_messages)
        }

        /// Creates a rotation dealer with InMemoryPublicMessagesStore.
        /// The manager is ready for rotation (outputs cleared after DKG completion).
        fn create_rotation_dealer_with_memory_store(
            &self,
            dealer_index: usize,
        ) -> (MpcManager, DkgOutput, Messages) {
            let mut rng = rand::thread_rng();
            let mut dealer_manager = self.setup.create_manager_with_store(
                dealer_index,
                Box::new(InMemoryPublicMessagesStore::new()),
            );

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_messages(&mut dealer_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = dealer_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Clear state to prepare for rotation (new committee formation)
            dealer_manager.dealer_messages.clear();
            dealer_manager.dealer_outputs.clear();
            dealer_manager.complaints_to_process.clear();
            dealer_manager.message_responses.clear();
            self.prepare_for_rotation(&mut dealer_manager);

            // Create rotation messages and store for reuse
            let msgs = dealer_manager.create_rotation_messages(&dkg_output, &mut rng);
            let rotation_messages = Messages::Rotation(msgs);
            let dealer_address = self.setup.address(dealer_index);
            dealer_manager
                .dealer_messages
                .insert(dealer_address, rotation_messages.clone());

            (dealer_manager, dkg_output, rotation_messages)
        }
    }

    #[test]
    fn test_try_sign_rotation_messages_all_or_nothing() {
        let rotation_setup = RotationTestSetup::new();

        // Create receiver (party 2 with weight=4)
        let (mut receiver_manager, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(2);

        // Create rotation dealer (party 0 with weight=3)
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(0);
        let rotation_dealer_addr = rotation_setup.setup.address(0);

        // Test 1: Happy path - all valid messages should succeed
        let rotation_outputs_before = receiver_manager.dealer_outputs.len();
        let result = receiver_manager.try_sign_rotation_messages(
            &receiver_dkg_output,
            rotation_dealer_addr,
            &rotation_messages,
        );

        assert!(result.is_ok(), "All valid messages should succeed");
        let signature = result.unwrap();
        assert!(
            !signature.as_ref().is_empty(),
            "Should return valid signature"
        );

        // Get the rotation messages map from the enum
        let rotation_map = match &rotation_messages {
            Messages::Rotation(map) => map,
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected rotation messages")
            }
        };

        // Verify outputs were stored (rotation_dealer has weight=3, so creates 3 rotation messages)
        let rotation_outputs_after = receiver_manager.dealer_outputs.len();
        assert_eq!(
            rotation_outputs_after - rotation_outputs_before,
            rotation_map.len(),
            "All rotation outputs should be stored"
        );

        // Test 2: Failure path - one invalid message in bundle should reject everything
        // Create a separate receiver to test failure case
        let (mut receiver_manager2, receiver2_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(2);

        // Tamper with one message in the bundle to make it invalid
        // We swap the messages between two share indices to make the commitment check fail.
        // The commitment for share_index X won't match the message created for share_index Y.
        let tampered_messages = if rotation_map.len() >= 2 {
            // Get two share indices and their messages
            let mut iter = rotation_map.iter();
            let (&idx1, msg1) = iter.next().unwrap();
            let (&idx2, msg2) = iter.next().unwrap();
            // Swap: idx1 now maps to msg2, idx2 now maps to msg1
            let mut tampered: BTreeMap<ShareIndex, avss::Message> = rotation_map
                .iter()
                .filter(|(idx, _)| **idx != idx1 && **idx != idx2)
                .map(|(&idx, msg)| (idx, msg.clone()))
                .collect();
            tampered.insert(idx1, msg2.clone());
            tampered.insert(idx2, msg1.clone());
            Messages::Rotation(tampered)
        } else if !rotation_map.is_empty() {
            // If only one message, use a non-existent share index
            let (&_orig_idx, msg) = rotation_map.iter().next().unwrap();
            let mut tampered: BTreeMap<ShareIndex, avss::Message> = BTreeMap::new();
            tampered.insert(std::num::NonZeroU16::new(9999).unwrap(), msg.clone());
            Messages::Rotation(tampered)
        } else {
            rotation_messages.clone()
        };

        let rotation_outputs_before = receiver_manager2.dealer_outputs.len();
        let result = receiver_manager2.try_sign_rotation_messages(
            &receiver2_dkg_output,
            rotation_dealer_addr,
            &tampered_messages,
        );

        // Should fail due to invalid message
        assert!(
            result.is_err(),
            "Should fail when any message in bundle is invalid"
        );

        // Verify NO outputs were stored (all-or-nothing semantics)
        let rotation_outputs_after = receiver_manager2.dealer_outputs.len();
        assert_eq!(
            rotation_outputs_before, rotation_outputs_after,
            "No rotation outputs should be stored when any message fails"
        );
    }

    #[test]
    fn test_try_sign_rotation_messages_rejects_already_processed_share_index() {
        let rotation_setup = RotationTestSetup::new();

        // Create receiver (party 2 with weight=4)
        let (mut receiver_manager, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(2);

        // Create rotation dealer (party 0 with weight=3)
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(0);
        let rotation_dealer_addr = rotation_setup.setup.address(0);

        // First call should succeed
        let result = receiver_manager.try_sign_rotation_messages(
            &receiver_dkg_output,
            rotation_dealer_addr,
            &rotation_messages,
        );
        assert!(result.is_ok(), "First call should succeed");

        // Second call with same messages should fail (share indices already processed)
        let result = receiver_manager.try_sign_rotation_messages(
            &receiver_dkg_output,
            rotation_dealer_addr,
            &rotation_messages,
        );

        assert!(
            result.is_err(),
            "Should reject already-processed share indices"
        );
        let err = result.unwrap_err();
        match err {
            MpcError::InvalidMessage { reason, .. } => {
                assert!(
                    reason.contains("already processed"),
                    "Error should mention already processed: {}",
                    reason
                );
            }
            _ => panic!("Expected InvalidMessage error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_sign_rotation_messages_rejects_wrong_dealer_share_index() {
        let rotation_setup = RotationTestSetup::new();

        // Create receiver (party 2 with weight=4)
        let (mut receiver_manager, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(2);

        // Create rotation dealer (party 0 with weight=3, owns share indices 1, 2, 3)
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(0);
        let rotation_dealer_addr = rotation_setup.setup.address(0);

        // Tamper with bundle: add a message with a share_index that belongs to party 2 (index 6)
        let rotation_map = match &rotation_messages {
            Messages::Rotation(map) => map.clone(),
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected rotation messages")
            }
        };
        let stolen_share_index = std::num::NonZeroU16::new(6).unwrap(); // Belongs to party 2, not party 0
        // Use any message as the content - the validation will fail on share_index ownership
        let any_message = rotation_map.iter().next().unwrap().1.clone();
        let mut tampered_map = rotation_map.clone();
        tampered_map.insert(stolen_share_index, any_message);
        let tampered_messages = Messages::Rotation(tampered_map);

        let result = receiver_manager.try_sign_rotation_messages(
            &receiver_dkg_output,
            rotation_dealer_addr,
            &tampered_messages,
        );

        assert!(
            result.is_err(),
            "Should reject share index not belonging to dealer"
        );
        let err = result.unwrap_err();
        match err {
            MpcError::InvalidMessage { reason, .. } => {
                assert!(
                    reason.contains("does not belong to dealer"),
                    "Error should mention share doesn't belong to dealer: {}",
                    reason
                );
            }
            _ => panic!("Expected InvalidMessage error, got: {:?}", err),
        }

        // Verify no outputs were stored (all-or-nothing semantics)
        assert!(
            receiver_manager.dealer_outputs.is_empty(),
            "No rotation outputs should be stored when validation fails"
        );
    }

    #[tokio::test]
    async fn test_run_key_rotation() {
        let mut rng = rand::thread_rng();
        let rotation_setup = RotationTestSetup::new();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)
        // Dealers are validators 0, 1, 4

        // Create test_manager (validator 0, weight=3) with memory store for message retrieval
        let (mut test_manager, test_dkg_output, _) =
            rotation_setup.create_rotation_dealer_with_memory_store(0);
        let test_addr = rotation_setup.setup.address(0);
        // In this test, DKG was done at epoch 100 (current epoch). The constructor
        // sets source_epoch = 99 (rotation recovery heuristic), but reconstruction
        // needs the epoch at which DKG messages were actually created.
        test_manager.source_epoch = rotation_setup.setup.epoch();
        test_manager.previous_output = Some(test_dkg_output.clone());
        let test_manager = Arc::new(RwLock::new(test_manager));

        // Create other managers for MockP2PChannel (validators 1-4)
        let mut other_managers_map = HashMap::new();
        for i in 1..5 {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_output = Some(output);
            other_managers_map.insert(rotation_setup.setup.address(i), manager);
        }
        let mock_p2p = MockP2PChannel::new(other_managers_map, test_addr);

        // Create rotation certificates covering < threshold share indices
        // so test_manager must run as dealer.
        // Validator 3 has weight=1 (1 share index), which is < threshold (4).
        let mut rotation_certificates = Vec::new();
        {
            let mut other_managers = mock_p2p.managers.lock().unwrap();
            let validator_idx = 3; // weight = 1
            let addr = rotation_setup.setup.address(validator_idx);

            // First, get the data we need from manager 3
            let (rotation_messages, own_sig, epoch, _prev_output_3) = {
                let manager = other_managers.get_mut(&addr).unwrap();
                let prev_output = manager.previous_output.clone().unwrap();
                let msgs = manager.create_rotation_messages(&prev_output, &mut rng);
                let rotation_messages = Messages::Rotation(msgs);
                manager
                    .dealer_messages
                    .insert(addr, rotation_messages.clone());
                let own_sig = manager
                    .try_sign_rotation_messages(&prev_output, addr, &rotation_messages)
                    .unwrap();
                let epoch = manager.dkg_config.epoch;
                (rotation_messages, own_sig, epoch, prev_output)
            };

            // Now get signature from validator 1
            let other_validator_idx = 1; // validator 1, weight=2
            let other_addr = rotation_setup.setup.address(other_validator_idx);
            let other_sig = {
                let other_manager = other_managers.get_mut(&other_addr).unwrap();
                let other_prev_output = other_manager.previous_output.clone().unwrap();
                other_manager
                    .dealer_messages
                    .insert(addr, rotation_messages.clone());
                other_manager
                    .try_sign_rotation_messages(&other_prev_output, addr, &rotation_messages)
                    .unwrap()
            };

            // Create certificate with signatures from validator 3 (own) and validator 1
            let own_member_sig = MemberSignature::new(epoch, addr, own_sig);
            let other_member_sig = MemberSignature::new(epoch, other_addr, other_sig);
            let cert = create_rotation_test_certificate(
                rotation_setup.setup.committee(),
                &rotation_messages,
                addr,
                vec![own_member_sig, other_member_sig],
            )
            .unwrap();
            rotation_certificates.push(CertificateV1::Rotation(cert));
        }

        // Create mock TOB with rotation certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(rotation_certificates);

        // Run key rotation
        let new_output = MpcManager::run_key_rotation(
            &test_manager,
            &rotation_setup.certificates(),
            &mock_p2p,
            &mut mock_tob,
        )
        .await
        .unwrap();

        // Verify results
        // Validator 0 has weight=3, so should have 3 shares
        assert_eq!(
            new_output.key_shares.shares.len(),
            3,
            "Should have shares equal to validator weight"
        );

        // Verify threshold is preserved
        assert_eq!(
            new_output.threshold, test_dkg_output.threshold,
            "Threshold should be preserved after rotation"
        );

        // Verify public key is preserved
        assert_eq!(
            new_output.public_key, test_dkg_output.public_key,
            "Public key should be preserved after rotation"
        );

        // Verify commitments exist for all share indices (total weight = 12)
        assert_eq!(
            new_output.commitments.len(),
            12,
            "Should have commitments for all share indices"
        );

        // Verify test_manager published its own rotation certificate
        let published = mock_tob.published.lock().unwrap();
        assert_eq!(
            published.len(),
            1,
            "Test manager should have published one rotation certificate"
        );
        match &published[0] {
            CertificateV1::Rotation(m) => {
                assert_eq!(
                    m.message().dealer_address,
                    test_addr,
                    "Published certificate should be from test manager"
                );
            }
            _ => panic!("Expected rotation certificate"),
        }
    }

    #[tokio::test]
    async fn test_run_key_rotation_with_complaint_recovery() {
        let mut rng = rand::thread_rng();
        let rotation_setup = RotationTestSetup::new();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)

        let test_party_idx = 0; // weight=3, victim of cheating
        let cheating_dealer_idx = 3; // weight=1

        // Create test_manager (validator 0)
        let (mut test_manager, test_dkg_output, _) =
            rotation_setup.create_rotation_dealer_with_memory_store(test_party_idx);
        let test_addr = rotation_setup.setup.address(test_party_idx);
        test_manager.source_epoch = rotation_setup.setup.epoch();
        test_manager.previous_output = Some(test_dkg_output.clone());

        // Create cheating dealer (validator 3) to get DKG output and share values
        let (cheating_dealer_mgr, cheating_dkg_output, honest_rotation_messages) =
            rotation_setup.create_rotation_dealer_with_memory_store(cheating_dealer_idx);
        let cheating_dealer_addr = rotation_setup.setup.address(cheating_dealer_idx);

        // Replace the first share's rotation message with a cheating one
        let honest_map = match &honest_rotation_messages {
            Messages::Rotation(map) => map.clone(),
            _ => panic!("Expected rotation messages"),
        };
        let first_share_index = *honest_map.keys().next().unwrap();
        let share_value = cheating_dkg_output
            .key_shares
            .shares
            .iter()
            .find(|s| s.index == first_share_index)
            .map(|s| s.value)
            .unwrap();
        let (_, cheating_message) = create_cheating_rotation_message(
            &rotation_setup.setup,
            &cheating_dealer_mgr.session_id,
            &cheating_dealer_addr,
            share_value,
            first_share_index,
            test_party_idx as u16,
            &mut rng,
        );
        let mut cheating_map = honest_map;
        cheating_map.insert(first_share_index, cheating_message);
        let cheating_rotation_messages = Messages::Rotation(cheating_map);

        // Collect signatures for the certificate before moving managers into MockP2P
        let epoch = cheating_dealer_mgr.dkg_config.epoch;

        // Signature from cheating dealer itself (validator 3)
        let cheating_dealer_sig = {
            let (mut mgr, output) =
                rotation_setup.create_receiver_with_memory_store(cheating_dealer_idx);
            mgr.previous_output = Some(output.clone());
            mgr.dealer_messages
                .insert(cheating_dealer_addr, cheating_rotation_messages.clone());
            mgr.try_sign_rotation_messages(
                &output,
                cheating_dealer_addr,
                &cheating_rotation_messages,
            )
            .unwrap()
        };

        // Create other managers for MockP2P (validators 1-4), collecting all signatures
        // for the certificate. Recovery needs threshold (4) complaint responses from signers.
        let mut other_managers_map = HashMap::new();
        let mut signer_sigs = Vec::new();
        for i in 1..5 {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_output = Some(output.clone());
            // Store and process cheating messages (their shares are fine)
            manager
                .dealer_messages
                .insert(cheating_dealer_addr, cheating_rotation_messages.clone());
            let sig = manager
                .try_sign_rotation_messages(
                    &output,
                    cheating_dealer_addr,
                    &cheating_rotation_messages,
                )
                .unwrap();
            // Skip cheating dealer (already has separate signature)
            if i != cheating_dealer_idx {
                signer_sigs.push(MemberSignature::new(
                    epoch,
                    rotation_setup.setup.address(i),
                    sig,
                ));
            }
            other_managers_map.insert(rotation_setup.setup.address(i), manager);
        }
        let mock_p2p = MockP2PChannel::new(other_managers_map, test_addr);

        // Create rotation certificate with signatures from cheating dealer + validators 1-4
        let mut all_sigs = vec![MemberSignature::new(
            epoch,
            cheating_dealer_addr,
            cheating_dealer_sig,
        )];
        all_sigs.extend(signer_sigs);
        let rotation_certificates = {
            let cert = create_rotation_test_certificate(
                rotation_setup.setup.committee(),
                &cheating_rotation_messages,
                cheating_dealer_addr,
                all_sigs,
            )
            .unwrap();
            vec![CertificateV1::Rotation(cert)]
        };

        let test_manager = Arc::new(RwLock::new(test_manager));
        let mut mock_tob = MockOrderedBroadcastChannel::new(rotation_certificates);

        // Run key rotation — should detect complaint and recover
        let new_output = MpcManager::run_key_rotation(
            &test_manager,
            &rotation_setup.certificates(),
            &mock_p2p,
            &mut mock_tob,
        )
        .await
        .unwrap();

        // Verify output is valid despite cheating dealer
        assert_eq!(
            new_output.key_shares.shares.len(),
            3,
            "Validator 0 (weight=3) should have 3 shares"
        );
        assert_eq!(
            new_output.public_key, test_dkg_output.public_key,
            "Public key should be preserved after rotation"
        );
        assert_eq!(
            new_output.commitments.len(),
            12,
            "Should have commitments for all share indices"
        );

        // Verify complaint was resolved
        let mgr = test_manager.read().unwrap();
        assert!(
            !mgr.complaints_to_process.keys().any(|k| matches!(
                k,
                ComplaintsToProcessKey::Rotation(addr, _) if *addr == cheating_dealer_addr
            )),
            "Rotation complaints should be removed after recovery"
        );
    }

    #[tokio::test]
    async fn test_prepare_previous_output_for_new_member() {
        let rotation_setup = RotationTestSetup::new();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)

        // Create existing members (validators 0-4) with completed DKG and previous_dkg_output set
        let mut existing_managers_map = HashMap::new();
        for i in 0..5 {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_output = Some(output);
            existing_managers_map.insert(rotation_setup.setup.address(i), manager);
        }

        // Get the expected public DKG output from an existing member
        let expected_output = existing_managers_map
            .values()
            .next()
            .unwrap()
            .previous_output
            .as_ref()
            .unwrap();
        let expected_public_key = expected_output.public_key;
        let expected_threshold = expected_output.threshold;
        let expected_commitments_len = expected_output.commitments.len();

        // Create a new member that's in the current committee but NOT in previous
        let mut rng = rand::thread_rng();
        let new_member_addr = Address::new([99u8; 32]);
        let new_member_encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let new_member_signing_key = Bls12381PrivateKey::generate(&mut rng);

        let epoch = rotation_setup.setup.committee_set.epoch();

        // Build committee set: previous has 5 members, current has 6 (includes new member)
        let current_members: Vec<_> = rotation_setup
            .setup
            .committee()
            .members()
            .iter()
            .cloned()
            .chain(std::iter::once(CommitteeMember::new(
                new_member_addr,
                new_member_signing_key.public_key(),
                EncryptionPublicKey::from_private_key(&new_member_encryption_key),
                2,
            )))
            .collect();
        let new_current_committee = Committee::new(current_members, epoch);
        let previous_committee = rotation_setup
            .setup
            .committee_set
            .previous_committee()
            .unwrap()
            .clone();

        let mut committees = BTreeMap::new();
        committees.insert(epoch - 1, previous_committee);
        committees.insert(epoch, new_current_committee);

        let mut new_committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        new_committee_set
            .set_epoch(epoch - 1)
            .set_pending_epoch_change(Some(epoch))
            .set_committees(committees);

        // Create new member's MpcManager
        let session_id = SessionId::new(TEST_CHAIN_ID, epoch, &ProtocolType::Dkg);
        let new_member_manager = MpcManager::new(
            new_member_addr,
            &new_committee_set,
            session_id,
            new_member_encryption_key,
            new_member_signing_key,
            Box::new(InMemoryPublicMessagesStore::new()),
            TEST_ALLOWED_DELTA,
            TEST_CHAIN_ID,
            None,
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();

        // Verify new member is NOT in previous committee
        assert!(
            new_member_manager
                .previous_committee
                .as_ref()
                .unwrap()
                .index_of(&new_member_addr)
                .is_none(),
            "New member should not be in previous committee"
        );

        // Create mock P2P channel with existing members
        let mock_p2p = MockP2PChannel::new(existing_managers_map, new_member_addr);

        // Call prepare_previous_output for new member
        let new_member_manager = Arc::new(RwLock::new(new_member_manager));
        let (previous_output, is_member_of_previous_committee) =
            MpcManager::prepare_previous_output(&new_member_manager, &[], &mock_p2p)
                .await
                .unwrap();

        // Verify is_member_of_previous_committee is false
        assert!(
            !is_member_of_previous_committee,
            "New member should not be identified as existing member"
        );

        // Verify the output was fetched from quorum (has correct public data)
        assert_eq!(
            previous_output.public_key, expected_public_key,
            "Public key should match"
        );
        assert_eq!(
            previous_output.threshold, expected_threshold,
            "Threshold should match"
        );
        assert_eq!(
            previous_output.commitments.len(),
            expected_commitments_len,
            "Commitments count should match"
        );

        // Verify key_shares is empty (new member has no previous shares)
        assert!(
            previous_output.key_shares.shares.is_empty(),
            "New member should have empty key_shares"
        );
    }

    #[test]
    fn test_process_certified_rotation_message_skips_processed_shares() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();

        // Create receiver (party 2 with weight=4)
        let (mut receiver_manager, receiver_dkg_output) =
            rotation_setup.create_receiver_with_memory_store(2);

        // Create rotation dealer (party 0 with weight=3, so 3 rotation messages)
        let (_, dealer_dkg_output, rotation_messages) = rotation_setup.create_rotation_dealer(0);
        let rotation_dealer_addr = rotation_setup.setup.address(0);

        // Verify we have enough rotation messages for this test
        let rotation_map = match &rotation_messages {
            Messages::Rotation(map) => map,
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected rotation messages")
            }
        };
        assert!(
            rotation_map.len() >= 3,
            "Need at least 3 rotation messages for this test"
        );

        // Store rotation messages in receiver's state
        receiver_manager
            .dealer_messages
            .insert(rotation_dealer_addr, rotation_messages.clone());

        // Process all shares to get valid outputs
        receiver_manager
            .try_sign_rotation_messages(
                &receiver_dkg_output,
                rotation_dealer_addr,
                &rotation_messages,
            )
            .unwrap();

        // Setup test scenario with 3 shares:
        // - Share 1: Keep output (should be skipped - already processed)
        // - Share 2: Remove output (should be re-processed)
        // - Share 3: Remove output, add complaint (should be skipped - pending complaint)
        let mut share_indices: Vec<_> = rotation_map.keys().copied().collect();
        share_indices.sort();
        let share1_index = share_indices[0];
        let share2_index = share_indices[1];
        let share3_index = share_indices[2];

        // Rotation: outputs keyed by share index
        let share1_original_output = receiver_manager
            .dealer_outputs
            .get(&DealerOutputsKey::Rotation(share1_index))
            .expect("Share 1 should have output")
            .clone();

        // Remove share 2's output (will be re-processed)
        receiver_manager
            .dealer_outputs
            .remove(&DealerOutputsKey::Rotation(share2_index));

        // Remove share 3's output and add a complaint
        receiver_manager
            .dealer_outputs
            .remove(&DealerOutputsKey::Rotation(share3_index));

        // Create a real complaint using a cheating message for share 3
        let share3_value = dealer_dkg_output
            .key_shares
            .shares
            .iter()
            .find(|s| s.index == share3_index)
            .map(|s| s.value)
            .unwrap();
        let cheating_msg = create_cheating_rotation_message(
            &rotation_setup.setup,
            &receiver_manager.session_id,
            &rotation_dealer_addr,
            share3_value,
            share3_index,
            2, // Corrupt receiver's share (party_id = 2)
            &mut rng,
        );
        let session_id = receiver_manager
            .session_id
            .rotation_session_id(&rotation_dealer_addr, share3_index);
        let receiver = avss::Receiver::new(
            receiver_manager.dkg_config.nodes.clone(),
            receiver_manager.party_id,
            receiver_manager.dkg_config.threshold,
            session_id.to_vec(),
            None,
            receiver_manager.encryption_key.clone(),
        );
        let complaint = match receiver.process_message(&cheating_msg.1).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint from corrupted share"),
        };
        // Rotation: complaints keyed by (dealer_addr, share_index)
        receiver_manager.complaints_to_process.insert(
            ComplaintsToProcessKey::Rotation(rotation_dealer_addr, share3_index),
            complaint,
        );

        let outputs_before = receiver_manager.dealer_outputs.len();

        // Call process_certified_rotation_message
        receiver_manager
            .process_certified_rotation_message(&rotation_dealer_addr, &dealer_dkg_output)
            .unwrap();

        // Verify share 1: output unchanged (skipped because already had output)
        // Rotation: outputs keyed by share index
        let share1_output_after = receiver_manager
            .dealer_outputs
            .get(&DealerOutputsKey::Rotation(share1_index))
            .expect("Share 1 should still have output");
        assert_eq!(
            share1_output_after.my_shares.shares.len(),
            share1_original_output.my_shares.shares.len(),
            "Share 1 output should not be overwritten"
        );

        // Verify share 2: was re-processed (new output created)
        assert!(
            receiver_manager
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Rotation(share2_index)),
            "Share 2 should be re-processed"
        );

        // Verify share 3: NOT processed (skipped due to complaint)
        assert!(
            !receiver_manager
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Rotation(share3_index)),
            "Share 3 should not have output (skipped due to complaint)"
        );
        assert!(
            receiver_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Rotation(
                    rotation_dealer_addr,
                    share3_index
                )),
            "Share 3 complaint should still exist"
        );

        // Verify only one new output was added (share 2)
        assert_eq!(
            receiver_manager.dealer_outputs.len() - outputs_before,
            1,
            "Only share 2 should be added"
        );
    }

    #[tokio::test]
    async fn test_recover_rotation_shares_via_complaint_success() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)

        // Create test party (validator 2, weight=4) - this party will be the victim
        let test_party_idx = 2;
        let (mut test_manager, test_dkg_output) =
            rotation_setup.create_receiver_with_memory_store(test_party_idx);
        let test_addr = rotation_setup.setup.address(test_party_idx);

        // Create rotation dealer (validator 0, weight=3)
        let dealer_idx = 0;
        let (mut dealer_manager, dealer_dkg_output, valid_rotation_messages) =
            rotation_setup.create_rotation_dealer_with_memory_store(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);
        dealer_manager.previous_output = Some(dealer_dkg_output.clone());

        // Get the rotation messages map
        let valid_rotation_map = match &valid_rotation_messages {
            Messages::Rotation(map) => map.clone(),
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected rotation messages")
            }
        };

        // Get the share index and value for the first rotation message
        let first_share_index = *valid_rotation_map.keys().next().unwrap();
        let share_value = dealer_dkg_output
            .key_shares
            .shares
            .iter()
            .find(|s| s.index == first_share_index)
            .map(|s| s.value)
            .unwrap();

        // Create a cheating rotation message that corrupts the share for test_party_idx
        // Use the test_manager's session_id which is the base session_id for rotation
        let (cheating_share_index, cheating_message) = create_cheating_rotation_message(
            &rotation_setup.setup,
            &test_manager.session_id,
            &dealer_addr,
            share_value,
            first_share_index,
            test_party_idx as u16, // Corrupt the test party's share
            &mut rng,
        );

        // Create rotation messages with the cheating message replacing the first valid one
        let mut cheating_map = valid_rotation_map.clone();
        cheating_map.insert(cheating_share_index, cheating_message.clone());
        let cheating_messages = Messages::Rotation(cheating_map);

        // Store the cheating messages in test manager
        test_manager
            .dealer_messages
            .insert(dealer_addr, cheating_messages.clone());

        // Test party processes cheating message with their CORRECT key, generating a complaint
        let session_id = test_manager
            .session_id
            .rotation_session_id(&dealer_addr, first_share_index);
        let receiver = avss::Receiver::new(
            test_manager.dkg_config.nodes.clone(),
            test_manager.party_id,
            test_manager.dkg_config.threshold,
            session_id.to_vec(),
            None, // No expected commitment
            test_manager.encryption_key.clone(),
        );
        let valid_complaint = match receiver.process_message(&cheating_message).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint from corrupted share"),
        };

        // Insert the complaint (Rotation: keyed by (dealer_addr, share_index))
        test_manager.complaints_to_process.insert(
            ComplaintsToProcessKey::Rotation(dealer_addr, first_share_index),
            valid_complaint,
        );

        // Create other managers who have the cheating messages and can respond to complaints
        // These parties CAN decrypt their shares correctly (only test party's share is corrupted)
        let mut other_managers_map = HashMap::new();
        for i in [1usize, 3, 4] {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_output = Some(output.clone());
            // Store the cheating messages - other parties can still process them
            manager
                .dealer_messages
                .insert(dealer_addr, cheating_messages.clone());
            // Other parties process and get valid outputs (their shares are not corrupted)
            manager
                .try_sign_rotation_messages(&output, dealer_addr, &cheating_messages)
                .unwrap();
            other_managers_map.insert(rotation_setup.setup.address(i), manager);
        }

        // Add dealer to other managers (dealer also has the cheating message since they created it)
        dealer_manager
            .dealer_messages
            .insert(dealer_addr, cheating_messages.clone());
        dealer_manager
            .try_sign_rotation_messages(&dealer_dkg_output, dealer_addr, &cheating_messages)
            .unwrap();
        other_managers_map.insert(dealer_addr, dealer_manager);

        let mock_p2p = MockP2PChannel::new(other_managers_map, test_addr);

        // Get signers (parties who can respond to complaint)
        let signers: Vec<Address> = [0usize, 1, 3, 4]
            .iter()
            .map(|&i| rotation_setup.setup.address(i))
            .collect();

        // Verify complaint exists before recovery (Rotation: keyed by (dealer_addr, share_index))
        assert!(
            test_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::Rotation(
                    dealer_addr,
                    first_share_index
                )),
            "Should have complaint before recovery"
        );
        assert!(
            !test_manager
                .dealer_outputs
                .contains_key(&DealerOutputsKey::Rotation(first_share_index)),
            "Should not have output before recovery"
        );

        let test_manager = Arc::new(RwLock::new(test_manager));

        // Call recover_rotation_shares_via_complaints
        let result = MpcManager::recover_rotation_shares_via_complaints(
            &test_manager,
            &dealer_addr,
            &test_dkg_output,
            signers,
            &mock_p2p,
        )
        .await;

        // Recovery should succeed
        assert!(
            result.is_ok(),
            "Recovery should succeed: {:?}",
            result.err()
        );

        // Verify complaint was removed
        {
            let mgr = test_manager.read().unwrap();
            assert!(
                !mgr.complaints_to_process
                    .contains_key(&ComplaintsToProcessKey::Rotation(
                        dealer_addr,
                        first_share_index
                    )),
                "Complaint should be removed after successful recovery"
            );

            // Verify output was created (Rotation: outputs keyed by share index)
            assert!(
                mgr.dealer_outputs
                    .contains_key(&DealerOutputsKey::Rotation(first_share_index)),
                "Output should be created for recovered share"
            );
        }
    }

    #[test]
    fn test_handle_complain_request_success() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();

        // Create victim party (validator 2, weight=4) who will generate a complaint
        let victim_idx = 2;
        let (victim_manager, victim_dkg_output) =
            rotation_setup.create_receiver_with_memory_store(victim_idx);

        // Create rotation dealer (validator 0, weight=3)
        let dealer_idx = 0;
        let (_, dealer_dkg_output, valid_rotation_messages) =
            rotation_setup.create_rotation_dealer_with_memory_store(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        // Get the rotation messages map
        let valid_rotation_map = match &valid_rotation_messages {
            Messages::Rotation(map) => map.clone(),
            Messages::Dkg(_) | Messages::NonceGeneration { .. } => {
                panic!("Expected rotation messages")
            }
        };

        // Get share info for the first rotation message
        let first_share_index = *valid_rotation_map.keys().next().unwrap();
        let share_value = dealer_dkg_output
            .key_shares
            .shares
            .iter()
            .find(|s| s.index == first_share_index)
            .map(|s| s.value)
            .unwrap();

        // Create a cheating rotation message that corrupts the share for victim
        let (cheating_share_index, cheating_message) = create_cheating_rotation_message(
            &rotation_setup.setup,
            &victim_manager.session_id,
            &dealer_addr,
            share_value,
            first_share_index,
            victim_idx as u16,
            &mut rng,
        );

        // Create rotation messages with the cheating message
        let mut cheating_map = valid_rotation_map.clone();
        cheating_map.insert(cheating_share_index, cheating_message.clone());
        let cheating_messages = Messages::Rotation(cheating_map);

        // Victim processes cheating message and generates a complaint
        let session_id = victim_manager
            .session_id
            .rotation_session_id(&dealer_addr, first_share_index);
        let commitment = victim_dkg_output
            .commitments
            .get(&first_share_index)
            .copied();
        let receiver = avss::Receiver::new(
            victim_manager.dkg_config.nodes.clone(),
            victim_manager.party_id,
            victim_manager.dkg_config.threshold,
            session_id.to_vec(),
            commitment,
            victim_manager.encryption_key.clone(),
        );
        let complaint = match receiver.process_message(&cheating_message).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint from corrupted share"),
        };

        // Create responder party (validator 1) who can handle the complaint
        let responder_idx = 1;
        let (mut responder_manager, responder_dkg_output) =
            rotation_setup.create_receiver_with_memory_store(responder_idx);
        responder_manager.previous_output = Some(responder_dkg_output.clone());

        // Responder stores the cheating messages
        responder_manager
            .dealer_messages
            .insert(dealer_addr, cheating_messages.clone());

        // Responder processes and gets valid outputs (their shares are not corrupted)
        responder_manager
            .try_sign_rotation_messages(&responder_dkg_output, dealer_addr, &cheating_messages)
            .unwrap();

        // Create the complaint request (response will contain ALL shares from dealer)
        // For rotation, share_index specifies which share triggered the complaint
        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: Some(first_share_index),
            complaint,
        };

        // Handle the complaint request
        let result = responder_manager.handle_complain_request(&request);

        assert!(
            result.is_ok(),
            "Should successfully handle complaint: {:?}",
            result.err()
        );
        let response = result.unwrap();
        // Response contains ALL shares from this dealer (if dealer cheated on one, reveal all)
        let rotation_responses = match &response {
            ComplaintResponses::Rotation(map) => map,
            ComplaintResponses::Dkg(_) | ComplaintResponses::NonceGeneration(_) => {
                panic!("Expected rotation complaint response")
            }
        };
        // Dealer has weight=3, so 3 share indices, all should be in response
        assert_eq!(rotation_responses.len(), 3);
        // The complained share should be in the response
        assert!(
            rotation_responses.contains_key(&first_share_index),
            "Response should include the complained share"
        );

        // Verify response is cached by dealer
        assert!(
            responder_manager
                .complaint_responses
                .contains_key(&dealer_addr),
            "Response should be cached"
        );
    }

    /// Shared store that can be cloned and reused across manager restarts.
    #[derive(Clone)]
    struct SharedMemoryStore {
        inner: Arc<std::sync::Mutex<InMemoryPublicMessagesStore>>,
    }

    impl SharedMemoryStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(std::sync::Mutex::new(InMemoryPublicMessagesStore::new())),
            }
        }
    }

    impl PublicMessagesStore for SharedMemoryStore {
        fn store_dealer_message(
            &mut self,
            dealer: &Address,
            message: &avss::Message,
        ) -> anyhow::Result<()> {
            self.inner
                .lock()
                .unwrap()
                .store_dealer_message(dealer, message)
        }

        fn get_dealer_message(
            &self,
            epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<avss::Message>> {
            self.inner.lock().unwrap().get_dealer_message(epoch, dealer)
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            self.inner.lock().unwrap().list_all_dealer_messages()
        }

        fn store_rotation_messages(
            &mut self,
            dealer: &Address,
            messages: &RotationMessages,
        ) -> anyhow::Result<()> {
            self.inner
                .lock()
                .unwrap()
                .store_rotation_messages(dealer, messages)
        }

        fn get_rotation_messages(
            &self,
            epoch: u64,
            dealer: &Address,
        ) -> anyhow::Result<Option<RotationMessages>> {
            self.inner
                .lock()
                .unwrap()
                .get_rotation_messages(epoch, dealer)
        }

        fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
            self.inner.lock().unwrap().list_all_rotation_messages()
        }
    }

    #[test]
    fn test_dealer_restart_reuses_stored_rotation_messages() {
        let mut rng = rand::thread_rng();
        let rotation_setup = RotationTestSetup::new();
        let dealer_index = 0;
        let dealer_addr = rotation_setup.setup.address(dealer_index);

        // Create a shared store that persists across "restarts"
        let shared_store = SharedMemoryStore::new();

        // Phase 1: Create dealer, generate rotation messages, store them
        let original_messages = {
            let mut dealer_manager = rotation_setup
                .setup
                .create_manager_with_store(dealer_index, Box::new(shared_store.clone()));

            // Process DKG messages to complete initial DKG
            for (i, message) in rotation_setup.dealer_messages.iter().enumerate() {
                let addr = rotation_setup
                    .setup
                    .address(rotation_setup.dealer_indices[i]);
                receive_dealer_messages(&mut dealer_manager, message, addr).unwrap();
            }
            let dkg_output = dealer_manager
                .complete_dkg(rotation_setup.certificates.keys().copied())
                .unwrap();

            // Clear state to prepare for rotation
            dealer_manager.dealer_messages.clear();
            dealer_manager.dealer_outputs.clear();
            rotation_setup.prepare_for_rotation(&mut dealer_manager);

            // Create and store rotation messages
            let msgs = dealer_manager.create_rotation_messages(&dkg_output, &mut rng);
            dealer_manager
                .store_rotation_messages(dealer_addr, &msgs)
                .unwrap();

            // Return the messages for comparison
            msgs
        };
        // dealer_manager is dropped here, simulating a crash/restart

        // Phase 2: Create new manager with same store, verify messages are loaded
        let mut new_dealer_manager = rotation_setup
            .setup
            .create_manager_with_store(dealer_index, Box::new(shared_store.clone()));

        // Process DKG messages again (needed for DKG output)
        for (i, message) in rotation_setup.dealer_messages.iter().enumerate() {
            let addr = rotation_setup
                .setup
                .address(rotation_setup.dealer_indices[i]);
            receive_dealer_messages(&mut new_dealer_manager, message, addr).unwrap();
        }
        let dkg_output = new_dealer_manager
            .complete_dkg(rotation_setup.certificates.keys().copied())
            .unwrap();
        new_dealer_manager.dealer_messages.clear();
        new_dealer_manager.dealer_outputs.clear();
        rotation_setup.prepare_for_rotation(&mut new_dealer_manager);

        // Load rotation messages from store (simulating restart recovery)
        let stored_messages = shared_store
            .get_rotation_messages(0, &dealer_addr)
            .unwrap()
            .expect("Rotation messages should be in store");

        // Verify the stored messages match the original
        assert_eq!(
            stored_messages.len(),
            original_messages.len(),
            "Should have same number of rotation messages"
        );
        for (share_index, original_msg) in &original_messages {
            let stored_msg = stored_messages
                .get(share_index)
                .expect("Should have message for share index");
            // Compare message hashes (messages contain random elements, so compare hashes)
            let original_hash = compute_messages_hash(&Messages::Rotation(
                std::iter::once((*share_index, original_msg.clone())).collect(),
            ));
            let stored_hash = compute_messages_hash(&Messages::Rotation(
                std::iter::once((*share_index, stored_msg.clone())).collect(),
            ));
            assert_eq!(
                original_hash, stored_hash,
                "Stored message should match original for share index {}",
                share_index
            );
        }

        // Load into dealer_messages (what would happen on restart)
        new_dealer_manager
            .dealer_messages
            .insert(dealer_addr, Messages::Rotation(stored_messages.clone()));

        // Verify the manager would reuse these messages (check the match arm in run_key_rotation_as_dealer)
        match new_dealer_manager.dealer_messages.get(&dealer_addr) {
            Some(Messages::Rotation(msgs)) => {
                assert_eq!(
                    msgs.len(),
                    original_messages.len(),
                    "Loaded messages should match original"
                );
            }
            _ => panic!("Expected rotation messages to be loaded"),
        }

        // Verify we can sign with the loaded messages
        let rotation_messages = Messages::Rotation(stored_messages);
        let signature = new_dealer_manager.try_sign_rotation_messages(
            &dkg_output,
            dealer_addr,
            &rotation_messages,
        );
        assert!(
            signature.is_ok(),
            "Should be able to sign with loaded messages: {:?}",
            signature.err()
        );
    }

    #[test]
    fn test_party_restart_uses_stored_rotation_messages() {
        let mut rng = rand::thread_rng();
        let rotation_setup = RotationTestSetup::new();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)

        let party_index = 3; // Not a dealer in rotation (dealers are 0, 1, 2)

        // Phase 1: Create rotation messages from dealers
        // First, complete DKG for each dealer to get their DKG outputs
        let mut dealer_dkg_outputs = Vec::new();
        let mut rotation_messages_map = HashMap::new();

        for dealer_idx in [0usize, 1, 2] {
            let dealer_addr = rotation_setup.setup.address(dealer_idx);
            let mut dealer_manager = rotation_setup.setup.create_manager(dealer_idx);

            // Complete DKG for dealer
            for (i, message) in rotation_setup.dealer_messages.iter().enumerate() {
                let addr = rotation_setup
                    .setup
                    .address(rotation_setup.dealer_indices[i]);
                receive_dealer_messages(&mut dealer_manager, message, addr).unwrap();
            }
            let dealer_dkg_output = dealer_manager
                .complete_dkg(rotation_setup.certificates.keys().copied())
                .unwrap();

            // Create rotation messages
            let rotation_msgs =
                dealer_manager.create_rotation_messages(&dealer_dkg_output, &mut rng);
            rotation_messages_map.insert(dealer_addr, rotation_msgs);
            dealer_dkg_outputs.push((dealer_idx, dealer_dkg_output));
        }

        // Phase 2: Pre-populate store with rotation messages (simulating what was stored before restart)
        let shared_store = SharedMemoryStore::new();
        for (dealer_addr, rotation_msgs) in &rotation_messages_map {
            shared_store
                .inner
                .lock()
                .unwrap()
                .store_rotation_messages(dealer_addr, rotation_msgs)
                .unwrap();
        }

        // Phase 3: Create party manager with pre-populated store (simulating restart)
        let mut party_manager = rotation_setup
            .setup
            .create_manager_with_store(party_index, Box::new(shared_store.clone()));
        rotation_setup.prepare_for_rotation(&mut party_manager);

        // Verify rotation messages were loaded from store
        for dealer_addr in rotation_messages_map.keys() {
            assert!(
                party_manager.dealer_messages.contains_key(dealer_addr),
                "Rotation messages for dealer {:?} should be loaded from store",
                dealer_addr
            );
            match party_manager.dealer_messages.get(dealer_addr) {
                Some(Messages::Rotation(_)) => {}
                _ => panic!("Expected rotation messages for dealer {:?}", dealer_addr),
            }
        }

        // Phase 4: Complete DKG (needed to get previous_output for key rotation)
        for (i, message) in rotation_setup.dealer_messages.iter().enumerate() {
            let addr = rotation_setup
                .setup
                .address(rotation_setup.dealer_indices[i]);
            receive_dealer_messages(&mut party_manager, message, addr).unwrap();
        }
        let dkg_output = party_manager
            .complete_dkg(rotation_setup.certificates.keys().copied())
            .unwrap();

        // Clear DKG outputs but keep rotation messages (they were loaded from store)
        party_manager.dealer_outputs.clear();

        // Phase 5: Process rotation messages and complete key rotation
        // The rotation messages are already in dealer_messages (loaded from store)
        // We need to process them to populate dealer_outputs
        for (dealer_addr, rotation_msgs) in &rotation_messages_map {
            for (share_index, message) in rotation_msgs {
                let output_key = DealerOutputsKey::Rotation(*share_index);
                let complaint_key = ComplaintsToProcessKey::Rotation(*dealer_addr, *share_index);
                if party_manager.dealer_outputs.contains_key(&output_key) {
                    continue;
                }
                let session_id = party_manager
                    .session_id
                    .rotation_session_id(dealer_addr, *share_index)
                    .to_vec();
                party_manager
                    .process_and_store_message(
                        party_manager.dkg_config.nodes.clone(),
                        party_manager.party_id,
                        party_manager.dkg_config.threshold,
                        session_id,
                        message,
                        None,
                        output_key,
                        complaint_key,
                    )
                    .unwrap();
            }
        }

        // Get certified share indices
        let certified_share_indices: Vec<ShareIndex> = party_manager
            .dealer_outputs
            .keys()
            .filter_map(|k| match k {
                DealerOutputsKey::Rotation(idx) => Some(*idx),
                _ => None,
            })
            .collect();

        // Complete key rotation using stored messages
        let rotation_output = party_manager
            .complete_key_rotation(&dkg_output, &certified_share_indices)
            .unwrap();

        // Verify the output is valid (public key should be derivable)
        assert!(
            !rotation_output.key_shares.shares.is_empty(),
            "Should have key shares from rotation"
        );
        assert_eq!(
            rotation_output.threshold, dkg_output.threshold,
            "Rotation output threshold should match DKG threshold"
        );
    }

    /// Tests that `reconstruct_from_dkg_certificates` uses the previous committee's
    /// parameters (nodes, party_id, threshold) to decrypt DKG messages, not the target
    /// committee's.
    #[test]
    fn test_reconstruct_from_dkg_certificates_with_shifted_party_ids() {
        let mut rng = rand::thread_rng();

        // Previous committee: 5 members with weights [3, 2, 4, 1, 2]
        // (total=12, threshold=4). Dealers: 0, 1, 4 (total weight=7 >= threshold).
        let rotation_setup = RotationTestSetup::new();
        let epoch = rotation_setup.setup.epoch(); // = 100

        // Complete DKG for all 5 members, storing messages in InMemoryPublicMessagesStore.
        // We need the DKG certificates and the stored messages for reconstruction.
        let mut dkg_outputs = Vec::new();
        let mut stores = Vec::new();
        for i in 0..5 {
            let (manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            dkg_outputs.push(output);
            stores.push(manager.public_messages_store);
        }

        let expected_public_key = dkg_outputs[0].public_key;
        let certificates = rotation_setup.certificates();

        // Create a new member that, when inserted before existing members, shifts party_ids.
        // Previous committee order: addr_0=[0;32], addr_1=[1;32], addr_2=[2;32], addr_3=[3;32], addr_4=[4;32]
        // party_ids:                     0            1            2            3            4
        //
        // Insert new member between addr_1 and addr_2:
        // Target committee order:  addr_0, addr_1, new_addr, addr_2, addr_3, addr_4
        // party_ids:                  0       1        2        3        4        5
        //
        // addr_4's party_id shifts from 4 (previous) to 5 (target).
        let new_member_addr = Address::new([99u8; 32]);
        let new_member_encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let new_member_signing_key = Bls12381PrivateKey::generate(&mut rng);

        let previous_members: Vec<_> = rotation_setup.setup.committee().members().to_vec();
        let mut target_members: Vec<_> = previous_members.clone();
        // Insert new member at position 2 to shift members 2, 3, 4
        target_members.insert(
            2,
            CommitteeMember::new(
                new_member_addr,
                new_member_signing_key.public_key(),
                EncryptionPublicKey::from_private_key(&new_member_encryption_key),
                2,
            ),
        );

        let target_epoch = epoch + 1;
        let previous_committee = Committee::new(previous_members, epoch);
        let target_committee = Committee::new(target_members, target_epoch);

        // Build CommitteeSet simulating a live reconfig:
        // epoch = 100 (current), pending_epoch_change = 101 (target)
        let mut committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        let mut committees = BTreeMap::new();
        committees.insert(epoch, previous_committee);
        committees.insert(target_epoch, target_committee);
        committee_set
            .set_epoch(epoch)
            .set_pending_epoch_change(Some(target_epoch))
            .set_committees(committees);

        // Test with a shifted member (addr_4, previous party_id=4, target party_id=5).
        let shifted_member_index = 4usize;
        let shifted_addr = rotation_setup.setup.address(shifted_member_index);
        assert_eq!(
            committee_set
                .committees()
                .get(&target_epoch)
                .unwrap()
                .index_of(&shifted_addr),
            Some(5), // shifted from 4 to 5
            "Party ID should be shifted in target committee"
        );

        // Create an InMemoryPublicMessagesStore with the DKG messages from the original DKG.
        let mut store = InMemoryPublicMessagesStore::new();
        for (i, &dealer_idx) in rotation_setup.dealer_indices.iter().enumerate() {
            let dealer_addr = rotation_setup.setup.address(dealer_idx);
            let msg = match &rotation_setup.dealer_messages[i] {
                Messages::Dkg(m) => m,
                _ => panic!("Expected DKG message"),
            };
            store.store_dealer_message(&dealer_addr, msg).unwrap();
        }

        // Create MpcManager for the shifted member with the target committee.
        let session_id = SessionId::new(TEST_CHAIN_ID, target_epoch, &ProtocolType::Dkg);
        let mut manager = MpcManager::new(
            shifted_addr,
            &committee_set,
            session_id,
            rotation_setup.setup.encryption_keys[shifted_member_index].clone(),
            rotation_setup.setup.signing_keys[shifted_member_index].clone(),
            Box::new(store),
            TEST_ALLOWED_DELTA,
            TEST_CHAIN_ID,
            None,
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();

        // Verify the party_id shift
        assert_eq!(manager.party_id, 5, "Target party_id should be 5");
        assert_eq!(
            manager
                .previous_committee
                .as_ref()
                .unwrap()
                .index_of(&shifted_addr),
            Some(4),
            "Previous party_id should be 4"
        );

        // This would panic with "index out of bounds: the len is 5 but the index is 5"
        // if previous committee parameters were not used for decryption.
        let reconstructed = manager
            .reconstruct_from_dkg_certificates(&certificates)
            .unwrap();

        // Verify the reconstructed output matches the original DKG
        assert_eq!(
            reconstructed.public_key, expected_public_key,
            "Reconstructed public key should match original DKG"
        );
        assert_eq!(
            reconstructed.threshold, dkg_outputs[shifted_member_index].threshold,
            "Reconstructed threshold should match"
        );
        assert_eq!(
            reconstructed.key_shares.shares.len(),
            dkg_outputs[shifted_member_index].key_shares.shares.len(),
            "Should have same number of key shares"
        );
    }

    /// Tests that `reconstruct_from_rotation_certificates` uses the previous committee's
    /// parameters to decrypt rotation messages.
    #[test]
    fn test_reconstruct_from_rotation_certificates_with_shifted_party_ids() {
        let mut rng = rand::thread_rng();

        // Step 1: Complete DKG at epoch 100 with 5 members, weights [3, 2, 4, 1, 2]
        let rotation_setup = RotationTestSetup::new();
        let dkg_epoch = rotation_setup.setup.epoch(); // = 100
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total=12, threshold=4)

        // Get DKG outputs for all 5 members
        let mut dkg_outputs = Vec::new();
        for i in 0..5 {
            let (_, output) = rotation_setup.create_receiver_with_completed_dkg(i);
            dkg_outputs.push(output);
        }
        let expected_public_key = dkg_outputs[0].public_key;

        // Step 2: Set up key rotation at epoch 101 with same 5 members.
        // Create a committee set for the rotation epoch:
        //   committees: {100: 5-member, 101: 5-member (same)}, epoch=100, pending=101
        let rotation_epoch = dkg_epoch + 1;
        let members: Vec<_> = rotation_setup.setup.committee().members().to_vec();
        let committee_at_100 = Committee::new(members.clone(), dkg_epoch);
        let committee_at_101 = Committee::new(members.clone(), rotation_epoch);

        let mut rotation_committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        let mut rotation_committees = BTreeMap::new();
        rotation_committees.insert(dkg_epoch, committee_at_100);
        rotation_committees.insert(rotation_epoch, committee_at_101);
        rotation_committee_set
            .set_epoch(dkg_epoch)
            .set_pending_epoch_change(Some(rotation_epoch))
            .set_committees(rotation_committees);

        // Create rotation MpcManagers at epoch 101 with KeyRotation protocol type.
        // Dealers: indices 0, 1, 4 (total weight = 3+2+2 = 7 >= threshold 4).
        let dealer_indices = [0usize, 1, 4];
        let mut rotation_certificates = Vec::new();
        let mut rotation_messages_by_dealer: Vec<(Address, Messages)> = Vec::new();

        for &dealer_idx in &dealer_indices {
            let dealer_addr = rotation_setup.setup.address(dealer_idx);
            let rotation_session_id =
                SessionId::new(TEST_CHAIN_ID, rotation_epoch, &ProtocolType::KeyRotation);
            let mut dealer_manager = MpcManager::new(
                dealer_addr,
                &rotation_committee_set,
                rotation_session_id.clone(),
                rotation_setup.setup.encryption_keys[dealer_idx].clone(),
                rotation_setup.setup.signing_keys[dealer_idx].clone(),
                Box::new(InMemoryPublicMessagesStore::new()),
                TEST_ALLOWED_DELTA,
                TEST_CHAIN_ID,
                None,
                TEST_BATCH_SIZE_PER_WEIGHT,
            )
            .unwrap();
            dealer_manager.previous_output = Some(dkg_outputs[dealer_idx].clone());

            // Create rotation messages (encrypted for epoch 101's nodes)
            let msgs = dealer_manager.create_rotation_messages(&dkg_outputs[dealer_idx], &mut rng);
            let rotation_messages = Messages::Rotation(msgs);
            dealer_manager
                .dealer_messages
                .insert(dealer_addr, rotation_messages.clone());

            // Self-sign
            let own_sig = dealer_manager
                .try_sign_rotation_messages(
                    &dkg_outputs[dealer_idx],
                    dealer_addr,
                    &rotation_messages,
                )
                .unwrap();

            // Get another validator's signature
            let other_idx = if dealer_idx == 0 { 1 } else { 0 };
            let other_addr = rotation_setup.setup.address(other_idx);
            let other_rotation_session_id =
                SessionId::new(TEST_CHAIN_ID, rotation_epoch, &ProtocolType::KeyRotation);
            let mut other_manager = MpcManager::new(
                other_addr,
                &rotation_committee_set,
                other_rotation_session_id,
                rotation_setup.setup.encryption_keys[other_idx].clone(),
                rotation_setup.setup.signing_keys[other_idx].clone(),
                Box::new(InMemoryPublicMessagesStore::new()),
                TEST_ALLOWED_DELTA,
                TEST_CHAIN_ID,
                None,
                TEST_BATCH_SIZE_PER_WEIGHT,
            )
            .unwrap();
            other_manager.previous_output = Some(dkg_outputs[other_idx].clone());
            let other_sig = other_manager
                .try_sign_rotation_messages(
                    &dkg_outputs[other_idx],
                    dealer_addr,
                    &rotation_messages,
                )
                .unwrap();

            // Create rotation certificate
            let epoch_for_cert = dealer_manager.dkg_config.epoch;
            let committee_for_cert = rotation_committee_set
                .committees()
                .get(&rotation_epoch)
                .unwrap();
            let cert = create_rotation_test_certificate(
                committee_for_cert,
                &rotation_messages,
                dealer_addr,
                vec![
                    MemberSignature::new(epoch_for_cert, dealer_addr, own_sig),
                    MemberSignature::new(epoch_for_cert, other_addr, other_sig),
                ],
            )
            .unwrap();
            rotation_certificates.push(CertificateV1::Rotation(cert));
            rotation_messages_by_dealer.push((dealer_addr, rotation_messages));
        }

        // Step 3: Create a 6-member target committee for epoch 102 with a new member
        // inserted at position 2, shifting members 2, 3, 4.
        let new_member_addr = Address::new([99u8; 32]);
        let new_member_encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let new_member_signing_key = Bls12381PrivateKey::generate(&mut rng);

        let mut target_members: Vec<_> = members.clone();
        target_members.insert(
            2,
            CommitteeMember::new(
                new_member_addr,
                new_member_signing_key.public_key(),
                EncryptionPublicKey::from_private_key(&new_member_encryption_key),
                2,
            ),
        );

        let target_epoch = dkg_epoch + 2;
        let previous_committee = Committee::new(members, rotation_epoch);
        let target_committee = Committee::new(target_members, target_epoch);

        let mut committee_set = CommitteeSet::new(Address::ZERO, Address::ZERO);
        let mut committees = BTreeMap::new();
        committees.insert(rotation_epoch, previous_committee);
        committees.insert(target_epoch, target_committee);
        committee_set
            .set_epoch(rotation_epoch)
            .set_pending_epoch_change(Some(target_epoch))
            .set_committees(committees);

        // Test with a shifted member (addr_4, previous party_id=4, target party_id=5).
        let shifted_member_index = 4usize;
        let shifted_addr = rotation_setup.setup.address(shifted_member_index);

        // Create an InMemoryPublicMessagesStore with the rotation messages
        let mut store = InMemoryPublicMessagesStore::new();
        for (dealer_addr, messages) in &rotation_messages_by_dealer {
            let rotation_msgs = match messages {
                Messages::Rotation(m) => m,
                _ => panic!("Expected rotation messages"),
            };
            store
                .store_rotation_messages(dealer_addr, rotation_msgs)
                .unwrap();
        }

        // Create MpcManager for the shifted member at epoch 102
        let session_id = SessionId::new(TEST_CHAIN_ID, target_epoch, &ProtocolType::KeyRotation);
        let mut manager = MpcManager::new(
            shifted_addr,
            &committee_set,
            session_id,
            rotation_setup.setup.encryption_keys[shifted_member_index].clone(),
            rotation_setup.setup.signing_keys[shifted_member_index].clone(),
            Box::new(store),
            TEST_ALLOWED_DELTA,
            TEST_CHAIN_ID,
            None,
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();

        // Verify the party_id shift
        assert_eq!(manager.party_id, 5, "Target party_id should be 5");
        assert_eq!(
            manager
                .previous_committee
                .as_ref()
                .unwrap()
                .index_of(&shifted_addr),
            Some(4),
            "Previous party_id should be 4"
        );

        let previous_threshold = manager.previous_threshold.unwrap();

        // This would panic with index-out-of-bounds if previous committee parameters were not used for decryption.
        let reconstructed = manager
            .reconstruct_from_rotation_certificates(&rotation_certificates, previous_threshold)
            .unwrap();

        // Verify the reconstructed output has valid data
        assert_eq!(
            reconstructed.public_key, expected_public_key,
            "Reconstructed public key should match original DKG"
        );
        assert!(
            !reconstructed.key_shares.shares.is_empty(),
            "Should have key shares from rotation reconstruction"
        );
    }

    fn create_nonce_dealer_message(
        setup: &TestSetup,
        dealer_index: usize,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> Messages {
        let config = setup.dkg_config();
        let dealer_address = setup.address(dealer_index);
        let dealer_party_id = setup.committee().index_of(&dealer_address).unwrap() as u16;
        let dealer_session_id = SessionId::nonce_dealer_session_id(
            TEST_CHAIN_ID,
            setup.epoch(),
            batch_index,
            &dealer_address,
        );
        let dealer = batch_avss::Dealer::new(
            config.nodes.clone(),
            dealer_party_id,
            config.threshold,
            config.max_faulty,
            dealer_session_id.to_vec(),
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();
        let message = dealer.create_message(rng).unwrap();
        Messages::NonceGeneration {
            batch_index,
            message,
        }
    }

    /// Creates a cheating nonce message that corrupts the encrypted shares for party 0.
    fn create_cheating_nonce_message(
        setup: &TestSetup,
        dealer_index: usize,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> Messages {
        use fastcrypto::groups::GroupElement;
        use fastcrypto::groups::secp256k1::ProjectivePoint;
        use fastcrypto::hash::Sha3_512;
        type S = <ProjectivePoint as GroupElement>::ScalarType;

        let config = setup.dkg_config();
        let dealer_address = setup.address(dealer_index);
        let dealer_party_id = setup.committee().index_of(&dealer_address).unwrap() as u16;
        let dealer_session_id = SessionId::nonce_dealer_session_id(
            TEST_CHAIN_ID,
            setup.epoch(),
            batch_index,
            &dealer_address,
        );

        let dealer_weight = config.nodes.weight_of(dealer_party_id).unwrap() as usize;
        let batch_size = dealer_weight * TEST_BATCH_SIZE_PER_WEIGHT as usize;
        let total_weight = config.nodes.total_weight();

        // Create random polynomials (one per nonce in the batch)
        let polynomials: Vec<Poly<S>> = (0..batch_size)
            .map(|_| Poly::<S>::rand(config.threshold - 1, rng))
            .collect();

        // Compute full public keys (g^{secret_l} for each nonce)
        let full_public_keys: Vec<ProjectivePoint> = polynomials
            .iter()
            .map(|p| ProjectivePoint::generator() * p.c0())
            .collect();

        // Blinding polynomial
        let blinding_poly = Poly::<S>::rand(config.threshold - 1, rng);
        let blinding_commit = ProjectivePoint::generator() * blinding_poly.c0();

        // Evaluate all polynomials at all share indices
        let share_evals: Vec<_> = polynomials
            .iter()
            .map(|p| p.eval_range(total_weight))
            .collect();
        let blinding_evals = blinding_poly.eval_range(total_weight);

        // Build pk_and_msgs: encrypt SharesForNode for each party
        let mut pk_and_msgs: Vec<_> = config
            .nodes
            .iter()
            .map(|node| {
                let share_ids = config.nodes.share_ids_of(node.id).unwrap();
                let shares_for_node = batch_avss::SharesForNode {
                    shares: share_ids
                        .into_iter()
                        .map(|index| batch_avss::ShareBatch {
                            index,
                            batch: share_evals.iter().map(|evals| evals[index]).collect(),
                            blinding_share: blinding_evals[index],
                        })
                        .collect(),
                };
                (node.pk.clone(), bcs::to_bytes(&shares_for_node).unwrap())
            })
            .collect();

        // Corrupt party 0's plaintext (flip one bit before encryption)
        pk_and_msgs[0].1[7] ^= 1;

        // Encrypt with the corrupted plaintext
        let random_oracle = RandomOracle::new(&Hex::encode(dealer_session_id.to_vec()));
        let ciphertext = MultiRecipientEncryption::encrypt(
            &pk_and_msgs,
            &random_oracle.extend("encryption"),
            rng,
        );

        // Compute challenge: hash(full_public_keys, blinding_commit, ciphertext)
        let challenge_oracle = random_oracle.extend("challenge");
        let inner_hash = Sha3_512::digest(
            bcs::to_bytes(&(full_public_keys.clone(), &blinding_commit, &ciphertext)).unwrap(),
        )
        .digest;
        let challenge: Vec<S> = (0..batch_size)
            .map(|l| challenge_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
            .collect();

        // Compute response polynomial: blinding_poly + sum(p_l * gamma_l)
        // Using eval_range then interpolate (same approach as the original code)
        let blinding_evals_t = blinding_poly
            .eval_range(total_weight)
            .take(config.threshold);
        let response_evals = share_evals
            .into_iter()
            .map(|e| e.take(config.threshold))
            .zip(challenge.iter())
            .fold(blinding_evals_t, |acc, (p_l, gamma_l)| acc + p_l * gamma_l);
        // Convert EvalRange to Vec<Eval> for interpolation
        let eval_points: Vec<_> = (1..=config.threshold)
            .map(|i| {
                let idx = ShareIndex::new(i).unwrap();
                fastcrypto_tbls::types::IndexedValue {
                    index: idx,
                    value: response_evals[idx],
                }
            })
            .collect();
        let response_polynomial = Poly::<S>::interpolate(&eval_points).unwrap();

        let message = bcs::from_bytes::<batch_avss::Message>(
            &bcs::to_bytes(&(
                full_public_keys,
                blinding_commit,
                ciphertext,
                response_polynomial,
            ))
            .unwrap(),
        )
        .unwrap();

        Messages::NonceGeneration {
            batch_index,
            message,
        }
    }

    /// Creates a complaint for a nonce message by decrypting with a wrong key.
    fn create_nonce_complaint(
        setup: &TestSetup,
        nonce_messages: &Messages,
        complainer_party_id: u16,
        dealer_index: usize,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> complaint::Complaint {
        let (batch_index, message) = match nonce_messages {
            Messages::NonceGeneration {
                batch_index,
                message,
            } => (*batch_index, message),
            _ => panic!("Expected NonceGeneration message"),
        };
        let config = setup.dkg_config();
        let dealer_address = setup.address(dealer_index);
        let dealer_party_id = setup.committee().index_of(&dealer_address).unwrap() as u16;
        let dealer_session_id = SessionId::nonce_dealer_session_id(
            TEST_CHAIN_ID,
            setup.epoch(),
            batch_index,
            &dealer_address,
        );
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(rng);
        let receiver = batch_avss::Receiver::new(
            config.nodes.clone(),
            complainer_party_id,
            dealer_party_id,
            config.threshold,
            dealer_session_id.to_vec(),
            wrong_key,
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();
        match receiver.process_message(message).unwrap() {
            batch_avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint with wrong key"),
        }
    }

    /// Send a message via handle_send_messages_request and assert success.
    fn send_and_assert_ok(
        receiver: &mut MpcManager,
        dealer_address: Address,
        messages: &Messages,
    ) -> SendMessagesResponse {
        let request = SendMessagesRequest {
            messages: messages.clone(),
        };
        let response = receiver
            .handle_send_messages_request(dealer_address, &request)
            .unwrap();
        assert!(!response.signature.as_ref().is_empty());
        response
    }

    /// Send a message and assert it returns an equivocation error.
    fn send_and_assert_equivocation(
        receiver: &mut MpcManager,
        dealer_address: Address,
        messages: &Messages,
    ) {
        let request = SendMessagesRequest {
            messages: messages.clone(),
        };
        let result = receiver.handle_send_messages_request(dealer_address, &request);
        assert!(result.is_err());
        match result.unwrap_err() {
            MpcError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_address);
                assert!(
                    reason.contains("different messages"),
                    "Expected equivocation error, got: {}",
                    reason
                );
            }
            other => panic!("Expected InvalidMessage error, got: {:?}", other),
        }
    }

    /// Retrieve a dealer's messages and verify hash matches.
    fn retrieve_and_verify_hash(
        manager: &MpcManager,
        dealer_address: Address,
        expected_messages: &Messages,
    ) {
        let request = RetrieveMessagesRequest {
            dealer: dealer_address,
        };
        let response = manager.handle_retrieve_messages_request(&request).unwrap();
        assert_eq!(
            compute_messages_hash(&response.messages),
            compute_messages_hash(expected_messages),
        );
    }

    /// Complain and assert "No message from dealer" error.
    fn complain_and_assert_no_message(
        manager: &mut MpcManager,
        dealer_address: Address,
        complaint: complaint::Complaint,
        share_index: Option<ShareIndex>,
    ) {
        let request = ComplainRequest {
            dealer: dealer_address,
            share_index,
            complaint,
        };
        let result = manager.handle_complain_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(
            err.to_string().contains("No message from dealer"),
            "Expected 'No message from dealer', got: {}",
            err
        );
    }

    #[test]
    fn test_handle_send_messages_request_rotation() {
        let rotation_setup = RotationTestSetup::new();

        // Create rotation dealer (party 0)
        let dealer_idx = 0;
        let (_, dealer_dkg_output, rotation_messages) =
            rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        // Create receiver (party 2) with completed DKG
        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output);

        let _ = dealer_dkg_output;
        let response = send_and_assert_ok(&mut receiver, dealer_addr, &rotation_messages);
        assert!(!response.signature.as_ref().is_empty());
    }

    #[test]
    fn test_handle_send_messages_request_rotation_idempotent() {
        let rotation_setup = RotationTestSetup::new();

        let dealer_idx = 0;
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output);

        let response1 = send_and_assert_ok(&mut receiver, dealer_addr, &rotation_messages);
        // Second call with identical request → cached response
        let request = SendMessagesRequest {
            messages: rotation_messages.clone(),
        };
        let response2 = receiver
            .handle_send_messages_request(dealer_addr, &request)
            .unwrap();
        assert_eq!(response1.signature, response2.signature);
    }

    #[test]
    fn test_handle_send_messages_request_rotation_equivocation() {
        let rotation_setup = RotationTestSetup::new();

        let dealer_idx = 0;
        let (_, _, rotation_messages1) = rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        // Create a second, different rotation dealer message from the same party
        let (_, _, rotation_messages2) = rotation_setup.create_rotation_dealer(dealer_idx);

        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output);

        // First succeeds
        send_and_assert_ok(&mut receiver, dealer_addr, &rotation_messages1);
        // Second with different messages → equivocation error
        send_and_assert_equivocation(&mut receiver, dealer_addr, &rotation_messages2);
    }

    #[test]
    fn test_handle_retrieve_messages_request_rotation_success() {
        let rotation_setup = RotationTestSetup::new();

        let dealer_idx = 0;
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output);

        send_and_assert_ok(&mut receiver, dealer_addr, &rotation_messages);
        retrieve_and_verify_hash(&receiver, dealer_addr, &rotation_messages);
    }

    #[test]
    fn test_handle_complain_request_rotation_no_message_from_dealer() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();

        let dealer_idx = 0;
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        let share_index = match &rotation_messages {
            Messages::Rotation(map) => *map.keys().next().unwrap(),
            _ => unreachable!(),
        };

        // Create receiver with completed DKG but WITHOUT receiving dealer message
        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output.clone());

        // Build a complaint using wrong key
        let session_id = receiver
            .session_id
            .rotation_session_id(&dealer_addr, share_index);
        let commitment = receiver_dkg_output.commitments.get(&share_index).copied();
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let Messages::Rotation(map) = &rotation_messages else {
            unreachable!()
        };
        let msg = map.get(&share_index).unwrap();
        let avss_receiver = avss::Receiver::new(
            receiver.dkg_config.nodes.clone(),
            receiver.party_id,
            receiver.dkg_config.threshold,
            session_id.to_vec(),
            commitment,
            wrong_key,
        );
        let complaint = match avss_receiver.process_message(msg).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint with wrong key"),
        };

        complain_and_assert_no_message(&mut receiver, dealer_addr, complaint, Some(share_index));
    }

    #[test]
    fn test_handle_complain_request_rotation_no_output() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();

        let dealer_idx = 0;
        let (_, _, rotation_messages) = rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        let share_index = match &rotation_messages {
            Messages::Rotation(map) => *map.keys().next().unwrap(),
            _ => unreachable!(),
        };

        let receiver_idx = 2;
        let (mut receiver, receiver_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(receiver_idx);
        receiver.previous_output = Some(receiver_dkg_output.clone());

        // Insert dealer messages but do NOT process them (no dealer_outputs)
        receiver
            .dealer_messages
            .insert(dealer_addr, rotation_messages.clone());

        // Build complaint
        let session_id = receiver
            .session_id
            .rotation_session_id(&dealer_addr, share_index);
        let commitment = receiver_dkg_output.commitments.get(&share_index).copied();
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let Messages::Rotation(map) = &rotation_messages else {
            unreachable!()
        };
        let msg = map.get(&share_index).unwrap();
        let avss_receiver = avss::Receiver::new(
            receiver.dkg_config.nodes.clone(),
            receiver.party_id,
            receiver.dkg_config.threshold,
            session_id.to_vec(),
            commitment,
            wrong_key,
        );
        let complaint = match avss_receiver.process_message(msg).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint with wrong key"),
        };

        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: Some(share_index),
            complaint,
        };
        let result = receiver.handle_complain_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(
            err.to_string().contains("No output for complained share"),
            "Expected 'No output for complained share', got: {}",
            err
        );
    }

    #[test]
    fn test_handle_complain_request_rotation_caches_response() {
        let rotation_setup = RotationTestSetup::new();
        let mut rng = rand::thread_rng();

        // Create victim party who will generate a complaint
        let victim_idx = 2;
        let (victim_manager, victim_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(victim_idx);

        // Create rotation dealer with a cheating message
        let dealer_idx = 0;
        let (_, dealer_dkg_output, valid_rotation_messages) =
            rotation_setup.create_rotation_dealer(dealer_idx);
        let dealer_addr = rotation_setup.setup.address(dealer_idx);

        let valid_rotation_map = match &valid_rotation_messages {
            Messages::Rotation(map) => map.clone(),
            _ => unreachable!(),
        };
        let first_share_index = *valid_rotation_map.keys().next().unwrap();
        let share_value = dealer_dkg_output
            .key_shares
            .shares
            .iter()
            .find(|s| s.index == first_share_index)
            .map(|s| s.value)
            .unwrap();

        let (cheating_share_index, cheating_message) = create_cheating_rotation_message(
            &rotation_setup.setup,
            &victim_manager.session_id,
            &dealer_addr,
            share_value,
            first_share_index,
            victim_idx as u16,
            &mut rng,
        );

        let mut cheating_map = valid_rotation_map.clone();
        cheating_map.insert(cheating_share_index, cheating_message.clone());
        let cheating_messages = Messages::Rotation(cheating_map);

        // Victim builds complaint
        let session_id = victim_manager
            .session_id
            .rotation_session_id(&dealer_addr, first_share_index);
        let commitment = victim_dkg_output
            .commitments
            .get(&first_share_index)
            .copied();
        let receiver = avss::Receiver::new(
            victim_manager.dkg_config.nodes.clone(),
            victim_manager.party_id,
            victim_manager.dkg_config.threshold,
            session_id.to_vec(),
            commitment,
            victim_manager.encryption_key.clone(),
        );
        let complaint = match receiver.process_message(&cheating_message).unwrap() {
            avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint from corrupted share"),
        };

        // Responder processes the cheating messages successfully (their shares are valid)
        let responder_idx = 1;
        let (mut responder, responder_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(responder_idx);
        responder.previous_output = Some(responder_dkg_output.clone());
        responder
            .dealer_messages
            .insert(dealer_addr, cheating_messages.clone());
        responder
            .try_sign_rotation_messages(&responder_dkg_output, dealer_addr, &cheating_messages)
            .unwrap();

        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: Some(first_share_index),
            complaint: complaint.clone(),
        };

        // First call computes and caches
        let response1 = responder.handle_complain_request(&request).unwrap();
        assert_eq!(responder.complaint_responses.len(), 1);

        // Second call returns cached
        let response2 = responder.handle_complain_request(&request).unwrap();
        assert_eq!(
            bcs::to_bytes(&response1).unwrap(),
            bcs::to_bytes(&response2).unwrap(),
            "Second call should return cached response"
        );
        assert_eq!(responder.complaint_responses.len(), 1);
    }

    #[test]
    fn test_handle_send_messages_request_nonce() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        let mut receiver = setup.create_manager(0);
        send_and_assert_ok(&mut receiver, dealer_addr, &nonce_messages);
    }

    #[test]
    fn test_handle_send_messages_request_nonce_idempotent() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        let mut receiver = setup.create_manager(0);
        let response1 = send_and_assert_ok(&mut receiver, dealer_addr, &nonce_messages);

        let request = SendMessagesRequest {
            messages: nonce_messages.clone(),
        };
        let response2 = receiver
            .handle_send_messages_request(dealer_addr, &request)
            .unwrap();
        assert_eq!(response1.signature, response2.signature);
    }

    #[test]
    fn test_handle_send_messages_request_nonce_equivocation() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages1 = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);
        let nonce_messages2 = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        let mut receiver = setup.create_manager(0);
        send_and_assert_ok(&mut receiver, dealer_addr, &nonce_messages1);
        send_and_assert_equivocation(&mut receiver, dealer_addr, &nonce_messages2);
    }

    #[test]
    fn test_handle_retrieve_messages_request_nonce_success() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        let mut receiver = setup.create_manager(0);
        send_and_assert_ok(&mut receiver, dealer_addr, &nonce_messages);
        retrieve_and_verify_hash(&receiver, dealer_addr, &nonce_messages);
    }

    #[test]
    fn test_handle_complain_request_nonce_no_message_from_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        // Create complaint using wrong key
        let complaint = create_nonce_complaint(&setup, &nonce_messages, 0, dealer_idx, &mut rng);

        // Receiver has no message from this dealer
        let mut receiver = setup.create_manager(0);
        complain_and_assert_no_message(&mut receiver, dealer_addr, complaint, None);
    }

    #[test]
    fn test_handle_complain_request_nonce_no_output() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);
        let nonce_messages = create_nonce_dealer_message(&setup, dealer_idx, 0, &mut rng);

        let complaint = create_nonce_complaint(&setup, &nonce_messages, 0, dealer_idx, &mut rng);

        // Insert message manually without processing (no nonce_outputs)
        let mut receiver = setup.create_manager(0);
        receiver
            .dealer_messages
            .insert(dealer_addr, nonce_messages.clone());

        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: None,
            complaint,
        };
        let result = receiver.handle_complain_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, MpcError::ProtocolFailed(_)));
        assert!(
            err.to_string()
                .contains("No nonce output for complained dealer"),
            "Expected nonce output error, got: {}",
            err
        );
    }

    #[test]
    fn test_handle_complain_request_nonce_caches_response() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);

        // Create cheating nonce message (corrupts party 0's shares)
        let cheating_messages = create_cheating_nonce_message(&setup, dealer_idx, 0, &mut rng);

        // Party 0 processes the cheating message → gets complaint
        let Messages::NonceGeneration {
            batch_index,
            ref message,
        } = cheating_messages
        else {
            unreachable!()
        };
        let config = setup.dkg_config();
        let dealer_party_id = setup.committee().index_of(&dealer_addr).unwrap() as u16;
        let dealer_session_id = SessionId::nonce_dealer_session_id(
            TEST_CHAIN_ID,
            setup.epoch(),
            batch_index,
            &dealer_addr,
        );
        let receiver0 = batch_avss::Receiver::new(
            config.nodes.clone(),
            0, // party 0
            dealer_party_id,
            config.threshold,
            dealer_session_id.to_vec(),
            setup.encryption_keys[0].clone(),
            TEST_BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();
        let complaint = match receiver0.process_message(message).unwrap() {
            batch_avss::ProcessedMessage::Complaint(c) => c,
            _ => panic!("Expected complaint from corrupted nonce shares"),
        };

        // Party 2 processes the same cheating message → valid output (their shares are fine)
        let mut party2 = setup.create_manager(2);
        send_and_assert_ok(&mut party2, dealer_addr, &cheating_messages);
        assert!(party2.dealer_nonce_outputs.contains_key(&dealer_addr));

        let request = ComplainRequest {
            dealer: dealer_addr,
            share_index: None,
            complaint: complaint.clone(),
        };

        // First call → computes and caches
        let response1 = party2.handle_complain_request(&request).unwrap();
        assert_eq!(party2.complaint_responses.len(), 1);
        assert!(party2.complaint_responses.contains_key(&dealer_addr));

        // Second call → returns cached
        let response2 = party2.handle_complain_request(&request).unwrap();
        assert_eq!(
            bcs::to_bytes(&response1).unwrap(),
            bcs::to_bytes(&response2).unwrap(),
            "Second call should return cached response"
        );
        assert_eq!(party2.complaint_responses.len(), 1);
    }

    #[tokio::test]
    async fn test_run_nonce_generation() {
        let mut rng = rand::thread_rng();
        let weights: [u16; 5] = [1, 1, 1, 2, 2];
        let num_validators = weights.len();
        let setup = TestSetup::with_weights(&weights);
        let batch_index = 0u32;

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();

        // Phase 1: Create nonce dealer messages for all validators
        let dealer_messages: Vec<Messages> = (0..num_validators)
            .map(|i| create_nonce_dealer_message(&setup, i, batch_index, &mut rng))
            .collect();

        // Phase 2: Collect signatures and create certificates
        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let response = send_and_assert_ok(manager, dealer_addr, messages);
                let sig = MemberSignature::new(
                    manager.dkg_config.epoch,
                    manager.address,
                    response.signature,
                );
                signatures.push(sig);
            }

            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::NonceGeneration { batch_index, cert });
        }

        // Phase 3: Test run_as_nonce_dealer() and run_as_nonce_party() for validator 0
        let mut test_manager = managers.remove(0);
        let max_faulty = test_manager.dkg_config.max_faulty;
        let required_weight = 2 * max_faulty + 1;

        // Create mock P2P channel with remaining managers
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));

        // Pre-populate validator 0's manager with all dealer messages
        for (j, messages) in dealer_messages.iter().enumerate() {
            send_and_assert_ok(&mut test_manager, setup.address(j), messages);
        }

        // Create mock TOB with certificates from dealers 1-4
        // (exclude dealer 0 since run_as_nonce_dealer will create its own)
        let other_certificates: Vec<_> = certificates.iter().skip(1).cloned().collect();
        let mut mock_tob = MockOrderedBroadcastChannel::new(other_certificates);

        let test_manager = Arc::new(RwLock::new(test_manager));

        MpcManager::run_as_nonce_dealer(&test_manager, batch_index, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();
        MpcManager::run_as_nonce_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify validator 0 has nonce outputs from enough dealers
        let mgr = test_manager.read().unwrap();
        let output_count = mgr.dealer_nonce_outputs.len();
        assert!(
            output_count >= required_weight as usize,
            "Should have at least {} nonce outputs, got {}",
            required_weight,
            output_count
        );
        // Verify no complaints remain
        assert!(
            !mgr.complaints_to_process
                .keys()
                .any(|k| matches!(k, ComplaintsToProcessKey::NonceGeneration(_))),
            "Should have no nonce complaints after successful run"
        );
    }

    #[tokio::test]
    async fn test_recover_nonce_shares_via_complaint() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let batch_index = 0u32;

        // Test party: validator 0 (will receive corrupted shares)
        let test_party_idx = 0;
        let mut test_manager = setup.create_manager(test_party_idx);
        let test_addr = setup.address(test_party_idx);

        // Dealer: validator 1
        let dealer_idx = 1;
        let dealer_addr = setup.address(dealer_idx);

        // Create a cheating nonce message (corrupts party 0's shares)
        let cheating_messages =
            create_cheating_nonce_message(&setup, dealer_idx, batch_index, &mut rng);

        // Store the cheating message in test manager
        test_manager.store_nonce_message(dealer_addr, &cheating_messages);

        // Process cheating message → generates complaint
        test_manager
            .process_certified_nonce_message(dealer_addr)
            .unwrap();

        // Verify complaint was generated
        assert!(
            test_manager
                .complaints_to_process
                .contains_key(&ComplaintsToProcessKey::NonceGeneration(dealer_addr)),
            "Should have complaint for cheating dealer"
        );
        assert!(
            !test_manager.dealer_nonce_outputs.contains_key(&dealer_addr),
            "Should not have nonce output before recovery"
        );

        // Create other managers who can respond to complaints
        // Their shares are NOT corrupted so they process successfully
        let mut other_managers_map = HashMap::new();
        for i in 1..5 {
            let mut manager = setup.create_manager(i);
            send_and_assert_ok(&mut manager, dealer_addr, &cheating_messages);
            assert!(manager.dealer_nonce_outputs.contains_key(&dealer_addr));
            other_managers_map.insert(setup.address(i), manager);
        }

        let mock_p2p = MockP2PChannel::new(other_managers_map, test_addr);

        let signers: Vec<Address> = (1..5).map(|i| setup.address(i)).collect();

        let test_manager = Arc::new(RwLock::new(test_manager));

        // Recover shares via complaint
        let result = MpcManager::recover_nonce_shares_via_complaint(
            &test_manager,
            &dealer_addr,
            signers,
            &mock_p2p,
        )
        .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed: {:?}",
            result.err()
        );

        // Verify complaint was removed and output was created
        let mgr = test_manager.read().unwrap();
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::NonceGeneration(dealer_addr)),
            "Complaint should be removed after recovery"
        );
        assert!(
            mgr.dealer_nonce_outputs.contains_key(&dealer_addr),
            "Nonce output should exist after recovery"
        );
    }

    #[tokio::test]
    async fn test_run_nonce_generation_with_complaint_recovery() {
        let mut rng = rand::thread_rng();
        let weights: [u16; 5] = [1, 1, 1, 2, 2];
        let num_validators = weights.len();
        let setup = TestSetup::with_weights(&weights);
        let batch_index = 0u32;
        let test_party_idx = 0;
        let cheating_dealer_idx = 3; // weight=2

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| setup.create_manager(i))
            .collect();

        // Phase 1: Create dealer messages. Dealer 3 creates cheating message targeting party 0.
        let dealer_messages: Vec<Messages> = (0..num_validators)
            .map(|i| {
                if i == cheating_dealer_idx {
                    create_cheating_nonce_message(&setup, i, batch_index, &mut rng)
                } else {
                    create_nonce_dealer_message(&setup, i, batch_index, &mut rng)
                }
            })
            .collect();

        // Phase 2: Collect signatures and create certificates.
        // Validator 0 cannot sign cheating dealer's message (corrupt shares).
        let mut certificates = Vec::new();
        for (dealer_idx, messages) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            let mut signatures = Vec::new();
            for (mgr_idx, manager) in managers.iter_mut().enumerate() {
                if dealer_idx == cheating_dealer_idx && mgr_idx == test_party_idx {
                    // Validator 0 can't sign — just store the message
                    manager.store_nonce_message(dealer_addr, messages);
                    continue;
                }
                let response = send_and_assert_ok(manager, dealer_addr, messages);
                let sig = MemberSignature::new(
                    manager.dkg_config.epoch,
                    manager.address,
                    response.signature,
                );
                signatures.push(sig);
            }

            let cert =
                create_test_certificate(setup.committee(), messages, dealer_addr, signatures)
                    .unwrap();
            certificates.push(CertificateV1::NonceGeneration { batch_index, cert });
        }

        // Phase 3: Run for validator 0
        let test_manager = managers.remove(0);
        let max_faulty = test_manager.dkg_config.max_faulty;
        let required_weight = 2 * max_faulty + 1;

        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(test_party_idx));

        let other_certificates: Vec<_> = certificates.iter().skip(1).cloned().collect();
        let mut mock_tob = MockOrderedBroadcastChannel::new(other_certificates);

        let test_manager = Arc::new(RwLock::new(test_manager));

        MpcManager::run_as_nonce_dealer(&test_manager, batch_index, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();
        MpcManager::run_as_nonce_party(&test_manager, &mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify enough nonce outputs collected
        let mgr = test_manager.read().unwrap();
        assert!(
            mgr.dealer_nonce_outputs.len() >= required_weight as usize,
            "Should have at least {} nonce outputs, got {}",
            required_weight,
            mgr.dealer_nonce_outputs.len()
        );
        // Verify cheating dealer's output was recovered
        let cheating_addr = setup.address(cheating_dealer_idx);
        assert!(
            mgr.dealer_nonce_outputs.contains_key(&cheating_addr),
            "Should have recovered nonce output for cheating dealer"
        );
        assert!(
            !mgr.complaints_to_process
                .contains_key(&ComplaintsToProcessKey::NonceGeneration(cheating_addr)),
            "Nonce complaint should be removed after recovery"
        );
    }
}
