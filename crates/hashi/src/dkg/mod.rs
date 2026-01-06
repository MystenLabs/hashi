//! Distributed Key Generation (DKG) module

pub mod rpc;
pub mod types;

use crate::committee::Bls12381PrivateKey;
use crate::committee::BlsSignatureAggregator;
use crate::committee::Committee;
use crate::communication::ChannelResult;
use crate::communication::OrderedBroadcastChannel;
use crate::communication::P2PChannel;
use crate::communication::with_timeout_and_retry;
use crate::dkg::types::Certificate;
use crate::dkg::types::DkgDealerMessageHash;
use crate::dkg::types::MpcMessageV1::Dkg;
use crate::dkg::types::MpcMessageV1::Rotation;
use crate::dkg::types::RotationDealerMessagesHash;
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
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::IndexedValue;
use fastcrypto_tbls::types::ShareIndex;
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use std::collections::HashMap;
use std::collections::HashSet;
use std::future::Future;
use std::sync::LazyLock;
use sui_sdk_types::Address;
pub use types::ComplainRequest;
pub use types::ComplainResponse;
use types::DkgConfig;
pub use types::DkgError;
pub use types::DkgOutput;
pub use types::DkgResult;
pub use types::EncryptionGroupElement;
pub use types::GetPublicDkgOutputRequest;
pub use types::GetPublicDkgOutputResponse;
pub use types::MessageHash;
pub use types::PublicDkgOutput;
pub use types::RetrieveMessageRequest;
pub use types::RetrieveMessageResponse;
pub use types::RetrieveRotationMessagesRequest;
pub use types::RetrieveRotationMessagesResponse;
pub use types::RotationComplainRequest;
pub use types::RotationComplainResponse;
pub use types::RotationMessages;
pub use types::RotationShareComplaintResponse;
pub use types::SendMessageRequest;
pub use types::SendMessageResponse;
pub use types::SendRotationMessagesRequest;
pub use types::SendRotationMessagesResponse;
pub use types::SessionId;

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";
const EXPECT_THRESHOLD_VALIDATED: &str = "threshold already validated";
const EXPECT_SERIALIZATION_SUCCESS: &str = "serialization should always succeed";

struct RotationComplainContext {
    request: RotationComplainRequest,
    recovery_contexts: HashMap<ShareIndex, (avss::Receiver, avss::Message)>,
}

// DKG protocol
// 1) A dealer sends out a message to all parties containing the encrypted shares and the public keys of the nonces.
// 2) Each party verifies the message and returns a signature. Once sufficient valid signatures are received from the parties, the dealer sends a certificate to Sui (TOB).
// 3) Once sufficient valid certificates are received, a party completes the protocol locally by aggregating the shares from the dealers.
pub struct DkgManager {
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

    // Mutable during the epoch
    pub dealer_outputs: HashMap<Address, avss::PartialOutput>,
    pub dealer_messages: HashMap<Address, avss::Message>,
    pub message_responses: HashMap<Address, SendMessageResponse>,
    pub complaints_to_process: HashMap<Address, complaint::Complaint>,
    pub complaint_responses: HashMap<Address, complaint::ComplaintResponse<avss::SharesForNode>>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
    pub rotation_outputs: HashMap<ShareIndex, avss::PartialOutput>,
    pub rotation_dealer_messages: HashMap<Address, RotationMessages>,
    pub rotation_message_responses: HashMap<Address, SendRotationMessagesResponse>,
    pub rotation_complaints_to_process: HashMap<(Address, ShareIndex), complaint::Complaint>,
    pub rotation_complaint_responses: HashMap<Address, Vec<RotationShareComplaintResponse>>,
    previous_dkg_output: Option<DkgOutput>,
}

// TODO: Factor out common code between DKG and key rotation.
impl DkgManager {
    pub fn new(
        address: Address,
        committee_set: &CommitteeSet,
        session_id: SessionId,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        signing_key: Bls12381PrivateKey,
        public_message_store: Box<dyn PublicMessagesStore>,
    ) -> DkgResult<Self> {
        let committee = committee_set
            .current_committee()
            .ok_or_else(|| DkgError::InvalidConfig("no committee for current epoch".into()))?
            .clone();
        let mut nodes_vec = Vec::with_capacity(committee.members().len());
        for (index, member) in committee.members().iter().enumerate() {
            let party_id = index as u16;
            debug_assert_eq!(party_id as usize, nodes_vec.len());
            nodes_vec.push(Node {
                id: party_id,
                pk: member.encryption_public_key().to_owned(),
                weight: member.weight() as u16,
            });
        }
        // TODO: Use `Nodes::new_reduce()`
        let nodes = Nodes::new(nodes_vec).map_err(|e| DkgError::CryptoError(e.to_string()))?;
        // TODO: Pass t and f as arguments instead of computing them
        let total_weight = nodes.total_weight();
        let max_faulty = (total_weight - 1) / 3;
        let threshold = max_faulty + 1;
        let dkg_config = DkgConfig::new(committee_set.epoch(), nodes, threshold, max_faulty)?;
        let party_id = committee
            .index_of(&address)
            .expect("address not in committee") as u16;
        let previous_committee = committee_set.previous_committee().cloned();
        let previous_nodes = previous_committee.as_ref().and_then(|prev_committee| {
            let mut prev_nodes_vec = Vec::with_capacity(prev_committee.members().len());
            for (index, member) in prev_committee.members().iter().enumerate() {
                prev_nodes_vec.push(Node {
                    id: index as u16,
                    pk: member.encryption_public_key().to_owned(),
                    weight: member.weight() as u16,
                });
            }
            Nodes::new(prev_nodes_vec).ok()
        });
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
            dealer_outputs: HashMap::new(),
            dealer_messages: HashMap::new(),
            message_responses: HashMap::new(),
            complaints_to_process: HashMap::new(),
            complaint_responses: HashMap::new(),
            public_messages_store: public_message_store,
            rotation_outputs: HashMap::new(),
            rotation_dealer_messages: HashMap::new(),
            rotation_message_responses: HashMap::new(),
            rotation_complaints_to_process: HashMap::new(),
            rotation_complaint_responses: HashMap::new(),
            previous_dkg_output: None,
        };
        manager.load_stored_messages()?;
        Ok(manager)
    }

    /// RPC endpoint handler for `SendMessageRequest`
    pub fn handle_send_message_request(
        &mut self,
        sender: Address,
        request: &SendMessageRequest,
    ) -> DkgResult<SendMessageResponse> {
        if let Some(existing_message) = self.dealer_messages.get(&sender) {
            let existing_hash = compute_message_hash(existing_message);
            let incoming_hash = compute_message_hash(&request.message);
            if existing_hash != incoming_hash {
                return Err(DkgError::InvalidMessage {
                    sender,
                    reason: "Dealer sent different messages".to_string(),
                });
            }
            if let Some(response) = self.message_responses.get(&sender) {
                return Ok(response.clone());
            }
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Message previously rejected due to invalid shares".to_string(),
            });
        }
        self.store_message(sender, &request.message)?;
        let signature = self.try_sign_message(sender, &request.message)?;
        let response = SendMessageResponse { signature };
        self.message_responses.insert(sender, response.clone());
        Ok(response)
    }

    /// RPC endpoint handler for `RetrieveMessageRequest`
    pub fn handle_retrieve_message_request(
        &self,
        request: &RetrieveMessageRequest,
    ) -> DkgResult<RetrieveMessageResponse> {
        let message = self
            .dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("Message not available".to_string()))?
            .clone();
        Ok(RetrieveMessageResponse { message })
    }

    /// RPC endpoint handler for `SendRotationMessagesRequest`
    pub fn handle_send_rotation_messages_request(
        &mut self,
        sender: Address,
        request: &SendRotationMessagesRequest,
    ) -> DkgResult<SendRotationMessagesResponse> {
        if let Some(existing_messages) = self.rotation_dealer_messages.get(&sender) {
            let existing_hash = compute_rotation_messages_hash(existing_messages);
            let incoming_hash = compute_rotation_messages_hash(&request.messages);
            if existing_hash != incoming_hash {
                return Err(DkgError::InvalidMessage {
                    sender,
                    reason: "Dealer sent different rotation messages".to_string(),
                });
            }
            if let Some(response) = self.rotation_message_responses.get(&sender) {
                return Ok(response.clone());
            }
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Rotation messages previously rejected due to invalid shares".to_string(),
            });
        }
        let previous = self
            .previous_dkg_output
            .clone()
            .ok_or_else(|| DkgError::ProtocolFailed("Rotation not started".to_string()))?;
        self.rotation_dealer_messages
            .insert(sender, request.messages.clone());
        let signature = self.try_sign_rotation_messages(&previous, sender, &request.messages)?;
        let response = SendRotationMessagesResponse { signature };
        self.rotation_message_responses
            .insert(sender, response.clone());
        Ok(response)
    }

    /// RPC endpoint handler for `RetrieveRotationMessagesRequest`
    pub fn handle_retrieve_rotation_messages_request(
        &self,
        request: &RetrieveRotationMessagesRequest,
    ) -> DkgResult<RetrieveRotationMessagesResponse> {
        let messages = self
            .rotation_dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| {
                DkgError::NotFound(format!("Rotation messages for dealer {:?}", request.dealer))
            })?;
        Ok(RetrieveRotationMessagesResponse {
            messages: messages.clone(),
        })
    }

    /// RPC endpoint handler for `ComplainRequest`
    pub fn handle_complain_request(
        &mut self,
        request: &ComplainRequest,
    ) -> DkgResult<ComplainResponse> {
        let cache_key = request.dealer;
        // It is safe to return a response from cache since we already know that dealer was malicious.
        if let Some(cached_response) = self.complaint_responses.get(&cache_key) {
            return Ok(ComplainResponse {
                response: cached_response.clone(),
            });
        }
        let message = self
            .dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No message from dealer".into()))?;
        let partial_output = self
            .dealer_outputs
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No shares for dealer".into()))?;
        let dealer_session_id = self.session_id.dealer_session_id(&request.dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None,
            self.encryption_key.clone(),
        );
        let response = receiver.handle_complaint(message, &request.complaint, partial_output)?;
        self.complaint_responses.insert(cache_key, response.clone());
        Ok(ComplainResponse { response })
    }

    /// RPC endpoint handler for `GetPublicDkgOutputRequest`
    pub fn handle_get_public_dkg_output_request(
        &self,
        request: &GetPublicDkgOutputRequest,
    ) -> DkgResult<GetPublicDkgOutputResponse> {
        let previous_epoch = self
            .dkg_config
            .epoch
            .checked_sub(1)
            .ok_or_else(|| DkgError::InvalidConfig("no previous epoch exists".to_string()))?;
        if request.epoch != previous_epoch {
            return Err(DkgError::NotFound(format!(
                "no DKG output for epoch {} (current epoch is {})",
                request.epoch, self.dkg_config.epoch
            )));
        }
        let output = self.previous_dkg_output.as_ref().ok_or_else(|| {
            DkgError::NotFound(format!(
                "DKG output for epoch {} not yet available",
                request.epoch
            ))
        })?;
        Ok(GetPublicDkgOutputResponse {
            output: PublicDkgOutput::from_dkg_output(output),
        })
    }

    /// RPC endpoint handler for `RotationComplainRequest`
    pub fn handle_rotation_complain_request(
        &mut self,
        request: &RotationComplainRequest,
    ) -> DkgResult<RotationComplainResponse> {
        // It is safe to return a response from cache since we already know that dealer was malicious.
        if let Some(cached_responses) = self.rotation_complaint_responses.get(&request.dealer) {
            return Ok(RotationComplainResponse {
                responses: cached_responses.clone(),
            });
        }
        let rotation_messages = self
            .rotation_dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No rotation messages from dealer".into()))?
            .clone();
        let previous_dkg_output = self
            .previous_dkg_output
            .as_ref()
            .expect("previous_dkg_output must be set during key rotation");
        let complained_message = rotation_messages.get(request.share_index).ok_or_else(|| {
            DkgError::ProtocolFailed(format!(
                "No rotation message for share index {}",
                request.share_index
            ))
        })?;
        let complained_output =
            self.rotation_outputs
                .get(&request.share_index)
                .ok_or_else(|| {
                    DkgError::ProtocolFailed(format!(
                        "No output for share index {}",
                        request.share_index
                    ))
                })?;
        let commitment = previous_dkg_output
            .commitments
            .get(&request.share_index)
            .copied();
        let session_id = self
            .session_id
            .rotation_session_id(&request.dealer, request.share_index);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            session_id.to_vec(),
            commitment,
            self.encryption_key.clone(),
        );
        let complained_response =
            receiver.handle_complaint(complained_message, &request.complaint, complained_output)?;
        let mut responses = Vec::with_capacity(rotation_messages.len());
        for (&share_index, _) in rotation_messages.iter() {
            let response = if share_index == request.share_index {
                complained_response.clone()
            } else if let Some(output) = self.rotation_outputs.get(&share_index) {
                complaint::ComplaintResponse::new(self.party_id, output.my_shares.clone())
            } else {
                continue;
            };
            responses.push(RotationShareComplaintResponse {
                share_index,
                response,
            });
        }
        self.rotation_complaint_responses
            .insert(request.dealer, responses.clone());
        Ok(RotationComplainResponse { responses })
    }

    // TODO: Consider making dealer and party flows concurrent
    pub async fn run(
        &mut self,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<DkgOutput> {
        if ordered_broadcast_channel.existing_certificate_weight()
            < self.dkg_config.threshold as u32
            && let Err(e) = self
                .run_as_dealer(p2p_channel, ordered_broadcast_channel, rng)
                .await
        {
            tracing::error!("Dealer phase failed: {}. Continuing as party only.", e);
        }
        self.run_as_party(p2p_channel, ordered_broadcast_channel)
            .await
    }

    pub async fn run_key_rotation(
        &mut self,
        dkg_certificates: &[Certificate],
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<DkgOutput> {
        let (previous, is_member_of_previous_committee) = self
            .prepare_previous_dkg_output(dkg_certificates, p2p_channel)
            .await?;
        self.previous_dkg_output = Some(previous.clone());
        if is_member_of_previous_committee {
            // TODO(Optimization): Skip dealer phase if enough rotation certificates already exist.
            if let Err(e) = self
                .run_key_rotation_as_dealer(&previous, p2p_channel, ordered_broadcast_channel, rng)
                .await
            {
                tracing::error!(
                    "Rotation dealer phase failed: {}. Continuing as party only.",
                    e
                );
            }
        }
        self.run_key_rotation_as_party(&previous, p2p_channel, ordered_broadcast_channel)
            .await
    }

    async fn run_as_dealer(
        &mut self,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<()> {
        // TODO(Optimization): Skip dealer phase if certificate is already on TOB
        let message = match self.dealer_messages.get(&self.address) {
            Some(msg) => msg.clone(),
            None => {
                let msg = self.create_dealer_message(rng);
                self.store_message(self.address, &msg)?;
                msg
            }
        };
        let my_signature = self
            .try_sign_message(self.address, &message)
            .expect("own message should always be valid");
        let message_hash = compute_message_hash(&message);
        let mut aggregator = BlsSignatureAggregator::new(
            &self.committee,
            Dkg(DkgDealerMessageHash {
                dealer_address: self.address,
                message_hash,
            }),
        );
        aggregator
            .add_signature_from(self.address, my_signature)
            .expect("first signature should always be valid");
        let recipients: Vec<_> = self
            .committee
            .members()
            .iter()
            .map(|m| m.validator_address())
            .filter(|addr| *addr != self.address)
            .collect();
        let request = SendMessageRequest { message };
        let results = send_to_many(&recipients, request, |addr, req| async move {
            p2p_channel.send_dkg_message(&addr, &req).await
        })
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
        let required_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        if aggregator.weight() >= required_weight as u64 {
            let cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            // TODO: do not fail in case my certificate is already published
            with_timeout_and_retry(|| ordered_broadcast_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    DkgError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    async fn run_as_party(
        &mut self,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
    ) -> DkgResult<DkgOutput> {
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= self.dkg_config.threshold as u32 {
                break;
            }
            let cert = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| DkgError::BroadcastError(e.to_string()))?;
            match cert.message {
                Dkg(ref message) => {
                    let dealer = message.dealer_address;
                    if certified_dealers.contains(&dealer) {
                        continue;
                    }
                    if let Err(e) = self.committee.verify_signature(&cert) {
                        tracing::info!("Invalid certificate signature from {:?}: {}", &dealer, e);
                        continue;
                    }
                    let needs_retrieval = match self.dealer_messages.get(&dealer) {
                        None => true,
                        Some(stored_msg) => {
                            compute_message_hash(stored_msg) != message.message_hash
                        }
                    };
                    if needs_retrieval {
                        tracing::info!(
                            "Certificate from dealer {:?} received but message missing or hash mismatch, retrieving from signers",
                            &dealer
                        );
                        self.retrieve_dealer_message(message, &cert, p2p_channel)
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
                    if !self.dealer_outputs.contains_key(&dealer)
                        && !self.complaints_to_process.contains_key(&dealer)
                    {
                        self.process_certified_dealer_message(dealer)?;
                    }
                    if self.complaints_to_process.contains_key(&dealer) {
                        self.recover_shares_via_complaint(
                            &dealer,
                            cert.signers(&self.committee)
                                .expect("certificate verified above"),
                            p2p_channel,
                        )
                        .await?;
                    }
                    let dealer_weight = self.committee.weight_of(&dealer).map_err(|_| {
                        DkgError::ProtocolFailed("Missing dealer weight".parse().unwrap())
                    })?;
                    dealer_weight_sum += dealer_weight as u32;
                    certified_dealers.insert(dealer);
                }
                Rotation(_) => continue,
            }
        }
        self.complete_dkg(certified_dealers.into_iter())
    }

    async fn run_key_rotation_as_dealer(
        &mut self,
        previous: &DkgOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<()> {
        let rotation_messages = self.create_rotation_messages(previous, rng);
        self.rotation_dealer_messages
            .insert(self.address, rotation_messages.clone());
        let my_signature = self
            .try_sign_rotation_messages(previous, self.address, &rotation_messages)
            .expect("own rotation messages should always be valid");
        let messages_hash = compute_rotation_messages_hash(&rotation_messages);
        let mut aggregator = BlsSignatureAggregator::new(
            &self.committee,
            Rotation(RotationDealerMessagesHash {
                dealer_address: self.address,
                messages_hash,
            }),
        );
        aggregator
            .add_signature_from(self.address, my_signature)
            .expect("first signature should always be valid");
        let recipients: Vec<_> = self
            .committee
            .members()
            .iter()
            .map(|m| m.validator_address())
            .filter(|addr| *addr != self.address)
            .collect();
        let request = SendRotationMessagesRequest {
            messages: rotation_messages.clone(),
        };
        let results = send_to_many(&recipients, request, |addr, req| async move {
            p2p_channel.send_rotation_messages(&addr, &req).await
        })
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
        let required_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        if aggregator.weight() >= required_weight as u64 {
            let cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            with_timeout_and_retry(|| ordered_broadcast_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    DkgError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    async fn run_key_rotation_as_party(
        &mut self,
        previous: &DkgOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<Certificate>,
    ) -> DkgResult<DkgOutput> {
        let mut certified_share_indices: Vec<_> = self.rotation_outputs.keys().copied().collect();
        let mut certified_dealers = HashSet::new();
        loop {
            if certified_share_indices.len() >= previous.threshold as usize {
                break;
            }
            let cert = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| DkgError::BroadcastError(e.to_string()))?;
            match &cert.message {
                Rotation(message) => {
                    let dealer = message.dealer_address;
                    if certified_dealers.contains(&dealer) {
                        continue;
                    }
                    if let Err(e) = self.committee.verify_signature(&cert) {
                        tracing::info!(
                            "Invalid rotation certificate signature from {:?}: {}",
                            &dealer,
                            e
                        );
                        continue;
                    }
                    let previous_nodes = self.previous_nodes.as_ref().ok_or_else(|| {
                        DkgError::InvalidConfig("Key rotation requires previous nodes".into())
                    })?;
                    let previous_committee = self.previous_committee.as_ref().ok_or_else(|| {
                        DkgError::InvalidConfig("Key rotation requires previous committee".into())
                    })?;
                    let dealer_party_id = previous_committee.index_of(&dealer).ok_or_else(|| {
                        DkgError::InvalidMessage {
                            sender: dealer,
                            reason: "Dealer not in previous committee".into(),
                        }
                    })? as u16;
                    let dealer_share_indices = previous_nodes
                        .share_ids_of(dealer_party_id)
                        .map_err(|_| DkgError::InvalidMessage {
                            sender: dealer,
                            reason: "Dealer has no shares in previous committee".into(),
                        })?;
                    let needs_retrieval = match self.rotation_dealer_messages.get(&dealer) {
                        None => true,
                        Some(stored_msgs) => {
                            compute_rotation_messages_hash(stored_msgs) != message.messages_hash
                        }
                    };
                    if needs_retrieval {
                        tracing::info!(
                            "Rotation messages from dealer {:?} not available or hash mismatch, retrieving from signers",
                            dealer
                        );
                        self.retrieve_rotation_messages(message, &cert, p2p_channel)
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
                    if dealer_share_indices.iter().any(|idx| {
                        !self.rotation_outputs.contains_key(idx)
                            && !self
                                .rotation_complaints_to_process
                                .contains_key(&(dealer, *idx))
                    }) {
                        self.process_certified_rotation_message(&dealer, previous)?;
                    }
                    let signers = cert
                        .signers(&self.committee)
                        .expect("certificate verified above");
                    self.recover_rotation_shares_via_complaints(
                        &dealer,
                        previous,
                        signers,
                        p2p_channel,
                    )
                    .await?;
                    certified_share_indices.extend(dealer_share_indices);
                    certified_dealers.insert(dealer);
                }
                Dkg(_) => continue,
            }
        }
        self.complete_key_rotation(previous, &certified_share_indices)
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
        dealer.create_message(rng).expect("checked threshold above")
    }

    fn store_message(&mut self, dealer: Address, message: &avss::Message) -> DkgResult<()> {
        self.dealer_messages.insert(dealer, message.clone());
        self.public_messages_store
            .store_dealer_message(&dealer, message)
            .map_err(|e| DkgError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn try_sign_message(
        &mut self,
        dealer: Address,
        message: &avss::Message,
    ) -> DkgResult<BLS12381Signature> {
        let dealer_session_id = self.session_id.dealer_session_id(&dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None, // commitment: None for initial DKG
            self.encryption_key.clone(),
        );
        match receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => {
                self.dealer_outputs.insert(dealer, output);
                let message_hash = compute_message_hash(message);
                let signature = self.signing_key.sign(
                    self.dkg_config.epoch,
                    self.address,
                    &Dkg(DkgDealerMessageHash {
                        dealer_address: dealer,
                        message_hash,
                    }),
                );
                Ok(signature.signature().clone())
            }
            avss::ProcessedMessage::Complaint(_) => Err(DkgError::InvalidMessage {
                sender: dealer,
                reason: "Invalid shares".to_string(),
            }),
        }
    }

    fn process_certified_dealer_message(&mut self, dealer: Address) -> DkgResult<()> {
        let message = self
            .dealer_messages
            .get(&dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No message for dealer".into()))?;
        let dealer_session_id = self.session_id.dealer_session_id(&dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None,
            self.encryption_key.clone(),
        );
        match receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => {
                self.dealer_outputs.insert(dealer, output);
            }
            avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints_to_process.insert(dealer, complaint);
            }
        }
        Ok(())
    }

    fn process_certified_rotation_message(
        &mut self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
    ) -> DkgResult<()> {
        let rotation_messages = self
            .rotation_dealer_messages
            .get(dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No rotation messages for dealer".into()))?
            .clone();
        for (&share_index, message) in rotation_messages.iter() {
            if self.rotation_outputs.contains_key(&share_index)
                || self
                    .rotation_complaints_to_process
                    .contains_key(&(*dealer, share_index))
            {
                continue;
            }
            let session_id = self.session_id.rotation_session_id(dealer, share_index);
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
                    self.rotation_outputs.insert(share_index, output);
                }
                avss::ProcessedMessage::Complaint(complaint) => {
                    self.rotation_complaints_to_process
                        .insert((*dealer, share_index), complaint);
                }
            }
        }
        Ok(())
    }

    fn complete_dkg(
        &self,
        certified_dealers: impl Iterator<Item = Address>,
    ) -> DkgResult<DkgOutput> {
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
                    .get(&dealer)
                    .ok_or_else(|| {
                        DkgError::ProtocolFailed(format!(
                            "No dealer output found for dealer: {:?}.",
                            dealer
                        ))
                    })?
                    .clone();
                Ok((dealer_party_id, output))
            })
            .collect::<Result<_, DkgError>>()?;
        let combined_output =
            avss::ReceiverOutput::complete_dkg(threshold, &self.dkg_config.nodes, outputs)
                .expect("checked that threshold is met");
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
        &mut self,
        message: &DkgDealerMessageHash,
        certificate: &Certificate,
        p2p_channel: &impl P2PChannel,
    ) -> DkgResult<()> {
        let request = RetrieveMessageRequest {
            dealer: message.dealer_address,
        };
        // TODO: Implement gradual escalation strategy for better network efficiency:
        // - Round 1: Call 1-2 random signers, wait ~2s
        // - Round 2: Call 2-3 more signers, wait ~2s
        // - and so on
        if certificate
            .is_signer(&self.address, &self.committee)
            .map_err(|e| DkgError::CryptoError(e.to_string()))?
        {
            tracing::error!(
                "Self in certificate signers but message not available for dealer {:?}.",
                message.dealer_address
            );
            return Err(DkgError::ProtocolFailed(
                "Self in certificate signers but message not available".to_string(),
            ));
        }
        let signers = certificate.signers(&self.committee).map_err(|_| {
            DkgError::ProtocolFailed(
                "Certificate does not match the current epoch or committee".to_string(),
            )
        })?;
        let result = fetch_first_valid(
            signers,
            request,
            |signer_address, request| async move {
                p2p_channel
                    .retrieve_message(&signer_address, &request)
                    .await
            },
            |r| r.message,
            compute_message_hash,
            message.message_hash,
            "message",
        )
        .await;
        match result {
            Some((_, msg)) => {
                self.store_message(message.dealer_address, &msg)?;
                Ok(())
            }
            None => Err(DkgError::PairwiseCommunicationError(
                "Failed to retrieve message from any signer".to_string(),
            )),
        }
    }

    async fn retrieve_rotation_messages(
        &mut self,
        message: &RotationDealerMessagesHash,
        certificate: &Certificate,
        p2p_channel: &impl P2PChannel,
    ) -> DkgResult<()> {
        let request = RetrieveRotationMessagesRequest {
            dealer: message.dealer_address,
        };
        if certificate
            .is_signer(&self.address, &self.committee)
            .map_err(|e| DkgError::CryptoError(e.to_string()))?
        {
            tracing::error!(
                "Self in certificate signers but rotation messages not available for dealer {:?}.",
                message.dealer_address
            );
            return Err(DkgError::ProtocolFailed(
                "Self in certificate signers but rotation messages not available".to_string(),
            ));
        }
        let signers = certificate.signers(&self.committee).map_err(|_| {
            DkgError::ProtocolFailed(
                "Certificate does not match the current epoch or committee".to_string(),
            )
        })?;
        let result = fetch_first_valid(
            signers,
            request,
            |signer_address, request| async move {
                p2p_channel
                    .retrieve_rotation_messages(&signer_address, &request)
                    .await
            },
            |r| r.messages,
            compute_rotation_messages_hash,
            message.messages_hash,
            "rotation messages",
        )
        .await;
        match result {
            Some((_, messages)) => {
                self.rotation_dealer_messages
                    .insert(message.dealer_address, messages);
                Ok(())
            }
            None => Err(DkgError::PairwiseCommunicationError(
                "Failed to retrieve rotation messages from any signer".to_string(),
            )),
        }
    }

    async fn recover_shares_via_complaint(
        &mut self,
        dealer: &Address,
        signers: impl IntoIterator<Item = Address>,
        p2p_channel: &impl P2PChannel,
    ) -> DkgResult<()> {
        let complaint = self
            .complaints_to_process
            .get(dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No complaint for dealer".into()))?
            .clone();
        let complaint_request = ComplainRequest {
            dealer: *dealer,
            complaint: complaint.clone(),
        };
        let dealer_session_id = self.session_id.dealer_session_id(dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None,
            self.encryption_key.clone(),
        );
        let message = self
            .dealer_messages
            .get(dealer)
            .expect("cannot have complaint without message");
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
            responses.push(response.response);
            match receiver.recover(message, responses.clone()) {
                Ok(partial_output) => {
                    self.dealer_outputs.insert(*dealer, partial_output);
                    self.complaints_to_process.remove(dealer);
                    return Ok(());
                }
                Err(FastCryptoError::InputTooShort(_)) => {
                    continue;
                }
                Err(e) => {
                    let error_msg = format!("Share recovery failed for dealer {:?}: {}", dealer, e);
                    tracing::error!("{}", error_msg);
                    return Err(DkgError::CryptoError(error_msg));
                }
            }
        }
        Err(DkgError::ProtocolFailed(format!(
            "Not enough valid complaint responses for dealer {:?}",
            dealer
        )))
    }

    async fn recover_rotation_shares_via_complaints(
        &mut self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
    ) -> DkgResult<()> {
        let Some(RotationComplainContext {
            request,
            recovery_contexts,
        }) = self.prepare_rotation_complain_request(dealer, previous_dkg_output)?
        else {
            return Ok(());
        };
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
            match p2p_channel.rotation_complain(signer, &request).await {
                Ok(response) => {
                    for share_response in response.responses {
                        if let Some(responses) = all_responses.get_mut(&share_response.share_index)
                        {
                            responses.push(share_response.response);
                        }
                    }
                    for share_index in pending_shares.clone() {
                        let responses = all_responses.get(&share_index).unwrap();
                        let (receiver, message) = recovery_contexts.get(&share_index).unwrap();
                        match receiver.recover(message, responses.clone()) {
                            Ok(partial_output) => {
                                self.rotation_outputs.insert(share_index, partial_output);
                                self.rotation_complaints_to_process
                                    .remove(&(*dealer, share_index));
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
                                return Err(DkgError::CryptoError(error_msg));
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

    fn load_stored_messages(&mut self) -> DkgResult<()> {
        let stored = self
            .public_messages_store
            .list_all_dealer_messages()
            .map_err(|e| DkgError::StorageError(e.to_string()))?;
        for (dealer, message) in stored {
            self.dealer_messages.insert(dealer, message);
        }
        Ok(())
    }

    fn prepare_rotation_complain_request(
        &self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
    ) -> DkgResult<Option<RotationComplainContext>> {
        let rotation_messages = self
            .rotation_dealer_messages
            .get(dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No rotation messages for dealer".into()))?;
        let complained_shares: Vec<_> = self
            .rotation_complaints_to_process
            .iter()
            .filter(|((d, _), _)| d == dealer)
            .map(|((_, share_index), complaint)| (*share_index, complaint.clone()))
            .collect();
        if complained_shares.is_empty() {
            return Ok(None);
        }
        let (first_share_index, first_complaint) = complained_shares.first().unwrap().clone();
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
                .get(*share_index)
                .ok_or_else(|| {
                    DkgError::ProtocolFailed(format!(
                        "No rotation message for share index {}",
                        share_index
                    ))
                })?
                .clone();
            recovery_contexts.insert(*share_index, (receiver, message));
        }

        let request = RotationComplainRequest {
            dealer: *dealer,
            share_index: first_share_index,
            complaint: first_complaint,
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
        let messages = previous_dkg_output
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
                let message = dealer
                    .create_message(rng)
                    .expect(EXPECT_THRESHOLD_VALIDATED);
                (share.index, message)
            })
            .collect();
        RotationMessages::new(messages)
    }

    fn try_sign_rotation_messages(
        &mut self,
        previous_dkg_output: &DkgOutput,
        dealer: Address,
        rotation_messages: &RotationMessages,
    ) -> DkgResult<BLS12381Signature> {
        let previous_committee = self.previous_committee.as_ref().ok_or_else(|| {
            DkgError::InvalidConfig("Key rotation requires previous committee".into())
        })?;
        let previous_nodes = self.previous_nodes.as_ref().ok_or_else(|| {
            DkgError::InvalidConfig("Key rotation requires previous nodes".into())
        })?;
        let dealer_party_id =
            previous_committee
                .index_of(&dealer)
                .ok_or_else(|| DkgError::InvalidMessage {
                    sender: dealer,
                    reason: "Dealer not in previous committee".into(),
                })? as u16;
        let dealer_share_indices: HashSet<_> = previous_nodes
            .share_ids_of(dealer_party_id)
            .map_err(|_| DkgError::InvalidMessage {
                sender: dealer,
                reason: "Dealer has no shares in previous committee".into(),
            })?
            .into_iter()
            .collect();
        let mut outputs = Vec::with_capacity(rotation_messages.len());
        for (&share_index, message) in rotation_messages.iter() {
            if !dealer_share_indices.contains(&share_index) {
                return Err(DkgError::InvalidMessage {
                    sender: dealer,
                    reason: format!("Share index {} does not belong to dealer", share_index),
                });
            }
            if self.rotation_outputs.contains_key(&share_index) {
                return Err(DkgError::InvalidMessage {
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
                    outputs.push((share_index, output));
                }
                avss::ProcessedMessage::Complaint(_) => {
                    return Err(DkgError::InvalidMessage {
                        sender: dealer,
                        reason: format!("Invalid rotation share for index {}", share_index),
                    });
                }
            }
        }
        self.rotation_outputs.extend(outputs);
        let messages_hash = compute_rotation_messages_hash(rotation_messages);
        let signature = self.signing_key.sign(
            self.dkg_config.epoch,
            self.address,
            &Rotation(RotationDealerMessagesHash {
                dealer_address: dealer,
                messages_hash,
            }),
        );
        Ok(signature.signature().clone())
    }

    fn complete_key_rotation(
        &mut self,
        previous_dkg_output: &DkgOutput,
        certified_share_indices: &[ShareIndex],
    ) -> DkgResult<DkgOutput> {
        let threshold = previous_dkg_output.threshold;
        let indexed_outputs: Vec<IndexedValue<avss::PartialOutput>> = certified_share_indices
            .iter()
            .take(threshold as usize)
            .map(|&share_index| {
                let output = self.rotation_outputs.get(&share_index).ok_or_else(|| {
                    DkgError::ProtocolFailed(format!(
                        "No rotation output found for share index: {}",
                        share_index
                    ))
                })?;
                Ok(IndexedValue {
                    index: share_index,
                    value: output.clone(),
                })
            })
            .collect::<Result<_, DkgError>>()?;
        let combined = avss::ReceiverOutput::complete_key_rotation(
            threshold,
            self.party_id,
            &self.dkg_config.nodes,
            &indexed_outputs,
        )?;
        if combined.vk != previous_dkg_output.public_key {
            return Err(DkgError::ProtocolFailed(
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

    // TODO: Handle new committee members who weren't in the previous committee.
    fn reconstruct_previous_dkg_output(
        &mut self,
        certificates: &[Certificate],
    ) -> DkgResult<DkgOutput> {
        let mut certified_dealers = HashMap::new();
        for cert in certificates {
            let (dealer_address, expected_hash) = match &cert.message {
                Dkg(msg) => (msg.dealer_address, msg.message_hash),
                Rotation(_) => {
                    return Err(DkgError::InvalidCertificate(
                        "Expected DKG certificate, got Rotation".into(),
                    ));
                }
            };
            let message = self
                .public_messages_store
                .get_dealer_message(&dealer_address)
                .map_err(|e| DkgError::StorageError(e.to_string()))?
                .ok_or_else(|| {
                    DkgError::StorageError(format!(
                        "Message not found for dealer: {:?}",
                        dealer_address
                    ))
                })?;
            let actual_hash = compute_message_hash(&message);
            if actual_hash != expected_hash {
                return Err(DkgError::ProtocolFailed(format!(
                    "Message hash mismatch for dealer {:?}: stored message does not match certificate",
                    dealer_address
                )));
            }
            self.dealer_messages.insert(dealer_address, message);
            self.process_certified_dealer_message(dealer_address)?;
            certified_dealers.insert(dealer_address, cert.clone());
        }
        self.complete_dkg(certified_dealers.into_keys())
    }

    pub async fn fetch_public_dkg_output_from_quorum(
        &self,
        p2p_channel: &impl P2PChannel,
        previous_committee_threshold: u64,
    ) -> DkgResult<PublicDkgOutput> {
        let previous_committee = self
            .previous_committee
            .as_ref()
            .expect("key rotation requires previous committee");
        let epoch = self
            .dkg_config
            .epoch
            .checked_sub(1)
            .expect("key rotation requires epoch > 0");
        let request = types::GetPublicDkgOutputRequest { epoch };
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
        Err(DkgError::NotEnoughApprovals {
            needed: (previous_committee_threshold + 1) as usize,
            got: max_weight as usize,
        })
    }

    async fn prepare_previous_dkg_output(
        &mut self,
        dkg_certificates: &[Certificate],
        p2p_channel: &impl P2PChannel,
    ) -> DkgResult<(DkgOutput, bool)> {
        let is_member_of_previous_committee = self
            .previous_committee
            .as_ref()
            .and_then(|c| c.index_of(&self.address))
            .is_some();
        let previous = if is_member_of_previous_committee {
            self.reconstruct_previous_dkg_output(dkg_certificates)?
        } else {
            tracing::debug!("New committee member: fetching public DKG output from quorum");
            let previous_nodes = self.previous_nodes.as_ref().ok_or_else(|| {
                DkgError::InvalidConfig("Key rotation requires previous nodes".into())
            })?;
            let threshold = compute_bft_threshold(previous_nodes.total_weight());
            let public_output = self
                .fetch_public_dkg_output_from_quorum(p2p_channel, threshold as u64)
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

fn compute_message_hash(message: &avss::Message) -> MessageHash {
    let message_bytes = bcs::to_bytes(message).expect(EXPECT_SERIALIZATION_SUCCESS);
    let mut hasher = Blake2b256::default();
    hasher.update(&message_bytes);
    hasher.finalize().into()
}

fn compute_bft_threshold(total_weight: u16) -> u16 {
    (total_weight - 1) / 3 + 1
}

fn compute_rotation_messages_hash(bundle: &RotationMessages) -> MessageHash {
    let bytes = bcs::to_bytes(bundle).expect(EXPECT_SERIALIZATION_SUCCESS);
    Blake2b256::digest(&bytes).into()
}

fn hash_public_dkg_output(output: &PublicDkgOutput) -> [u8; 32] {
    let bytes = bcs::to_bytes(output).expect(EXPECT_SERIALIZATION_SUCCESS);
    Blake2b256::digest(&bytes).into()
}

async fn send_to_many<Req, Resp, F, Fut>(
    recipients: &[Address],
    request: Req,
    send: F,
) -> Vec<(Address, ChannelResult<Resp>)>
where
    Req: Clone + Send + Sync,
    Resp: Send,
    F: Fn(Address, Req) -> Fut + Clone + Send + Sync,
    Fut: Future<Output = ChannelResult<Resp>> + Send,
{
    join_all(recipients.iter().map(|&addr| {
        let req = request.clone();
        let send = send.clone();
        async move {
            let result = with_timeout_and_retry(|| send(addr, req.clone())).await;
            (addr, result)
        }
    }))
    .await
}

fn validate_retrieved<T>(
    result: ChannelResult<T>,
    signer_address: Address,
    compute_hash: impl FnOnce(&T) -> MessageHash,
    expected_hash: MessageHash,
    context: &str,
) -> Option<T> {
    match result {
        Ok(data) => {
            if compute_hash(&data) == expected_hash {
                Some(data)
            } else {
                tracing::info!(
                    "Signer {:?} returned {} with wrong hash",
                    signer_address,
                    context
                );
                None
            }
        }
        Err(e) => {
            tracing::info!(
                "Failed to retrieve {} from signer {:?}: {}",
                context,
                signer_address,
                e
            );
            None
        }
    }
}

async fn fetch_first_valid<Output, Response, Request, FetchFn, ExtractFn, HashFn, FetchFuture>(
    signers: impl IntoIterator<Item = Address>,
    request: Request,
    fetch: FetchFn,
    extract: ExtractFn,
    compute_hash: HashFn,
    expected_hash: MessageHash,
    context: &'static str,
) -> Option<(Address, Output)>
where
    Output: Send,
    Response: Send,
    Request: Clone + Send + Sync,
    FetchFn: Fn(Address, Request) -> FetchFuture + Clone + Send + Sync,
    FetchFuture: Future<Output = ChannelResult<Response>> + Send,
    ExtractFn: Fn(Response) -> Output + Clone + Send + Sync,
    HashFn: Fn(&Output) -> MessageHash + Clone + Send + Sync,
{
    let futures: Vec<_> = signers
        .into_iter()
        .map(|addr| {
            let req = request.clone();
            let fetch = fetch.clone();
            let extract = extract.clone();
            let compute_hash = compute_hash.clone();
            async move {
                let result = with_timeout_and_retry(|| fetch(addr, req.clone())).await;
                let validated = validate_retrieved(
                    result.map(&extract),
                    addr,
                    &compute_hash,
                    expected_hash,
                    context,
                );
                (addr, validated)
            }
        })
        .collect();
    let mut stream: FuturesUnordered<_> = futures.into_iter().collect();
    while let Some((addr, result)) = stream.next().await {
        if let Some(output) = result {
            return Some((addr, output));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::Committee;
    use crate::committee::CommitteeMember;
    use crate::committee::EncryptionPublicKey;
    use crate::committee::MemberSignature;
    use crate::dkg::types::ProtocolType;
    use crate::onchain::types::MemberInfo;
    use fastcrypto::encoding::Encoding;
    use fastcrypto::encoding::Hex;
    use fastcrypto::groups::Scalar;
    use fastcrypto_tbls::ecies_v1::MultiRecipientEncryption;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::random_oracle::RandomOracle;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    struct MockPublicMessagesStore;

    impl PublicMessagesStore for MockPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            _dealer: &Address,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_dealer_message(&self, _dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
            Ok(None)
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, avss::Message)>> {
            Ok(vec![])
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn receive_dealer_message(
        manager: &mut DkgManager,
        message: &avss::Message,
        dealer: Address,
    ) -> DkgResult<MemberSignature> {
        manager.store_message(dealer, message)?;
        let sig = manager.try_sign_message(dealer, message)?;
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

        fn create_manager(&self, validator_index: usize) -> DkgManager {
            self.create_manager_with_store(validator_index, Box::new(MockPublicMessagesStore))
        }

        fn create_manager_with_store(
            &self,
            validator_index: usize,
            store: Box<dyn PublicMessagesStore>,
        ) -> DkgManager {
            let address = Address::new([validator_index as u8; 32]);
            let session_id = SessionId::new(
                "testchain",
                self.committee_set.epoch(),
                &ProtocolType::DkgKeyGeneration,
            );
            DkgManager::new(
                address,
                &self.committee_set,
                session_id,
                self.encryption_keys[validator_index].clone(),
                self.signing_keys[validator_index].clone(),
                store,
            )
            .unwrap()
        }

        fn address(&self, validator_index: usize) -> Address {
            Address::new([validator_index as u8; 32])
        }

        fn session_id(&self) -> SessionId {
            SessionId::new(
                "testchain",
                self.committee_set.epoch(),
                &ProtocolType::DkgKeyGeneration,
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
        ) -> DkgManager {
            let mut manager = self.create_manager(validator_index);
            let dealer_message = manager.create_dealer_message(rng);
            let address = self.address(validator_index);
            receive_dealer_message(&mut manager, &dealer_message, address).unwrap();
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
        dealer_message: &avss::Message,
        dealer_address: Address,
        signatures: Vec<MemberSignature>,
    ) -> DkgResult<Certificate> {
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address,
            message_hash,
        });
        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);
        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| DkgError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| DkgError::CryptoError(e.to_string()))
    }

    fn create_rotation_test_certificate(
        committee: &Committee,
        rotation_messages: &RotationMessages,
        dealer_address: Address,
        signatures: Vec<MemberSignature>,
    ) -> DkgResult<Certificate> {
        let messages_hash = compute_rotation_messages_hash(rotation_messages);
        let rotation_message = Rotation(RotationDealerMessagesHash {
            dealer_address,
            messages_hash,
        });
        let mut aggregator = BlsSignatureAggregator::new(committee, rotation_message);
        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| DkgError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| DkgError::CryptoError(e.to_string()))
    }

    struct MockP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, DkgManager>>>,
        current_sender: Address,
    }

    impl MockP2PChannel {
        fn new(managers: HashMap<Address, DkgManager>, current_sender: Address) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for MockP2PChannel {
        async fn send_dkg_message(
            &self,
            recipient: &Address,
            request: &SendMessageRequest,
        ) -> ChannelResult<SendMessageResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_message_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            party: &Address,
            request: &RetrieveMessageRequest,
        ) -> ChannelResult<RetrieveMessageResponse> {
            let managers = self.managers.lock().unwrap();
            let manager = managers.get(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_retrieve_message_request(request)
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
        ) -> ChannelResult<ComplainResponse> {
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

        async fn rotation_complain(
            &self,
            party: &Address,
            request: &RotationComplainRequest,
        ) -> ChannelResult<RotationComplainResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_rotation_complain_request(request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn send_rotation_messages(
            &self,
            recipient: &Address,
            request: &SendRotationMessagesRequest,
        ) -> ChannelResult<SendRotationMessagesResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_rotation_messages_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_rotation_messages(
            &self,
            party: &Address,
            request: &RetrieveRotationMessagesRequest,
        ) -> ChannelResult<RetrieveRotationMessagesResponse> {
            let managers = self.managers.lock().unwrap();
            let manager = managers.get(party).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_retrieve_rotation_messages_request(request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
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
    }

    struct MockOrderedBroadcastChannel {
        certificates: std::sync::Mutex<std::collections::VecDeque<Certificate>>,
        published: std::sync::Mutex<Vec<Certificate>>,
        /// Override for existing_certificate_weight().
        /// If set, returns this value instead of the pending message count.
        override_existing_weight: Option<u32>,
        /// If set, publish() will fail with this error message.
        fail_on_publish: Option<String>,
    }

    impl MockOrderedBroadcastChannel {
        fn new(certificates: Vec<Certificate>) -> Self {
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
    }

    #[async_trait::async_trait]
    impl OrderedBroadcastChannel<Certificate> for MockOrderedBroadcastChannel {
        async fn publish(&self, message: Certificate) -> ChannelResult<()> {
            if let Some(ref error_msg) = self.fail_on_publish {
                return Err(crate::communication::ChannelError::RequestFailed(
                    error_msg.clone(),
                ));
            }
            self.published.lock().unwrap().push(message);
            Ok(())
        }

        async fn receive(&mut self) -> ChannelResult<Certificate> {
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

        async fn try_receive_timeout(
            &mut self,
            _duration: std::time::Duration,
        ) -> ChannelResult<Option<Certificate>> {
            unimplemented!()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(self.certificates.lock().unwrap().len())
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
    ) -> (DkgManager, TestSetup) {
        let setup = TestSetup::new(num_validators);
        let manager = setup.create_manager(validator_index);
        (manager, setup)
    }

    struct FailingP2PChannel {
        error_message: String,
    }

    #[async_trait::async_trait]
    impl P2PChannel for FailingP2PChannel {
        async fn send_dkg_message(
            &self,
            _recipient: &Address,
            _request: &SendMessageRequest,
        ) -> ChannelResult<SendMessageResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> ChannelResult<RetrieveMessageResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplainResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn rotation_complain(
            &self,
            _party: &Address,
            _request: &RotationComplainRequest,
        ) -> ChannelResult<RotationComplainResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn send_rotation_messages(
            &self,
            _recipient: &Address,
            _request: &SendRotationMessagesRequest,
        ) -> ChannelResult<SendRotationMessagesResponse> {
            Err(crate::communication::ChannelError::RequestFailed(
                self.error_message.clone(),
            ))
        }

        async fn retrieve_rotation_messages(
            &self,
            _party: &Address,
            _request: &RetrieveRotationMessagesRequest,
        ) -> ChannelResult<RetrieveRotationMessagesResponse> {
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
    }

    struct SucceedingP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, DkgManager>>>,
        current_sender: Address,
    }

    impl SucceedingP2PChannel {
        fn new(managers: HashMap<Address, DkgManager>, current_sender: Address) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for SucceedingP2PChannel {
        async fn send_dkg_message(
            &self,
            recipient: &Address,
            request: &SendMessageRequest,
        ) -> ChannelResult<SendMessageResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::RequestFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_message_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> ChannelResult<RetrieveMessageResponse> {
            unimplemented!("SucceedingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplainResponse> {
            unimplemented!("SucceedingP2PChannel does not implement complain")
        }

        async fn rotation_complain(
            &self,
            _party: &Address,
            _request: &RotationComplainRequest,
        ) -> ChannelResult<RotationComplainResponse> {
            unimplemented!("SucceedingP2PChannel does not implement rotation_complain")
        }

        async fn send_rotation_messages(
            &self,
            _recipient: &Address,
            _request: &SendRotationMessagesRequest,
        ) -> ChannelResult<SendRotationMessagesResponse> {
            unimplemented!("SucceedingP2PChannel does not implement send_rotation_messages")
        }

        async fn retrieve_rotation_messages(
            &self,
            _party: &Address,
            _request: &RetrieveRotationMessagesRequest,
        ) -> ChannelResult<RetrieveRotationMessagesResponse> {
            unimplemented!("SucceedingP2PChannel does not implement retrieve_rotation_messages")
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("SucceedingP2PChannel does not implement get_public_dkg_output")
        }
    }

    struct PartiallyFailingP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, DkgManager>>>,
        current_sender: Address,
        /// Recipients that always fail (even on retry)
        failed_recipients: std::sync::Arc<std::sync::Mutex<HashSet<Address>>>,
        max_failures: usize,
    }

    impl PartiallyFailingP2PChannel {
        fn new(
            managers: HashMap<Address, DkgManager>,
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
        async fn send_dkg_message(
            &self,
            recipient: &Address,
            request: &SendMessageRequest,
        ) -> ChannelResult<SendMessageResponse> {
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
                .handle_send_message_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::RequestFailed(format!(
                        "Handler failed: {}",
                        e
                    ))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> ChannelResult<RetrieveMessageResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplainResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement complain")
        }

        async fn rotation_complain(
            &self,
            _party: &Address,
            _request: &RotationComplainRequest,
        ) -> ChannelResult<RotationComplainResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement rotation_complain")
        }

        async fn send_rotation_messages(
            &self,
            _recipient: &Address,
            _request: &SendRotationMessagesRequest,
        ) -> ChannelResult<SendRotationMessagesResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement send_rotation_messages")
        }

        async fn retrieve_rotation_messages(
            &self,
            _party: &Address,
            _request: &RetrieveRotationMessagesRequest,
        ) -> ChannelResult<RetrieveRotationMessagesResponse> {
            unimplemented!(
                "PartiallyFailingP2PChannel does not implement retrieve_rotation_messages"
            )
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement get_public_dkg_output")
        }
    }

    /// P2P channel that returns pre-collected complaint responses.
    /// Useful for testing scenarios where responses are prepared ahead of time.
    struct PreCollectedP2PChannel {
        responses: std::sync::Mutex<HashMap<Address, ComplainResponse>>,
    }

    impl PreCollectedP2PChannel {
        fn new(responses: HashMap<Address, ComplainResponse>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for PreCollectedP2PChannel {
        async fn send_dkg_message(
            &self,
            _: &Address,
            _: &SendMessageRequest,
        ) -> ChannelResult<SendMessageResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement send_dkg_message")
        }

        async fn retrieve_message(
            &self,
            _: &Address,
            _: &RetrieveMessageRequest,
        ) -> ChannelResult<RetrieveMessageResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            party: &Address,
            _request: &ComplainRequest,
        ) -> ChannelResult<ComplainResponse> {
            self.responses
                .lock()
                .unwrap()
                .get(party)
                .cloned()
                .ok_or_else(|| {
                    crate::communication::ChannelError::RequestFailed("No response".into())
                })
        }

        async fn rotation_complain(
            &self,
            _party: &Address,
            _request: &RotationComplainRequest,
        ) -> ChannelResult<RotationComplainResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement rotation_complain")
        }

        async fn send_rotation_messages(
            &self,
            _recipient: &Address,
            _request: &SendRotationMessagesRequest,
        ) -> ChannelResult<SendRotationMessagesResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement send_rotation_messages")
        }

        async fn retrieve_rotation_messages(
            &self,
            _party: &Address,
            _request: &RetrieveRotationMessagesRequest,
        ) -> ChannelResult<RetrieveRotationMessagesResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement retrieve_rotation_messages")
        }

        async fn get_public_dkg_output(
            &self,
            _party: &Address,
            _request: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement get_public_dkg_output")
        }
    }

    struct FailingOrderedBroadcastChannel {
        error_message: String,
        fail_on_publish: bool,
        fail_on_receive: bool,
    }

    #[async_trait::async_trait]
    impl OrderedBroadcastChannel<Certificate> for FailingOrderedBroadcastChannel {
        async fn publish(&self, _message: Certificate) -> ChannelResult<()> {
            if self.fail_on_publish {
                Err(crate::communication::ChannelError::RequestFailed(
                    self.error_message.clone(),
                ))
            } else {
                Ok(())
            }
        }

        async fn receive(&mut self) -> ChannelResult<Certificate> {
            if self.fail_on_receive {
                Err(crate::communication::ChannelError::RequestFailed(
                    self.error_message.clone(),
                ))
            } else {
                unreachable!()
            }
        }

        async fn try_receive_timeout(
            &mut self,
            _duration: std::time::Duration,
        ) -> ChannelResult<Option<Certificate>> {
            unreachable!()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(0)
        }
    }

    #[test]
    fn test_dkg_manager_new_from_committee_set() {
        let setup = TestSetup::new(5);

        let encryption_key = setup.encryption_keys[0].clone();
        let signing_key = setup.signing_keys[0].clone();
        let address = setup.address(0);
        let session_id = setup.session_id();

        let manager = DkgManager::new(
            address,
            &setup.committee_set,
            session_id,
            encryption_key,
            signing_key,
            Box::new(MockPublicMessagesStore),
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
    fn test_dkg_manager_new_fails_if_no_committee_for_epoch() {
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

        let session_id = SessionId::new("test", epoch, &ProtocolType::DkgKeyGeneration);
        let result = DkgManager::new(
            Address::new([0; 32]),
            &committee_set,
            session_id,
            encryption_keys[0].clone(),
            signing_keys[0].clone(),
            Box::new(MockPublicMessagesStore),
        );

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Should fail with no committee for epoch"),
        };
        assert!(
            err.to_string().contains("no committee for current epoch"),
            "Error should mention missing committee"
        );
    }

    #[test]
    fn test_dkg_manager_new_with_weighted_committee() {
        let setup = TestSetup::with_weights(&[1, 2, 3, 4, 5]); // total = 15

        let manager = setup.create_manager(0);

        // With total_weight=15: max_faulty = (15-1)/3 = 4, threshold = 5
        assert_eq!(manager.dkg_config.threshold, 5);
        assert_eq!(manager.dkg_config.max_faulty, 4);
    }

    #[test]
    fn test_dkg_manager_new_party_id_follows_canonical_order() {
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
    }

    impl InMemoryPublicMessagesStore {
        fn new() -> Self {
            Self {
                stored: HashMap::new(),
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

        fn get_dealer_message(&self, dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
            Ok(self.stored.get(dealer).cloned())
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, avss::Message)>> {
            Ok(self.stored.iter().map(|(k, v)| (*k, v.clone())).collect())
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            self.stored.clear();
            Ok(())
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

        fn get_dealer_message(&self, _dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, avss::Message)>> {
            Ok(vec![])
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
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

        // Create receiver (party 1) with custom storage
        let storage = InMemoryPublicMessagesStore::new();
        let mut receiver_manager = setup.create_manager_with_store(1, Box::new(storage));

        // Receiver processes the dealer's message
        let signature =
            receive_dealer_message(&mut receiver_manager, &message, dealer_address).unwrap();

        // Verify signature format
        assert_eq!(signature.address(), &receiver_manager.address);

        // Verify receiver output was stored in memory
        assert!(
            receiver_manager
                .dealer_outputs
                .contains_key(&dealer_address)
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

        // Create receiver with failing storage
        let mut receiver_manager =
            setup.create_manager_with_store(1, Box::new(FailingPublicMessagesStore));

        // Receiver processes the dealer's message - should fail due to storage error
        let result = receive_dealer_message(&mut receiver_manager, &message, dealer_address);

        // Verify operation fails with storage error
        assert!(result.is_err(), "Should fail when storage fails");
        match result {
            Err(DkgError::StorageError(msg)) => {
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

        // Each dealer creates a message
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|dm| dm.create_dealer_message(&mut rng))
            .collect();

        // Receiver processes all dealer messages and creates certificates
        let certified_dealers = dealer_messages
            .iter()
            .enumerate()
            .map(|(i, message)| {
                let dealer_address = dealer_managers[i].address;
                // Receiver processes the message
                let _sig = receive_dealer_message(&mut receiver_manager, message, dealer_address);
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

        // Phase 1: Pre-create all dealer messages
        let dealer_messages: Vec<_> = managers
            .iter()
            .map(|mgr| mgr.create_dealer_message(&mut rng))
            .collect();

        // Phase 2: Pre-compute all signatures and certificates
        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // Collect signatures from all validators
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_message(manager, message, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(setup.committee(), message, dealer_addr, signatures)
                .unwrap();
            certificates.push(cert);
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
        for (j, message) in dealer_messages.iter().enumerate() {
            receive_dealer_message(&mut test_manager, message, setup.address(j)).unwrap();
        }

        // Create mock ordered broadcast channel with certificates from dealers 1-4
        // (exclude dealer 0 since run_as_dealer() will create its own certificate)
        let other_certificates: Vec<_> = certificates.iter().skip(1).cloned().collect();
        let other_certificates_len = other_certificates.len();
        let mut mock_tob = MockOrderedBroadcastChannel::new(other_certificates);

        // Call run_as_dealer() and run_as_party() for validator 0
        test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await
            .unwrap();
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
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
        let addr0 = setup.address(0);
        for j in 1..num_validators {
            let addr_j = setup.address(j);
            let other_mgr = other_managers.get(&addr_j).unwrap();
            assert!(
                other_mgr.dealer_outputs.contains_key(&addr0),
                "Validator {} should have dealer output from validator 0",
                j
            );
        }
    }

    /// Test setup for run() tests. Creates managers and certificates.
    struct RunTestSetup {
        test_manager: DkgManager,
        mock_p2p: MockP2PChannel,
        certificates: Vec<Certificate>,
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
        let dealer_messages: Vec<_> = managers
            .iter()
            .skip(1) // Skip validator 0
            .map(|mgr| mgr.create_dealer_message(&mut rng))
            .collect();

        // Create certificates for dealers 1-4
        let mut certificates = Vec::new();
        for (idx, message) in dealer_messages.iter().enumerate() {
            let dealer_idx = idx + 1; // Dealers 1-4
            let dealer_addr = setup.address(dealer_idx);

            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_message(manager, message, dealer_addr).unwrap();
                signatures.push(sig);
            }

            let cert = create_test_certificate(setup.committee(), message, dealer_addr, signatures)
                .unwrap();
            certificates.push(cert);
        }

        // Extract test_manager (validator 0)
        let test_manager = managers.remove(0);

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
        let mut rng = rand::thread_rng();
        let mut setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // Override weight to 0 so dealer phase runs, but provide enough certs for party to complete
        let mut mock_tob =
            MockOrderedBroadcastChannel::new(setup.certificates).with_override_weight(0);

        let output = setup
            .test_manager
            .run(&setup.mock_p2p, &mut mock_tob, &mut rng)
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
        let mut rng = rand::thread_rng();
        let mut setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // With 4 certificates and threshold = 2, existing_weight = 4 >= 2, dealer skips
        let mut mock_tob = MockOrderedBroadcastChannel::new(setup.certificates);

        let output = setup
            .test_manager
            .run(&setup.mock_p2p, &mut mock_tob, &mut rng)
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
        let mut rng = rand::thread_rng();
        let mut setup = setup_run_test();

        // All certificates are from dealers 1-4 (not dealer 0)
        // Override weight to 0 so dealer phase runs, but make publish fail
        let mut mock_tob = MockOrderedBroadcastChannel::new(setup.certificates)
            .with_override_weight(0)
            .with_fail_on_publish("simulated publish failure");

        let output = setup
            .test_manager
            .run(&setup.mock_p2p, &mut mock_tob, &mut rng)
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
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let setup = TestSetup::new(num_validators);

        // Create manager for validator 0
        let mut test_manager = setup.create_manager(0);

        // Create managers for other validators
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| (setup.address(i), setup.create_manager(i)))
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Call run_as_dealer()
        let result = test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;

        // Verify success
        assert!(result.is_ok());

        // Verify own dealer output is stored
        let addr0 = setup.address(0);
        assert!(test_manager.dealer_outputs.contains_key(&addr0));

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let addr = setup.address(i);
            let other_mgr = other_managers.get(&addr).unwrap();
            assert!(
                other_mgr.dealer_outputs.contains_key(&addr0),
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
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(threshold as usize)
            .map(|mgr| mgr.create_dealer_message(&mut rng))
            .collect();

        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_message(manager, message, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(setup.committee(), message, dealer_addr, signatures)
                .unwrap();
            certificates.push(cert);
        }

        // Create mock TOB with threshold certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates.clone());

        // Call run_as_party() for validator 0
        let mut test_manager = managers.remove(0);
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
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
        let dealer_0_message_hash = compute_message_hash(&dealer_0_message);
        let dealer_0_dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_0_addr,
            message_hash: dealer_0_message_hash,
        });

        // Create dealer 1 with cheating message (corrupts party 2's shares)
        let dealer_1_addr = setup.address(1);
        let dealer_1_message = create_cheating_message(&setup, 1, 2, &mut rng);
        let dealer_1_message_hash = compute_message_hash(&dealer_1_message);
        let dealer_1_dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_1_addr,
            message_hash: dealer_1_message_hash,
        });

        // Create party 2 manager (will have complaint for dealer 1)
        let party_addr = setup.address(2);
        let mut party_manager = setup.create_manager(2);

        // Party 2 successfully processes dealer 0's message
        receive_dealer_message(&mut party_manager, &dealer_0_message, dealer_0_addr).unwrap();

        // Party 2 stores dealer 1's cheating message and creates complaint during processing
        party_manager
            .store_message(dealer_1_addr, &dealer_1_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_1_addr)
            .unwrap();
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_1_addr)
        );

        // Create other parties who can successfully process dealer 1's message
        let mut other_managers = HashMap::new();
        for party_id in [0usize, 1, 3, 4] {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            // They successfully process dealer 1's cheating message
            receive_dealer_message(&mut mgr, &dealer_1_message, dealer_1_addr).unwrap();
            other_managers.insert(addr, mgr);
        }

        let epoch = setup.epoch();
        // Create certificates with signers (excluding party 2 who has complaint)
        let cert_0 = create_certificate_with_signers(
            setup.committee(),
            dealer_0_addr,
            &dealer_0_message,
            [
                (0usize, setup.address(0)),
                (1, setup.address(1)),
                (3, setup.address(3)),
            ]
            .iter()
            .map(|(i, a)| setup.signing_keys[*i].sign(epoch, *a, &dealer_0_dkg_message))
            .collect(),
        )
        .unwrap();

        let cert_1 = create_certificate_with_signers(
            setup.committee(),
            dealer_1_addr,
            &dealer_1_message,
            [
                (0usize, setup.address(0)),
                (1, setup.address(1)),
                (3, setup.address(3)),
            ]
            .iter()
            .map(|(i, a)| setup.signing_keys[*i].sign(epoch, *a, &dealer_1_dkg_message))
            .collect(),
        )
        .unwrap();

        let certificates = vec![cert_0, cert_1];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);
        let mock_p2p = MockP2PChannel::new(other_managers, party_addr);

        // Verify complaint exists before run_as_party
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_1_addr)
        );

        // Run as party - should recover shares via complaint
        let output = party_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify complaint was resolved
        assert!(
            !party_manager
                .complaints_to_process
                .contains_key(&dealer_1_addr),
            "Complaint should be cleared after successful recovery"
        );
        assert!(
            party_manager.dealer_outputs.contains_key(&dealer_1_addr),
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
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(threshold)
            .map(|mgr| mgr.create_dealer_message(&mut rng))
            .collect();

        let mut valid_certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_message(manager, message, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(setup.committee(), message, dealer_addr, signatures)
                .unwrap();
            valid_certificates.push(cert);
        }

        // Create certificate that will fail validation due to hash mismatch
        // (test_manager processes a DIFFERENT message than what's in the cert)
        let invalid_dealer_msg = managers[3].create_dealer_message(&mut rng);
        let different_dealer_msg = managers[3].create_dealer_message(&mut rng);
        let dealer_addr_3 = setup.address(3);

        // test_manager processes the DIFFERENT message
        receive_dealer_message(&mut managers[0], &different_dealer_msg, dealer_addr_3).unwrap();
        // Other managers process the actual message (for cert creation)
        for manager in managers.iter_mut().skip(1) {
            receive_dealer_message(manager, &invalid_dealer_msg, dealer_addr_3).unwrap();
        }

        // Create certificate for invalid_dealer_msg (but test_manager has different_dealer_msg stored)
        let invalid_signatures: Vec<_> = managers
            .iter()
            .skip(1) // Skip test_manager who has wrong message
            .map(|mgr| {
                let message_hash = compute_message_hash(&invalid_dealer_msg);
                let dkg_message = Dkg(DkgDealerMessageHash {
                    dealer_address: dealer_addr_3,
                    message_hash,
                });
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
            invalid_cert, // hash mismatch - will be recovered from P2P
        ];
        // Add remaining valid certificates if any
        for cert in valid_certificates.iter().skip(1) {
            all_certificates.push(cert.clone());
        }

        let num_certs = all_certificates.len();
        let mut mock_tob = MockOrderedBroadcastChannel::new(all_certificates);

        // Call run_as_party() for validator 0
        let mut test_manager = managers.remove(0);
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (setup.address(idx + 1), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(0));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
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
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(2)
            .map(|mgr| mgr.create_dealer_message(&mut rng))
            .collect();

        // Create certificates
        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = setup.address(dealer_idx);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = receive_dealer_message(manager, message, dealer_addr).unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(setup.committee(), message, dealer_addr, signatures)
                .unwrap();
            certificates.push(cert);
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
        let mut test_manager = managers.remove(2);
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| {
                let addr_idx = if idx < 2 { idx } else { idx + 1 };
                (setup.address(addr_idx), mgr)
            })
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, setup.address(2));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
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
        let mut rng = rand::thread_rng();
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let failing_p2p = FailingP2PChannel {
            error_message: "network error".to_string(),
        };
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let result = test_manager
            .run_as_dealer(&failing_p2p, &mut mock_tob, &mut rng)
            .await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        assert!(logs_contain("Failed to send message"));
        assert!(logs_contain("network error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_tob_publish_error() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create test manager (validator 0)
        let mut test_manager = setup.create_manager(0);

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

        let result = test_manager
            .run_as_dealer(&succeeding_p2p, &mut failing_tob, &mut rng)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(ERR_PUBLISH_CERT_FAILED));
        assert!(err.to_string().contains("consensus error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_partial_failures_still_collects_enough() {
        let mut rng = rand::thread_rng();
        // Use 7 validators so we have more room for failures
        // threshold=4, max_faulty=1, required_sigs=5
        // Dealer sends to 6 others, fail 1, succeed 5
        let setup = TestSetup::new(7);

        let mut test_manager = setup.create_manager(0);

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

        let result = test_manager
            .run_as_dealer(&partially_failing_p2p, &mut mock_tob, &mut rng)
            .await;

        assert!(result.is_ok());
        // Verify that a certificate was published
        assert_eq!(mock_tob.published_count(), 1);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_run_as_dealer_partial_failures_insufficient_signatures() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        let mut test_manager = setup.create_manager(0);

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

        let result = test_manager
            .run_as_dealer(&partially_failing_p2p, &mut mock_tob, &mut rng)
            .await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        // Verify logging occurred for the 3 failures
        assert!(logs_contain("Failed to send message"));
    }
    #[tokio::test]
    async fn test_run_as_dealer_includes_own_signature() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create manager for validator 0 (the dealer)
        let dealer_addr = setup.address(0);
        let mut test_manager = setup.create_manager(0);

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
        let result = test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;

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
        let mut test_manager = setup.create_manager(0);

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "receive timeout".to_string(),
            fail_on_publish: false,
            fail_on_receive: true,
        };

        let mock_p2p = MockP2PChannel::new(HashMap::new(), setup.address(0));
        let result = test_manager.run_as_party(&mock_p2p, &mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::BroadcastError(_)));
        assert!(err.to_string().contains("receive timeout"));
    }
    //
    struct WeightBasedTestSetup {
        setup: TestSetup,
        dealer_messages: Vec<(Address, avss::Message)>,
        certificates: Vec<Certificate>,
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
                (manager.address, message)
            })
            .collect();

        // Create certificates from the stored messages
        let certificates: Vec<_> = dealer_messages
            .iter()
            .map(|(dealer_addr, message)| {
                create_weight_based_test_certificate(&setup, dealer_addr, message)
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
        message: &avss::Message,
    ) -> Certificate {
        let message_hash = compute_message_hash(message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: *dealer_addr,
            message_hash,
        });

        let config = setup.dkg_config();
        let committee = setup.committee();
        let mut aggregator =
            crate::committee::BlsSignatureAggregator::new(committee, dkg_message.clone());

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

        aggregator.finish().unwrap()
    }

    // Helper to create and setup a party manager for testing
    async fn setup_party_and_run(
        test_setup: &WeightBasedTestSetup,
        party_index: usize,
    ) -> (DkgResult<DkgOutput>, MockOrderedBroadcastChannel) {
        let party_addr = test_setup.setup.address(party_index);

        let mut party_manager = test_setup.setup.create_manager(party_index);

        // Pre-process the dealer messages so validation passes
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = receive_dealer_message(&mut party_manager, message, *dealer_addr);
        }

        // Create mock TOB with certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(test_setup.certificates.clone());

        // Run party collection
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

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
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = receive_dealer_message(&mut party_manager, message, *dealer_addr);
        }

        // Create mock TOB with the modified certificates (including duplicates)
        let mut mock_tob = MockOrderedBroadcastChannel::new(modified_certificates);

        // Run party collection
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;
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
        let mut party_manager = setup.create_manager(3);

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
                let message_hash = compute_message_hash(&msg1);
                let dkg_message = Dkg(DkgDealerMessageHash {
                    dealer_address: dealer1_addr,
                    message_hash,
                });
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let signatures_2: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let message_hash = compute_message_hash(&msg2);
                let dkg_message = Dkg(DkgDealerMessageHash {
                    dealer_address: dealer2_addr,
                    message_hash,
                });
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
        let certificates = vec![cert1, cert2];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        // Verify party doesn't have any dealer messages yet
        assert!(party_manager.dealer_messages.is_empty());

        // Run as party - should retrieve missing messages via P2P
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

        assert!(result.is_ok());
        assert!(party_manager.dealer_messages.contains_key(&dealer1_addr));
        assert!(party_manager.dealer_messages.contains_key(&dealer2_addr));
        assert!(party_manager.dealer_outputs.contains_key(&dealer1_addr));
        assert!(party_manager.dealer_outputs.contains_key(&dealer2_addr));
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
        let mut party_manager = setup.create_manager(3);

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
        let create_sigs = |dealer_addr: Address, msg: &avss::Message| -> Vec<MemberSignature> {
            (0..3)
                .map(|i| {
                    let addr = setup.address(i);
                    let message_hash = compute_message_hash(msg);
                    let dkg_message = Dkg(DkgDealerMessageHash {
                        dealer_address: dealer_addr,
                        message_hash,
                    });
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
        let certificates = vec![cert1, cert2, cert3];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        // Run as party - should process dealer1 successfully, then ABORT on dealer2 retrieval failure
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

        // Should fail with PairwiseCommunicationError
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::PairwiseCommunicationError(_)));

        // Verify party has dealer1 message (processed before failure)
        assert!(party_manager.dealer_messages.contains_key(&dealer1_addr));
        // But NOT dealer2 or dealer3 (aborted before processing these)
        assert!(!party_manager.dealer_messages.contains_key(&dealer2_addr));
        assert!(!party_manager.dealer_messages.contains_key(&dealer3_addr));
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
        let dealer0_message_hash = compute_message_hash(&dealer0_message);
        let dealer0_dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer0_addr,
            message_hash: dealer0_message_hash,
        });

        // Create dealer 1 - would be processed if we continued
        let dealer1_addr = setup.address(1);
        let dealer1_mgr = setup.create_dealer_with_message(1, &mut rng);
        let dealer1_message = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();
        let dealer1_message_hash = compute_message_hash(&dealer1_message);
        let dealer1_dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer1_addr,
            message_hash: dealer1_message_hash,
        });

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
            [
                (0usize, setup.address(0)),
                (1, setup.address(1)),
                (3, setup.address(3)),
            ]
            .iter()
            .map(|(i, a)| setup.signing_keys[*i].sign(epoch, *a, &dealer0_dkg_message))
            .collect(),
        )
        .unwrap();
        let cert1 = create_certificate_with_signers(
            setup.committee(),
            dealer1_addr,
            &dealer1_message,
            [
                (0usize, setup.address(0)),
                (1, setup.address(1)),
                (3, setup.address(3)),
            ]
            .iter()
            .map(|(i, a)| setup.signing_keys[*i].sign(epoch, *a, &dealer1_dkg_message))
            .collect(),
        )
        .unwrap();

        // Create mock P2P with no responders (recovery will fail)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Create mock TOB with both certificates
        let certificates = vec![cert0, cert1];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        // Run as party - should ABORT on dealer0 recovery failure
        // With retry logic, failed signers are skipped, so we get ProtocolFailed
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

        // Should fail with ProtocolFailed (all signers failed, not enough responses)
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );

        // Verify dealer1 was NOT processed (aborted before reaching it)
        assert!(
            !party_manager.dealer_outputs.contains_key(&dealer1_addr),
            "Dealer1 should NOT be processed - aborted before reaching it"
        );

        // Dealer0 should NOT be in dealer_outputs (recovery failed, DKG aborted)
        assert!(
            !party_manager.dealer_outputs.contains_key(&dealer0_addr),
            "Dealer0 should NOT have output - recovery failed and aborted"
        );

        // Complaint for dealer0 should still be present (wasn't removed due to failure)
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer0_addr),
            "Complaint should remain after recovery failure"
        );
    }

    #[tokio::test]
    async fn test_handle_send_message_request() {
        // Test that handle_send_message_request works with the new request/response types
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 1) with its encryption key
        let dealer_address = setup.address(1);
        let dealer_manager = setup.create_manager(1);

        // Create receiver (party 0) with its encryption key
        let receiver_address = setup.address(0);
        let mut receiver_manager = setup.create_manager(0);

        // Dealer creates a message
        let dealer_message = dealer_manager.create_dealer_message(&mut rng);

        // Create a request as if dealer sent it to receiver
        let request = SendMessageRequest {
            message: dealer_message.clone(),
        };

        // Receiver handles the request
        let response = receiver_manager
            .handle_send_message_request(dealer_address, &request)
            .unwrap();

        // Verify we got a valid BLS signature (non-empty)
        assert!(!response.signature.as_ref().is_empty());
        let _ = receiver_address; // suppress unused warning
    }

    #[tokio::test]
    async fn test_handle_retrieve_message_request_success() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 0)
        let dealer_address = setup.address(0);
        let mut dealer_manager = setup.create_manager(0);

        // Dealer creates and processes its own message (stores in dealer_messages)
        let dealer_message = dealer_manager.create_dealer_message(&mut rng);
        receive_dealer_message(&mut dealer_manager, &dealer_message, dealer_address).unwrap();

        // Party requests the dealer's message
        let request = RetrieveMessageRequest {
            dealer: dealer_address,
        };
        let response = dealer_manager
            .handle_retrieve_message_request(&request)
            .unwrap();

        let expected_hash = compute_message_hash(&dealer_message);
        let received_hash = compute_message_hash(&response.message);
        assert_eq!(received_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_handle_retrieve_message_request_message_not_available() {
        let setup = TestSetup::new(5);

        // Create dealer (party 0) but don't create/process any message
        let dealer_address = setup.address(0);
        let dealer_manager = setup.create_manager(0);

        // Party requests the dealer's message
        let request = RetrieveMessageRequest {
            dealer: dealer_address,
        };
        let result = dealer_manager.handle_retrieve_message_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
        assert!(err.to_string().contains("Message not available"));
    }

    #[test]
    fn test_handle_complain_request_no_message_from_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let (dealer_address, _dealer_message, complaint) =
            create_dealer_message_and_complaint(&setup, &mut rng);

        // Create manager (party 1) without any dealer messages
        let mut manager = setup.create_manager(1);

        let request = ComplainRequest {
            dealer: dealer_address,
            complaint,
        };

        // Manager has no message from this dealer
        let result = manager.handle_complain_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No message from dealer"));
    }

    #[test]
    fn test_handle_complain_request_no_shares_for_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let (dealer_address, dealer_message, complaint) =
            create_dealer_message_and_complaint(&setup, &mut rng);

        // Create manager that has the message but NOT dealer_output
        let mut manager = setup.create_manager(1);

        // Manually insert message without processing (so no dealer_output)
        manager
            .dealer_messages
            .insert(dealer_address, dealer_message.clone());

        let request = ComplainRequest {
            dealer: dealer_address,
            complaint,
        };

        // Manager has message but no dealer_output
        let result = manager.handle_complain_request(&request);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No shares for dealer"));
    }

    #[test]
    fn test_handle_complain_request_caches_response() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create a cheating dealer message with corrupted shares for party 1
        let cheating_message = create_cheating_message(&setup, 0, 1, &mut rng);

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

        let result = receiver1.process_message(&cheating_message);
        let complaint = match result {
            Ok(avss::ProcessedMessage::Complaint(c)) => c,
            Ok(_) => panic!("Expected complaint but got valid shares"),
            Err(e) => panic!("Processing failed with error: {:?}", e),
        };

        // Party 2 processes the SAME cheating message
        // Party 2's shares are valid (not corrupted) so it gets valid output
        let mut party2_manager = setup.create_manager(2);

        // Set up party 2 with the cheating message
        receive_dealer_message(&mut party2_manager, &cheating_message, dealer_addr).unwrap();

        let request = ComplainRequest {
            dealer: dealer_addr,
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
            bcs::to_bytes(&response1.response).unwrap(),
            bcs::to_bytes(&response2.response).unwrap(),
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
        let cheating_message = create_cheating_message(&setup, 0, 1, &mut rng);

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        party_manager
            .store_message(dealer_addr, &cheating_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_addr)
        );

        // Create exactly threshold (2) parties that can respond
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_message(&mut mgr, &cheating_message, dealer_addr).unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers.iter().map(|(addr, _)| *addr).collect();

        let managers_map: HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        // Recover with exactly threshold signers
        // Tests incremental recovery: receiver.recover() returns InputTooShort after first response,
        // continues to collect second response, then succeeds
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.into_iter(), &mock_p2p)
            .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed: {:?}",
            result.err()
        );
        assert!(party_manager.dealer_outputs.contains_key(&dealer_addr));
        assert!(
            !party_manager
                .complaints_to_process
                .contains_key(&dealer_addr),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_skips_failed_signers() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);
        let dealer_addr = setup.address(0);

        // Create cheating message with corrupted shares for party 1
        let cheating_message = create_cheating_message(&setup, 0, 1, &mut rng);

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        party_manager
            .store_message(dealer_addr, &cheating_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_addr)
        );

        // Create 2 parties that can respond (threshold is 2)
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_message(&mut mgr, &cheating_message, dealer_addr).unwrap();
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

        // Recovery should succeed despite first signer failing
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.into_iter(), &mock_p2p)
            .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed despite failed signer: {:?}",
            result.err()
        );
        assert!(party_manager.dealer_outputs.contains_key(&dealer_addr));
        assert!(
            !party_manager
                .complaints_to_process
                .contains_key(&dealer_addr),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_complaint_for_dealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create manager without any complaints
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);

        // Create a dealer address that has no complaint
        let dealer_addr = setup.address(0);
        let dealer_manager = setup.create_dealer_with_message(0, &mut rng);

        let dealer_message = dealer_manager.dealer_messages.get(&dealer_addr).unwrap();
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        });

        // Create a minimal certificate
        let committee = setup.committee();
        let cert = create_certificate_with_signers(
            committee,
            dealer_addr,
            dealer_message,
            [(1usize, party_addr)]
                .iter()
                .map(|(i, a)| setup.signing_keys[*i].sign(setup.epoch(), *a, &dkg_message))
                .collect(),
        )
        .unwrap();

        // Create empty mock P2P channel
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Call recover_shares_via_complaint - should fail because no complaint exists
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                cert.signers(&party_manager.committee).unwrap(),
                &mock_p2p,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
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

        // Call recover_shares_via_complaint - should fail because P2P call fails
        // With retry logic, failed signers are skipped (continue), so we get ProtocolFailed
        // instead of BroadcastError
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.into_iter(), &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::ProtocolFailed(_)),
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
        let cheating_message = create_cheating_message(&setup, 0, 1, &mut rng);

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        party_manager
            .store_message(dealer_addr, &cheating_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_addr)
        );

        // Create only 1 other party that can respond (threshold is 2, so insufficient)
        let mut other_managers = vec![];
        for party_id in 2..3 {
            let addr = setup.address(party_id);
            let mut mgr = setup.create_manager(party_id);
            receive_dealer_message(&mut mgr, &cheating_message, dealer_addr).unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers.iter().map(|(addr, _)| *addr).collect();

        let managers_map: HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        // Attempt recovery with insufficient signers
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.into_iter(), &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::ProtocolFailed(_)),
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
        let cheating_message = create_cheating_message(&setup, 0, 1, &mut rng);

        // Party 1 receives corrupted message and creates complaint
        let party_addr = setup.address(1);
        let mut party_manager = setup.create_manager(1);
        party_manager
            .store_message(dealer_addr, &cheating_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();
        assert!(
            party_manager
                .complaints_to_process
                .contains_key(&dealer_addr)
        );

        // Remove the dealer message to simulate the edge case
        party_manager.dealer_messages.remove(&dealer_addr);

        // Create mock P2P (empty is fine since we should fail before contacting anyone)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Try to recover - should fail because dealer message is missing
        let _ = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                [Address::new([2; 32])].into_iter(),
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
        let dealer_message = create_cheating_message(&setup, 0, 1, &mut rng);

        // Create responders 3 and 4 who successfully process the dealer message
        let addr3 = setup.address(3);
        let mut mgr3 = setup.create_manager(3);
        receive_dealer_message(&mut mgr3, &dealer_message, dealer_addr).unwrap();

        let addr4 = setup.address(4);
        let mut mgr4 = setup.create_manager(4);
        receive_dealer_message(&mut mgr4, &dealer_message, dealer_addr).unwrap();

        // Party 1 complains
        let mut party_manager = setup.create_manager(1);
        party_manager
            .store_message(dealer_addr, &dealer_message)
            .unwrap();
        party_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();

        // Pre-collect complaint responses from parties 3 and 4
        let complaint = party_manager
            .complaints_to_process
            .get(&dealer_addr)
            .unwrap()
            .clone();
        let request = ComplainRequest {
            dealer: dealer_addr,
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

        // Attempt recovery - parties 3 and 4 are not in the modified config
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, vec![addr3, addr4].into_iter(), &p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::CryptoError(_)),
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
        let mut party_manager = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_manager.dealer_messages.get(&dealer_address).unwrap();

        // Create DkgMessage and validator signatures
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address,
            message_hash,
        });

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

        // Party requests dealer's share from certificate signers
        let result = party_manager
            .retrieve_dealer_message(dkg_message.as_dkg_message(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        assert!(party_manager.dealer_messages.contains_key(&dealer_address));
        // Message is stored but not yet processed (that happens during run_as_party)
        assert!(!party_manager.dealer_outputs.contains_key(&dealer_address));

        // Process the message to verify it's valid
        party_manager
            .process_certified_dealer_message(dealer_address)
            .unwrap();
        assert!(party_manager.dealer_outputs.contains_key(&dealer_address));
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
        let mut party_mgr = setup.create_manager(2);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        });

        // Create certificate with two signers: validator 1 (not in P2P) and dealer (validator 0)
        // Validator 1 signs first, then validator 0
        let validator_1_addr = Address::new([1; 32]);
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

        // Should succeed by trying validator 1 (fails), then dealer (succeeds)
        let result = party_mgr
            .retrieve_dealer_message(dkg_message.as_dkg_message(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        assert!(party_mgr.dealer_messages.contains_key(&dealer_addr));
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
        let mut party_mgr = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        });

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

        // Should abort with ProtocolFailed error due to invariant violation
        let result = party_mgr
            .retrieve_dealer_message(dkg_message.as_dkg_message(), &cert, &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
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
        let mut party_mgr = setup.create_manager(1);

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash = compute_message_hash(dealer_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        });

        // Create certificate with signers 2 and 3 (both will be offline in P2P)
        let signer_2_addr = Address::new([2; 32]);
        let signer_3_addr = Address::new([3; 32]);
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

        // Should fail because all signers are offline
        let result = party_mgr
            .retrieve_dealer_message(dkg_message.as_dkg_message(), &cert, &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::PairwiseCommunicationError(_)));
        assert!(err.to_string().contains("Failed to retrieve"));
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
        let mut party_mgr = setup.create_manager(2);

        // Create Byzantine signer that has WRONG message stored for dealer A
        // (It has dealer B's message stored under dealer A's key.)
        let byzantine_signer_addr = Address::new([3; 32]);
        let mut byzantine_signer = setup.create_manager(3);
        // Byzantine: store dealer B's message under dealer A's address
        byzantine_signer
            .dealer_messages
            .insert(dealer_a_addr, message_b.clone());

        // Create DkgMessage for dealer A
        let message_hash_a = compute_message_hash(&message_a);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_a_addr,
            message_hash: message_hash_a,
        });

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

        // Party requests dealer A's message
        // 1. Tries Byzantine signer first -> returns message B
        // 2. Computes hash(message B) != hash(message A) -> rejects, continues
        // 3. Tries real dealer A -> returns message A -> hash matches -> success
        let result = party_mgr
            .retrieve_dealer_message(dkg_message.as_dkg_message(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        // Should have dealer A's correct message (from second signer)
        assert!(party_mgr.dealer_messages.contains_key(&dealer_a_addr));
    }
    fn create_certificate_with_signers(
        committee: &Committee,
        dealer_address: Address,
        message: &avss::Message,
        signatures: Vec<MemberSignature>,
    ) -> DkgResult<Certificate> {
        let message_hash = compute_message_hash(message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address,
            message_hash,
        });

        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);

        for signature in signatures {
            aggregator
                .add_signature(signature)
                .map_err(|e| DkgError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| DkgError::CryptoError(e.to_string()))
    }

    fn create_complaint_for_dealer(
        setup: &TestSetup,
        dealer_message: &avss::Message,
        party_id: u16,
        dealer_index: usize,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> complaint::Complaint {
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
        let template_message = dealer.create_message(rng).unwrap();

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
        let template_message = dealer.create_message(rng).unwrap();

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
    ) -> (Address, avss::Message, complaint::Complaint) {
        let dealer_address = setup.address(0);
        let dealer_manager = setup.create_manager(0);
        let dealer_message = dealer_manager.create_dealer_message(rng);
        // Create complaint from party 1 using wrong encryption key
        let complaint = create_complaint_for_dealer(setup, &dealer_message, 1, 0, rng);
        (dealer_address, dealer_message, complaint)
    }

    fn setup_party_with_complaint(
        party_manager: &mut DkgManager,
        dealer_address: &Address,
        dealer_message: &avss::Message,
        complaint: complaint::Complaint,
    ) {
        party_manager
            .complaints_to_process
            .insert(*dealer_address, complaint);
        party_manager
            .dealer_messages
            .insert(*dealer_address, dealer_message.clone());
    }

    fn create_handle_send_message_test_setup(
        _rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (TestSetup, Address, DkgManager, Address, DkgManager) {
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
    async fn test_handle_send_message_request_idempotent() {
        // Test that same request returns cached response (idempotent)
        let mut rng = rand::thread_rng();
        let (_setup, dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_message_test_setup(&mut rng);

        let dealer_message = dealer_manager.create_dealer_message(&mut rng);
        let request = SendMessageRequest {
            message: dealer_message.clone(),
        };

        // First request
        let response1 = receiver_manager
            .handle_send_message_request(dealer_address, &request)
            .unwrap();

        // Second request with same message - should return cached response
        let response2 = receiver_manager
            .handle_send_message_request(dealer_address, &request)
            .unwrap();

        // Responses should be identical (same signature bytes)
        assert_eq!(response1.signature, response2.signature);
    }

    #[tokio::test]
    async fn test_handle_send_message_request_equivocation() {
        // Test that different message from same dealer triggers error
        let mut rng = rand::thread_rng();
        let (_setup, dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_message_test_setup(&mut rng);

        // First message from dealer
        let dealer_message1 = dealer_manager.create_dealer_message(&mut rng);
        let request1 = SendMessageRequest {
            message: dealer_message1.clone(),
        };

        // Process first request successfully
        let response1 = receiver_manager
            .handle_send_message_request(dealer_address, &request1)
            .unwrap();
        // Verify we got a valid BLS signature (non-empty)
        assert!(!response1.signature.as_ref().is_empty());

        // Second DIFFERENT message from same dealer (equivocation)
        let dealer_message2 = dealer_manager.create_dealer_message(&mut rng);
        let request2 = SendMessageRequest {
            message: dealer_message2.clone(),
        };

        // Should return error
        let result = receiver_manager.handle_send_message_request(dealer_address, &request2);
        assert!(result.is_err());

        match result.unwrap_err() {
            DkgError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_address);
                assert!(reason.contains("different messages"));
            }
            _ => panic!("Expected InvalidMessage error"),
        }
    }

    #[tokio::test]
    async fn test_handle_send_message_request_invalid_shares_no_panic_on_retry() {
        // Second RPC call with invalid shares should not panic.

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(5);

        // Create dealer (party 1)
        let dealer_addr = setup.address(1);

        // Create a cheating message with corrupted shares for party 0
        let cheating_message = create_cheating_message(
            &setup, 1, // dealer_index
            0, // Corrupt shares for party 0 (receiver)
            &mut rng,
        );

        // Create receiver (party 0)
        let mut receiver_manager = setup.create_manager(0);

        let request = SendMessageRequest {
            message: cheating_message.clone(),
        };

        // First call: message is invalid, should return error
        let result1 = receiver_manager.handle_send_message_request(dealer_addr, &request);
        assert!(result1.is_err(), "Invalid shares should return error");
        match result1.unwrap_err() {
            DkgError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_addr);
                assert!(reason.contains("Invalid shares"));
            }
            _ => panic!("Expected InvalidMessage error"),
        }

        // Second call: same message - should return error with "previously rejected" message
        let result2 = receiver_manager.handle_send_message_request(dealer_addr, &request);
        assert!(result2.is_err(), "Second call should also return error");
        match result2.unwrap_err() {
            DkgError::InvalidMessage { sender, reason } => {
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

        // Verify receiver can still serve the message via RetrieveMessageRequest
        let retrieve_request = RetrieveMessageRequest {
            dealer: dealer_addr,
        };
        let retrieve_response = receiver_manager
            .handle_retrieve_message_request(&retrieve_request)
            .unwrap();
        assert_eq!(
            compute_message_hash(&retrieve_response.message),
            compute_message_hash(&cheating_message),
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
        let cheating_message = create_cheating_message(
            &setup, 1, // dealer_index
            0, // Corrupt shares for party 0 (receiver)
            &mut rng,
        );

        // Parties 2, 3, 4 can validate this message (shares are valid for them)
        // and will sign the certificate
        let mut signers = Vec::new();
        for i in 2..5usize {
            let addr = setup.address(i);
            let mut mgr = setup.create_manager(i);
            let sig = receive_dealer_message(&mut mgr, &cheating_message, dealer_addr).unwrap();
            signers.push((addr, mgr, sig));
        }

        // Create certificate signed by parties 2, 3, 4
        let message_hash = compute_message_hash(&cheating_message);
        let dkg_message = Dkg(DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        });
        let committee = setup.committee();
        let mut aggregator = BlsSignatureAggregator::new(committee, dkg_message);
        for (_, _, sig) in &signers {
            aggregator.add_signature(sig.clone()).unwrap();
        }
        let certificate = aggregator.finish().unwrap();

        // Party 0 doesn't have the message yet (simulating it wasn't received via SendMessage)
        let receiver_addr = setup.address(0);
        let mut receiver_manager = setup.create_manager(0);

        // Create P2P channel with signers who have the message
        let other_managers: HashMap<Address, DkgManager> = signers
            .into_iter()
            .map(|(addr, mgr, _)| (addr, mgr))
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, receiver_addr);

        // Retrieve message - should succeed even though shares are invalid for party 0
        let dkg_dealer_hash = DkgDealerMessageHash {
            dealer_address: dealer_addr,
            message_hash,
        };
        let result = receiver_manager
            .retrieve_dealer_message(&dkg_dealer_hash, &certificate, &mock_p2p)
            .await;

        assert!(
            result.is_ok(),
            "retrieve_dealer_message should succeed for invalid shares. Error: {:?}",
            result.err()
        );

        // Verify message was stored
        assert!(
            receiver_manager.dealer_messages.contains_key(&dealer_addr),
            "Invalid message should be stored for later complaint processing"
        );

        // Now process the message - should create a complaint
        receiver_manager
            .process_certified_dealer_message(dealer_addr)
            .unwrap();

        assert!(
            receiver_manager
                .complaints_to_process
                .contains_key(&dealer_addr),
            "Processing invalid message should create complaint"
        );
        assert!(
            !receiver_manager.dealer_outputs.contains_key(&dealer_addr),
            "Invalid message should not create dealer output"
        );
    }

    /// A store that tracks calls to store_dealer_message.
    struct TrackingPublicMessagesStore {
        stored: HashMap<Address, avss::Message>,
        store_count: Arc<AtomicUsize>,
    }

    impl TrackingPublicMessagesStore {
        fn new(store_count: Arc<AtomicUsize>) -> Self {
            Self {
                stored: HashMap::new(),
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

        fn get_dealer_message(&self, dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
            Ok(self.stored.get(dealer).cloned())
        }

        fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, avss::Message)>> {
            Ok(self.stored.iter().map(|(k, v)| (*k, v.clone())).collect())
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            self.stored.clear();
            Ok(())
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
        async fn send_dkg_message(
            &self,
            recipient: &Address,
            request: &SendMessageRequest,
        ) -> crate::communication::ChannelResult<SendMessageResponse> {
            self.inner.send_dkg_message(recipient, request).await
        }

        async fn retrieve_message(
            &self,
            party: &Address,
            request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            self.retrieve_count.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve_message(party, request).await
        }

        async fn complain(
            &self,
            party: &Address,
            request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            self.inner.complain(party, request).await
        }

        async fn send_rotation_messages(
            &self,
            recipient: &Address,
            request: &SendRotationMessagesRequest,
        ) -> crate::communication::ChannelResult<SendRotationMessagesResponse> {
            self.inner.send_rotation_messages(recipient, request).await
        }

        async fn retrieve_rotation_messages(
            &self,
            party: &Address,
            request: &RetrieveRotationMessagesRequest,
        ) -> crate::communication::ChannelResult<RetrieveRotationMessagesResponse> {
            self.inner.retrieve_rotation_messages(party, request).await
        }

        async fn rotation_complain(
            &self,
            party: &Address,
            request: &RotationComplainRequest,
        ) -> crate::communication::ChannelResult<RotationComplainResponse> {
            self.inner.rotation_complain(party, request).await
        }

        async fn get_public_dkg_output(
            &self,
            party: &Address,
            request: &GetPublicDkgOutputRequest,
        ) -> crate::communication::ChannelResult<GetPublicDkgOutputResponse> {
            self.inner.get_public_dkg_output(party, request).await
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
        let original_hash = compute_message_hash(&original_message);

        // Create tracking store with pre-populated message (simulating persistence)
        let store_count = Arc::new(AtomicUsize::new(0));
        let mut store = TrackingPublicMessagesStore::new(store_count.clone());
        store.pre_populate(dealer_address, original_message);

        // Simulate restart: create manager for same party with stored message
        let mut restarted_manager = setup.create_manager_with_store(0, Box::new(store));

        // Verify message was loaded
        assert_eq!(restarted_manager.address, dealer_address);
        let loaded = restarted_manager
            .dealer_messages
            .get(&dealer_address)
            .unwrap();
        assert_eq!(compute_message_hash(loaded), original_hash);

        // Create other managers for P2P
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| (setup.address(i), setup.create_manager(i)))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, dealer_address);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Run run_as_dealer - should reuse stored message
        let result = restarted_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;
        assert!(result.is_ok());

        // Verify store_dealer_message was NOT called (message already existed)
        assert_eq!(
            store_count.load(Ordering::SeqCst),
            0,
            "store_dealer_message should not be called when message already exists"
        );

        // Verify the message in dealer_messages still has the same hash
        let final_message = restarted_manager
            .dealer_messages
            .get(&dealer_address)
            .unwrap();
        assert_eq!(
            compute_message_hash(final_message),
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

        // Create tracking store with pre-populated messages (simulating restart)
        let store_count = Arc::new(AtomicUsize::new(0));
        let mut store = TrackingPublicMessagesStore::new(store_count.clone());
        store.pre_populate(dealer1_addr, msg1.clone());
        store.pre_populate(dealer2_addr, msg2.clone());

        // Create party (validator 3) with pre-stored messages
        let party_addr = setup.address(3);
        let mut party_manager = setup.create_manager_with_store(3, Box::new(store));

        // Verify messages were loaded on construction
        assert!(
            party_manager.dealer_messages.contains_key(&dealer1_addr),
            "dealer1 message should be loaded"
        );
        assert!(
            party_manager.dealer_messages.contains_key(&dealer2_addr),
            "dealer2 message should be loaded"
        );

        // Create certificates
        let epoch = setup.epoch();
        let signatures_1: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let message_hash = compute_message_hash(&msg1);
                let dkg_message = Dkg(DkgDealerMessageHash {
                    dealer_address: dealer1_addr,
                    message_hash,
                });
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let signatures_2: Vec<MemberSignature> = (0..3)
            .map(|i| {
                let addr = setup.address(i);
                let message_hash = compute_message_hash(&msg2);
                let dkg_message = Dkg(DkgDealerMessageHash {
                    dealer_address: dealer2_addr,
                    message_hash,
                });
                setup.signing_keys[i].sign(epoch, addr, &dkg_message)
            })
            .collect();

        let cert1 =
            create_test_certificate(setup.committee(), &msg1, dealer1_addr, signatures_1).unwrap();
        let cert2 =
            create_test_certificate(setup.committee(), &msg2, dealer2_addr, signatures_2).unwrap();

        // Create tracking P2P channel to verify retrieve_message is NOT called
        let retrieve_count = Arc::new(AtomicUsize::new(0));
        let mut dealers = HashMap::new();
        dealers.insert(dealer1_addr, dealer1_mgr);
        dealers.insert(dealer2_addr, dealer2_mgr);
        let inner_p2p = MockP2PChannel::new(dealers, party_addr);
        let tracking_p2p = TrackingP2PChannel::new(inner_p2p, retrieve_count.clone());

        // Create mock TOB with certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(vec![cert1, cert2]);

        // Run as party
        let result = party_manager
            .run_as_party(&tracking_p2p, &mut mock_tob)
            .await;
        assert!(result.is_ok());

        // Verify retrieve_message was NOT called (messages were already in memory)
        assert_eq!(
            retrieve_count.load(Ordering::SeqCst),
            0,
            "retrieve_message should not be called when messages are pre-stored"
        );

        // Verify dealer outputs were created from stored messages
        assert!(
            party_manager.dealer_outputs.contains_key(&dealer1_addr),
            "dealer1 output should be created"
        );
        assert!(
            party_manager.dealer_outputs.contains_key(&dealer2_addr),
            "dealer2 output should be created"
        );
    }

    /// For rotation tests that provides a completed DKG setup.
    struct RotationTestSetup {
        setup: TestSetup,
        certificates: HashMap<Address, Certificate>,
        dealer_messages: Vec<avss::Message>,
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

            // Each dealer creates a message
            let dealer_messages: Vec<_> = dealer_managers
                .iter()
                .map(|dm| dm.create_dealer_message(&mut rng))
                .collect();

            // Create certificates by collecting signatures
            let mut certificates = HashMap::new();
            for (i, message) in dealer_messages.iter().enumerate() {
                let dealer_address = dealer_managers[i].address;

                let validator_signatures = vec![
                    receive_dealer_message(&mut dealer_managers[0], message, dealer_address)
                        .unwrap(),
                    receive_dealer_message(&mut dealer_managers[1], message, dealer_address)
                        .unwrap(),
                ];

                let cert = create_test_certificate(
                    setup.committee(),
                    message,
                    dealer_address,
                    validator_signatures,
                )
                .unwrap();

                certificates.insert(dealer_address, cert);
            }

            Self {
                setup,
                certificates,
                dealer_messages,
                dealer_indices,
            }
        }

        fn certificates(&self) -> Vec<Certificate> {
            self.certificates.values().cloned().collect()
        }

        fn create_receiver_with_completed_dkg(
            &self,
            receiver_index: usize,
        ) -> (DkgManager, DkgOutput) {
            let mut receiver_manager = self.setup.create_manager(receiver_index);

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_message(&mut receiver_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = receiver_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            (receiver_manager, dkg_output)
        }

        /// Creates a manager with InMemoryPublicMessagesStore and completed DKG.
        /// The store contains all dealer messages for later reconstruction.
        fn create_receiver_with_memory_store(
            &self,
            receiver_index: usize,
        ) -> (DkgManager, DkgOutput) {
            let mut receiver_manager = self.setup.create_manager_with_store(
                receiver_index,
                Box::new(InMemoryPublicMessagesStore::new()),
            );

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_message(&mut receiver_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = receiver_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            (receiver_manager, dkg_output)
        }

        /// Creates a rotation dealer that has completed DKG and generates rotation messages.
        fn create_rotation_dealer(
            &self,
            dealer_index: usize,
        ) -> (DkgManager, DkgOutput, RotationMessages) {
            let mut rng = rand::thread_rng();
            let mut dealer_manager = self.setup.create_manager(dealer_index);

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_message(&mut dealer_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = dealer_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Create rotation messages
            let rotation_messages = dealer_manager.create_rotation_messages(&dkg_output, &mut rng);

            (dealer_manager, dkg_output, rotation_messages)
        }

        /// Creates a rotation dealer with InMemoryPublicMessagesStore.
        fn create_rotation_dealer_with_memory_store(
            &self,
            dealer_index: usize,
        ) -> (DkgManager, DkgOutput, RotationMessages) {
            let mut rng = rand::thread_rng();
            let mut dealer_manager = self.setup.create_manager_with_store(
                dealer_index,
                Box::new(InMemoryPublicMessagesStore::new()),
            );

            // Process all dealer messages
            for (i, message) in self.dealer_messages.iter().enumerate() {
                let dealer_address = self.setup.address(self.dealer_indices[i]);
                receive_dealer_message(&mut dealer_manager, message, dealer_address).unwrap();
            }

            // Complete DKG
            let dkg_output = dealer_manager
                .complete_dkg(self.certificates.keys().copied())
                .unwrap();

            // Create rotation messages
            let rotation_messages = dealer_manager.create_rotation_messages(&dkg_output, &mut rng);

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
        let rotation_outputs_before = receiver_manager.rotation_outputs.len();
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

        // Verify outputs were stored (rotation_dealer has weight=3, so creates 3 rotation messages)
        let rotation_outputs_after = receiver_manager.rotation_outputs.len();
        assert_eq!(
            rotation_outputs_after - rotation_outputs_before,
            rotation_messages.len(),
            "All rotation outputs should be stored"
        );

        // Test 2: Failure path - one invalid message in bundle should reject everything
        // Create a separate receiver to test failure case
        let (mut receiver_manager2, receiver2_dkg_output) =
            rotation_setup.create_receiver_with_completed_dkg(2);

        // Tamper with one message in the bundle to make it invalid
        // We swap the messages between two share indices to make the commitment check fail.
        // The commitment for share_index X won't match the message created for share_index Y.
        let tampered_messages = if rotation_messages.len() >= 2 {
            // Get two share indices and their messages
            let mut iter = rotation_messages.iter();
            let (&idx1, msg1) = iter.next().unwrap();
            let (&idx2, msg2) = iter.next().unwrap();
            // Swap: idx1 now maps to msg2, idx2 now maps to msg1
            let mut tampered: BTreeMap<ShareIndex, avss::Message> = rotation_messages
                .iter()
                .filter(|(idx, _)| **idx != idx1 && **idx != idx2)
                .map(|(&idx, msg)| (idx, msg.clone()))
                .collect();
            tampered.insert(idx1, msg2.clone());
            tampered.insert(idx2, msg1.clone());
            RotationMessages::new(tampered)
        } else if !rotation_messages.is_empty() {
            // If only one message, use a non-existent share index
            let (&_orig_idx, msg) = rotation_messages.iter().next().unwrap();
            let mut tampered = BTreeMap::new();
            tampered.insert(std::num::NonZeroU16::new(9999).unwrap(), msg.clone());
            RotationMessages::new(tampered)
        } else {
            rotation_messages.clone()
        };

        let rotation_outputs_before = receiver_manager2.rotation_outputs.len();
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
        let rotation_outputs_after = receiver_manager2.rotation_outputs.len();
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
            DkgError::InvalidMessage { reason, .. } => {
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
        let mut tampered_messages = rotation_messages.clone();
        let stolen_share_index = std::num::NonZeroU16::new(6).unwrap(); // Belongs to party 2, not party 0
        // Use any message as the content - the validation will fail on share_index ownership
        let any_message = rotation_messages.iter().next().unwrap().1.clone();
        tampered_messages.insert(stolen_share_index, any_message);

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
            DkgError::InvalidMessage { reason, .. } => {
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
            receiver_manager.rotation_outputs.is_empty(),
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
        test_manager.previous_dkg_output = Some(test_dkg_output.clone());

        // Create other managers for MockP2PChannel (validators 1-4)
        let mut other_managers_map = HashMap::new();
        for i in 1..5 {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_dkg_output = Some(output);
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
            let manager = other_managers.get_mut(&addr).unwrap();
            let prev_output = manager.previous_dkg_output.clone().unwrap();

            // Create rotation messages
            let rotation_messages = manager.create_rotation_messages(&prev_output, &mut rng);
            manager
                .rotation_dealer_messages
                .insert(addr, rotation_messages.clone());

            // Sign own messages
            let own_sig = manager
                .try_sign_rotation_messages(&prev_output, addr, &rotation_messages)
                .unwrap();

            // Collect signature from test_manager
            test_manager
                .rotation_dealer_messages
                .insert(addr, rotation_messages.clone());
            let test_sig = test_manager
                .try_sign_rotation_messages(&test_dkg_output, addr, &rotation_messages)
                .unwrap();

            // Create certificate
            let epoch = manager.dkg_config.epoch;
            let own_member_sig = MemberSignature::new(epoch, addr, own_sig);
            let test_member_sig = MemberSignature::new(epoch, test_addr, test_sig);
            let cert = create_rotation_test_certificate(
                rotation_setup.setup.committee(),
                &rotation_messages,
                addr,
                vec![own_member_sig, test_member_sig],
            )
            .unwrap();
            rotation_certificates.push(cert);
        }

        // Create mock TOB with rotation certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(rotation_certificates);

        // Run key rotation
        let new_output = test_manager
            .run_key_rotation(
                &rotation_setup.certificates(),
                &mock_p2p,
                &mut mock_tob,
                &mut rng,
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
        match &published[0].message {
            Rotation(m) => {
                assert_eq!(
                    m.dealer_address, test_addr,
                    "Published certificate should be from test manager"
                );
            }
            _ => panic!("Expected rotation certificate"),
        }
    }

    #[tokio::test]
    async fn test_prepare_previous_dkg_output_for_new_member() {
        let rotation_setup = RotationTestSetup::new();
        // RotationTestSetup uses weights [3, 2, 4, 1, 2] (total = 12, threshold = 4)

        // Create existing members (validators 0-4) with completed DKG and previous_dkg_output set
        let mut existing_managers_map = HashMap::new();
        for i in 0..5 {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_dkg_output = Some(output);
            existing_managers_map.insert(rotation_setup.setup.address(i), manager);
        }

        // Get the expected public DKG output from an existing member
        let expected_output = existing_managers_map
            .values()
            .next()
            .unwrap()
            .previous_dkg_output
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
            .set_epoch(epoch)
            .set_committees(committees);

        // Create new member's DkgManager
        let session_id = SessionId::new("testchain", epoch, &ProtocolType::DkgKeyGeneration);
        let mut new_member_manager = DkgManager::new(
            new_member_addr,
            &new_committee_set,
            session_id,
            new_member_encryption_key,
            new_member_signing_key,
            Box::new(InMemoryPublicMessagesStore::new()),
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

        // Call prepare_previous_dkg_output for new member
        let (previous_output, is_member_of_previous_committee) = new_member_manager
            .prepare_previous_dkg_output(&[], &mock_p2p)
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

        assert!(
            rotation_messages.len() >= 3,
            "Need at least 3 rotation messages for this test"
        );

        // Store rotation messages in receiver's state
        receiver_manager
            .rotation_dealer_messages
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
        let mut share_indices: Vec<_> = rotation_messages.keys().copied().collect();
        share_indices.sort();
        let share1_index = share_indices[0];
        let share2_index = share_indices[1];
        let share3_index = share_indices[2];

        let share1_original_output = receiver_manager
            .rotation_outputs
            .get(&share1_index)
            .expect("Share 1 should have output")
            .clone();

        // Remove share 2's output (will be re-processed)
        receiver_manager.rotation_outputs.remove(&share2_index);

        // Remove share 3's output and add a complaint
        receiver_manager.rotation_outputs.remove(&share3_index);

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
        receiver_manager
            .rotation_complaints_to_process
            .insert((rotation_dealer_addr, share3_index), complaint);

        let outputs_before = receiver_manager.rotation_outputs.len();

        // Call process_certified_rotation_message
        receiver_manager
            .process_certified_rotation_message(&rotation_dealer_addr, &dealer_dkg_output)
            .unwrap();

        // Verify share 1: output unchanged (skipped because already had output)
        let share1_output_after = receiver_manager
            .rotation_outputs
            .get(&share1_index)
            .expect("Share 1 should still have output");
        assert_eq!(
            share1_output_after.my_shares.shares.len(),
            share1_original_output.my_shares.shares.len(),
            "Share 1 output should not be overwritten"
        );

        // Verify share 2: was re-processed (new output created)
        assert!(
            receiver_manager
                .rotation_outputs
                .contains_key(&share2_index),
            "Share 2 should be re-processed"
        );

        // Verify share 3: NOT processed (skipped due to complaint)
        assert!(
            !receiver_manager
                .rotation_outputs
                .contains_key(&share3_index),
            "Share 3 should not have output (skipped due to complaint)"
        );
        assert!(
            receiver_manager
                .rotation_complaints_to_process
                .contains_key(&(rotation_dealer_addr, share3_index)),
            "Share 3 complaint should still exist"
        );

        // Verify only one new output was added (share 2)
        assert_eq!(
            receiver_manager.rotation_outputs.len() - outputs_before,
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
        dealer_manager.previous_dkg_output = Some(dealer_dkg_output.clone());

        // Get the share index and value for the first rotation message
        let first_share_index = *valid_rotation_messages.keys().next().unwrap();
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
        let mut cheating_messages = valid_rotation_messages.clone();
        cheating_messages.insert(cheating_share_index, cheating_message.clone());

        // Store the cheating messages in test manager
        test_manager
            .rotation_dealer_messages
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

        // Insert the complaint
        test_manager
            .rotation_complaints_to_process
            .insert((dealer_addr, first_share_index), valid_complaint);

        // Create other managers who have the cheating messages and can respond to complaints
        // These parties CAN decrypt their shares correctly (only test party's share is corrupted)
        let mut other_managers_map = HashMap::new();
        for i in [1usize, 3, 4] {
            let (mut manager, output) = rotation_setup.create_receiver_with_memory_store(i);
            manager.previous_dkg_output = Some(output.clone());
            // Store the cheating messages - other parties can still process them
            manager
                .rotation_dealer_messages
                .insert(dealer_addr, cheating_messages.clone());
            // Other parties process and get valid outputs (their shares are not corrupted)
            manager
                .try_sign_rotation_messages(&output, dealer_addr, &cheating_messages)
                .unwrap();
            other_managers_map.insert(rotation_setup.setup.address(i), manager);
        }

        // Add dealer to other managers (dealer also has the cheating message since they created it)
        dealer_manager
            .rotation_dealer_messages
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

        // Verify complaint exists before recovery
        assert!(
            test_manager
                .rotation_complaints_to_process
                .contains_key(&(dealer_addr, first_share_index)),
            "Should have complaint before recovery"
        );
        assert!(
            !test_manager
                .rotation_outputs
                .contains_key(&first_share_index),
            "Should not have output before recovery"
        );

        // Call recover_rotation_shares_via_complaints
        let result = test_manager
            .recover_rotation_shares_via_complaints(
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
        assert!(
            !test_manager
                .rotation_complaints_to_process
                .contains_key(&(dealer_addr, first_share_index)),
            "Complaint should be removed after successful recovery"
        );

        // Verify output was created
        assert!(
            test_manager
                .rotation_outputs
                .contains_key(&first_share_index),
            "Output should be created for recovered share"
        );
    }

    #[test]
    fn test_handle_rotation_complain_request_success() {
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

        // Get share info for the first rotation message
        let first_share_index = *valid_rotation_messages.keys().next().unwrap();
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
        let mut cheating_messages = valid_rotation_messages.clone();
        cheating_messages.insert(cheating_share_index, cheating_message.clone());

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
        responder_manager.previous_dkg_output = Some(responder_dkg_output.clone());

        // Responder stores the cheating messages
        responder_manager
            .rotation_dealer_messages
            .insert(dealer_addr, cheating_messages.clone());

        // Responder processes and gets valid outputs (their shares are not corrupted)
        responder_manager
            .try_sign_rotation_messages(&responder_dkg_output, dealer_addr, &cheating_messages)
            .unwrap();

        // Create the complaint request with one complaint (response will contain ALL shares)
        let request = RotationComplainRequest {
            dealer: dealer_addr,
            share_index: first_share_index,
            complaint,
        };

        // Handle the complaint request
        let result = responder_manager.handle_rotation_complain_request(&request);

        assert!(
            result.is_ok(),
            "Should successfully handle complaint: {:?}",
            result.err()
        );
        let response = result.unwrap();
        // Response contains ALL shares from the dealer (all-or-nothing semantics)
        assert_eq!(response.responses.len(), cheating_messages.len());
        // The complained share should be in the response
        assert!(
            response
                .responses
                .iter()
                .any(|r| r.share_index == first_share_index),
            "Response should include the complained share"
        );

        // Verify response is cached by dealer
        assert!(
            responder_manager
                .rotation_complaint_responses
                .contains_key(&dealer_addr),
            "Response should be cached"
        );
    }
}
