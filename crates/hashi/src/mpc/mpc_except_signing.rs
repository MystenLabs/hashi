// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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
pub use crate::mpc::types::NonceMessage;
pub use crate::mpc::types::ProtocolType;
pub use crate::mpc::types::ProtocolTypeIndicator;
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
use fastcrypto::serde_helpers::ToFromByteArray;
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
    pub dkg_messages: HashMap<Address, avss::Message>,
    pub rotation_messages: HashMap<Address, RotationMessages>,
    pub nonce_messages: HashMap<Address, NonceMessage>,
    pub message_responses: HashMap<Address, SendMessagesResponse>,
    pub complaints_to_process: HashMap<ComplaintsToProcessKey, complaint::Complaint>,
    pub complaint_responses: HashMap<Address, ComplaintResponses>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
    /// Must be `BTreeMap` so that all nodes iterate outputs in
    /// the same deterministic order when constructing `Presignatures`.
    pub dealer_nonce_outputs: BTreeMap<Address, batch_avss::ReceiverOutput>,
    /// Test-only: corrupt shares for this target address during dealing.
    test_corrupt_shares_for: Option<Address>,
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
        test_corrupt_shares_for: Option<Address>,
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
        let max_faulty = ((total_weight - threshold) / 2).min(threshold - 1);
        let dkg_config = DkgConfig::new(epoch, nodes, threshold, max_faulty)?;
        let party_id = committee
            .index_of(&address)
            .expect("address not in committee") as u16;
        let my_pk = PublicKey::<EncryptionGroupElement>::from_private_key(&encryption_key);
        let committee_pk = &dkg_config
            .nodes
            .node_id_to_node(party_id as PartyId)
            .expect("party_id not in nodes")
            .pk;
        let keys_match =
            my_pk.as_element().to_byte_array() == committee_pk.as_element().to_byte_array();
        tracing::info!(
            epoch,
            party_id,
            address = %address,
            threshold,
            total_weight,
            max_faulty,
            num_nodes = dkg_config.nodes.num_nodes(),
            encryption_keys_match = keys_match,
            my_encryption_pk = hex::encode(my_pk.as_element().to_byte_array()),
            committee_encryption_pk = hex::encode(committee_pk.as_element().to_byte_array()),
            "MpcManager initialized"
        );
        if !keys_match {
            tracing::error!(
                "Encryption key mismatch: config private key derives a different public key \
                 from what is registered on-chain for this node."
            );
        }
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
            dkg_messages: HashMap::new(),
            rotation_messages: HashMap::new(),
            nonce_messages: HashMap::new(),
            message_responses: HashMap::new(),
            complaints_to_process: HashMap::new(),
            complaint_responses: HashMap::new(),
            public_messages_store: public_message_store,
            chain_id: chain_id.to_string(),
            source_epoch,
            previous_output: None,
            batch_size_per_weight,
            dealer_nonce_outputs: BTreeMap::new(),
            test_corrupt_shares_for,
        };
        manager.load_stored_messages()?;
        Ok(manager)
    }

    pub fn handle_send_messages_request(
        &mut self,
        sender: Address,
        request: &SendMessagesRequest,
    ) -> MpcResult<SendMessagesResponse> {
        let existing = self.get_dealer_messages(request.messages.protocol_type(), &sender);
        if let Some(existing_messages) = existing {
            let existing_hash = compute_messages_hash(&existing_messages);
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
                reason: "Message previously received but no valid response was produced"
                    .to_string(),
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
            Messages::NonceGeneration(nonce) => {
                self.store_nonce_message(sender, nonce);
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
        if let Some(messages) = self.get_dealer_messages(request.protocol_type, &request.dealer) {
            return Ok(RetrieveMessagesResponse { messages });
        }
        // Mainly for last-epoch retrieval
        let messages = match request.protocol_type {
            ProtocolTypeIndicator::Dkg => self
                .public_messages_store
                .get_dealer_message(request.epoch, &request.dealer)
                .map_err(|e| MpcError::StorageError(e.to_string()))?
                .map(Messages::Dkg),
            ProtocolTypeIndicator::KeyRotation => self
                .public_messages_store
                .get_rotation_messages(request.epoch, &request.dealer)
                .map_err(|e| MpcError::StorageError(e.to_string()))?
                .map(Messages::Rotation),
            ProtocolTypeIndicator::NonceGeneration => None,
        };
        messages
            .map(|m| RetrieveMessagesResponse { messages: m })
            .ok_or_else(|| MpcError::NotFound(format!("Messages for dealer {:?}", request.dealer)))
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
            .get_dealer_messages(request.protocol_type, &request.dealer)
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
                    receiver.handle_complaint(&message, &request.complaint, partial_output)?;
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
            Messages::NonceGeneration(NonceMessage {
                batch_index,
                message,
            }) => {
                let nonce_output =
                    self.dealer_nonce_outputs
                        .get(&request.dealer)
                        .ok_or_else(|| {
                            MpcError::ProtocolFailed("No nonce output for complained dealer".into())
                        })?;
                let receiver = self.create_nonce_receiver(request.dealer, batch_index)?;
                let complaint_response =
                    receiver.handle_complaint(&message, &request.complaint, nonce_output)?;
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
    pub async fn run_dkg(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<DkgOutput> {
        let certified = tob_channel.certified_dealers().await;
        let (certified_reduced_weight, threshold) = {
            let mgr = mpc_manager.read().unwrap();
            let weight: u16 = certified
                .iter()
                .filter_map(|d| {
                    let party_id = mgr.committee.index_of(d)? as u16;
                    mgr.dkg_config.nodes.weight_of(party_id).ok()
                })
                .sum();
            (weight, mgr.dkg_config.threshold)
        };
        if certified_reduced_weight < threshold
            && let Err(e) = Self::run_dkg_as_dealer(mpc_manager, p2p_channel, tob_channel).await
        {
            tracing::error!("Dealer phase failed: {}. Continuing as party only.", e);
        }
        Self::run_dkg_as_party(mpc_manager, p2p_channel, tob_channel).await
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
            // Load rotation messages from DB for restart recovery.
            // For live rotation this is a no-op (no messages stored yet).
            for (dealer, message) in mgr
                .public_messages_store
                .list_all_rotation_messages()
                .map_err(|e| MpcError::StorageError(e.to_string()))?
            {
                if let Messages::Rotation(msgs) = message {
                    mgr.rotation_messages.insert(dealer, msgs);
                }
            }
        }
        if is_member_of_previous_committee
            && {
                let certified = ordered_broadcast_channel.certified_dealers().await;
                let mgr = mpc_manager.read().unwrap();
                let prev_committee = mgr.previous_committee.as_ref().expect(
                    "previous_committee must be set when is_member_of_previous_committee is true",
                );
                let prev_nodes = mgr.previous_nodes.as_ref().expect(
                    "previous_nodes must be set when is_member_of_previous_committee is true",
                );
                let certified_share_count: usize = certified
                    .iter()
                    .filter_map(|d| {
                        let party_id = prev_committee.index_of(d)? as u16;
                        prev_nodes.share_ids_of(party_id).ok()
                    })
                    .map(|ids| ids.len())
                    .sum();
                certified_share_count < previous.threshold as usize
            }
            && let Err(e) = Self::run_key_rotation_as_dealer(
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
            mgr.nonce_messages.clear();
            mgr.complaints_to_process.clear();
            mgr.message_responses.clear();
            mgr.complaint_responses.clear();
        }
        let certified = tob_channel.certified_dealers().await;
        let (certified_reduced_weight, required_reduced_weight) = {
            let mgr = mpc_manager.read().unwrap();
            let weight: u16 = certified
                .iter()
                .filter_map(|d| {
                    let party_id = mgr.committee.index_of(d)? as u16;
                    mgr.dkg_config.nodes.weight_of(party_id).ok()
                })
                .sum();
            (weight, mgr.required_nonce_weight() as u16)
        };
        if certified_reduced_weight < required_reduced_weight
            && let Err(e) =
                Self::run_as_nonce_dealer(mpc_manager, batch_index, p2p_channel, tob_channel).await
        {
            tracing::error!(
                "Nonce dealer phase failed: {}. Continuing as party only.",
                e
            );
        }
        let certified =
            Self::run_as_nonce_party(mpc_manager, batch_index, p2p_channel, tob_channel).await?;
        let mut mgr = mpc_manager.write().unwrap();
        // Keep only the outputs selected by the party phase. The RPC handler's
        // `try_sign_nonce_message` may have inserted additional outputs
        // concurrently — discard them so all nodes use the same deterministic set.
        let pre_filter = mgr.dealer_nonce_outputs.len();
        mgr.dealer_nonce_outputs
            .retain(|addr, _| certified.contains(addr));
        let dealers: Vec<_> = mgr.dealer_nonce_outputs.keys().collect();
        tracing::info!(
            "run_nonce_generation: epoch={}, batch_index={batch_index}, \
             {pre_filter} outputs before filter, {} after. dealers={dealers:?}",
            mgr.dkg_config.epoch,
            dealers.len(),
        );
        Ok(mgr.dealer_nonce_outputs.values().cloned().collect())
    }

    pub fn reconstruct_presignatures(
        &self,
        batch_index: u32,
        certs: &[(Address, hashi_types::move_types::DealerSubmissionV1)],
    ) -> MpcResult<Vec<batch_avss::ReceiverOutput>> {
        let certified_dealers = self.certified_nonce_dealers_from_certs(certs);
        let messages = self
            .public_messages_store
            .list_nonce_messages(batch_index)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        let mut outputs = BTreeMap::new();
        for (dealer, message) in messages {
            if !certified_dealers.contains(&dealer) {
                continue;
            }
            let receiver = self.create_nonce_receiver(dealer, batch_index)?;
            match receiver.process_message(&message)? {
                batch_avss::ProcessedMessage::Valid(output) => {
                    outputs.insert(dealer, output);
                }
                batch_avss::ProcessedMessage::Complaint(_) => {
                    tracing::info!(
                        "Skipping dealer {dealer:?} during presignature reconstruction: complaint"
                    );
                    continue;
                }
            }
        }
        let dealers: Vec<_> = outputs.keys().collect();
        tracing::info!(
            "reconstruct_presignatures(batch_index={batch_index}): {} dealers={dealers:?}",
            dealers.len(),
        );
        Ok(outputs.into_values().collect())
    }

    fn certified_nonce_dealers_from_certs(
        &self,
        certs: &[(Address, hashi_types::move_types::DealerSubmissionV1)],
    ) -> HashSet<Address> {
        let required_weight = self.required_nonce_weight();
        let mut weight_sum = 0u32;
        let mut certified = HashSet::new();
        for (dealer, _) in certs {
            if let Some(party_id) = self.committee.index_of(dealer)
                && let Ok(w) = self.dkg_config.nodes.weight_of(party_id as u16)
            {
                weight_sum += w as u32;
                certified.insert(*dealer);
                if weight_sum >= required_weight {
                    break;
                }
            }
        }
        certified
    }

    async fn run_dkg_as_dealer(
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
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
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
        if aggregator.reduced_weight() >= dealer_data.required_reduced_weight {
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

    async fn run_dkg_as_party(
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
                match mgr.dkg_messages.get(&dealer) {
                    None => true,
                    Some(stored_msg) => {
                        compute_messages_hash(&Messages::Dkg(stored_msg.clone()))
                            != message.messages_hash
                    }
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
                // Delete stale output from the RPC handler so the party phase
                // reprocesses with the retrieved (certified) message.
                mpc_manager
                    .write()
                    .unwrap()
                    .dealer_outputs
                    .remove(&DealerOutputsKey::Dkg(dealer));
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
                tracing::info!(
                    "DKG complaint detected for dealer {:?}, recovering via Complain RPC",
                    dealer
                );
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
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
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
        if aggregator.reduced_weight() >= dealer_data.required_reduced_weight {
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
        let mut certified_share_indices: Vec<ShareIndex> = Vec::new();
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
                match mgr.rotation_messages.get(&dealer) {
                    None => true,
                    Some(stored_msgs) => {
                        compute_messages_hash(&Messages::Rotation(stored_msgs.clone()))
                            != message.messages_hash
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
                // Delete stale outputs from the RPC handler so the party phase
                // reprocesses with the retrieved (certified) messages.
                {
                    let mut mgr = mpc_manager.write().unwrap();
                    for idx in &dealer_share_indices {
                        mgr.dealer_outputs.remove(&DealerOutputsKey::Rotation(*idx));
                    }
                }
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
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
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
        if aggregator.reduced_weight() >= dealer_data.required_reduced_weight {
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
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
    ) -> MpcResult<HashSet<Address>> {
        let required_weight = {
            let mgr = mpc_manager.read().unwrap();
            mgr.required_nonce_weight()
        };
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= required_weight {
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
                let mut mgr = mpc_manager.write().unwrap();
                mgr.needs_nonce_retrieval(dealer, batch_index, &message.messages_hash)
            };
            if needs_retrieval {
                tracing::info!(
                    "Nonce message for dealer {:?} not found in memory or DB, retrieving from signers",
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
                // Delete stale output from the RPC handler so the party phase
                // reprocesses with the retrieved (certified) message.
                mpc_manager
                    .write()
                    .unwrap()
                    .dealer_nonce_outputs
                    .remove(&dealer);
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
                tracing::info!(
                    "Nonce gen complaint detected for dealer {:?}, recovering via Complain RPC",
                    dealer
                );
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
        Ok(certified_dealers)
    }

    fn create_dealer_message(
        &self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> avss::Message {
        let dealer_session_id = self.session_id.dealer_session_id(&self.address);
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.dkg_config.nodes);
        let dealer = avss::Dealer::new(
            None,
            nodes,
            self.dkg_config.threshold,
            self.dkg_config.max_faulty,
            dealer_session_id.to_vec(),
        )
        .expect("checked threshold above");
        dealer.create_message(rng)
    }

    fn store_dkg_message(&mut self, dealer: Address, message: &avss::Message) -> MpcResult<()> {
        self.dkg_messages.insert(dealer, message.clone());
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
        self.rotation_messages.insert(dealer, messages.clone());
        self.public_messages_store
            .store_rotation_messages(&dealer, messages)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn store_nonce_message(&mut self, dealer: Address, nonce: &NonceMessage) {
        self.nonce_messages.insert(dealer, nonce.clone());
        if let Err(e) = self.public_messages_store.store_nonce_message(
            nonce.batch_index,
            &dealer,
            &nonce.message,
        ) {
            tracing::error!("Failed to persist nonce message for dealer {dealer:?}: {e}");
        }
    }

    fn needs_nonce_retrieval(
        &mut self,
        dealer: Address,
        batch_index: u32,
        expected_hash: &MessageHash,
    ) -> bool {
        if let Some(stored) = self.nonce_messages.get(&dealer) {
            return compute_messages_hash(&Messages::NonceGeneration(stored.clone()))
                != *expected_hash;
        }
        let found_in_db = self
            .public_messages_store
            .list_nonce_messages(batch_index)
            .ok()
            .and_then(|msgs| {
                msgs.into_iter()
                    .find(|(addr, _)| *addr == dealer)
                    .map(|(_, msg)| msg)
            });
        if let Some(db_msg) = found_in_db {
            let nonce = NonceMessage {
                batch_index,
                message: db_msg,
            };
            let hash_mismatch =
                compute_messages_hash(&Messages::NonceGeneration(nonce.clone())) != *expected_hash;
            self.nonce_messages.insert(dealer, nonce);
            hash_mismatch
        } else {
            true
        }
    }

    fn try_sign_dkg_message(
        &mut self,
        dealer: Address,
        messages: &Messages,
    ) -> MpcResult<BLS12381Signature> {
        let message = match messages {
            Messages::Dkg(msg) => msg,
            Messages::Rotation(_) | Messages::NonceGeneration(_) => {
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
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.dkg_config.nodes);
        let dealer = batch_avss::Dealer::new(
            nodes,
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
        Ok(Messages::NonceGeneration(NonceMessage {
            batch_index,
            message,
        }))
    }

    fn try_sign_nonce_message(
        &mut self,
        dealer: Address,
        messages: &Messages,
    ) -> MpcResult<BLS12381Signature> {
        let (batch_index, message) = match messages {
            Messages::NonceGeneration(nonce) => (nonce.batch_index, &nonce.message),
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
        let message = self
            .dkg_messages
            .get(&dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No message for dealer".into()))?
            .clone();
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
        let nonce = self
            .nonce_messages
            .get(&dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No message for dealer".into()))?;
        let (batch_index, message) = (nonce.batch_index, nonce.message.clone());
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
        let rotation_messages = self
            .rotation_messages
            .get(dealer)
            .ok_or_else(|| MpcError::ProtocolFailed("No rotation messages for dealer".into()))?
            .clone();
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
        match process_avss_message(
            &self.encryption_key,
            nodes,
            party_id,
            threshold,
            session_id,
            message,
            commitment,
        )? {
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
        let certified_dealers: Vec<Address> = certified_dealers.collect();
        tracing::info!(
            "complete_dkg: epoch={}, {} certified dealers={:?}, dealer_outputs has {} entries",
            self.dkg_config.epoch,
            certified_dealers.len(),
            certified_dealers,
            self.dealer_outputs.len(),
        );
        let outputs: HashMap<PartyId, avss::PartialOutput> = certified_dealers
            .into_iter()
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
        tracing::info!(
            "complete_dkg: epoch={}, result vk={}",
            self.dkg_config.epoch,
            hex::encode(combined_output.vk.to_byte_array())
        );
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
                tracing::warn!(
                    "Self in certificate signers but DKG message not in memory or DB for dealer {:?} \
                     — retrieving from other signers",
                    message.dealer_address
                );
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
                protocol_type: ProtocolTypeIndicator::Dkg,
                epoch: mgr.dkg_config.epoch,
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
                tracing::warn!(
                    "Self in certificate signers but nonce message not in memory or DB for dealer {:?} \
                     — retrieving from other signers",
                    message.dealer_address
                );
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
                protocol_type: ProtocolTypeIndicator::NonceGeneration,
                epoch: mgr.dkg_config.epoch,
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
                        let Messages::NonceGeneration(ref nonce) = response.messages else {
                            unreachable!(
                                "Hash matched nonce certificate but got {:?}",
                                std::mem::discriminant(&response.messages)
                            );
                        };
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.store_nonce_message(message.dealer_address, nonce);
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
        let messages = match self.dkg_messages.get(&self.address) {
            Some(msg) => Messages::Dkg(msg.clone()),
            None => {
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
        let messages = match self.rotation_messages.get(&self.address) {
            Some(msgs) => Messages::Rotation(msgs.clone()),
            None => {
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
        let messages = match self.nonce_messages.get(&self.address) {
            Some(nonce) => Messages::NonceGeneration(nonce.clone()),
            None => {
                let msgs = self.create_nonce_dealer_message(batch_index, rng)?;
                if let Messages::NonceGeneration(ref nonce) = msgs {
                    self.store_nonce_message(self.address, nonce);
                }
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
        let required_reduced_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        let reduced_weights: HashMap<Address, u16> = self
            .committee
            .members()
            .iter()
            .filter_map(|m| {
                let party_id = self.committee.index_of(&m.validator_address())? as u16;
                let weight = self.dkg_config.nodes.weight_of(party_id).ok()?;
                Some((m.validator_address(), weight))
            })
            .collect();
        let request = SendMessagesRequest { messages };
        DealerFlowData {
            request,
            recipients,
            messages_hash,
            my_signature,
            required_reduced_weight,
            committee: self.committee.clone(),
            reduced_weights,
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
                tracing::warn!(
                    "Self in certificate signers but rotation message not in memory or DB for dealer {:?} \
                     — retrieving from other signers",
                    message.dealer_address
                );
            }
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
                protocol_type: ProtocolTypeIndicator::KeyRotation,
                epoch: mgr.dkg_config.epoch,
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
                protocol_type: ProtocolTypeIndicator::Dkg,
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
            let message = mgr
                .dkg_messages
                .get(dealer)
                .expect("cannot have complaint without message")
                .clone();
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
                protocol_type: ProtocolTypeIndicator::NonceGeneration,
            };
            let nonce = mgr
                .nonce_messages
                .get(dealer)
                .expect("cannot have complaint without message");
            let (batch_index, message) = (nonce.batch_index, nonce.message.clone());
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
            tracing::info!(
                "Rotation complaint detected for dealer {:?}, recovering via Complain RPC",
                dealer
            );
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
            if let Messages::Dkg(msg) = message {
                self.dkg_messages.insert(dealer, msg);
            }
        }
        for (dealer, message) in self
            .public_messages_store
            .list_all_rotation_messages()
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            if let Messages::Rotation(msgs) = message {
                self.rotation_messages.insert(dealer, msgs);
            }
        }
        Ok(())
    }

    fn prepare_rotation_complain_request(
        &self,
        dealer: &Address,
        previous_dkg_output: &DkgOutput,
    ) -> MpcResult<Option<RotationComplainContext>> {
        let rotation_messages = self
            .rotation_messages
            .get(dealer)
            .expect("cannot have complaint without message");
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
            protocol_type: ProtocolTypeIndicator::KeyRotation,
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
                let nodes = self.maybe_corrupt_nodes_for_testing(&self.dkg_config.nodes);
                let dealer = avss::Dealer::new(
                    Some(share.value),
                    nodes,
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
            Messages::Dkg(_) | Messages::NonceGeneration(_) => {
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
        tracing::info!(
            "complete_key_rotation: epoch={}, {} certified_share_indices={:?}, \
             previous_vk={}, threshold={threshold}",
            self.dkg_config.epoch,
            certified_share_indices.len(),
            certified_share_indices,
            hex::encode(previous_dkg_output.public_key.to_byte_array()),
        );
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
        tracing::info!(
            "complete_key_rotation: epoch={}, result vk={}, matches_previous={}",
            self.dkg_config.epoch,
            hex::encode(combined.vk.to_byte_array()),
            combined.vk == previous_dkg_output.public_key,
        );
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

    fn reconstruct_previous_output(&self, certificates: &[CertificateV1]) -> MpcResult<DkgOutput> {
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
                unreachable!(
                    "Nonce generation certificates cannot appear as previous certificates for key rotation"
                )
            }
        }
    }

    fn reconstruct_from_dkg_certificates(
        &self,
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
        let mut outputs: HashMap<PartyId, avss::PartialOutput> = HashMap::new();
        let mut dealer_weight_sum = 0u16;
        for cert in certificates {
            // This matches the behavior of `run_as_party` during DKG, which also
            // stops at threshold.
            if dealer_weight_sum >= previous_threshold {
                break;
            }
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
            let dealer_party_id = previous_committee
                .index_of(&dealer_address)
                .expect("certified dealer must be in previous committee")
                as u16;
            let session_id = source_session_id
                .dealer_session_id(&dealer_address)
                .to_vec();
            match process_avss_message(
                &self.encryption_key,
                previous_nodes.clone(),
                previous_party_id,
                previous_threshold,
                session_id,
                &message,
                None,
            )? {
                avss::ProcessedMessage::Valid(output) => {
                    outputs.insert(dealer_party_id, output);
                }
                avss::ProcessedMessage::Complaint(_) => {
                    tracing::info!(
                        "Skipping dealer {:?} during DKG reconstruction: complaint (shares invalid for this node)",
                        dealer_address
                    );
                    continue;
                }
            }
            let dealer_weight = previous_nodes
                .weight_of(dealer_party_id)
                .expect("party_id must be valid");
            dealer_weight_sum += dealer_weight;
        }
        if dealer_weight_sum < previous_threshold {
            return Err(MpcError::NotEnoughApprovals {
                needed: previous_threshold as usize,
                got: dealer_weight_sum as usize,
            });
        }
        let dealer_ids: Vec<_> = outputs.keys().copied().collect();
        tracing::info!(
            "reconstruct_from_dkg_certificates: {} dealers (party_ids={:?}), \
             dealer_weight_sum={dealer_weight_sum}, threshold={previous_threshold}",
            dealer_ids.len(),
            dealer_ids,
        );
        let combined_output =
            avss::ReceiverOutput::complete_dkg(previous_threshold, &previous_nodes, outputs)
                .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "reconstruct_from_dkg_certificates: result vk={}",
            hex::encode(combined_output.vk.to_byte_array()),
        );
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
        &self,
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
        let mut local_outputs: HashMap<ShareIndex, avss::PartialOutput> = HashMap::new();
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
            for (share_index, message) in rotation_msgs {
                let session_id = source_session_id
                    .rotation_session_id(&dealer_address, share_index)
                    .to_vec();
                // Pass None for commitment. Re-verification would be redundant since we trust the certificates.
                match process_avss_message(
                    &self.encryption_key,
                    previous_nodes.clone(),
                    previous_party_id,
                    previous_threshold,
                    session_id,
                    &message,
                    None,
                )? {
                    avss::ProcessedMessage::Valid(output) => {
                        local_outputs.insert(share_index, output);
                    }
                    avss::ProcessedMessage::Complaint(_) => {
                        tracing::info!(
                            "Skipping dealer {:?} share {} during rotation reconstruction: complaint",
                            dealer_address,
                            share_index
                        );
                        continue;
                    }
                }
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
                let output = local_outputs.get(&share_index).ok_or_else(|| {
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
        let used_indices: Vec<_> = indexed_outputs.iter().map(|o| o.index).collect();
        tracing::info!(
            "reconstruct_from_rotation_certificates: {} share_indices={:?}, \
             threshold={previous_threshold}",
            used_indices.len(),
            used_indices,
        );
        let combined = avss::ReceiverOutput::complete_key_rotation(
            previous_threshold,
            previous_party_id,
            &previous_nodes,
            &indexed_outputs,
        )
        .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "reconstruct_from_rotation_certificates: result vk={}",
            hex::encode(combined.vk.to_byte_array()),
        );
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
            Self::retrieve_missing_previous_messages(
                mpc_manager,
                previous_certificates,
                p2p_channel,
            )
            .await?;
            let mgr = Arc::clone(mpc_manager);
            let certs = previous_certificates.to_vec();
            spawn_blocking(move || {
                let mgr = mgr.read().unwrap();
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
        tracing::info!(
            "prepare_previous_output: is_member_of_previous_committee={is_member_of_previous_committee}, \
             previous_vk={}",
            hex::encode(previous.public_key.to_byte_array()),
        );
        Ok((previous, is_member_of_previous_committee))
    }

    async fn retrieve_missing_previous_messages(
        mpc_manager: &Arc<RwLock<Self>>,
        previous_certificates: &[CertificateV1],
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        for cert in previous_certificates {
            let (msg, certificate, protocol_type, needs_retrieval) = match cert {
                CertificateV1::Dkg(dkg_cert) => {
                    let msg = dkg_cert.message();
                    let missing = {
                        let mgr = mpc_manager.read().unwrap();
                        mgr.public_messages_store
                            .get_dealer_message(mgr.source_epoch, &msg.dealer_address)
                            .map_err(|e| MpcError::StorageError(e.to_string()))?
                            .is_none()
                    };
                    (
                        msg,
                        dkg_cert as &DealerCertificate,
                        ProtocolTypeIndicator::Dkg,
                        missing,
                    )
                }
                CertificateV1::Rotation(rotation_cert) => {
                    let msg = rotation_cert.message();
                    let missing = {
                        let mgr = mpc_manager.read().unwrap();
                        mgr.public_messages_store
                            .get_rotation_messages(mgr.source_epoch, &msg.dealer_address)
                            .map_err(|e| MpcError::StorageError(e.to_string()))?
                            .is_none()
                    };
                    (
                        msg,
                        rotation_cert as &DealerCertificate,
                        ProtocolTypeIndicator::KeyRotation,
                        missing,
                    )
                }
                _ => continue,
            };
            if needs_retrieval {
                tracing::info!(
                    "Previous epoch {:?} message for dealer {:?} not in DB, retrieving from signers",
                    protocol_type,
                    msg.dealer_address
                );
                Self::retrieve_message_using_previous_committee(
                    mpc_manager,
                    msg,
                    certificate,
                    protocol_type,
                    p2p_channel,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn retrieve_message_using_previous_committee(
        mpc_manager: &Arc<RwLock<Self>>,
        message: &DealerMessagesHash,
        certificate: &DealerCertificate,
        protocol_type: ProtocolTypeIndicator,
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (request, signers) = {
            let mgr = mpc_manager.read().unwrap();
            let previous_committee = mgr.previous_committee.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("Previous committee required for message retrieval".into())
            })?;
            let request = RetrieveMessagesRequest {
                dealer: message.dealer_address,
                protocol_type,
                epoch: mgr.source_epoch,
            };
            let signers = certificate.signers(previous_committee).map_err(|_| {
                MpcError::ProtocolFailed(
                    "Certificate does not match the previous committee".to_string(),
                )
            })?;
            (request, signers)
        };
        for signer in signers {
            match p2p_channel.retrieve_messages(&signer, &request).await {
                Ok(response) => {
                    if compute_messages_hash(&response.messages) == message.messages_hash {
                        let mut mgr = mpc_manager.write().unwrap();
                        match &response.messages {
                            Messages::Dkg(msg) => {
                                mgr.store_dkg_message(message.dealer_address, msg)?;
                            }
                            Messages::Rotation(msgs) => {
                                mgr.store_rotation_messages(message.dealer_address, msgs)?;
                            }
                            _ => {
                                tracing::warn!(
                                    "Unexpected message type from signer {:?} for dealer {:?}",
                                    signer,
                                    message.dealer_address
                                );
                                continue;
                            }
                        }
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
                        "Failed to retrieve previous epoch message from signer {:?}: {}",
                        signer,
                        e
                    );
                }
            }
        }
        Err(MpcError::PairwiseCommunicationError(format!(
            "Could not retrieve previous epoch message for dealer {:?} from any signer",
            message.dealer_address
        )))
    }

    fn get_dealer_messages(
        &self,
        protocol_type: ProtocolTypeIndicator,
        dealer: &Address,
    ) -> Option<Messages> {
        match protocol_type {
            ProtocolTypeIndicator::Dkg => self
                .dkg_messages
                .get(dealer)
                .map(|m| Messages::Dkg(m.clone())),
            ProtocolTypeIndicator::KeyRotation => self
                .rotation_messages
                .get(dealer)
                .map(|m| Messages::Rotation(m.clone())),
            ProtocolTypeIndicator::NonceGeneration => self
                .nonce_messages
                .get(dealer)
                .map(|m| Messages::NonceGeneration(m.clone())),
        }
    }

    fn required_nonce_weight(&self) -> u32 {
        2 * self.dkg_config.max_faulty as u32 + 1
    }

    fn maybe_corrupt_nodes_for_testing(
        &self,
        nodes: &Nodes<EncryptionGroupElement>,
    ) -> Nodes<EncryptionGroupElement> {
        if let Some(target) = self.test_corrupt_shares_for
            && let Some(party_id) = self.committee.index_of(&target)
        {
            let mut node_list: Vec<Node<EncryptionGroupElement>> = nodes.iter().cloned().collect();
            let random_key = PrivateKey::new(&mut rand::thread_rng());
            node_list[party_id].pk = PublicKey::from_private_key(&random_key);
            tracing::info!(
                "Test: corrupted encryption key for party {party_id} ({})",
                target
            );
            return Nodes::new(node_list).unwrap();
        }
        nodes.clone()
    }
}

pub fn fallback_encryption_public_key() -> PublicKey<EncryptionGroupElement> {
    static FALLBACK_ENCRYPTION_PK: LazyLock<PublicKey<EncryptionGroupElement>> =
        LazyLock::new(|| PublicKey::from(EncryptionGroupElement::hash_to_group_element(b"hashi")));
    FALLBACK_ENCRYPTION_PK.clone()
}

fn process_avss_message(
    encryption_key: &PrivateKey<EncryptionGroupElement>,
    nodes: Nodes<EncryptionGroupElement>,
    party_id: u16,
    threshold: u16,
    session_id: Vec<u8>,
    message: &avss::Message,
    commitment: Option<G>,
) -> MpcResult<avss::ProcessedMessage> {
    let receiver = avss::Receiver::new(
        nodes,
        party_id,
        threshold,
        session_id,
        commitment,
        encryption_key.clone(),
    );
    receiver.process_message(message).map_err(MpcError::from)
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
#[path = "mpc_except_signing_tests.rs"]
mod tests;
