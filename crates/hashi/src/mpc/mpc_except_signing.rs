// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::communication::OrderedBroadcastChannel;
use crate::communication::P2PChannel;
use crate::communication::send_to_many;
use crate::communication::with_timeout_and_retry;
use crate::constants::is_production_sui_chain;
use crate::metrics::MPC_LABEL_DKG;
use crate::metrics::MPC_LABEL_KEY_ROTATION;
use crate::metrics::MPC_LABEL_NONCE_GENERATION;
use crate::metrics::Metrics;
use crate::mpc::types::CertificateV1;
pub use crate::mpc::types::ComplainRequest;
pub use crate::mpc::types::ComplaintResponses;
pub use crate::mpc::types::ComplaintResponsesKey;
pub use crate::mpc::types::ComplaintsToProcessKey;
use crate::mpc::types::DealerCertificate;
pub use crate::mpc::types::DealerFlowData;
use crate::mpc::types::DealerMessagesHash;
pub use crate::mpc::types::DealerOutputsKey;
pub use crate::mpc::types::EncryptionGroupElement;
pub use crate::mpc::types::GetPublicMpcOutputRequest;
pub use crate::mpc::types::GetPublicMpcOutputResponse;
pub use crate::mpc::types::MessageHash;
pub use crate::mpc::types::MessageResponsesKey;
pub use crate::mpc::types::Messages;
use crate::mpc::types::MpcConfig;
pub use crate::mpc::types::MpcError;
pub use crate::mpc::types::MpcOutput;
pub use crate::mpc::types::MpcResult;
pub use crate::mpc::types::NonceMessage;
pub use crate::mpc::types::NonceReconstructionOutcome;
pub use crate::mpc::types::ProtocolType;
pub use crate::mpc::types::ProtocolTypeIndicator;
pub use crate::mpc::types::PublicMpcOutput;
use crate::mpc::types::ReconstructionOutcome;
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

const MAX_BASIS_POINTS: u32 = 10000;
const MIN_TOTAL_WEIGHT_AFTER_REDUCTION: u16 = 100;
const PRUNE_KEEP_RECENT_BATCHES: u32 = 2;

pub struct MpcManager {
    // Immutable during the epoch
    pub party_id: PartyId,
    pub address: Address,
    pub mpc_config: MpcConfig,
    pub session_id: SessionId,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub signing_key: Bls12381PrivateKey,
    pub committee: Committee,
    pub previous_committee: Option<Committee>,
    pub previous_nodes: Option<Nodes<EncryptionGroupElement>>,
    pub previous_threshold: Option<u16>,
    /// Used to reconstruct source session IDs during certificate reconstruction.
    chain_id: String,
    pub previous_epoch: u64,
    previous_output: Option<MpcOutput>,
    current_output: Option<MpcOutput>,
    pub batch_size_per_weight: u16,

    // Mutable during the epoch
    // TODO: Rename these fields so it is clear at the call site which are
    // backed by persistent store and which live only in memory.
    pub dealer_outputs: HashMap<DealerOutputsKey, avss::PartialOutput>,
    pub dkg_messages: HashMap<Address, avss::Message>,
    pub rotation_messages: HashMap<Address, RotationMessages>,
    pub nonce_messages: HashMap<(u32, Address), NonceMessage>,
    pub message_responses: HashMap<MessageResponsesKey, MpcResult<SendMessagesResponse>>,
    pub complaints_to_process: HashMap<ComplaintsToProcessKey, complaint::Complaint>,
    pub complaint_responses: HashMap<ComplaintResponsesKey, ComplaintResponses>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
    /// Must be `BTreeMap` so that all nodes iterate outputs in
    /// the same deterministic order when constructing `Presignatures`.
    pub dealer_nonce_outputs: BTreeMap<(u32, Address), batch_avss::ReceiverOutput>,
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
        chain_id: &str,
        weight_divisor: Option<u16>,
        batch_size_per_weight: u16,
        test_corrupt_shares_for: Option<Address>,
    ) -> MpcResult<Self> {
        if weight_divisor.is_some() {
            assert!(
                !is_production_sui_chain(chain_id),
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
        let (nodes, threshold, max_faulty) = build_reduced_nodes(
            &committee,
            committee.mpc_threshold_in_basis_points(),
            committee.mpc_max_faulty_in_basis_points(),
            committee.mpc_weight_reduction_allowed_delta(),
            weight_divisor,
            chain_id,
        )?;
        let total_weight = nodes.total_weight();
        let mpc_config = MpcConfig::new(epoch, nodes, threshold, max_faulty);
        let party_id = committee
            .index_of(&address)
            .expect("address not in committee") as u16;
        let my_pk = PublicKey::<EncryptionGroupElement>::from_private_key(&encryption_key);
        let committee_pk = &mpc_config
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
            num_nodes = mpc_config.nodes.num_nodes(),
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
        let (previous_epoch, previous_committee) = if committee_set.pending_epoch_change().is_some()
        {
            // Live reconfig
            let source = committee_set.epoch();
            (source, committee_set.committees().get(&source).cloned())
        } else {
            match committee_set
                .committees()
                .range(..epoch)
                .next_back()
                .map(|(&k, c)| (k, c.clone()))
            {
                // Rotation recovery
                Some((prev, committee)) => (prev, Some(committee)),
                // Genesis or post-initial-DKG single-committee state
                None => (committee_set.epoch(), None),
            }
        };
        let (previous_nodes, previous_threshold) = match previous_committee.as_ref() {
            Some(prev_committee) => {
                let (nodes, threshold, _prev_max_faulty) = build_reduced_nodes(
                    prev_committee,
                    prev_committee.mpc_threshold_in_basis_points(),
                    prev_committee.mpc_max_faulty_in_basis_points(),
                    prev_committee.mpc_weight_reduction_allowed_delta(),
                    weight_divisor,
                    chain_id,
                )?;
                (Some(nodes), Some(threshold))
            }
            None => (None, None),
        };
        let mut manager = Self {
            party_id,
            address,
            mpc_config,
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
            previous_epoch,
            previous_output: None,
            current_output: None,
            batch_size_per_weight,
            dealer_nonce_outputs: BTreeMap::new(),
            test_corrupt_shares_for,
        };
        manager.load_stored_messages()?;
        Ok(manager)
    }

    // Only for devnet key recovery CLI tool
    pub fn set_previous_epoch(&mut self, epoch: u64) {
        self.previous_epoch = epoch;
    }

    pub fn handle_send_messages_request(
        &mut self,
        sender: Address,
        request: &SendMessagesRequest,
    ) -> MpcResult<SendMessagesResponse> {
        let cache_key = match &request.messages {
            Messages::Dkg(_) => MessageResponsesKey::Dkg { sender },
            Messages::Rotation(_) => MessageResponsesKey::Rotation { sender },
            Messages::NonceGeneration(nonce) => MessageResponsesKey::NonceGen {
                batch_index: nonce.batch_index,
                sender,
            },
        };
        let batch_index = match &request.messages {
            Messages::NonceGeneration(nonce) => Some(nonce.batch_index),
            _ => None,
        };
        let existing =
            self.get_dealer_messages(request.messages.protocol_type(), &sender, batch_index);
        if let Some(existing_messages) = existing {
            let existing_hash = compute_messages_hash(&existing_messages);
            let incoming_hash = compute_messages_hash(&request.messages);
            if existing_hash != incoming_hash {
                return Err(MpcError::InvalidMessage {
                    sender,
                    reason: "Dealer sent different messages".to_string(),
                });
            }
            if let Some(cached) = self.message_responses.get(&cache_key) {
                return cached.clone();
            }
            tracing::info!(
                "handle_send_messages_request: existing message from {sender:?} but no \
                 cached response (e.g. post-restart), re-processing"
            );
        }
        let result = match &request.messages {
            Messages::Dkg(msg) => {
                self.cache_and_persist_dkg_message(self.mpc_config.epoch, sender, msg)?;
                self.try_sign_dkg_message(sender, &request.messages)
            }
            Messages::Rotation(msgs) => {
                let previous = self
                    .previous_output
                    .clone()
                    .ok_or_else(|| MpcError::NotReady("Rotation not started".into()))?;
                self.cache_and_persist_rotation_messages(self.mpc_config.epoch, sender, msgs)?;
                self.try_sign_rotation_messages(&previous, sender, &request.messages)
            }
            Messages::NonceGeneration(nonce) => {
                self.cache_and_persist_nonce_message(self.mpc_config.epoch, sender, nonce)?;
                self.try_sign_nonce_message(sender, &request.messages)
            }
        }
        .map(|signature| SendMessagesResponse { signature });
        self.message_responses.insert(cache_key, result.clone());
        result
    }

    pub fn handle_retrieve_messages_request(
        &self,
        request: &RetrieveMessagesRequest,
    ) -> MpcResult<RetrieveMessagesResponse> {
        if request.epoch == self.mpc_config.epoch
            && let Some(messages) = self.get_dealer_messages(
                request.protocol_type,
                &request.dealer,
                request.batch_index,
            )
        {
            return Ok(RetrieveMessagesResponse { messages });
        }
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
            ProtocolTypeIndicator::NonceGeneration => {
                let batch_index = request.batch_index.ok_or_else(|| {
                    MpcError::NotFound("batch_index required for nonce gen retrieval".into())
                })?;
                self.public_messages_store
                    .get_nonce_message(request.epoch, batch_index, &request.dealer)
                    .map_err(|e| MpcError::StorageError(e.to_string()))?
                    .map(|msg| {
                        Messages::NonceGeneration(NonceMessage {
                            batch_index,
                            message: msg,
                        })
                    })
            }
        };
        messages
            .map(|m| RetrieveMessagesResponse { messages: m })
            .ok_or_else(|| MpcError::NotFound(format!("Messages for dealer {:?}", request.dealer)))
    }

    pub fn handle_complain_request(
        &mut self,
        request: &ComplainRequest,
    ) -> MpcResult<ComplaintResponses> {
        let cache_key = match request.protocol_type {
            ProtocolTypeIndicator::Dkg => ComplaintResponsesKey::Dkg {
                dealer: request.dealer,
            },
            ProtocolTypeIndicator::KeyRotation => ComplaintResponsesKey::Rotation {
                dealer: request.dealer,
            },
            ProtocolTypeIndicator::NonceGeneration => {
                let batch_index = request
                    .batch_index
                    .ok_or_else(|| MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "batch_index required for nonce complaint".into(),
                    })?;
                ComplaintResponsesKey::NonceGen {
                    batch_index,
                    dealer: request.dealer,
                }
            }
        };
        // It is safe to return a response from cache since we already know that dealer was malicious.
        let cache_is_current = request.epoch == self.mpc_config.epoch;
        if cache_is_current && let Some(cached_response) = self.complaint_responses.get(&cache_key)
        {
            return Ok(cached_response.clone());
        }
        let cached_messages = cache_is_current
            .then(|| {
                self.get_dealer_messages(
                    request.protocol_type,
                    &request.dealer,
                    request.batch_index,
                )
            })
            .flatten();
        let messages = if let Some(m) = cached_messages {
            m
        } else {
            let from_db = match request.protocol_type {
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
                ProtocolTypeIndicator::NonceGeneration => request
                    .batch_index
                    .map(|batch_index| -> MpcResult<Option<Messages>> {
                        Ok(self
                            .public_messages_store
                            .get_nonce_message(request.epoch, batch_index, &request.dealer)
                            .map_err(|e| MpcError::StorageError(e.to_string()))?
                            .map(|msg| {
                                Messages::NonceGeneration(NonceMessage {
                                    batch_index,
                                    message: msg,
                                })
                            }))
                    })
                    .transpose()?
                    .flatten(),
            };
            from_db.ok_or_else(|| MpcError::NotFound("No message from dealer".into()))?
        };
        let responses = match messages {
            Messages::Dkg(message) => {
                let partial_output =
                    self.get_or_derive_dkg_output(&request.dealer, &message, request.epoch)?;
                let (nodes, party_id, threshold) = self.config_for_epoch(request.epoch)?;
                let session_id = self
                    .base_session_id_for_epoch(request.epoch, &ProtocolType::Dkg)
                    .dealer_session_id(&request.dealer);
                let receiver = avss::Receiver::new(
                    nodes,
                    party_id,
                    threshold,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                );
                let complaint_response =
                    receiver.handle_complaint(&message, &request.complaint, &partial_output)?;
                ComplaintResponses::Dkg(complaint_response)
            }
            Messages::Rotation(rotation_messages) => {
                let complained_share_index =
                    request
                        .share_index
                        .ok_or_else(|| MpcError::InvalidMessage {
                            sender: request.dealer,
                            reason: "Rotation complaint requires share_index".into(),
                        })?;
                let (nodes, party_id, threshold) = self.config_for_epoch(request.epoch)?;
                let mut all_outputs: BTreeMap<ShareIndex, avss::PartialOutput> = BTreeMap::new();
                for (&share_index, message) in &rotation_messages {
                    all_outputs.insert(
                        share_index,
                        self.get_or_derive_rotation_output(
                            &request.dealer,
                            share_index,
                            message,
                            request.epoch,
                        )?,
                    );
                }
                let complained_message = rotation_messages
                    .get(&complained_share_index)
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation message for complained share_index {}",
                            complained_share_index
                        ))
                    })?;
                let complained_output =
                    all_outputs.get(&complained_share_index).ok_or_else(|| {
                        MpcError::ProtocolFailed("No output for complained share".into())
                    })?;
                let session_id = self
                    .base_session_id_for_epoch(request.epoch, &ProtocolType::KeyRotation)
                    .rotation_session_id(&request.dealer, complained_share_index);
                let receiver = avss::Receiver::new(
                    nodes,
                    party_id,
                    threshold,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                );
                let complained_response = receiver.handle_complaint(
                    complained_message,
                    &request.complaint,
                    complained_output,
                )?;
                let mut responses = BTreeMap::new();
                for (&share_index, output) in &all_outputs {
                    let response = if share_index == complained_share_index {
                        complained_response.clone()
                    } else {
                        complaint::ComplaintResponse::new(self.party_id, output.my_shares.clone())
                    };
                    responses.insert(share_index, response);
                }
                ComplaintResponses::Rotation(responses)
            }
            Messages::NonceGeneration(NonceMessage {
                batch_index,
                message,
            }) => {
                let nonce_output = if let Some(output) = self
                    .dealer_nonce_outputs
                    .get(&(batch_index, request.dealer))
                {
                    output.clone()
                } else {
                    let receiver = self.create_nonce_receiver(request.dealer, batch_index)?;
                    match receiver.process_message(&message)? {
                        batch_avss::ProcessedMessage::Valid(output) => output,
                        batch_avss::ProcessedMessage::Complaint(_) => {
                            return Err(MpcError::NotFound(
                                "Peer is also a victim of this nonce dealer — cannot help with complaint".into(),
                            ));
                        }
                    }
                };
                let receiver = self.create_nonce_receiver(request.dealer, batch_index)?;
                let complaint_response =
                    receiver.handle_complaint(&message, &request.complaint, &nonce_output)?;
                ComplaintResponses::NonceGeneration(complaint_response)
            }
        };
        if cache_is_current {
            self.complaint_responses
                .insert(cache_key, responses.clone());
        }
        Ok(responses)
    }

    pub fn handle_get_public_mpc_output_request(
        &self,
        request: &GetPublicMpcOutputRequest,
    ) -> MpcResult<GetPublicMpcOutputResponse> {
        let output = if request.epoch == self.mpc_config.epoch {
            // Reduce availability lag
            self.current_output.as_ref()
        } else if request.epoch == self.previous_epoch {
            self.previous_output.as_ref()
        } else {
            return Err(MpcError::NotFound(format!(
                "no DKG output for epoch {} (current epoch is {})",
                request.epoch, self.mpc_config.epoch
            )));
        };
        let output = output.ok_or_else(|| {
            MpcError::NotFound(format!(
                "DKG output for epoch {} not yet available",
                request.epoch
            ))
        })?;
        Ok(GetPublicMpcOutputResponse {
            output: PublicMpcOutput::from_mpc_output(output),
        })
    }

    // TODO: Consider making dealer and party flows concurrent
    pub async fn run_dkg(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<MpcOutput> {
        let certified = tob_channel.certified_dealers().await;
        let (certified_reduced_weight, threshold) = {
            let mgr = mpc_manager.read().unwrap();
            let weight: u32 = certified
                .iter()
                .filter_map(|d| {
                    let party_id = mgr.committee.index_of(d)? as u16;
                    mgr.mpc_config
                        .nodes
                        .weight_of(party_id)
                        .ok()
                        .map(|w| w as u32)
                })
                .sum();
            (weight, mgr.mpc_config.threshold as u32)
        };
        if certified_reduced_weight < threshold
            && let Err(e) =
                Self::run_dkg_as_dealer(mpc_manager, p2p_channel, tob_channel, metrics).await
        {
            tracing::error!("Dealer phase failed: {}. Continuing as party only.", e);
        }
        let output = Self::run_dkg_as_party(mpc_manager, p2p_channel, tob_channel, metrics).await?;
        mpc_manager.write().unwrap().current_output = Some(output.clone());
        Ok(output)
    }

    pub async fn run_key_rotation(
        mpc_manager: &Arc<RwLock<Self>>,
        previous_certificates: &[CertificateV1],
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<MpcOutput> {
        tracing::info!("run_key_rotation: starting prepare_previous_output");
        let _timer = metrics
            .mpc_rotation_prepare_previous_duration_seconds
            .with_label_values(&[MPC_LABEL_KEY_ROTATION])
            .start_timer();
        let (previous, is_member_of_previous_committee) =
            Self::prepare_previous_output(mpc_manager, previous_certificates, p2p_channel).await?;
        drop(_timer);
        tracing::info!(
            "run_key_rotation: prepare_previous_output complete, \
             is_member={is_member_of_previous_committee}",
        );
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
        // Optimization: a node that fell back to the new-member path has empty
        // key shares and cannot generate valid rotation messages.
        let has_previous_shares = !previous.key_shares.shares.is_empty();
        if is_member_of_previous_committee
            && has_previous_shares
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
                        let messages = mgr.rotation_messages.get(d)?;
                        if messages.is_empty() {
                            return None;
                        }
                        let party_id = prev_committee.index_of(d)? as u16;
                        prev_nodes.share_ids_of(party_id).ok()
                    })
                    .map(|ids| ids.len())
                    .sum();
                tracing::info!(
                    "run_key_rotation: certified_share_count={certified_share_count}, \
                     threshold={}, skip_dealer={}",
                    previous.threshold,
                    certified_share_count >= previous.threshold as usize,
                );
                certified_share_count < previous.threshold as usize
            }
            && let Err(e) = Self::run_key_rotation_as_dealer(
                mpc_manager,
                &previous,
                p2p_channel,
                ordered_broadcast_channel,
                metrics,
            )
            .await
        {
            tracing::error!(
                "Rotation dealer phase failed: {}. Continuing as party only.",
                e
            );
        }
        tracing::info!("run_key_rotation: entering party phase");
        let output = Self::run_key_rotation_as_party(
            mpc_manager,
            &previous,
            p2p_channel,
            ordered_broadcast_channel,
            metrics,
        )
        .await?;
        mpc_manager.write().unwrap().current_output = Some(output.clone());
        Ok(output)
    }

    pub async fn run_nonce_generation(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<Vec<batch_avss::ReceiverOutput>> {
        Self::prune_nonce_state(mpc_manager, batch_index);
        let certified = tob_channel.certified_dealers().await;
        let (certified_reduced_weight, required_reduced_weight) = {
            let mgr = mpc_manager.read().unwrap();
            let weight: u32 = certified
                .iter()
                .filter_map(|d| {
                    let party_id = mgr.committee.index_of(d)? as u16;
                    mgr.mpc_config
                        .nodes
                        .weight_of(party_id)
                        .ok()
                        .map(|w| w as u32)
                })
                .sum();
            (weight, mgr.required_nonce_weight())
        };
        if certified_reduced_weight < required_reduced_weight
            && let Err(e) = Self::run_as_nonce_dealer(
                mpc_manager,
                batch_index,
                p2p_channel,
                tob_channel,
                metrics,
            )
            .await
        {
            tracing::error!(
                "Nonce dealer phase failed: {}. Continuing as party only.",
                e
            );
        }
        let certified =
            Self::run_as_nonce_party(mpc_manager, batch_index, p2p_channel, tob_channel, metrics)
                .await?;
        let mut mgr = mpc_manager.write().unwrap();
        // Keep only the outputs selected by the party phase. The RPC handler's
        // `try_sign_nonce_message` may have inserted additional outputs
        // concurrently — discard them so all nodes use the same deterministic set.
        let pre_filter = mgr
            .dealer_nonce_outputs
            .keys()
            .filter(|(b, _)| *b == batch_index)
            .count();
        let mut dealers = Vec::new();
        let mut outputs = Vec::new();
        mgr.dealer_nonce_outputs.retain(|(b, addr), output| {
            if *b != batch_index {
                return true;
            }
            if certified.contains(addr) {
                dealers.push(*addr);
                outputs.push(output.clone());
                true
            } else {
                false
            }
        });
        tracing::info!(
            "run_nonce_generation: epoch={}, batch_index={batch_index}, \
             {pre_filter} outputs before filter, {} after. dealers={dealers:?}",
            mgr.mpc_config.epoch,
            dealers.len(),
        );
        Ok(outputs)
    }

    pub fn reconstruct_presignatures(
        &self,
        batch_index: u32,
        certs: &[(Address, hashi_types::move_types::DealerSubmissionV1)],
    ) -> MpcResult<NonceReconstructionOutcome> {
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
            if let Some(output) = self.dealer_nonce_outputs.get(&(batch_index, dealer)) {
                outputs.insert(dealer, output.clone());
                continue;
            }
            let receiver = self.create_nonce_receiver(dealer, batch_index)?;
            match receiver.process_message(&message)? {
                batch_avss::ProcessedMessage::Valid(output) => {
                    outputs.insert(dealer, output);
                }
                batch_avss::ProcessedMessage::Complaint(complaint) => {
                    return Ok(NonceReconstructionOutcome::NeedsComplaintRecovery {
                        dealer_address: dealer,
                        complaint,
                        batch_index,
                    });
                }
            }
        }
        let dealers: Vec<_> = outputs.keys().collect();
        tracing::info!(
            "reconstruct_presignatures(batch_index={batch_index}): {} dealers={dealers:?}",
            dealers.len(),
        );
        Ok(NonceReconstructionOutcome::Success(
            outputs.into_values().collect(),
        ))
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
                && let Ok(w) = self.mpc_config.nodes.weight_of(party_id as u16)
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
        metrics: &Metrics,
    ) -> MpcResult<()> {
        // TODO(Optimization): Skip dealer phase if certificate is already on TOB
        let _timer = metrics
            .mpc_dealer_crypto_duration_seconds
            .with_label_values(&[MPC_LABEL_DKG])
            .start_timer();
        let dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_dkg_dealer_flow(&mut rng)
            })
            .await?
        };
        drop(_timer);
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let _timer = metrics
            .mpc_p2p_broadcast_duration_seconds
            .with_label_values(&[MPC_LABEL_DKG])
            .start_timer();
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        drop(_timer);
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
            let _timer = metrics
                .mpc_cert_publish_duration_seconds
                .with_label_values(&[MPC_LABEL_DKG])
                .start_timer();
            with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
            drop(_timer);
        }
        Ok(())
    }

    async fn run_dkg_as_party(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<MpcOutput> {
        let threshold = {
            let mgr = mpc_manager.read().unwrap();
            mgr.mpc_config.threshold as u32
        };
        let mut certified_dealers = HashSet::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= threshold {
                break;
            }
            let _timer = metrics
                .mpc_tob_poll_duration_seconds
                .with_label_values(&[MPC_LABEL_DKG])
                .start_timer();
            let cert = tob_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            drop(_timer);
            let CertificateV1::Dkg(dkg_cert) = cert else {
                continue;
            };
            let message = dkg_cert.message();
            let dealer = message.dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            {
                let _timer = metrics
                    .mpc_cert_verify_duration_seconds
                    .with_label_values(&[MPC_LABEL_DKG])
                    .start_timer();
                let mgr = Arc::clone(mpc_manager);
                let cert = dkg_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                drop(_timer);
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
                let _timer = metrics
                    .mpc_message_retrieval_duration_seconds
                    .with_label_values(&[MPC_LABEL_DKG])
                    .start_timer();
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
                drop(_timer);
                // Delete stale output from the RPC handler so the party phase
                // reprocesses with the retrieved (certified) message.
                mpc_manager
                    .write()
                    .unwrap()
                    .dealer_outputs
                    .remove(&DealerOutputsKey::Dkg(dealer));
            }
            let _timer = metrics
                .mpc_message_process_duration_seconds
                .with_label_values(&[MPC_LABEL_DKG])
                .start_timer();
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
            drop(_timer);
            if has_complaint {
                tracing::info!(
                    "DKG complaint detected for dealer {:?}, recovering via Complain RPC",
                    dealer
                );
                let _timer = metrics
                    .mpc_complaint_recovery_duration_seconds
                    .with_label_values(&[MPC_LABEL_DKG])
                    .start_timer();
                let (signers, epoch, message) = {
                    let mgr = mpc_manager.read().unwrap();
                    let signers = dkg_cert
                        .signers(&mgr.committee)
                        .expect("certificate verified above");
                    let message = mgr
                        .dkg_messages
                        .get(&dealer)
                        .ok_or_else(|| {
                            MpcError::ProtocolFailed(format!(
                                "No DKG message for dealer {:?} during complaint recovery",
                                dealer
                            ))
                        })?
                        .clone();
                    (signers, mgr.mpc_config.epoch, message)
                };
                let recovered = Self::recover_shares_via_complaint(
                    mpc_manager,
                    &dealer,
                    &message,
                    signers,
                    p2p_channel,
                    epoch,
                )
                .await?;
                {
                    let mut mgr = mpc_manager.write().unwrap();
                    mgr.dealer_outputs
                        .insert(DealerOutputsKey::Dkg(dealer), recovered);
                    mgr.complaints_to_process
                        .remove(&ComplaintsToProcessKey::Dkg(dealer));
                }
                drop(_timer);
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
                mgr.mpc_config
                    .nodes
                    .weight_of(party_id)
                    .map_err(|_| MpcError::ProtocolFailed("Missing dealer weight".to_string()))?
            };
            dealer_weight_sum += dealer_weight as u32;
            certified_dealers.insert(dealer);
        }
        let _timer = metrics
            .mpc_completion_duration_seconds
            .with_label_values(&[MPC_LABEL_DKG])
            .start_timer();
        let output = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mgr = mgr.read().unwrap();
                mgr.complete_dkg(certified_dealers.into_iter())
            })
            .await?
        };
        drop(_timer);
        Ok(output)
    }

    async fn run_key_rotation_as_dealer(
        mpc_manager: &Arc<RwLock<Self>>,
        previous: &MpcOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<()> {
        // TODO(Optimization): Skip dealer phase if certificate is already on TOB
        let _timer = metrics
            .mpc_dealer_crypto_duration_seconds
            .with_label_values(&[MPC_LABEL_KEY_ROTATION])
            .start_timer();
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
        drop(_timer);
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let _timer = metrics
            .mpc_p2p_broadcast_duration_seconds
            .with_label_values(&[MPC_LABEL_KEY_ROTATION])
            .start_timer();
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        drop(_timer);
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
            let _timer = metrics
                .mpc_cert_publish_duration_seconds
                .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                .start_timer();
            with_timeout_and_retry(|| ordered_broadcast_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
            drop(_timer);
        }
        Ok(())
    }

    async fn run_key_rotation_as_party(
        mpc_manager: &Arc<RwLock<Self>>,
        previous: &MpcOutput,
        p2p_channel: &impl P2PChannel,
        ordered_broadcast_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<MpcOutput> {
        let mut certified_share_indices: Vec<ShareIndex> = Vec::new();
        let mut certified_dealers = HashSet::new();
        tracing::info!(
            "run_key_rotation_as_party: waiting for certs (threshold={})",
            previous.threshold,
        );
        loop {
            if certified_share_indices.len() >= previous.threshold as usize {
                break;
            }
            let _timer = metrics
                .mpc_tob_poll_duration_seconds
                .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                .start_timer();
            let cert = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            drop(_timer);
            let CertificateV1::Rotation(rotation_cert) = cert else {
                continue;
            };
            let message = rotation_cert.message();
            let dealer = message.dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            {
                let _timer = metrics
                    .mpc_cert_verify_duration_seconds
                    .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                    .start_timer();
                let mgr = Arc::clone(mpc_manager);
                let cert = rotation_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                drop(_timer);
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
                let _timer = metrics
                    .mpc_message_retrieval_duration_seconds
                    .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                    .start_timer();
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
                drop(_timer);
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
                let _timer = metrics
                    .mpc_message_process_duration_seconds
                    .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                    .start_timer();
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
                drop(_timer);
            }
            let (signers, epoch, rotation_msgs) = {
                let mgr = mpc_manager.read().unwrap();
                let signers = rotation_cert
                    .signers(&mgr.committee)
                    .expect("certificate verified above");
                let msgs = mgr
                    .rotation_messages
                    .get(&dealer)
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation messages for dealer {:?} during complaint recovery",
                            dealer
                        ))
                    })?
                    .clone();
                (signers, mgr.mpc_config.epoch, msgs)
            };
            let _timer = metrics
                .mpc_complaint_recovery_duration_seconds
                .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                .start_timer();
            let recovered = Self::recover_rotation_shares_via_complaints(
                mpc_manager,
                &dealer,
                &rotation_msgs,
                signers,
                p2p_channel,
                epoch,
            )
            .await?;
            {
                let mut mgr = mpc_manager.write().unwrap();
                for (share_index, output) in recovered {
                    mgr.dealer_outputs
                        .insert(DealerOutputsKey::Rotation(share_index), output);
                    mgr.complaints_to_process
                        .remove(&ComplaintsToProcessKey::Rotation(dealer, share_index));
                }
            }
            drop(_timer);
            // Only add indices that have outputs (avoids adding indices for
            // dealers with empty rotation messages, e.g. a node that rejoined
            // with no shares from the new-member fallback).
            {
                let mgr = mpc_manager.read().unwrap();
                for idx in dealer_share_indices {
                    if !certified_share_indices.contains(&idx)
                        && mgr
                            .dealer_outputs
                            .contains_key(&DealerOutputsKey::Rotation(idx))
                    {
                        certified_share_indices.push(idx);
                    }
                }
            }
            certified_dealers.insert(dealer);
            tracing::info!(
                "run_key_rotation_as_party: processed dealer {dealer}, \
                 certified_dealers={}, certified_shares={}",
                certified_dealers.len(),
                certified_share_indices.len(),
            );
        }
        tracing::info!("run_key_rotation_as_party: threshold met, calling complete_key_rotation",);
        let _timer = metrics
            .mpc_completion_duration_seconds
            .with_label_values(&[MPC_LABEL_KEY_ROTATION])
            .start_timer();
        let output = {
            let mgr = Arc::clone(mpc_manager);
            let previous = previous.clone();
            spawn_blocking(move || {
                let mut mgr = mgr.write().unwrap();
                mgr.complete_key_rotation(&previous, &certified_share_indices)
            })
            .await?
        };
        drop(_timer);
        Ok(output)
    }

    async fn run_as_nonce_dealer(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<()> {
        let _timer = metrics
            .mpc_dealer_crypto_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_nonce_dealer_flow(batch_index, &mut rng)
            })
            .await?
        };
        drop(_timer);
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.messages_hash.clone(),
            dealer_data.reduced_weights,
        );
        aggregator
            .add_signature(dealer_data.my_signature)
            .expect("first signature should always be valid");
        let _timer = metrics
            .mpc_p2p_broadcast_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let results = send_to_many(
            dealer_data.recipients.iter().copied(),
            dealer_data.request,
            |addr, req| async move { p2p_channel.send_messages(&addr, &req).await },
        )
        .await;
        drop(_timer);
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
            let _timer = metrics
                .mpc_cert_publish_duration_seconds
                .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                .start_timer();
            with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
                .await
                .map_err(|e| {
                    MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
            drop(_timer);
        }
        Ok(())
    }

    async fn run_as_nonce_party(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
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
            let _timer = metrics
                .mpc_tob_poll_duration_seconds
                .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                .start_timer();
            let cert = tob_channel
                .receive()
                .await
                .map_err(|e| MpcError::BroadcastError(e.to_string()))?;
            drop(_timer);
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
                let _timer = metrics
                    .mpc_cert_verify_duration_seconds
                    .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                    .start_timer();
                let mgr = Arc::clone(mpc_manager);
                let cert = nonce_cert.clone();
                let verified = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee.verify_signature(&cert)
                })
                .await;
                drop(_timer);
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
                let _timer = metrics
                    .mpc_message_retrieval_duration_seconds
                    .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                    .start_timer();
                Self::retrieve_nonce_message(
                    mpc_manager,
                    message,
                    &nonce_cert,
                    p2p_channel,
                    batch_index,
                )
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Failed to retrieve nonce message from any signer for dealer {:?}: {}",
                        &dealer,
                        e
                    );
                    e
                })?;
                drop(_timer);
                // Delete stale output from the RPC handler so the party phase
                // reprocesses with the retrieved (certified) message.
                mpc_manager
                    .write()
                    .unwrap()
                    .dealer_nonce_outputs
                    .remove(&(batch_index, dealer));
            }
            let _timer = metrics
                .mpc_message_process_duration_seconds
                .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                .start_timer();
            let has_complaint = {
                let mgr = Arc::clone(mpc_manager);
                spawn_blocking(move || {
                    let mut mgr = mgr.write().unwrap();
                    if !mgr
                        .dealer_nonce_outputs
                        .contains_key(&(batch_index, dealer))
                        && !mgr.complaints_to_process.contains_key(
                            &ComplaintsToProcessKey::NonceGeneration {
                                batch_index,
                                dealer,
                            },
                        )
                    {
                        mgr.process_certified_nonce_message(dealer, batch_index)?;
                    }
                    Ok::<_, MpcError>(mgr.complaints_to_process.contains_key(
                        &ComplaintsToProcessKey::NonceGeneration {
                            batch_index,
                            dealer,
                        },
                    ))
                })
                .await?
            };
            drop(_timer);
            if has_complaint {
                tracing::info!(
                    "Nonce gen complaint detected for dealer {:?}, recovering via Complain RPC",
                    dealer
                );
                let _timer = metrics
                    .mpc_complaint_recovery_duration_seconds
                    .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                    .start_timer();
                let (signers, epoch) = {
                    let mgr = mpc_manager.read().unwrap();
                    let signers = nonce_cert
                        .signers(&mgr.committee)
                        .expect("certificate verified above");
                    (signers, mgr.mpc_config.epoch)
                };
                Self::recover_nonce_shares_via_complaint(
                    mpc_manager,
                    &dealer,
                    batch_index,
                    signers,
                    p2p_channel,
                    epoch,
                )
                .await?;
                drop(_timer);
            }
            let dealer_weight = {
                let mgr = mpc_manager.read().unwrap();
                if !mgr
                    .dealer_nonce_outputs
                    .contains_key(&(batch_index, dealer))
                {
                    tracing::warn!("No nonce output for {:?} after processing", dealer);
                    continue;
                }
                let party_id = mgr
                    .committee
                    .index_of(&dealer)
                    .expect("dealer must be in committee") as u16;
                mgr.mpc_config
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
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.mpc_config.nodes);
        let dealer = avss::Dealer::new(
            None,
            nodes,
            self.mpc_config.threshold,
            dealer_session_id.to_vec(),
        )
        .expect("checked threshold above");
        dealer.create_message(rng)
    }

    fn cache_and_persist_dkg_message(
        &mut self,
        epoch: u64,
        dealer: Address,
        message: &avss::Message,
    ) -> MpcResult<()> {
        self.dkg_messages.insert(dealer, message.clone());
        self.public_messages_store
            .store_dealer_message(epoch, &dealer, message)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn cache_and_persist_rotation_messages(
        &mut self,
        epoch: u64,
        dealer: Address,
        messages: &RotationMessages,
    ) -> MpcResult<()> {
        self.rotation_messages.insert(dealer, messages.clone());
        self.public_messages_store
            .store_rotation_messages(epoch, &dealer, messages)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn cache_and_persist_nonce_message(
        &mut self,
        epoch: u64,
        dealer: Address,
        nonce: &NonceMessage,
    ) -> MpcResult<()> {
        self.nonce_messages
            .insert((nonce.batch_index, dealer), nonce.clone());
        self.public_messages_store
            .store_nonce_message(epoch, nonce.batch_index, &dealer, &nonce.message)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn needs_nonce_retrieval(
        &mut self,
        dealer: Address,
        batch_index: u32,
        expected_hash: &MessageHash,
    ) -> bool {
        if let Some(stored) = self.nonce_messages.get(&(batch_index, dealer)) {
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
            self.nonce_messages.insert((batch_index, dealer), nonce);
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
            self.mpc_config.nodes.clone(),
            self.party_id,
            self.mpc_config.threshold,
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
                        .sign(self.mpc_config.epoch, self.address, &dkg_message);
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
            self.mpc_config.epoch,
            batch_index,
            &dealer,
        );
        batch_avss::Receiver::new(
            self.mpc_config.nodes.clone(),
            self.party_id,
            dealer_party_id,
            self.mpc_config.threshold,
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
            self.mpc_config.epoch,
            batch_index,
            &self.address,
        );
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.mpc_config.nodes);
        let dealer = batch_avss::Dealer::new(
            nodes,
            self.party_id,
            self.mpc_config.threshold,
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
                self.dealer_nonce_outputs
                    .insert((batch_index, dealer), output);
                let nonce_message = DealerMessagesHash {
                    dealer_address: dealer,
                    messages_hash: compute_messages_hash(messages),
                };
                let signature =
                    self.signing_key
                        .sign(self.mpc_config.epoch, self.address, &nonce_message);
                Ok(signature.signature().clone())
            }
            batch_avss::ProcessedMessage::Complaint(_) => Err(MpcError::InvalidMessage {
                sender: dealer,
                reason: "Invalid nonce shares".to_string(),
            }),
        }
    }

    fn prune_nonce_state(mpc_manager: &Arc<RwLock<Self>>, batch_index: u32) {
        let cutoff = batch_index.saturating_sub(PRUNE_KEEP_RECENT_BATCHES - 1);
        if cutoff == 0 {
            return;
        }
        let mut mgr = mpc_manager.write().unwrap();
        mgr.nonce_messages.retain(|(b, _), _| *b >= cutoff);
        mgr.dealer_nonce_outputs.retain(|(b, _), _| *b >= cutoff);
        mgr.complaints_to_process.retain(|k, _| match k {
            ComplaintsToProcessKey::NonceGeneration { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
        mgr.message_responses.retain(|k, _| match k {
            MessageResponsesKey::NonceGen { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
        mgr.complaint_responses.retain(|k, _| match k {
            ComplaintResponsesKey::NonceGen { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
    }

    fn process_certified_dkg_message(&mut self, dealer: Address) -> MpcResult<()> {
        let output_key = DealerOutputsKey::Dkg(dealer);
        let complaint_key = ComplaintsToProcessKey::Dkg(dealer);
        let message = self
            .dkg_messages
            .get(&dealer)
            .ok_or_else(|| MpcError::NotFound("No DKG message for dealer".into()))?
            .clone();
        let session_id = self.session_id.dealer_session_id(&dealer).to_vec();
        self.process_and_store_message(
            self.mpc_config.nodes.clone(),
            self.party_id,
            self.mpc_config.threshold,
            session_id,
            &message,
            None,
            output_key,
            complaint_key,
        )
    }

    fn process_certified_nonce_message(
        &mut self,
        dealer: Address,
        batch_index: u32,
    ) -> MpcResult<()> {
        let message = match self.nonce_messages.get(&(batch_index, dealer)) {
            Some(nonce) => nonce.message.clone(),
            None => self
                .public_messages_store
                .get_nonce_message(self.mpc_config.epoch, batch_index, &dealer)
                .map_err(|e| MpcError::StorageError(e.to_string()))?
                .ok_or_else(|| MpcError::NotFound("No nonce message for dealer".into()))?,
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
            self.mpc_config.epoch,
            batch_index,
            &dealer,
        );
        let receiver = batch_avss::Receiver::new(
            self.mpc_config.nodes.clone(),
            self.party_id,
            dealer_party_id,
            self.mpc_config.threshold,
            dealer_sid.to_vec(),
            self.encryption_key.clone(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        match receiver.process_message(&message)? {
            batch_avss::ProcessedMessage::Valid(output) => {
                self.dealer_nonce_outputs
                    .insert((batch_index, dealer), output);
            }
            batch_avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints_to_process.insert(
                    ComplaintsToProcessKey::NonceGeneration {
                        batch_index,
                        dealer,
                    },
                    complaint,
                );
            }
        }
        Ok(())
    }

    fn process_certified_rotation_message(
        &mut self,
        dealer: &Address,
        previous_dkg_output: &MpcOutput,
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
                self.mpc_config.nodes.clone(),
                self.party_id,
                self.mpc_config.threshold,
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
    ) -> MpcResult<MpcOutput> {
        let threshold = self.mpc_config.threshold;
        let certified_dealers: Vec<Address> = certified_dealers.collect();
        tracing::info!(
            "complete_dkg: epoch={}, {} certified dealers={:?}, dealer_outputs has {} entries",
            self.mpc_config.epoch,
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
            avss::ReceiverOutput::complete_dkg(threshold, &self.mpc_config.nodes, outputs)
                .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "complete_dkg: epoch={}, result vk={}",
            self.mpc_config.epoch,
            hex::encode(combined_output.vk.to_byte_array())
        );
        Ok(MpcOutput {
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
                epoch: mgr.mpc_config.epoch,
                batch_index: None,
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
                        let epoch = mgr.mpc_config.epoch;
                        mgr.cache_and_persist_dkg_message(epoch, message.dealer_address, msg)?;
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
        batch_index: u32,
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
                epoch: mgr.mpc_config.epoch,
                batch_index: Some(batch_index),
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
                        let epoch = mgr.mpc_config.epoch;
                        mgr.cache_and_persist_nonce_message(epoch, message.dealer_address, nonce)?;
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

    fn prepare_dkg_dealer_flow(
        &mut self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.dkg_messages.get(&self.address) {
            Some(msg) => Messages::Dkg(msg.clone()),
            None => match self
                .public_messages_store
                .get_dealer_message(self.mpc_config.epoch, &self.address)
            {
                Ok(Some(msg)) => {
                    self.dkg_messages.insert(self.address, msg.clone());
                    Messages::Dkg(msg)
                }
                Ok(None) => {
                    let msg = self.create_dealer_message(rng);
                    self.cache_and_persist_dkg_message(self.mpc_config.epoch, self.address, &msg)?;
                    Messages::Dkg(msg)
                }
                Err(e) => return Err(MpcError::StorageError(e.to_string())),
            },
        };
        let signature = self.try_sign_dkg_message(self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn prepare_rotation_dealer_flow(
        &mut self,
        previous: &MpcOutput,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.rotation_messages.get(&self.address) {
            Some(msgs) => Messages::Rotation(msgs.clone()),
            None => match self
                .public_messages_store
                .get_rotation_messages(self.mpc_config.epoch, &self.address)
            {
                Ok(Some(msgs)) => {
                    self.rotation_messages.insert(self.address, msgs.clone());
                    Messages::Rotation(msgs)
                }
                Ok(None) => {
                    let msgs = self.create_rotation_messages(previous, rng);
                    self.cache_and_persist_rotation_messages(
                        self.mpc_config.epoch,
                        self.address,
                        &msgs,
                    )?;
                    Messages::Rotation(msgs)
                }
                Err(e) => return Err(MpcError::StorageError(e.to_string())),
            },
        };
        let signature = self.try_sign_rotation_messages(previous, self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn prepare_nonce_dealer_flow(
        &mut self,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.nonce_messages.get(&(batch_index, self.address)) {
            Some(nonce) => Messages::NonceGeneration(nonce.clone()),
            None => match self.public_messages_store.get_nonce_message(
                self.mpc_config.epoch,
                batch_index,
                &self.address,
            ) {
                Ok(Some(msg)) => {
                    let nonce = NonceMessage {
                        batch_index,
                        message: msg,
                    };
                    self.nonce_messages
                        .insert((batch_index, self.address), nonce.clone());
                    Messages::NonceGeneration(nonce)
                }
                Ok(None) => {
                    let msgs = self.create_nonce_dealer_message(batch_index, rng)?;
                    if let Messages::NonceGeneration(ref nonce) = msgs {
                        self.cache_and_persist_nonce_message(
                            self.mpc_config.epoch,
                            self.address,
                            nonce,
                        )?;
                    }
                    msgs
                }
                Err(e) => return Err(MpcError::StorageError(e.to_string())),
            },
        };
        let signature = self.try_sign_nonce_message(self.address, &messages)?;
        Ok(self.build_dealer_flow_data(messages, signature))
    }

    fn build_dealer_flow_data(
        &self,
        messages: Messages,
        signature: BLS12381Signature,
    ) -> DealerFlowData {
        let my_signature = MemberSignature::new(self.mpc_config.epoch, self.address, signature);
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
        let required_reduced_weight = self.mpc_config.threshold + self.mpc_config.max_faulty;
        let reduced_weights: HashMap<Address, u16> = self
            .committee
            .members()
            .iter()
            .filter_map(|m| {
                let party_id = self.committee.index_of(&m.validator_address())? as u16;
                let weight = self.mpc_config.nodes.weight_of(party_id).ok()?;
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
                epoch: mgr.mpc_config.epoch,
                batch_index: None,
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
                        let epoch = mgr.mpc_config.epoch;
                        mgr.cache_and_persist_rotation_messages(
                            epoch,
                            message.dealer_address,
                            msgs,
                        )?;
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
        message: &avss::Message,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
        epoch: u64,
    ) -> MpcResult<avss::PartialOutput> {
        let (complaint_request, receiver) = {
            let mgr = mpc_manager.read().unwrap();
            let complaint = mgr
                .complaints_to_process
                .get(&ComplaintsToProcessKey::Dkg(*dealer))
                .ok_or_else(|| MpcError::ProtocolFailed("No complaint for dealer".into()))?;
            let (nodes, party_id, threshold) = mgr.config_for_epoch(epoch)?;
            let complaint_request = ComplainRequest {
                dealer: *dealer,
                share_index: None,
                batch_index: None,
                complaint: complaint.clone(),
                protocol_type: ProtocolTypeIndicator::Dkg,
                epoch,
            };
            let dealer_session_id = mgr
                .base_session_id_for_epoch(epoch, &ProtocolType::Dkg)
                .dealer_session_id(dealer);
            let receiver = avss::Receiver::new(
                nodes,
                party_id,
                threshold,
                dealer_session_id.to_vec(),
                None,
                mgr.encryption_key.clone(),
            );
            (complaint_request, receiver)
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
                    return Ok(partial_output);
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

    pub(crate) async fn recover_nonce_shares_via_complaint(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: &Address,
        batch_index: u32,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
        epoch: u64,
    ) -> MpcResult<()> {
        let (complaint_request, receiver, message) = {
            let mgr = mpc_manager.read().unwrap();
            let complaint = mgr
                .complaints_to_process
                .get(&ComplaintsToProcessKey::NonceGeneration {
                    batch_index,
                    dealer: *dealer,
                })
                .ok_or_else(|| MpcError::ProtocolFailed("No nonce complaint for dealer".into()))?;
            let message = match mgr.nonce_messages.get(&(batch_index, *dealer)) {
                Some(nonce) => nonce.message.clone(),
                None => mgr
                    .public_messages_store
                    .get_nonce_message(epoch, batch_index, dealer)
                    .map_err(|e| MpcError::StorageError(e.to_string()))?
                    .ok_or_else(|| MpcError::NotFound("No nonce message for dealer".into()))?,
            };
            let (nodes, party_id, threshold) = mgr.config_for_epoch(epoch)?;
            let complaint_request = ComplainRequest {
                dealer: *dealer,
                share_index: None,
                batch_index: Some(batch_index),
                complaint: complaint.clone(),
                protocol_type: ProtocolTypeIndicator::NonceGeneration,
                epoch,
            };
            let dealer_party_id = mgr
                .committee
                .index_of(dealer)
                .expect("dealer must be in committee") as u16;
            let dealer_sid =
                SessionId::nonce_dealer_session_id(&mgr.chain_id, epoch, batch_index, dealer);
            let receiver = batch_avss::Receiver::new(
                nodes,
                party_id,
                dealer_party_id,
                threshold,
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
                    mgr.dealer_nonce_outputs
                        .insert((batch_index, *dealer), output);
                    mgr.complaints_to_process
                        .remove(&ComplaintsToProcessKey::NonceGeneration {
                            batch_index,
                            dealer: *dealer,
                        });
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
        rotation_messages: &RotationMessages,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
        epoch: u64,
    ) -> MpcResult<HashMap<ShareIndex, avss::PartialOutput>> {
        let (request, recovery_contexts) = {
            let mgr = mpc_manager.read().unwrap();
            let Some(RotationComplainContext {
                request,
                recovery_contexts,
            }) = mgr.prepare_rotation_complain_request(dealer, rotation_messages, epoch)?
            else {
                return Ok(HashMap::new());
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
        let mut recovered_outputs: HashMap<ShareIndex, avss::PartialOutput> = HashMap::new();
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
                                recovered_outputs.insert(share_index, partial_output);
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
            return Err(MpcError::ProtocolFailed(format!(
                "Not enough valid complaint responses for dealer {:?}: missing shares {:?}",
                dealer, pending_shares
            )));
        }
        Ok(recovered_outputs)
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
        rotation_messages: &RotationMessages,
        epoch: u64,
    ) -> MpcResult<Option<RotationComplainContext>> {
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
        let (nodes, party_id, threshold) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::KeyRotation);
        let mut recovery_contexts: HashMap<ShareIndex, (avss::Receiver, avss::Message)> =
            HashMap::new();
        for (share_index, _complaint) in &complained_shares {
            let session_id = base_sid.rotation_session_id(dealer, *share_index);
            let receiver = avss::Receiver::new(
                nodes.clone(),
                party_id,
                threshold,
                session_id.to_vec(),
                None,
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
            batch_index: None,
            complaint: first_complaint.clone(),
            protocol_type: ProtocolTypeIndicator::KeyRotation,
            epoch,
        };
        Ok(Some(RotationComplainContext {
            request,
            recovery_contexts,
        }))
    }

    fn create_rotation_messages(
        &self,
        previous_dkg_output: &MpcOutput,
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
                let nodes = self.maybe_corrupt_nodes_for_testing(&self.mpc_config.nodes);
                let dealer = avss::Dealer::new(
                    Some(share.value),
                    nodes,
                    self.mpc_config.threshold,
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
        previous_dkg_output: &MpcOutput,
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
                self.mpc_config.nodes.clone(),
                self.party_id,
                self.mpc_config.threshold,
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
                .sign(self.mpc_config.epoch, self.address, &rotation_message);
        Ok(signature.signature().clone())
    }

    fn complete_key_rotation(
        &mut self,
        previous_dkg_output: &MpcOutput,
        certified_share_indices: &[ShareIndex],
    ) -> MpcResult<MpcOutput> {
        let threshold = previous_dkg_output.threshold;
        tracing::info!(
            "complete_key_rotation: epoch={}, {} certified_share_indices={:?}, \
             previous_vk={}, threshold={threshold}",
            self.mpc_config.epoch,
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
            &self.mpc_config.nodes,
            &indexed_outputs,
        )
        .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "complete_key_rotation: epoch={}, result vk={}, matches_previous={}",
            self.mpc_config.epoch,
            hex::encode(combined.vk.to_byte_array()),
            combined.vk == previous_dkg_output.public_key,
        );
        if combined.vk != previous_dkg_output.public_key {
            return Err(MpcError::ProtocolFailed(
                "Key rotation produced different public key".into(),
            ));
        }
        Ok(MpcOutput {
            public_key: combined.vk,
            key_shares: combined.my_shares,
            commitments: combined
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: self.mpc_config.threshold,
        })
    }

    pub fn reconstruct_previous_output(
        &self,
        certificates: &[CertificateV1],
        complaint_cache: &HashMap<DealerOutputsKey, avss::PartialOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        match certificates.first() {
            Some(CertificateV1::Dkg(_)) | None => {
                self.reconstruct_from_dkg_certificates(certificates, complaint_cache)
            }
            Some(CertificateV1::Rotation(_)) => {
                let previous_threshold = self.previous_threshold.ok_or_else(|| {
                    MpcError::InvalidConfig("Key rotation requires previous threshold".into())
                })?;
                self.reconstruct_from_rotation_certificates(
                    certificates,
                    previous_threshold,
                    complaint_cache,
                )
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
        complaint_cache: &HashMap<DealerOutputsKey, avss::PartialOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
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
            SessionId::new(&self.chain_id, self.previous_epoch, &ProtocolType::Dkg);
        let mut outputs: HashMap<PartyId, avss::PartialOutput> = HashMap::new();
        let mut dealer_weight_sum = 0u32;
        for cert in certificates {
            // This matches the behavior of `run_as_party` during DKG, which also
            // stops at threshold.
            if dealer_weight_sum >= previous_threshold as u32 {
                break;
            }
            let CertificateV1::Dkg(dkg_cert) = cert else {
                return Err(MpcError::InvalidCertificate(
                    "Mixed certificate types: expected all DKG certificates".into(),
                ));
            };
            let msg = dkg_cert.message();
            let dealer_address = msg.dealer_address;
            let previous_epoch = self.previous_epoch;
            let message = self
                .public_messages_store
                .get_dealer_message(previous_epoch, &dealer_address)
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
            if let Some(output) = complaint_cache.get(&DealerOutputsKey::Dkg(dealer_address)) {
                outputs.insert(dealer_party_id, output.clone());
                let dealer_weight = previous_nodes
                    .weight_of(dealer_party_id)
                    .expect("party_id must be valid");
                dealer_weight_sum += dealer_weight as u32;
                continue;
            }
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
                avss::ProcessedMessage::Complaint(complaint) => {
                    return Ok(ReconstructionOutcome::NeedsDkgComplaintRecovery {
                        dealer_address,
                        complaint,
                        message,
                    });
                }
            }
            let dealer_weight = previous_nodes
                .weight_of(dealer_party_id)
                .expect("party_id must be valid");
            dealer_weight_sum += dealer_weight as u32;
        }
        if dealer_weight_sum < previous_threshold as u32 {
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
        Ok(ReconstructionOutcome::Success(MpcOutput {
            public_key: combined_output.vk,
            key_shares: combined_output.my_shares,
            commitments: combined_output
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: previous_threshold,
        }))
    }

    fn reconstruct_from_rotation_certificates(
        &self,
        certificates: &[CertificateV1],
        previous_threshold: u16,
        complaint_cache: &HashMap<DealerOutputsKey, avss::PartialOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
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
            self.previous_epoch,
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
            let previous_epoch = self.previous_epoch;
            let rotation_msgs = self
                .public_messages_store
                .get_rotation_messages(previous_epoch, &dealer_address)
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
                if let Some(output) = complaint_cache.get(&DealerOutputsKey::Rotation(share_index))
                {
                    tracing::info!(
                        "reconstruct_from_rotation_certificates: complaint cache hit for \
                         dealer {:?} share_index={share_index}",
                        dealer_address,
                    );
                    local_outputs.insert(share_index, output.clone());
                    certified_share_indices.push(share_index);
                    continue;
                }
                let session_id = source_session_id
                    .rotation_session_id(&dealer_address, share_index)
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
                        local_outputs.insert(share_index, output);
                    }
                    avss::ProcessedMessage::Complaint(complaint) => {
                        return Ok(ReconstructionOutcome::NeedsRotationComplaintRecovery {
                            dealer_address,
                            share_index,
                            complaint,
                            message,
                        });
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
        Ok(ReconstructionOutcome::Success(MpcOutput {
            public_key: combined.vk,
            key_shares: combined.my_shares,
            commitments: combined
                .commitments
                .into_iter()
                .map(|c| (c.index, c.value))
                .collect(),
            threshold: previous_threshold,
        }))
    }

    pub async fn fetch_public_mpc_output_from_quorum(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        previous_committee_threshold: u64,
    ) -> MpcResult<PublicMpcOutput> {
        let (previous_committee, epoch) = {
            let mgr = mpc_manager.read().unwrap();
            let previous_committee = mgr
                .previous_committee
                .clone()
                .expect("key rotation requires previous committee");
            (previous_committee, mgr.previous_epoch)
        };
        let request = GetPublicMpcOutputRequest { epoch };
        let mut futures: FuturesUnordered<_> = previous_committee
            .members()
            .iter()
            .map(|member| {
                let addr = member.validator_address();
                let weight = member.weight();
                let req = request.clone();
                async move {
                    let result = p2p_channel.get_public_mpc_output(&addr, &req).await;
                    (addr, weight, result)
                }
            })
            .collect();
        let mut responses: HashMap<[u8; 32], (PublicMpcOutput, u64)> = HashMap::new();
        while let Some((addr, weight, result)) = futures.next().await {
            match result {
                Ok(response) => {
                    let hash = hash_public_mpc_output(&response.output);
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
    ) -> MpcResult<(MpcOutput, bool)> {
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
            let reconstruction_result = async {
                Self::retrieve_missing_previous_messages(
                    mpc_manager,
                    previous_certificates,
                    p2p_channel,
                )
                .await?;
                Self::reconstruct_with_complaint_recovery(
                    mpc_manager,
                    previous_certificates,
                    p2p_channel,
                )
                .await
            }
            .await;
            match reconstruction_result {
                Ok(output) => output,
                Err(e) => {
                    tracing::info!("Reconstruction failed ({e}), falling back to new-member path");
                    Self::fetch_and_build_public_output(mpc_manager, p2p_channel, threshold_opt)
                        .await?
                }
            }
        } else {
            Self::fetch_and_build_public_output(mpc_manager, p2p_channel, threshold_opt).await?
        };
        tracing::info!(
            "prepare_previous_output: is_member_of_previous_committee={is_member_of_previous_committee}, \
             previous_vk={}",
            hex::encode(previous.public_key.to_byte_array()),
        );
        Ok((previous, is_member_of_previous_committee))
    }

    async fn fetch_and_build_public_output(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        threshold_opt: Option<u16>,
    ) -> MpcResult<MpcOutput> {
        let threshold = threshold_opt.ok_or_else(|| {
            MpcError::InvalidConfig("Key rotation requires previous threshold".into())
        })?;
        let public_output =
            Self::fetch_public_mpc_output_from_quorum(mpc_manager, p2p_channel, threshold as u64)
                .await?;
        Ok(MpcOutput {
            public_key: public_output.public_key,
            key_shares: avss::SharesForNode { shares: vec![] },
            commitments: public_output.commitments,
            threshold,
        })
    }

    /// Reconstruct the previous epoch's output, recovering via Complain RPCs
    /// if cheating dealers' corrupted messages are encountered in DB.
    async fn reconstruct_with_complaint_recovery(
        mpc_manager: &Arc<RwLock<Self>>,
        previous_certificates: &[CertificateV1],
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<MpcOutput> {
        let mut complaint_cache: HashMap<DealerOutputsKey, avss::PartialOutput> = HashMap::new();
        loop {
            let mgr = Arc::clone(mpc_manager);
            let certs = previous_certificates.to_vec();
            let cache_snapshot = complaint_cache.clone();
            match spawn_blocking(move || {
                let mgr = mgr.read().unwrap();
                mgr.reconstruct_previous_output(&certs, &cache_snapshot)
            })
            .await?
            {
                ReconstructionOutcome::Success(output) => return Ok(output),
                ReconstructionOutcome::NeedsDkgComplaintRecovery {
                    dealer_address,
                    complaint,
                    message,
                } => {
                    tracing::info!(
                        "Complaint during DKG reconstruction for dealer {:?}, recovering via Complain RPC",
                        dealer_address
                    );
                    let signers = {
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.complaints_to_process
                            .insert(ComplaintsToProcessKey::Dkg(dealer_address), complaint);
                        Self::collect_signers_for_dealer(
                            &mgr,
                            previous_certificates,
                            &dealer_address,
                        )
                    };
                    let previous_epoch = mpc_manager.read().unwrap().previous_epoch;
                    let recovered = Self::recover_shares_via_complaint(
                        mpc_manager,
                        &dealer_address,
                        &message,
                        signers,
                        p2p_channel,
                        previous_epoch,
                    )
                    .await?;
                    complaint_cache.insert(DealerOutputsKey::Dkg(dealer_address), recovered);
                    mpc_manager
                        .write()
                        .unwrap()
                        .complaints_to_process
                        .remove(&ComplaintsToProcessKey::Dkg(dealer_address));
                }
                ReconstructionOutcome::NeedsRotationComplaintRecovery {
                    dealer_address,
                    share_index: complained_share_index,
                    complaint,
                    message: _message,
                } => {
                    tracing::info!(
                        "Complaint during rotation reconstruction for dealer {:?} share {}, recovering via Complain RPC",
                        dealer_address,
                        complained_share_index,
                    );
                    let (previous_epoch, rotation_msgs) = {
                        let mgr = mpc_manager.read().unwrap();
                        let previous_epoch = mgr.previous_epoch;
                        let msgs = mgr
                            .public_messages_store
                            .get_rotation_messages(previous_epoch, &dealer_address)
                            .map_err(|e| MpcError::StorageError(e.to_string()))?
                            .ok_or_else(|| {
                                MpcError::NotFound(format!(
                                    "Rotation messages not found for dealer {:?}",
                                    dealer_address
                                ))
                            })?;
                        (previous_epoch, msgs)
                    };
                    let signers = {
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.complaints_to_process.insert(
                            ComplaintsToProcessKey::Rotation(
                                dealer_address,
                                complained_share_index,
                            ),
                            complaint,
                        );
                        Self::collect_signers_for_dealer(
                            &mgr,
                            previous_certificates,
                            &dealer_address,
                        )
                    };
                    let recovered = Self::recover_rotation_shares_via_complaints(
                        mpc_manager,
                        &dealer_address,
                        &rotation_msgs,
                        signers,
                        p2p_channel,
                        previous_epoch,
                    )
                    .await?;
                    let mut mgr = mpc_manager.write().unwrap();
                    for (share_index, output) in recovered {
                        complaint_cache.insert(DealerOutputsKey::Rotation(share_index), output);
                        mgr.complaints_to_process
                            .remove(&ComplaintsToProcessKey::Rotation(
                                dealer_address,
                                share_index,
                            ));
                    }
                }
            }
        }
    }

    fn collect_signers_for_dealer(
        mgr: &Self,
        previous_certificates: &[CertificateV1],
        dealer_address: &Address,
    ) -> Vec<Address> {
        let previous_committee = mgr
            .previous_committee
            .as_ref()
            .expect("previous_committee must be set");
        previous_certificates
            .iter()
            .filter_map(|c| {
                let msg = match c {
                    CertificateV1::Dkg(dc) => dc.message(),
                    CertificateV1::Rotation(rc) => rc.message(),
                    _ => return None,
                };
                if msg.dealer_address == *dealer_address {
                    c.signers(previous_committee).ok()
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_default()
    }

    /// Reconstruct presignatures from DB, recovering via Complain RPCs if
    /// cheating dealers' corrupted nonce messages are encountered.
    pub(crate) async fn reconstruct_presignatures_with_complaint_recovery(
        mpc_manager: &Arc<RwLock<Self>>,
        epoch: u64,
        batch_index: u32,
        certs: &[(Address, hashi_types::move_types::DealerSubmissionV1)],
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<Vec<batch_avss::ReceiverOutput>> {
        loop {
            let outcome = mpc_manager
                .read()
                .unwrap()
                .reconstruct_presignatures(batch_index, certs)?;
            match outcome {
                NonceReconstructionOutcome::Success(outputs) => return Ok(outputs),
                NonceReconstructionOutcome::NeedsComplaintRecovery {
                    dealer_address,
                    complaint,
                    batch_index: complaint_batch_index,
                } => {
                    tracing::info!(
                        "Complaint during nonce reconstruction for dealer {:?}, recovering via Complain RPC",
                        dealer_address
                    );
                    let signers = {
                        let mut mgr = mpc_manager.write().unwrap();
                        mgr.complaints_to_process.insert(
                            ComplaintsToProcessKey::NonceGeneration {
                                batch_index: complaint_batch_index,
                                dealer: dealer_address,
                            },
                            complaint,
                        );
                        if !mgr
                            .nonce_messages
                            .contains_key(&(complaint_batch_index, dealer_address))
                            && let Ok(Some(msg)) = mgr.public_messages_store.get_nonce_message(
                                epoch,
                                complaint_batch_index,
                                &dealer_address,
                            )
                        {
                            mgr.nonce_messages.insert(
                                (complaint_batch_index, dealer_address),
                                NonceMessage {
                                    batch_index: complaint_batch_index,
                                    message: msg,
                                },
                            );
                        }
                        certs
                            .iter()
                            .find(|(addr, _)| *addr == dealer_address)
                            .map(|(_, cert)| {
                                let members = mgr.committee.members();
                                cert.signature
                                    .signers_bitmap
                                    .iter()
                                    .filter_map(|&idx| {
                                        members.get(idx as usize).map(|m| m.validator_address())
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    };
                    Self::recover_nonce_shares_via_complaint(
                        mpc_manager,
                        &dealer_address,
                        complaint_batch_index,
                        signers,
                        p2p_channel,
                        epoch,
                    )
                    .await?;
                }
            }
        }
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
                            .get_dealer_message(mgr.previous_epoch, &msg.dealer_address)
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
                            .get_rotation_messages(mgr.previous_epoch, &msg.dealer_address)
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
                epoch: mgr.previous_epoch,
                batch_index: None,
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
                    let actual_hash = compute_messages_hash(&response.messages);
                    if actual_hash == message.messages_hash {
                        let mut mgr = mpc_manager.write().unwrap();
                        let previous_epoch = mgr.previous_epoch;
                        match &response.messages {
                            Messages::Dkg(msg) => {
                                mgr.cache_and_persist_dkg_message(
                                    previous_epoch,
                                    message.dealer_address,
                                    msg,
                                )?;
                            }
                            Messages::Rotation(msgs) => {
                                mgr.cache_and_persist_rotation_messages(
                                    previous_epoch,
                                    message.dealer_address,
                                    msgs,
                                )?;
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
                        "Message hash mismatch from signer {:?} for dealer {:?}: \
                         expected={:?}, got={:?}",
                        signer,
                        message.dealer_address,
                        message.messages_hash,
                        actual_hash,
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

    fn base_session_id_for_epoch(&self, epoch: u64, protocol_type: &ProtocolType) -> SessionId {
        if epoch == self.mpc_config.epoch {
            self.session_id.clone()
        } else {
            SessionId::new(&self.chain_id, self.previous_epoch, protocol_type)
        }
    }

    fn config_for_epoch(&self, epoch: u64) -> MpcResult<(Nodes<EncryptionGroupElement>, u16, u16)> {
        if epoch == self.mpc_config.epoch {
            Ok((
                self.mpc_config.nodes.clone(),
                self.party_id,
                self.mpc_config.threshold,
            ))
        } else {
            let committee = self.previous_committee.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("No previous committee for cross-epoch complaint".into())
            })?;
            let nodes = self.previous_nodes.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("No previous nodes for cross-epoch complaint".into())
            })?;
            let threshold = self.previous_threshold.ok_or_else(|| {
                MpcError::InvalidConfig("No previous threshold for cross-epoch complaint".into())
            })?;
            let party_id = committee.index_of(&self.address).ok_or_else(|| {
                MpcError::InvalidConfig("This node is not in the previous committee".into())
            })? as u16;
            Ok((nodes.clone(), party_id, threshold))
        }
    }

    fn get_or_derive_dkg_output(
        &self,
        dealer: &Address,
        message: &avss::Message,
        epoch: u64,
    ) -> MpcResult<avss::PartialOutput> {
        if let Some(output) = self.dealer_outputs.get(&DealerOutputsKey::Dkg(*dealer)) {
            return Ok(output.clone());
        }
        // Cross-epoch fallback: re-derive from message
        let (nodes, party_id, threshold) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::Dkg);
        let session_id = base_sid.dealer_session_id(dealer);
        match process_avss_message(
            &self.encryption_key,
            nodes,
            party_id,
            threshold,
            session_id.to_vec(),
            message,
            None,
        )? {
            avss::ProcessedMessage::Valid(output) => Ok(output),
            avss::ProcessedMessage::Complaint(_) => Err(MpcError::NotFound(
                "Peer is also a victim of this dealer — cannot help with complaint".into(),
            )),
        }
    }

    fn get_or_derive_rotation_output(
        &self,
        dealer: &Address,
        share_index: ShareIndex,
        message: &avss::Message,
        epoch: u64,
    ) -> MpcResult<avss::PartialOutput> {
        if epoch == self.mpc_config.epoch
            && let Some(output) = self
                .dealer_outputs
                .get(&DealerOutputsKey::Rotation(share_index))
        {
            return Ok(output.clone());
        }
        let (nodes, party_id, threshold) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::KeyRotation);
        let session_id = base_sid.rotation_session_id(dealer, share_index);
        match process_avss_message(
            &self.encryption_key,
            nodes,
            party_id,
            threshold,
            session_id.to_vec(),
            message,
            None,
        )? {
            avss::ProcessedMessage::Valid(output) => Ok(output),
            avss::ProcessedMessage::Complaint(_) => Err(MpcError::NotFound(
                "Peer is also a victim of this dealer — cannot help with rotation complaint".into(),
            )),
        }
    }

    fn get_dealer_messages(
        &self,
        protocol_type: ProtocolTypeIndicator,
        dealer: &Address,
        batch_index: Option<u32>,
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
            ProtocolTypeIndicator::NonceGeneration => {
                let batch_index = batch_index?;
                self.nonce_messages
                    .get(&(batch_index, *dealer))
                    .map(|m| Messages::NonceGeneration(m.clone()))
            }
        }
    }

    fn required_nonce_weight(&self) -> u32 {
        2 * self.mpc_config.max_faulty as u32 + 1
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

fn build_reduced_nodes(
    committee: &Committee,
    threshold_in_basis_points: u16,
    max_faulty_in_basis_points: u16,
    weight_reduction_allowed_delta: u16,
    test_weight_divisor: u16,
    chain_id: &str,
) -> MpcResult<(Nodes<EncryptionGroupElement>, u16, u16)> {
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
    let threshold =
        (total_weight as u32 * threshold_in_basis_points as u32).div_ceil(MAX_BASIS_POINTS) as u16;
    let max_faulty =
        (total_weight as u32 * max_faulty_in_basis_points as u32).div_ceil(MAX_BASIS_POINTS) as u16;
    let lower_bound = if is_production_sui_chain(chain_id) {
        MIN_TOTAL_WEIGHT_AFTER_REDUCTION
    } else {
        MIN_TOTAL_WEIGHT_AFTER_REDUCTION.min(total_weight)
    };
    Nodes::new_reduced_with_f(
        nodes_vec,
        threshold,
        max_faulty,
        weight_reduction_allowed_delta,
        lower_bound,
    )
    .map_err(|e| MpcError::CryptoError(e.to_string()))
}

fn hash_public_mpc_output(output: &PublicMpcOutput) -> [u8; 32] {
    let bytes = bcs::to_bytes(output).expect(EXPECT_SERIALIZATION_SUCCESS);
    Blake2b256::digest(&bytes).digest
}

pub(crate) async fn spawn_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) if e.is_cancelled() => std::future::pending().await,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

#[cfg(test)]
#[path = "mpc_except_signing_tests.rs"]
mod tests;
