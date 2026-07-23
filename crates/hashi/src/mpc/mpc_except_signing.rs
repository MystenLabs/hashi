// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::communication::ChannelResult;
use crate::communication::OrderedBroadcastChannel;
use crate::communication::P2PChannel;
use crate::communication::send_each;
use crate::communication::send_to_many;
use crate::communication::with_timeout_and_retry;
use crate::constants::is_production_sui_chain;
use crate::metrics::MPC_LABEL_DKG;
use crate::metrics::MPC_LABEL_KEY_ROTATION;
use crate::metrics::MPC_LABEL_NONCE_GENERATION;
use crate::metrics::Metrics;
use crate::mpc::types::AvidCertificate;
use crate::mpc::types::AvidDealerFlowData;
use crate::mpc::types::AvidNonceMessage;
use crate::mpc::types::AvidNonceMessageKind;
use crate::mpc::types::AvidNonceRetrievalMessage;
use crate::mpc::types::AvidRoundState;
use crate::mpc::types::CertificateV1;
pub use crate::mpc::types::ComplainRequest;
pub use crate::mpc::types::ComplaintResponse;
pub use crate::mpc::types::ComplaintResponsesKey;
pub use crate::mpc::types::ComplaintsToProcessKey;
use crate::mpc::types::DealerCertificate;
pub use crate::mpc::types::DealerFlowData;
use crate::mpc::types::DealerMessagesHash;
pub use crate::mpc::types::DealerOutputsKey;
use crate::mpc::types::DkgReconstructionContext;
pub use crate::mpc::types::EncryptionGroupElement;
pub use crate::mpc::types::GetPublicMpcOutputRequest;
pub use crate::mpc::types::GetPublicMpcOutputResponse;
use crate::mpc::types::HeldAvidEchoes;
pub use crate::mpc::types::MessageHash;
pub use crate::mpc::types::MessageResponsesKey;
pub use crate::mpc::types::Messages;
use crate::mpc::types::MpcConfig;
pub use crate::mpc::types::MpcError;
pub use crate::mpc::types::MpcOutput;
use crate::mpc::types::MpcOutputRecoveryOutcome;
pub use crate::mpc::types::MpcResult;
use crate::mpc::types::NonceCertToVerify;
use crate::mpc::types::NonceGenerationProtocol;
pub use crate::mpc::types::NonceMessage;
pub use crate::mpc::types::NonceReconstructionOutcome;
use crate::mpc::types::PresignatureDerivationVersion;
pub use crate::mpc::types::ProtocolComplaint;
pub use crate::mpc::types::ProtocolType;
pub use crate::mpc::types::ProtocolTypeIndicator;
pub use crate::mpc::types::PublicMpcOutput;
use crate::mpc::types::ReconstructionOutcome;
pub use crate::mpc::types::RetrieveMessagesRequest;
pub use crate::mpc::types::RetrieveMessagesResponse;
use crate::mpc::types::RotationComplainContext;
use crate::mpc::types::RotationMessages;
use crate::mpc::types::RotationReconstructionContext;
pub use crate::mpc::types::SendMessagesRequest;
pub use crate::mpc::types::SendMessagesResponse;
pub use crate::mpc::types::SessionId;
use crate::mpc::types::VerifiedAvidVoteCert;
use crate::mpc::types::hash_avid_vote;
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
use fastcrypto_tbls::threshold_schnorr::Certificate;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
use fastcrypto_tbls::types::IndexedValue;
use fastcrypto_tbls::types::ShareIndex;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::MemberSignature;
use rand::seq::SliceRandom;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::RwLock;
use std::time::Duration;
use sui_sdk_types::Address;

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";
const EXPECT_THRESHOLD_VALIDATED: &str = "Threshold already validated";
const EXPECT_THRESHOLD_MET: &str = "Already checked earlier that threshold is met";
const EXPECT_SERIALIZATION_SUCCESS: &str = "Serialization should always succeed";

const MAX_BASIS_POINTS: u32 = 10000;
const MIN_TOTAL_WEIGHT_AFTER_REDUCTION: u16 = 100;
const PRUNE_KEEP_RECENT_BATCHES: u32 = 2;
const HEDGED_RETRIEVE_INITIAL_ROUND_SIZE: usize = 2;
const HEDGED_RETRIEVE_ROUND_GROWTH_FACTOR: usize = 2;
const HEDGED_RETRIEVE_ROUND_TIMEOUT: Duration = Duration::from_secs(1);

type AvidEchoAndVote = (
    BLS12381Signature,
    batch_avss_avid::AvidVote,
    Vec<(Address, Messages)>,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertKind {
    AvssVote,
    AvidVote,
}

pub struct MpcManager {
    // Immutable during the epoch
    pub party_id: PartyId,
    pub address: Address,
    pub mpc_config: MpcConfig,
    pub session_id: SessionId,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub previous_encryption_key: Option<PrivateKey<EncryptionGroupElement>>,
    pub signing_key: Bls12381PrivateKey,
    pub committee: Committee,
    pub previous_committee: Option<Committee>,
    pub previous_nodes: Option<Nodes<EncryptionGroupElement>>,
    pub previous_reconfig_output_threshold: Option<u16>,
    pub previous_reconfig_output_max_faulty: Option<u16>,
    pub previous_reconfig_input_threshold: Option<u16>,
    chain_id: String,
    pub previous_epoch: u64,
    previous_output: Option<MpcOutput>,
    current_output: Option<MpcOutput>,
    pub batch_size_per_weight: u16,

    // Mutable during the epoch
    pub dealer_outputs: HashMap<DealerOutputsKey, avss::AvssOutput>,
    pub current_dkg_messages: HashMap<Address, avss::Message>,
    pub current_rotation_messages: HashMap<Address, RotationMessages>,
    pub rotation_ack_signatures: HashMap<Address, (MessageHash, BLS12381Signature)>,
    pub current_nonce_messages: HashMap<(u32, Address), NonceMessage>,
    pub current_avid_round_state: HashMap<(u32, Address), AvidRoundState>,
    pub current_avid_verified_common:
        HashMap<(u32, Address), batch_avss_avid::VerifiedAvssCommonMessage>,
    pub avid_held_echoes: HashMap<(u32, Address), HeldAvidEchoes>,
    pub message_responses: HashMap<MessageResponsesKey, MpcResult<SendMessagesResponse>>,
    pub complaints_to_process: HashMap<ComplaintsToProcessKey, ProtocolComplaint>,
    pub complaint_responses: HashMap<ComplaintResponsesKey, ComplaintResponse>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
    /// Must be `BTreeMap` so that all nodes iterate outputs in
    /// the same deterministic order when constructing `Presignatures`.
    pub dealer_nonce_outputs: BTreeMap<(u32, Address), batch_avss::ReceiverOutput>,
    pub dealer_avid_nonce_outputs: BTreeMap<(u32, Address), batch_avss_avid::ReceiverOutput>,
    /// Test-only: corrupt shares for this target address during dealing.
    test_corrupt_shares_for: Option<Address>,
}

impl MpcManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        committee_set: &CommitteeSet,
        epoch: u64,
        session_id: SessionId,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        previous_encryption_key: Option<PrivateKey<EncryptionGroupElement>>,
        signing_key: Bls12381PrivateKey,
        public_message_store: Box<dyn PublicMessagesStore>,
        chain_id: &str,
        weight_divisor: Option<u16>,
        batch_size_per_weight: u16,
        test_corrupt_shares_for: Option<Address>,
        presignature_derivation_activation_epoch: u64,
        metrics: &Metrics,
    ) -> MpcResult<Self> {
        if weight_divisor.is_some() {
            assert!(
                !is_production_sui_chain(chain_id),
                "weight_divisor must not be set on mainnet or testnet"
            );
        }
        let weight_divisor = weight_divisor.unwrap_or(1);
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
        let nonce_generation_protocol =
            NonceGenerationProtocol::from_onchain(committee.mpc_nonce_generation_protocol())?;
        let presignature_derivation_version = PresignatureDerivationVersion::from_activation_epoch(
            epoch,
            presignature_derivation_activation_epoch,
        );
        let mpc_config = MpcConfig::new(
            epoch,
            nodes,
            threshold,
            max_faulty,
            nonce_generation_protocol,
            presignature_derivation_version,
        );
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
        metrics.mpc_party_reduced_weight.set(
            mpc_config
                .nodes
                .weight_of(party_id)
                .expect("party_id was just derived from this committee") as i64,
        );
        if !keys_match {
            return Err(MpcError::InvalidConfig(format!(
                "encryption key mismatch at epoch {epoch}: local {my} vs on-chain {chain}",
                my = hex::encode(my_pk.as_element().to_byte_array()),
                chain = hex::encode(committee_pk.as_element().to_byte_array()),
            )));
        }
        let (previous_epoch, previous_committee) =
            match committee_set.previous_committee_for_target(epoch) {
                Some((prev, committee)) => (prev, Some(committee.clone())),
                None => (committee_set.epoch(), None),
            };
        let (
            previous_nodes,
            previous_reconfig_output_threshold,
            previous_reconfig_output_max_faulty,
        ) = match previous_committee.as_ref() {
            Some(prev_committee) => {
                let (nodes, threshold, prev_max_faulty) = build_reduced_nodes(
                    prev_committee,
                    prev_committee.mpc_threshold_in_basis_points(),
                    prev_committee.mpc_max_faulty_in_basis_points(),
                    prev_committee.mpc_weight_reduction_allowed_delta(),
                    weight_divisor,
                    chain_id,
                )?;
                (Some(nodes), Some(threshold), Some(prev_max_faulty))
            }
            None => (None, None, None),
        };
        let previous_reconfig_input_threshold = committee_set
            .committees()
            .range(..previous_epoch)
            .next_back()
            .map(|(_, input_committee)| -> MpcResult<u16> {
                let (_, threshold, _) = build_reduced_nodes(
                    input_committee,
                    input_committee.mpc_threshold_in_basis_points(),
                    input_committee.mpc_max_faulty_in_basis_points(),
                    input_committee.mpc_weight_reduction_allowed_delta(),
                    weight_divisor,
                    chain_id,
                )?;
                Ok(threshold)
            })
            .transpose()?;
        let mut manager = Self {
            party_id,
            address,
            mpc_config,
            session_id,
            encryption_key,
            previous_encryption_key,
            signing_key,
            committee,
            previous_committee,
            previous_nodes,
            previous_reconfig_output_threshold,
            previous_reconfig_output_max_faulty,
            previous_reconfig_input_threshold,
            dealer_outputs: HashMap::new(),
            current_dkg_messages: HashMap::new(),
            current_rotation_messages: HashMap::new(),
            rotation_ack_signatures: HashMap::new(),
            current_nonce_messages: HashMap::new(),
            current_avid_round_state: HashMap::new(),
            current_avid_verified_common: HashMap::new(),
            avid_held_echoes: HashMap::new(),
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
            dealer_avid_nonce_outputs: BTreeMap::new(),
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
        if matches!(request.messages, Messages::AvidNonceRetrieval(_)) {
            return Err(MpcError::InvalidMessage {
                sender,
                reason: "retrieval messages are response-only".into(),
            });
        }
        let cache_key = match &request.messages {
            Messages::Dkg(_) => MessageResponsesKey::Dkg { sender },
            Messages::Rotation(_) => MessageResponsesKey::Rotation { sender },
            Messages::NonceGeneration(nonce) => MessageResponsesKey::NonceGeneration {
                batch_index: nonce.batch_index,
                sender,
            },
            Messages::NonceGenerationAvid(avid) => MessageResponsesKey::NonceGeneration {
                batch_index: avid.batch_index,
                sender,
            },
            Messages::AvidNonceRetrieval(_) => unreachable!("rejected above"),
        };
        let batch_index = match &request.messages {
            Messages::NonceGeneration(nonce) => Some(nonce.batch_index),
            Messages::NonceGenerationAvid(avid) => Some(avid.batch_index),
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
                if self.mpc_config.nonce_generation_protocol != NonceGenerationProtocol::Vanilla {
                    return Err(MpcError::InvalidMessage {
                        sender,
                        reason: "vanilla nonce generation messages are rejected in an AVID epoch"
                            .into(),
                    });
                }
                self.cache_and_persist_nonce_message(self.mpc_config.epoch, sender, nonce)?;
                self.try_sign_nonce_message(sender, &request.messages)
            }
            Messages::NonceGenerationAvid(avid) => {
                if self.mpc_config.nonce_generation_protocol != NonceGenerationProtocol::Avid {
                    return Err(MpcError::InvalidMessage {
                        sender,
                        reason: "AVID nonce messages are rejected in a vanilla nonce generation \
                                 epoch"
                            .into(),
                    });
                }
                self.handle_avid_nonce_message(sender, avid)
            }
            Messages::AvidNonceRetrieval(_) => unreachable!("rejected above"),
        }
        .map(|signature| SendMessagesResponse { signature });
        self.message_responses.insert(cache_key, result.clone());
        result
    }

    pub fn handle_retrieve_messages_request(
        &self,
        requester: Address,
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
                if self.mpc_config.nonce_generation_protocol == NonceGenerationProtocol::Avid {
                    return self.serve_avid_nonce_retrieval(requester, batch_index, request);
                }
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

    fn serve_avid_nonce_retrieval(
        &self,
        requester: Address,
        batch_index: u32,
        request: &RetrieveMessagesRequest,
    ) -> MpcResult<RetrieveMessagesResponse> {
        if request.epoch != self.mpc_config.epoch {
            return Err(MpcError::NotFound(
                "AVID retrieval serves the current epoch only".into(),
            ));
        }
        let common = self.get_avid_round_common(batch_index, &request.dealer);
        let (avid_vote, echo) = match &self.get_avid_held_echoes(batch_index, &request.dealer) {
            Some((vote, echoes)) => {
                let echo = echoes.iter().find_map(|(addr, msg)| {
                    (*addr == requester).then(|| match msg {
                        Messages::NonceGenerationAvid(AvidNonceMessage {
                            kind: AvidNonceMessageKind::Echo { echo, .. },
                            ..
                        }) => echo.clone(),
                        _ => unreachable!("held echoes are echo messages"),
                    })
                });
                (Some(vote.clone()), echo)
            }
            None => (None, None),
        };
        if common.is_none() && avid_vote.is_none() && echo.is_none() {
            return Err(MpcError::NotFound(format!(
                "no AVID round state for dealer {:?}",
                request.dealer
            )));
        }
        tracing::info!(
            "AVID echo pull served: requester {:?}, dealer {:?}, batch_index={batch_index}, \
             common={}, vote={}, echo={}",
            requester,
            request.dealer,
            common.is_some(),
            avid_vote.is_some(),
            echo.is_some()
        );
        Ok(RetrieveMessagesResponse {
            messages: Messages::AvidNonceRetrieval(AvidNonceRetrievalMessage {
                common,
                echo,
                avid_vote,
            }),
        })
    }

    pub fn handle_complain_request(
        &mut self,
        caller: Address,
        request: &ComplainRequest,
    ) -> MpcResult<ComplaintResponse> {
        let cache_key = match request.protocol_type {
            ProtocolTypeIndicator::Dkg => ComplaintResponsesKey::Dkg {
                dealer: request.dealer,
            },
            ProtocolTypeIndicator::KeyRotation => {
                let share_index = request
                    .share_index
                    .ok_or_else(|| MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "Rotation complaint requires share_index".into(),
                    })?;
                ComplaintResponsesKey::Rotation {
                    dealer: request.dealer,
                    share_index,
                }
            }
            ProtocolTypeIndicator::NonceGeneration => {
                let batch_index = request
                    .batch_index
                    .ok_or_else(|| MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "batch_index required for nonce complaint".into(),
                    })?;
                ComplaintResponsesKey::NonceGeneration {
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
        if matches!(
            request.complaint,
            ProtocolComplaint::AvidReveal(_) | ProtocolComplaint::AvidBlame { .. }
        ) {
            if request.protocol_type != ProtocolTypeIndicator::NonceGeneration {
                return Err(MpcError::InvalidMessage {
                    sender: caller,
                    reason: "AVID complaints require the nonce-generation protocol type".into(),
                });
            }
            let response = self.handle_avid_nonce_complaint_request(caller, request)?;
            if cache_is_current {
                self.complaint_responses.insert(cache_key, response.clone());
            }
            return Ok(response);
        }
        if request.protocol_type == ProtocolTypeIndicator::NonceGeneration
            && self.mpc_config.nonce_generation_protocol != NonceGenerationProtocol::Vanilla
        {
            return Err(MpcError::InvalidMessage {
                sender: caller,
                reason: "vanilla nonce complaints are rejected in an AVID epoch".into(),
            });
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
                let (nodes, party_id, params) = self.config_for_epoch(request.epoch)?;
                let accuser_id = self.accuser_party_id(request.epoch, &caller)?;
                let session_id = self
                    .base_session_id_for_epoch(request.epoch, &ProtocolType::Dkg)
                    .dealer_session_id(&request.dealer);
                let receiver = avss::Receiver::new(
                    nodes,
                    party_id,
                    params,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                )?;
                let ProtocolComplaint::Avss(complaint) = &request.complaint else {
                    return Err(MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "DKG complaint requires an AVSS complaint".into(),
                    });
                };
                let complaint_response =
                    receiver.handle_complaint(&message, accuser_id, complaint, &partial_output)?;
                ComplaintResponse::Dkg(complaint_response)
            }
            Messages::Rotation(rotation_messages) => {
                let complained_share_index =
                    request
                        .share_index
                        .ok_or_else(|| MpcError::InvalidMessage {
                            sender: request.dealer,
                            reason: "Rotation complaint requires share_index".into(),
                        })?;
                let complained_message = rotation_messages
                    .get(&complained_share_index)
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation message for complained share_index {}",
                            complained_share_index
                        ))
                    })?;
                let (nodes, party_id, params) = self.config_for_epoch(request.epoch)?;
                let accuser_id = self.accuser_party_id(request.epoch, &caller)?;
                let complained_output = self.get_or_derive_rotation_output(
                    &request.dealer,
                    complained_share_index,
                    complained_message,
                    request.epoch,
                )?;
                let session_id = self
                    .base_session_id_for_epoch(request.epoch, &ProtocolType::KeyRotation)
                    .rotation_session_id(&request.dealer, complained_share_index);
                let receiver = avss::Receiver::new(
                    nodes,
                    party_id,
                    params,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                )?;
                let ProtocolComplaint::Avss(complaint) = &request.complaint else {
                    return Err(MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "Rotation complaint requires an AVSS complaint".into(),
                    });
                };
                let response = receiver.handle_complaint(
                    complained_message,
                    accuser_id,
                    complaint,
                    &complained_output,
                )?;
                ComplaintResponse::Rotation(response)
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
                let ProtocolComplaint::BatchedAvss(complaint) = &request.complaint else {
                    return Err(MpcError::InvalidMessage {
                        sender: request.dealer,
                        reason: "Nonce-generation complaint requires a nonce complaint".into(),
                    });
                };
                let complaint_response =
                    receiver.handle_complaint(&message, complaint, &nonce_output)?;
                ComplaintResponse::NonceGeneration(complaint_response)
            }
            Messages::NonceGenerationAvid(_) | Messages::AvidNonceRetrieval(_) => {
                return Err(MpcError::ProtocolFailed(
                    "AVID nonce generation complaint handling is not yet implemented".into(),
                ));
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
        mpc_manager
            .write()
            .unwrap()
            .set_current_output(output.clone());
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
            Self::prepare_previous_output(mpc_manager, previous_certificates, p2p_channel, metrics)
                .await?;
        drop(_timer);
        tracing::info!(
            "run_key_rotation: prepare_previous_output complete, \
             is_member={is_member_of_previous_committee}",
        );
        {
            let mut mgr = mpc_manager.write().unwrap();
            mgr.set_previous_output(previous.clone());
            // Load rotation messages from DB for restart recovery.
            // For live rotation this is a no-op (no messages stored yet).
            for (dealer, message) in mgr
                .public_messages_store
                .list_all_rotation_messages()
                .map_err(|e| MpcError::StorageError(e.to_string()))?
            {
                if let Messages::Rotation(msgs) = message {
                    mgr.current_rotation_messages.insert(dealer, msgs);
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
                        let messages = mgr.current_rotation_messages.get(d)?;
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
        tracing::info!(
            "run_key_rotation: entering party phase, previous_vk={}, \
             previous_threshold={}, previous_commitments_len={}",
            hex::encode(previous.public_key.to_byte_array()),
            previous.threshold,
            previous.commitments.len(),
        );
        let output = Self::run_key_rotation_as_party(
            mpc_manager,
            &previous,
            p2p_channel,
            ordered_broadcast_channel,
            metrics,
        )
        .await?;
        mpc_manager
            .write()
            .unwrap()
            .set_current_output(output.clone());
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
        let protocol = {
            let mgr = mpc_manager.read().unwrap();
            mgr.mpc_config.nonce_generation_protocol
        };
        if certified_reduced_weight < required_reduced_weight {
            let dealer_result = match protocol {
                NonceGenerationProtocol::Vanilla => {
                    Self::run_as_nonce_dealer(
                        mpc_manager,
                        batch_index,
                        p2p_channel,
                        tob_channel,
                        metrics,
                    )
                    .await
                }
                NonceGenerationProtocol::Avid => {
                    Self::run_as_avid_nonce_dealer(
                        mpc_manager,
                        batch_index,
                        p2p_channel,
                        tob_channel,
                        metrics,
                    )
                    .await
                }
            };
            if let Err(e) = dealer_result {
                tracing::error!(
                    "Nonce dealer phase failed: {}. Continuing as party only.",
                    e
                );
            }
        }
        let certified = match protocol {
            NonceGenerationProtocol::Vanilla => {
                Self::run_as_nonce_party(
                    mpc_manager,
                    batch_index,
                    p2p_channel,
                    tob_channel,
                    metrics,
                )
                .await?
            }
            NonceGenerationProtocol::Avid => {
                Self::run_as_avid_nonce_party(
                    mpc_manager,
                    batch_index,
                    p2p_channel,
                    tob_channel,
                    metrics,
                )
                .await?
            }
        };
        let mut mgr = mpc_manager.write().unwrap();
        // Keep only the outputs selected by the party phase. The RPC handler may have inserted
        // additional outputs concurrently — discard them so all nodes use the same deterministic
        // set.
        let (pre_filter, dealers, outputs) = match protocol {
            NonceGenerationProtocol::Vanilla => consume_certified_nonce_outputs(
                &mut mgr.dealer_nonce_outputs,
                batch_index,
                &certified,
                |output| output.clone(),
            ),
            NonceGenerationProtocol::Avid => {
                let indices = mgr
                    .mpc_config
                    .nodes
                    .share_ids_of(mgr.party_id)
                    .map_err(|e| MpcError::CryptoError(e.to_string()))?;
                consume_certified_nonce_outputs(
                    &mut mgr.dealer_avid_nonce_outputs,
                    batch_index,
                    &certified,
                    |output| output.clone().into_legacy(&indices),
                )
            }
        };
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
        let (certified_dealers, _) = self.certified_nonce_dealers_from_certs(certs);
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

    pub(crate) fn certified_nonce_dealers_from_certs<T>(
        &self,
        certs: &[(Address, T)],
    ) -> (HashSet<Address>, u32) {
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
        (certified, weight_sum)
    }

    pub(crate) async fn verified_nonce_certs<T>(
        mpc_manager: &Arc<RwLock<Self>>,
        epoch: u64,
        certs: Vec<(Address, T)>,
    ) -> Vec<(Address, T)>
    where
        T: NonceCertToVerify,
    {
        let mut verified = Vec::with_capacity(certs.len());
        for (dealer, cert) in certs {
            let dealer_cert = match cert.to_dealer_certificate(epoch) {
                Ok(dealer_cert) => dealer_cert,
                Err(e) => {
                    tracing::info!("recovery: dropping malformed nonce cert from {dealer:?}: {e}");
                    continue;
                }
            };
            let mgr = Arc::clone(mpc_manager);
            let verification = spawn_blocking(move || {
                mgr.read().unwrap().committee.verify_signature(&dealer_cert)
            })
            .await;
            match verification {
                Ok(()) => verified.push((dealer, cert)),
                Err(e) => tracing::info!(
                    "recovery: dropping nonce cert with invalid signature from {dealer:?}: {e}"
                ),
            }
        }
        verified
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
                match mgr.current_dkg_messages.get(&dealer) {
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
                        .current_dkg_messages
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
                let recovered = Self::recover_dkg_shares_via_complaint(
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
                // Use the reduced weights, not the original committee weights.
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
                match mgr.current_rotation_messages.get(&dealer) {
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
                    .current_rotation_messages
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
            Self::publish_nonce_generation_cert(tob_channel, batch_index, nonce_cert, metrics)
                .await?;
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
            Parameters {
                t: self.mpc_config.threshold,
                f: self.mpc_config.max_faulty,
            },
            dealer_session_id.to_vec(),
            rng,
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
        if epoch == self.mpc_config.epoch {
            self.current_dkg_messages.insert(dealer, message.clone());
        }
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
        if epoch == self.mpc_config.epoch {
            self.current_rotation_messages
                .insert(dealer, messages.clone());
        }
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
        if epoch == self.mpc_config.epoch {
            self.current_nonce_messages
                .insert((nonce.batch_index, dealer), nonce.clone());
        }
        self.public_messages_store
            .store_nonce_message(epoch, nonce.batch_index, &dealer, &nonce.message)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn cache_and_persist_avid_round_state(
        &mut self,
        epoch: u64,
        batch_index: u32,
        dealer: Address,
        state: &AvidRoundState,
    ) -> MpcResult<()> {
        if epoch == self.mpc_config.epoch {
            self.current_avid_round_state
                .insert((batch_index, dealer), state.clone());
        }
        self.public_messages_store
            .store_avid_round_state(epoch, batch_index, &dealer, state)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn cache_and_persist_avid_held_echoes(
        &mut self,
        batch_index: u32,
        dealer: Address,
        held: HeldAvidEchoes,
    ) -> MpcResult<()> {
        self.public_messages_store
            .store_avid_held_echoes(self.mpc_config.epoch, batch_index, &dealer, &held)
            .map_err(|e| MpcError::StorageError(e.to_string()))?;
        self.avid_held_echoes.insert((batch_index, dealer), held);
        Ok(())
    }

    fn get_avid_held_echoes(&self, batch_index: u32, dealer: &Address) -> Option<HeldAvidEchoes> {
        self.avid_held_echoes
            .get(&(batch_index, *dealer))
            .cloned()
            .or_else(|| {
                self.public_messages_store
                    .get_avid_held_echoes(self.mpc_config.epoch, batch_index, dealer)
                    .ok()
                    .flatten()
            })
    }

    fn needs_nonce_retrieval(
        &mut self,
        dealer: Address,
        batch_index: u32,
        expected_hash: &MessageHash,
    ) -> bool {
        if let Some(stored) = self.current_nonce_messages.get(&(batch_index, dealer)) {
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
            self.current_nonce_messages
                .insert((batch_index, dealer), nonce);
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
            Messages::Rotation(_)
            | Messages::NonceGeneration(_)
            | Messages::NonceGenerationAvid(_)
            | Messages::AvidNonceRetrieval(_) => {
                panic!("try_sign_dkg_message called with non-DKG messages")
            }
        };
        let dealer_session_id = self.session_id.dealer_session_id(&dealer);
        let receiver = avss::Receiver::new(
            self.mpc_config.nodes.clone(),
            self.party_id,
            Parameters {
                t: self.mpc_config.threshold,
                f: self.mpc_config.max_faulty,
            },
            dealer_session_id.to_vec(),
            None, // commitment: None for initial DKG
            self.encryption_key.clone(),
        )?;
        let result = receiver.process_message(message, &mut rand::thread_rng())?;
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
            Messages::Dkg(_)
            | Messages::Rotation(_)
            | Messages::NonceGenerationAvid(_)
            | Messages::AvidNonceRetrieval(_) => {
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

    fn create_avid_nonce_receiver(
        &self,
        dealer: Address,
        batch_index: u32,
    ) -> MpcResult<batch_avss_avid::Receiver> {
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
        batch_avss_avid::Receiver::new(
            self.mpc_config.nodes.clone(),
            self.party_id,
            dealer_party_id,
            Parameters {
                t: self.mpc_config.threshold,
                f: self.mpc_config.max_faulty,
            },
            dealer_session_id.to_vec(),
            self.encryption_key.clone(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn create_avid_nonce_dealer_builder(
        &self,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<batch_avss_avid::AvssMessageBuilder> {
        let dealer_sid = SessionId::nonce_dealer_session_id(
            &self.chain_id,
            self.mpc_config.epoch,
            batch_index,
            &self.address,
        );
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.mpc_config.nodes);
        let dealer = batch_avss_avid::Dealer::new(
            nodes,
            self.party_id,
            Parameters {
                t: self.mpc_config.threshold,
                f: self.mpc_config.max_faulty,
            },
            dealer_sid.to_vec(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        dealer
            .create_avss_messages(rng)
            .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn avid_nonce_optimistic_messages(
        &self,
        builder: &batch_avss_avid::AvssMessageBuilder,
        batch_index: u32,
    ) -> Vec<(Address, Messages)> {
        self.committee
            .members()
            .iter()
            .zip(builder.messages())
            .map(|(member, (_party_id, message))| {
                (
                    member.validator_address(),
                    Messages::NonceGenerationAvid(AvidNonceMessage {
                        batch_index,
                        kind: AvidNonceMessageKind::Optimistic(message),
                    }),
                )
            })
            .collect()
    }

    fn try_sign_avid_nonce_optimistic(
        &mut self,
        dealer: Address,
        batch_index: u32,
        message: &batch_avss_avid::AvssMessage,
    ) -> MpcResult<BLS12381Signature> {
        let receiver = self.create_avid_nonce_receiver(dealer, batch_index)?;
        let (output, avss_vote, verified_common) = receiver
            .process_avss_message(message)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        self.dealer_avid_nonce_outputs
            .insert((batch_index, dealer), output);
        self.current_avid_verified_common
            .insert((batch_index, dealer), verified_common);
        let state = AvidRoundState {
            common: message.common.clone(),
            own_ciphertext: message.ciphertext.clone(),
        };
        self.cache_and_persist_avid_round_state(
            self.mpc_config.epoch,
            batch_index,
            dealer,
            &state,
        )?;
        let confirm = DealerMessagesHash {
            dealer_address: dealer,
            messages_hash: MessageHash::from(avss_vote.common_message_hash.digest),
        };
        let signature = self
            .signing_key
            .sign(self.mpc_config.epoch, self.address, &confirm);
        Ok(signature.signature().clone())
    }

    fn create_avid_nonce_dispersal_messages(
        &self,
        builder: &batch_avss_avid::AvssMessageBuilder,
        confirm_cert: DealerCertificate,
        batch_index: u32,
    ) -> MpcResult<Vec<(Address, Messages)>> {
        let dealer_sid = SessionId::nonce_dealer_session_id(
            &self.chain_id,
            self.mpc_config.epoch,
            batch_index,
            &self.address,
        );
        let nodes = self.maybe_corrupt_nodes_for_testing(&self.mpc_config.nodes);
        let dealer = batch_avss_avid::Dealer::new(
            nodes,
            self.party_id,
            Parameters {
                t: self.mpc_config.threshold,
                f: self.mpc_config.max_faulty,
            },
            dealer_sid.to_vec(),
            self.batch_size_per_weight,
        )
        .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        let avid_confirm =
            AvidCertificate::confirm(confirm_cert.clone(), Arc::new(self.committee.clone()))?;
        let avid_builder = dealer
            .create_avid_messages(builder, avid_confirm)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        self.committee
            .members()
            .iter()
            .enumerate()
            .map(|(j, member)| {
                let message = avid_builder
                    .message_for(j as u16)
                    .map_err(|e| MpcError::CryptoError(e.to_string()))?;
                Ok((
                    member.validator_address(),
                    Messages::NonceGenerationAvid(AvidNonceMessage {
                        batch_index,
                        kind: AvidNonceMessageKind::Dispersal {
                            dispersal: message.dispersal,
                            confirm_cert: confirm_cert.clone(),
                        },
                    }),
                ))
            })
            .collect()
    }

    fn avid_nonce_echo_and_vote(
        &mut self,
        dealer: Address,
        batch_index: u32,
        common: batch_avss_avid::AvssCommonMessage,
        dispersal: batch_avss_avid::Dispersal,
        confirm_cert: DealerCertificate,
    ) -> MpcResult<AvidEchoAndVote> {
        let own_common = self
            .get_avid_round_common(batch_index, &dealer)
            .ok_or_else(|| {
                MpcError::NotReady("no verified common message for this AVID round".into())
            })?;
        if own_common.hash() != common.hash() {
            return Err(MpcError::InvalidMessage {
                sender: dealer,
                reason: "dispersal common does not match this node's verified round state".into(),
            });
        }
        self.ensure_avid_nonce_output(dealer, batch_index)?;
        let receiver = self.create_avid_nonce_receiver(dealer, batch_index)?;
        let verified_common = self.avid_round_verified_common(dealer, batch_index)?;
        let avid_confirm =
            AvidCertificate::confirm(confirm_cert, Arc::new(self.committee.clone()))?;
        let avid_message = batch_avss_avid::AvidMessage {
            dispersal,
            avss_cert: avid_confirm,
        };
        let (echo_builder, avid_vote) = receiver
            .process_avid_message(&verified_common, avid_message)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        let target = DealerMessagesHash {
            dealer_address: dealer,
            messages_hash: hash_avid_vote(&avid_vote),
        };
        let vote = self
            .signing_key
            .sign(self.mpc_config.epoch, self.address, &target)
            .signature()
            .clone();
        let echoes = avid_vote
            .vote
            .recipients
            .iter()
            .map(|&r| {
                let echo = echo_builder
                    .create_echo(r)
                    .map_err(|e| MpcError::CryptoError(e.to_string()))?;
                let addr = self
                    .committee
                    .members()
                    .get(r as usize)
                    .ok_or_else(|| {
                        MpcError::CryptoError(format!("echo recipient {r} not in committee"))
                    })?
                    .validator_address();
                Ok((
                    addr,
                    Messages::NonceGenerationAvid(AvidNonceMessage {
                        batch_index,
                        kind: AvidNonceMessageKind::Echo { dealer, echo },
                    }),
                ))
            })
            .collect::<MpcResult<Vec<_>>>()?;

        Ok((vote, avid_vote, echoes))
    }

    fn handle_avid_nonce_complaint_request(
        &mut self,
        caller: Address,
        request: &ComplainRequest,
    ) -> MpcResult<ComplaintResponse> {
        if self.mpc_config.nonce_generation_protocol != NonceGenerationProtocol::Avid {
            return Err(MpcError::InvalidMessage {
                sender: caller,
                reason: "AVID nonce complaints are rejected in a vanilla nonce generation epoch"
                    .into(),
            });
        }
        if request.epoch != self.mpc_config.epoch {
            return Err(MpcError::NotFound(
                "AVID complaints serve the current epoch only".into(),
            ));
        }
        let batch_index = request
            .batch_index
            .ok_or_else(|| MpcError::InvalidMessage {
                sender: caller,
                reason: "batch_index required for nonce complaint".into(),
            })?;
        let accuser_id =
            self.committee
                .index_of(&caller)
                .ok_or_else(|| MpcError::InvalidMessage {
                    sender: caller,
                    reason: "complainer not in committee".into(),
                })? as PartyId;
        let state = self
            .get_avid_round_state(batch_index, &request.dealer)?
            .ok_or_else(|| {
                MpcError::NotFound("no AVID round state for the complained round".into())
            })?;
        let receiver = self.create_avid_nonce_receiver(request.dealer, batch_index)?;
        let verified_common = self.avid_round_verified_common(request.dealer, batch_index)?;
        let mut rng = rand::thread_rng();
        let response = match &request.complaint {
            ProtocolComplaint::AvidReveal(complaint) => receiver
                .handle_avss_complaint(
                    complaint,
                    accuser_id,
                    &verified_common,
                    state.own_ciphertext,
                    &mut rng,
                )
                .map_err(|e| MpcError::CryptoError(e.to_string()))?,
            ProtocolComplaint::AvidBlame {
                complaint,
                vote_cert,
            } => {
                let (held_vote, _) = self
                    .get_avid_held_echoes(batch_index, &request.dealer)
                    .ok_or_else(|| {
                        MpcError::NotFound("no held vote for the complained round".into())
                    })?;
                let cert = AvidCertificate::vote(
                    vote_cert.clone(),
                    held_vote,
                    Arc::new(self.committee.clone()),
                )?
                .into_verified()
                .map_err(|e| MpcError::CryptoError(e.to_string()))?;
                receiver
                    .handle_avid_complaint(
                        complaint,
                        accuser_id,
                        &verified_common,
                        &cert,
                        state.own_ciphertext,
                        &mut rng,
                    )
                    .map_err(|e| MpcError::CryptoError(e.to_string()))?
            }
            ProtocolComplaint::Avss(_) | ProtocolComplaint::BatchedAvss(_) => {
                unreachable!("routed by the AVID complaint check")
            }
        };
        tracing::info!(
            "AVID nonce complaint answered: accuser {:?}, dealer {:?}, batch_index={batch_index}, \
             kind {}",
            caller,
            request.dealer,
            match &request.complaint {
                ProtocolComplaint::AvidReveal(_) => "reveal",
                ProtocolComplaint::AvidBlame { .. } => "blame",
                _ => unreachable!("routed by the AVID complaint check"),
            }
        );
        Ok(ComplaintResponse::NonceGenerationAvid(response))
    }

    fn ensure_avid_nonce_output(&mut self, dealer: Address, batch_index: u32) -> MpcResult<()> {
        if self
            .dealer_avid_nonce_outputs
            .contains_key(&(batch_index, dealer))
        {
            return Ok(());
        }
        let state = self
            .get_avid_round_state(batch_index, &dealer)?
            .ok_or_else(|| {
                MpcError::NotReady("no verified common message for this AVID round".into())
            })?;
        let message = batch_avss_avid::AvssMessage {
            common: state.common,
            ciphertext: state.own_ciphertext,
        };
        self.try_sign_avid_nonce_optimistic(dealer, batch_index, &message)?;
        tracing::info!(
            "AVID nonce output re-derived from persisted round state: dealer {:?}, \
             batch_index={batch_index}",
            dealer
        );
        Ok(())
    }

    fn get_avid_round_common(
        &self,
        batch_index: u32,
        dealer: &Address,
    ) -> Option<batch_avss_avid::AvssCommonMessage> {
        self.get_avid_round_state(batch_index, dealer)
            .ok()
            .flatten()
            .map(|s| s.common)
    }

    fn get_avid_round_state(
        &self,
        batch_index: u32,
        dealer: &Address,
    ) -> MpcResult<Option<AvidRoundState>> {
        self.current_avid_round_state
            .get(&(batch_index, *dealer))
            .cloned()
            .map(|s| Ok(Some(s)))
            .unwrap_or_else(|| {
                self.public_messages_store
                    .get_avid_round_state(self.mpc_config.epoch, batch_index, dealer)
                    .map_err(|e| MpcError::StorageError(e.to_string()))
            })
    }

    fn avid_round_verified_common(
        &mut self,
        dealer: Address,
        batch_index: u32,
    ) -> MpcResult<batch_avss_avid::VerifiedAvssCommonMessage> {
        if let Some(verified) = self
            .current_avid_verified_common
            .get(&(batch_index, dealer))
        {
            return Ok(verified.clone());
        }
        let state = self
            .get_avid_round_state(batch_index, &dealer)?
            .ok_or_else(|| {
                MpcError::NotReady("no verified common message for this AVID round".into())
            })?;
        let receiver = self.create_avid_nonce_receiver(dealer, batch_index)?;
        let message = batch_avss_avid::AvssMessage {
            common: state.common,
            ciphertext: state.own_ciphertext,
        };
        let (_, _, verified_common) = receiver
            .process_avss_message(&message)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        self.current_avid_verified_common
            .insert((batch_index, dealer), verified_common.clone());
        Ok(verified_common)
    }

    fn handle_avid_nonce_message(
        &mut self,
        sender: Address,
        message: &AvidNonceMessage,
    ) -> MpcResult<BLS12381Signature> {
        let batch_index = message.batch_index;
        match &message.kind {
            AvidNonceMessageKind::Optimistic(msg) => {
                if let Some(common) = self.get_avid_round_common(batch_index, &sender)
                    && common.hash() != msg.common.hash()
                {
                    return Err(MpcError::InvalidMessage {
                        sender,
                        reason: "Dealer sent different messages".to_string(),
                    });
                }
                self.try_sign_avid_nonce_optimistic(sender, batch_index, msg)
            }
            AvidNonceMessageKind::Dispersal {
                dispersal,
                confirm_cert,
            } => {
                let common = self
                    .get_avid_round_common(batch_index, &sender)
                    .ok_or_else(|| {
                        MpcError::NotReady("no verified common message for this AVID round".into())
                    })?;
                let (vote, avid_vote, echoes) = self.avid_nonce_echo_and_vote(
                    sender,
                    batch_index,
                    common,
                    dispersal.clone(),
                    confirm_cert.clone(),
                )?;
                let vote_hash = hash_avid_vote(&avid_vote);
                if let Some((held_vote, _)) = self.get_avid_held_echoes(batch_index, &sender)
                    && hash_avid_vote(&held_vote) != vote_hash
                {
                    return Err(MpcError::InvalidMessage {
                        sender,
                        reason: "Dealer sent a different dispersal".to_string(),
                    });
                }
                self.cache_and_persist_avid_held_echoes(
                    batch_index,
                    sender,
                    (avid_vote.clone(), echoes),
                )?;
                Ok(vote)
            }
            AvidNonceMessageKind::Echo { .. } => Err(MpcError::InvalidMessage {
                sender,
                reason: "AVID echoes are pull-served, not pushed".into(),
            }),
        }
    }

    fn prepare_avid_nonce_dealer_flow(
        &mut self,
        batch_index: u32,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<AvidDealerFlowData> {
        let epoch = self.mpc_config.epoch;
        let builder = match self
            .public_messages_store
            .get_avid_dealer_builder(epoch, batch_index)
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            Some(builder) => builder,
            None => {
                let builder = self.create_avid_nonce_dealer_builder(batch_index, rng)?;
                self.public_messages_store
                    .store_avid_dealer_builder(epoch, batch_index, &builder)
                    .map_err(|e| MpcError::StorageError(e.to_string()))?;
                builder
            }
        };
        let mut messages = self.avid_nonce_optimistic_messages(&builder, batch_index);
        let own_index = messages
            .iter()
            .position(|(addr, _)| *addr == self.address)
            .ok_or_else(|| MpcError::ProtocolFailed("dealer not in committee".into()))?;
        let (_, own_message) = messages.remove(own_index);
        let Messages::NonceGenerationAvid(AvidNonceMessage {
            kind: AvidNonceMessageKind::Optimistic(own_avss),
            ..
        }) = own_message
        else {
            unreachable!("avid_nonce_optimistic_messages yields optimistic messages");
        };
        let signature =
            self.try_sign_avid_nonce_optimistic(self.address, batch_index, &own_avss)?;
        let my_signature = MemberSignature::new(epoch, self.address, signature);
        let confirm_target = DealerMessagesHash {
            dealer_address: self.address,
            messages_hash: MessageHash::from(own_avss.common.hash().digest),
        };
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
        let total_reduced_weight = self.mpc_config.nodes.total_weight() as u32;
        let vote_quorum_weight = total_reduced_weight - self.mpc_config.max_faulty as u32;
        Ok(AvidDealerFlowData {
            builder,
            confirm_target,
            my_signature,
            recipient_messages: messages,
            committee: self.committee.clone(),
            reduced_weights,
            total_reduced_weight,
            vote_quorum_weight,
        })
    }

    async fn run_as_avid_nonce_dealer(
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
        let mut dealer_data = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                let mut rng = rand::thread_rng();
                let mut mgr = mgr.write().unwrap();
                mgr.prepare_avid_nonce_dealer_flow(batch_index, &mut rng)
            })
            .await?
        };
        drop(_timer);
        let mut aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            dealer_data.confirm_target.clone(),
            dealer_data.reduced_weights.clone(),
        );
        aggregator
            .add_signature(dealer_data.my_signature.clone())
            .expect("first signature should always be valid");
        let _timer = metrics
            .mpc_p2p_broadcast_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let requests: Vec<_> = std::mem::take(&mut dealer_data.recipient_messages)
            .into_iter()
            .map(|(addr, messages)| (addr, SendMessagesRequest { messages }))
            .collect();
        let results = send_each(requests, |addr, req| async move {
            p2p_channel.send_messages(&addr, &req).await
        })
        .await;
        drop(_timer);
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    if let Err(e) = aggregator.add_signature_from(addr, response.signature) {
                        tracing::info!("Invalid Confirm signature from {:?}: {}", addr, e);
                    }
                }
                Err(e) => {
                    tracing::info!("Failed to send optimistic message to {:?}: {}", addr, e)
                }
            }
        }
        let confirmed = aggregator.reduced_weight() as u32;
        if confirmed >= dealer_data.total_reduced_weight {
            let cert = aggregator
                .finish()
                .expect("signatures should always be valid");
            return Self::publish_nonce_generation_cert(tob_channel, batch_index, cert, metrics)
                .await;
        }
        let pending = dealer_data.total_reduced_weight - confirmed;
        let (max_faulty, min_confirm_weight, address) = {
            let mgr = mpc_manager.read().unwrap();
            (
                mgr.mpc_config.max_faulty as u32,
                (mgr.mpc_config.threshold + mgr.mpc_config.max_faulty) as u32,
                mgr.address,
            )
        };
        if pending > max_faulty || confirmed < min_confirm_weight {
            tracing::warn!(
                "AVID nonce round abandoned: pending weight {pending} > f={max_faulty} or \
                 confirmed weight {confirmed} < t+f={min_confirm_weight} (batch_index={batch_index})"
            );
            return Ok(());
        }
        tracing::info!(
            "AVID nonce round entered the pessimistic path: dealer {address:?}, \
             batch_index={batch_index}, confirmed weight {confirmed}, pending weight {pending}"
        );
        let confirm_cert = aggregator
            .finish()
            .expect("signatures should always be valid");
        let _timer = metrics
            .mpc_dealer_crypto_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let builder = dealer_data.builder;
        let (vote_target, my_vote, recipient_dispersals) = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || -> MpcResult<_> {
                let mut mgr = mgr.write().unwrap();
                let mut dispersals =
                    mgr.create_avid_nonce_dispersal_messages(&builder, confirm_cert, batch_index)?;
                let own_index = dispersals
                    .iter()
                    .position(|(addr, _)| *addr == mgr.address)
                    .ok_or_else(|| MpcError::ProtocolFailed("dealer not in committee".into()))?;
                let (_, own_dispersal) = dispersals.remove(own_index);
                let Messages::NonceGenerationAvid(own_avid) = &own_dispersal else {
                    unreachable!("create_avid_nonce_dispersal_messages yields AVID messages");
                };
                let own_address = mgr.address;
                let signature = mgr.handle_avid_nonce_message(own_address, own_avid)?;
                let vote_hash = hash_avid_vote(
                    &mgr.avid_held_echoes
                        .get(&(batch_index, mgr.address))
                        .expect("own dispersal was just processed")
                        .0,
                );
                let vote_target = DealerMessagesHash {
                    dealer_address: mgr.address,
                    messages_hash: vote_hash,
                };
                let my_vote = MemberSignature::new(mgr.mpc_config.epoch, mgr.address, signature);
                Ok((vote_target, my_vote, dispersals))
            })
            .await?
        };
        drop(_timer);
        let mut vote_aggregator = BlsSignatureAggregator::new_with_reduced_weights(
            &dealer_data.committee,
            vote_target,
            dealer_data.reduced_weights.clone(),
        );
        vote_aggregator
            .add_signature(my_vote)
            .expect("first signature should always be valid");
        let _timer = metrics
            .mpc_p2p_broadcast_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        let requests: Vec<_> = recipient_dispersals
            .into_iter()
            .map(|(addr, messages)| (addr, SendMessagesRequest { messages }))
            .collect();
        let results = send_each(requests, |addr, req| async move {
            p2p_channel.send_messages(&addr, &req).await
        })
        .await;
        drop(_timer);
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    if let Err(e) = vote_aggregator.add_signature_from(addr, response.signature) {
                        tracing::info!("Invalid Vote signature from {:?}: {}", addr, e);
                    }
                }
                Err(e) => tracing::info!("No Vote from {:?}: {}", addr, e),
            }
        }
        if (vote_aggregator.reduced_weight() as u32) >= dealer_data.vote_quorum_weight {
            tracing::info!(
                "AVID nonce Vote quorum reached: dealer {address:?}, batch_index={batch_index}, \
                 weight {} >= {}",
                vote_aggregator.reduced_weight(),
                dealer_data.vote_quorum_weight
            );
            let cert = vote_aggregator
                .finish()
                .expect("signatures should always be valid");
            return Self::publish_nonce_generation_cert(tob_channel, batch_index, cert, metrics)
                .await;
        }
        tracing::warn!(
            "AVID Vote quorum not reached: {} < {} (batch_index={batch_index})",
            vote_aggregator.reduced_weight(),
            dealer_data.vote_quorum_weight
        );
        Ok(())
    }

    fn reduced_weight_of_cert(&self, cert: &DealerCertificate) -> MpcResult<u32> {
        let signers = cert
            .signers(&self.committee)
            .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?;
        Ok(signers
            .iter()
            .filter_map(|addr| {
                let party_id = self.committee.index_of(addr)? as u16;
                self.mpc_config
                    .nodes
                    .weight_of(party_id)
                    .ok()
                    .map(|w| w as u32)
            })
            .sum())
    }

    fn resolve_avid_cert_kind_locally(
        &self,
        batch_index: u32,
        dealer: &Address,
        digest: &MessageHash,
    ) -> Option<CertKind> {
        if let Some(common) = self.get_avid_round_common(batch_index, dealer)
            && MessageHash::from(common.hash().digest) == *digest
        {
            return Some(CertKind::AvssVote);
        }
        if let Some((vote, _)) = self.get_avid_held_echoes(batch_index, dealer)
            && hash_avid_vote(&vote) == *digest
        {
            return Some(CertKind::AvidVote);
        }
        None
    }

    async fn pull_and_resolve_avid_cert(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: Address,
        batch_index: u32,
        nonce_cert: &DealerCertificate,
        p2p_channel: &impl P2PChannel,
        metrics: &Metrics,
    ) -> MpcResult<CertKind> {
        let (request, signers) = {
            let mgr = mpc_manager.read().unwrap();
            let request = RetrieveMessagesRequest {
                dealer,
                protocol_type: ProtocolTypeIndicator::NonceGeneration,
                epoch: mgr.mpc_config.epoch,
                batch_index: Some(batch_index),
            };
            let signers: Vec<Address> = nonce_cert
                .signers(&mgr.committee)
                .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?
                .into_iter()
                .filter(|addr| *addr != mgr.address)
                .collect();
            (request, signers)
        };
        let complaint_signers = signers.clone();
        let results = send_to_many(signers, request, |addr, req| async move {
            p2p_channel.retrieve_messages(&addr, &req).await
        })
        .await;
        let bundles: Vec<(Address, AvidNonceRetrievalMessage)> = results
            .into_iter()
            .filter_map(|(addr, result)| match result {
                Ok(RetrieveMessagesResponse {
                    messages: Messages::AvidNonceRetrieval(bundle),
                }) => Some((addr, bundle)),
                Ok(_) => {
                    tracing::info!("Unexpected retrieval response from {:?}", addr);
                    None
                }
                Err(e) => {
                    tracing::info!("AVID retrieval from {:?} failed: {}", addr, e);
                    None
                }
            })
            .collect();
        let mgr = Arc::clone(mpc_manager);
        let nonce_cert = nonce_cert.clone();
        let outcome = spawn_blocking(move || {
            let mut mgr = mgr.write().unwrap();
            let digest = nonce_cert.message().messages_hash;
            let avid_vote = bundles.iter().find_map(|(_, b)| {
                b.avid_vote
                    .as_ref()
                    .filter(|v| hash_avid_vote(v) == digest)
                    .cloned()
            });
            let Some(avid_vote) = avid_vote else {
                let common_pins = bundles.iter().any(|(_, b)| {
                    b.common
                        .as_ref()
                        .is_some_and(|c| MessageHash::from(c.hash().digest) == digest)
                });
                return if common_pins {
                    Ok((CertKind::AvssVote, None))
                } else {
                    Err(MpcError::NotFound(
                        "no pulled artifact pins to the certified digest".into(),
                    ))
                };
            };
            let expected_common_hash = avid_vote.common_message_hash;
            let common = bundles
                .iter()
                .find_map(|(_, b)| {
                    b.common
                        .as_ref()
                        .filter(|c| c.hash() == expected_common_hash)
                        .cloned()
                })
                .ok_or_else(|| {
                    MpcError::NotFound("no common message pins to the certified vote".into())
                })?;
            let vote_cert = AvidCertificate::vote(
                nonce_cert.clone(),
                avid_vote,
                Arc::new(mgr.committee.clone()),
            )?
            .into_verified()
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
            let mut verified_echoes = Vec::new();
            for (addr, bundle) in &bundles {
                let Some(echo) = bundle.echo.clone() else {
                    continue;
                };
                let Some(sender) = mgr.committee.index_of(addr).map(|i| i as PartyId) else {
                    continue;
                };
                match mgr.verify_avid_nonce_echo(dealer, batch_index, sender, echo, &vote_cert) {
                    Ok(verified) => verified_echoes.push(verified),
                    Err(e) => tracing::info!("Echo from {:?} failed to verify: {}", addr, e),
                }
            }
            let mut rng = rand::thread_rng();
            match mgr.decode_avid_nonce_share(
                dealer,
                batch_index,
                common.clone(),
                &verified_echoes,
                &vote_cert,
                &mut rng,
            ) {
                Ok((batch_avss_avid::DecodeAndDecryptOutcome::Valid(..), _)) => {
                    tracing::info!(
                        "AVID laggard decode completed: dealer {:?}, batch_index={batch_index}",
                        dealer
                    );
                }
                Ok((
                    batch_avss_avid::DecodeAndDecryptOutcome::InvalidDecryption(complaint),
                    verified_common,
                )) => {
                    return Ok((
                        CertKind::AvidVote,
                        Some((ProtocolComplaint::AvidReveal(complaint), verified_common)),
                    ));
                }
                Ok((
                    batch_avss_avid::DecodeAndDecryptOutcome::InvalidDispersal(complaint),
                    verified_common,
                )) => {
                    return Ok((
                        CertKind::AvidVote,
                        Some((
                            ProtocolComplaint::AvidBlame {
                                complaint,
                                vote_cert: nonce_cert,
                            },
                            verified_common,
                        )),
                    ));
                }
                Err(e) => {
                    tracing::warn!("AVID decode for dealer {:?} failed: {}", dealer, e);
                }
            }
            Ok((CertKind::AvidVote, None))
        })
        .await?;
        let (kind, complaint) = outcome;
        if let Some((complaint, verified_common)) = complaint
            && let Err(e) = Self::recover_avid_nonce_shares_via_complaint(
                mpc_manager,
                dealer,
                batch_index,
                verified_common,
                complaint,
                complaint_signers,
                p2p_channel,
                metrics,
            )
            .await
        {
            tracing::warn!(
                "AVID complaint recovery for dealer {:?} failed: {}",
                dealer,
                e
            );
        }
        Ok(kind)
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_avid_nonce_shares_via_complaint(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: Address,
        batch_index: u32,
        verified_common: batch_avss_avid::VerifiedAvssCommonMessage,
        complaint: ProtocolComplaint,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
        metrics: &Metrics,
    ) -> MpcResult<()> {
        let epoch = {
            let mgr = mpc_manager.read().unwrap();
            mgr.mpc_config.epoch
        };
        let request = ComplainRequest {
            dealer,
            share_index: None,
            batch_index: Some(batch_index),
            complaint,
            protocol_type: ProtocolTypeIndicator::NonceGeneration,
            epoch,
        };
        let receiver = {
            let mgr = Arc::clone(mpc_manager);
            spawn_blocking(move || {
                mgr.read()
                    .unwrap()
                    .create_avid_nonce_receiver(dealer, batch_index)
            })
            .await?
        };
        let receiver = Arc::new(receiver);
        let verified_common = Arc::new(verified_common);
        let mut verified: Vec<batch_avss_avid::VerifiedComplaintResponse> = Vec::new();
        let mut futures = fan_out_complaints(signers, p2p_channel, &request);
        while let Some((signer, result)) = futures.next().await {
            let response = match result {
                Ok(ComplaintResponse::NonceGenerationAvid(response)) => response,
                Ok(_) => {
                    tracing::info!(
                        "Unexpected response kind in AVID complaint recovery from {:?}",
                        signer
                    );
                    continue;
                }
                Err(e) => {
                    tracing::info!("AVID complaint to {:?} failed: {}", signer, e);
                    continue;
                }
            };
            let responder_id = {
                let mgr = mpc_manager.read().unwrap();
                match mgr.committee.index_of(&signer) {
                    Some(index) => index as PartyId,
                    None => continue,
                }
            };
            let result = {
                let receiver = Arc::clone(&receiver);
                let verified_common = Arc::clone(&verified_common);
                let verified_so_far = verified.clone();
                spawn_blocking(move || {
                    let response = receiver
                        .verify_complaint_response(responder_id, response, &verified_common)
                        .map_err(|e| {
                            tracing::info!(
                                "Complaint response from {:?} failed to verify: {}",
                                signer,
                                e
                            );
                        })
                        .ok()?;
                    let mut attempt = verified_so_far;
                    attempt.push(response.clone());
                    Some((response, receiver.recover(&verified_common, attempt).ok()))
                })
                .await
            };
            let Some((response, output)) = result else {
                continue;
            };
            verified.push(response);
            if let Some(output) = output {
                let mut mgr = mpc_manager.write().unwrap();
                mgr.dealer_avid_nonce_outputs
                    .insert((batch_index, dealer), output);
                tracing::info!(
                    "AVID nonce shares recovered via complaint: dealer {:?}, \
                     batch_index={batch_index}, responses used {}",
                    dealer,
                    verified.len()
                );
                metrics.mpc_avid_complaints_recovered_total.inc();
                return Ok(());
            }
        }
        Err(MpcError::ProtocolFailed(
            "AVID complaint recovery did not reach the response quorum".into(),
        ))
    }

    async fn run_as_avid_nonce_party(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        p2p_channel: &impl P2PChannel,
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        metrics: &Metrics,
    ) -> MpcResult<HashSet<Address>> {
        let (required_weight, total_reduced_weight, vote_quorum_weight) = {
            let mgr = mpc_manager.read().unwrap();
            let total = mgr.mpc_config.nodes.total_weight() as u32;
            (
                mgr.required_nonce_weight(),
                total,
                total - mgr.mpc_config.max_faulty as u32,
            )
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
            let dealer = nonce_cert.message().dealer_address;
            if certified_dealers.contains(&dealer) {
                continue;
            }
            let signer_weight = {
                let _timer = metrics
                    .mpc_cert_verify_duration_seconds
                    .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                    .start_timer();
                let mgr = Arc::clone(mpc_manager);
                let cert = nonce_cert.clone();
                let result = spawn_blocking(move || {
                    let mgr = mgr.read().unwrap();
                    mgr.committee
                        .verify_signature(&cert)
                        .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?;
                    mgr.reduced_weight_of_cert(&cert)
                })
                .await;
                drop(_timer);
                match result {
                    Ok(weight) => weight,
                    Err(e) => {
                        tracing::info!("Invalid nonce certificate from {:?}: {}", dealer, e);
                        continue;
                    }
                }
            };
            let digest = nonce_cert.message().messages_hash;
            let kind = {
                let mgr = mpc_manager.read().unwrap();
                mgr.resolve_avid_cert_kind_locally(batch_index, &dealer, &digest)
            };
            let kind = match kind {
                Some(kind) => kind,
                None => {
                    let _timer = metrics
                        .mpc_message_retrieval_duration_seconds
                        .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
                        .start_timer();
                    let result = Self::pull_and_resolve_avid_cert(
                        mpc_manager,
                        dealer,
                        batch_index,
                        &nonce_cert,
                        p2p_channel,
                        metrics,
                    )
                    .await;
                    drop(_timer);
                    match result {
                        Ok(kind) => kind,
                        Err(e) => {
                            tracing::warn!(
                                "Could not resolve AVID cert kind for dealer {:?}: {}",
                                dealer,
                                e
                            );
                            continue;
                        }
                    }
                }
            };
            let required_cert_weight = match kind {
                CertKind::AvssVote => total_reduced_weight,
                CertKind::AvidVote => vote_quorum_weight,
            };
            if signer_weight < required_cert_weight {
                tracing::warn!(
                    "AVID nonce cert for dealer {:?} below quorum: {} < {} ({:?})",
                    dealer,
                    signer_weight,
                    required_cert_weight,
                    kind
                );
                continue;
            }
            let dealer_weight = {
                let mut mgr = mpc_manager.write().unwrap();
                if let Err(e) = mgr.ensure_avid_nonce_output(dealer, batch_index) {
                    tracing::warn!(
                        "No AVID nonce output for {:?} after processing: {}",
                        dealer,
                        e
                    );
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
            tracing::info!(
                "AVID nonce round consumed: dealer {:?}, batch_index={batch_index}, kind {:?}",
                dealer,
                kind
            );
            metrics
                .mpc_avid_rounds_total
                .with_label_values(&[match kind {
                    CertKind::AvssVote => "confirm",
                    CertKind::AvidVote => "vote",
                }])
                .inc();
            dealer_weight_sum += dealer_weight as u32;
            certified_dealers.insert(dealer);
        }
        Ok(certified_dealers)
    }

    async fn publish_nonce_generation_cert(
        tob_channel: &mut impl OrderedBroadcastChannel<CertificateV1>,
        batch_index: u32,
        cert: DealerCertificate,
        metrics: &Metrics,
    ) -> MpcResult<()> {
        let cert = CertificateV1::NonceGeneration { batch_index, cert };
        let _timer = metrics
            .mpc_cert_publish_duration_seconds
            .with_label_values(&[MPC_LABEL_NONCE_GENERATION])
            .start_timer();
        with_timeout_and_retry(|| tob_channel.publish(cert.clone()))
            .await
            .map_err(|e| MpcError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e)))
    }

    fn verify_avid_nonce_echo(
        &self,
        dealer: Address,
        batch_index: u32,
        sender: PartyId,
        echo: batch_avss_avid::Echo,
        vote_cert: &VerifiedAvidVoteCert,
    ) -> MpcResult<batch_avss_avid::VerifiedEcho> {
        let receiver = self.create_avid_nonce_receiver(dealer, batch_index)?;
        receiver
            .verify_avid_echo_message(echo, sender, vote_cert)
            .map_err(|e| MpcError::CryptoError(e.to_string()))
    }

    fn decode_avid_nonce_share(
        &mut self,
        dealer: Address,
        batch_index: u32,
        common: batch_avss_avid::AvssCommonMessage,
        echoes: &[batch_avss_avid::VerifiedEcho],
        vote_cert: &VerifiedAvidVoteCert,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<(
        batch_avss_avid::DecodeAndDecryptOutcome,
        batch_avss_avid::VerifiedAvssCommonMessage,
    )> {
        let receiver = self.create_avid_nonce_receiver(dealer, batch_index)?;
        let verified_common = receiver
            .verify_common_message(vote_cert, common)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        let outcome = receiver
            .decode_and_decrypt(echoes, &verified_common, rng)
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
        if let batch_avss_avid::DecodeAndDecryptOutcome::Valid(output) = &outcome {
            self.dealer_avid_nonce_outputs
                .insert((batch_index, dealer), output.clone());
        }
        Ok((outcome, verified_common))
    }

    fn prune_nonce_state(mpc_manager: &Arc<RwLock<Self>>, batch_index: u32) {
        let cutoff = batch_index.saturating_sub(PRUNE_KEEP_RECENT_BATCHES - 1);
        if cutoff == 0 {
            return;
        }
        let mut mgr = mpc_manager.write().unwrap();
        mgr.current_nonce_messages.retain(|(b, _), _| *b >= cutoff);
        mgr.current_avid_round_state
            .retain(|(b, _), _| *b >= cutoff);
        mgr.current_avid_verified_common
            .retain(|(b, _), _| *b >= cutoff);
        mgr.dealer_nonce_outputs.retain(|(b, _), _| *b >= cutoff);
        mgr.dealer_avid_nonce_outputs
            .retain(|(b, _), _| *b >= cutoff);
        mgr.avid_held_echoes.retain(|(b, _), _| *b >= cutoff);
        mgr.complaints_to_process.retain(|k, _| match k {
            ComplaintsToProcessKey::NonceGeneration { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
        mgr.message_responses.retain(|k, _| match k {
            MessageResponsesKey::NonceGeneration { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
        mgr.complaint_responses.retain(|k, _| match k {
            ComplaintResponsesKey::NonceGeneration { batch_index: b, .. } => *b >= cutoff,
            _ => true,
        });
    }

    fn process_certified_dkg_message(&mut self, dealer: Address) -> MpcResult<()> {
        let output_key = DealerOutputsKey::Dkg(dealer);
        let complaint_key = ComplaintsToProcessKey::Dkg(dealer);
        let message = self
            .current_dkg_messages
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
        let message = match self.current_nonce_messages.get(&(batch_index, dealer)) {
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
                    ProtocolComplaint::BatchedAvss(complaint),
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
            .current_rotation_messages
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
            )
            .map_err(|e| {
                tracing::error!(
                    "process_certified_rotation_message failed: dealer={dealer}, \
                     share_index={share_index}, err={e}"
                );
                e
            })?;
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
            Parameters {
                t: threshold,
                f: self.mpc_config.max_faulty,
            },
            session_id,
            message,
            commitment,
        )? {
            avss::ProcessedMessage::Valid(output) => {
                self.dealer_outputs.insert(output_key, output);
            }
            avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints_to_process
                    .insert(complaint_key, ProtocolComplaint::Avss(complaint));
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
        let outputs: HashMap<PartyId, avss::AvssOutput> = certified_dealers
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
            avss::DkOutput::complete_dkg(threshold, &self.mpc_config.nodes, outputs)
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
        let messages = hedged_retrieve(signers, p2p_channel, &request, message.messages_hash)
            .await
            .ok_or_else(|| {
                MpcError::PairwiseCommunicationError(format!(
                    "Could not retrieve message for dealer {:?} from any signer",
                    message.dealer_address
                ))
            })?;
        let Messages::Dkg(ref msg) = messages else {
            unreachable!(
                "Hash matched DKG certificate but got {:?}",
                std::mem::discriminant(&messages)
            );
        };
        let mut mgr = mpc_manager.write().unwrap();
        let epoch = mgr.mpc_config.epoch;
        mgr.cache_and_persist_dkg_message(epoch, message.dealer_address, msg)?;
        Ok(())
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
        let messages = hedged_retrieve(signers, p2p_channel, &request, message.messages_hash)
            .await
            .ok_or_else(|| {
                MpcError::PairwiseCommunicationError(format!(
                    "Could not retrieve nonce message for dealer {:?} from any signer",
                    message.dealer_address
                ))
            })?;
        let Messages::NonceGeneration(ref nonce) = messages else {
            unreachable!(
                "Hash matched nonce certificate but got {:?}",
                std::mem::discriminant(&messages)
            );
        };
        let mut mgr = mpc_manager.write().unwrap();
        let epoch = mgr.mpc_config.epoch;
        mgr.cache_and_persist_nonce_message(epoch, message.dealer_address, nonce)?;
        Ok(())
    }

    fn prepare_dkg_dealer_flow(
        &mut self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> MpcResult<DealerFlowData> {
        let messages = match self.current_dkg_messages.get(&self.address) {
            Some(msg) => Messages::Dkg(msg.clone()),
            None => match self
                .public_messages_store
                .get_dealer_message(self.mpc_config.epoch, &self.address)
            {
                Ok(Some(msg)) => {
                    self.current_dkg_messages.insert(self.address, msg.clone());
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
        let messages = match self.current_rotation_messages.get(&self.address) {
            Some(msgs) => Messages::Rotation(msgs.clone()),
            None => match self
                .public_messages_store
                .get_rotation_messages(self.mpc_config.epoch, &self.address)
            {
                Ok(Some(msgs)) => {
                    self.current_rotation_messages
                        .insert(self.address, msgs.clone());
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
        let messages = match self
            .current_nonce_messages
            .get(&(batch_index, self.address))
        {
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
                    self.current_nonce_messages
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
        let messages = hedged_retrieve(signers, p2p_channel, &request, message.messages_hash)
            .await
            .ok_or_else(|| {
                MpcError::PairwiseCommunicationError(
                    "Failed to retrieve rotation messages from any signer".to_string(),
                )
            })?;
        let Messages::Rotation(ref msgs) = messages else {
            unreachable!(
                "Hash matched rotation certificate but got {:?}",
                std::mem::discriminant(&messages)
            );
        };
        let mut mgr = mpc_manager.write().unwrap();
        let epoch = mgr.mpc_config.epoch;
        mgr.cache_and_persist_rotation_messages(epoch, message.dealer_address, msgs)?;
        Ok(())
    }

    async fn recover_dkg_shares_via_complaint(
        mpc_manager: &Arc<RwLock<Self>>,
        dealer: &Address,
        message: &avss::Message,
        signers: Vec<Address>,
        p2p_channel: &impl P2PChannel,
        epoch: u64,
    ) -> MpcResult<avss::AvssOutput> {
        let (complaint_request, receiver, committee) = {
            let mgr = mpc_manager.read().unwrap();
            let complaint = mgr
                .complaints_to_process
                .get(&ComplaintsToProcessKey::Dkg(*dealer))
                .ok_or_else(|| MpcError::ProtocolFailed("No complaint for dealer".into()))?;
            let (nodes, party_id, params) = mgr.config_for_epoch(epoch)?;
            let committee = mgr.committee_for_epoch(epoch)?.clone();
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
                params,
                dealer_session_id.to_vec(),
                None,
                mgr.encryption_key.clone(),
            )?;
            (complaint_request, receiver, committee)
        };
        let receiver = Arc::new(receiver);
        let mut responses = Vec::new();
        let mut futures = fan_out_complaints(signers, p2p_channel, &complaint_request);
        while let Some((signer, result)) = futures.next().await {
            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("Complaint to {:?} failed: {}", signer, e);
                    continue;
                }
            };
            let complaint_response = match response {
                ComplaintResponse::Dkg(resp) => resp,
                ComplaintResponse::Rotation(_)
                | ComplaintResponse::NonceGeneration(_)
                | ComplaintResponse::NonceGenerationAvid(_) => {
                    tracing::info!("Unexpected non-DKG response in DKG complaint recovery");
                    continue;
                }
            };
            let Some(verified) = verify_complaint_response_from_signer(
                &receiver,
                &committee,
                message,
                &signer,
                complaint_response,
            ) else {
                continue;
            };
            responses.push(verified);
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
            let message = match mgr.current_nonce_messages.get(&(batch_index, *dealer)) {
                Some(nonce) => nonce.message.clone(),
                None => mgr
                    .public_messages_store
                    .get_nonce_message(epoch, batch_index, dealer)
                    .map_err(|e| MpcError::StorageError(e.to_string()))?
                    .ok_or_else(|| MpcError::NotFound("No nonce message for dealer".into()))?,
            };
            let (nodes, party_id, params) = mgr.config_for_epoch(epoch)?;
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
                params.t,
                dealer_sid.to_vec(),
                mgr.encryption_key.clone(),
                mgr.batch_size_per_weight,
            )
            .map_err(|e| MpcError::CryptoError(e.to_string()))?;
            (complaint_request, receiver, message)
        };
        let receiver = Arc::new(receiver);
        let mut responses = Vec::new();
        let mut futures = fan_out_complaints(signers, p2p_channel, &complaint_request);
        while let Some((signer, result)) = futures.next().await {
            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("Nonce complaint to {:?} failed: {}", signer, e);
                    continue;
                }
            };
            let complaint_response = match response {
                ComplaintResponse::NonceGeneration(resp) => resp,
                ComplaintResponse::Dkg(_)
                | ComplaintResponse::Rotation(_)
                | ComplaintResponse::NonceGenerationAvid(_) => {
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
    ) -> MpcResult<HashMap<ShareIndex, avss::AvssOutput>> {
        let (recovery_contexts, committee) = {
            let mgr = mpc_manager.read().unwrap();
            let contexts =
                mgr.prepare_rotation_complain_requests(dealer, rotation_messages, epoch)?;
            (contexts, mgr.committee_for_epoch(epoch)?.clone())
        };
        if recovery_contexts.is_empty() {
            return Ok(HashMap::new());
        }
        tracing::info!(
            "Rotation complaint detected for dealer {:?} ({} share(s)), recovering via Complain RPC",
            dealer,
            recovery_contexts.len()
        );
        let per_share = recovery_contexts.into_iter().map(|ctx| {
            let signers = signers.clone();
            let committee = committee.clone();
            async move {
                let share_index = ctx.share_index();
                let receiver = Arc::new(ctx.receiver);
                let message = ctx.message;
                let mut responses: Vec<avss::VerifiedComplaintResponse> = Vec::new();
                let mut futures = fan_out_complaints(signers, p2p_channel, &ctx.request);
                while let Some((signer, result)) = futures.next().await {
                    let resp = match result {
                        Ok(ComplaintResponse::Rotation(resp)) => resp,
                        Ok(_) => {
                            tracing::info!(
                                "Unexpected non-rotation response from {} in rotation complaint recovery",
                                signer
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::info!(
                                "Failed to get rotation complaint response from {}: {}",
                                signer,
                                e
                            );
                            continue;
                        }
                    };
                    let Some(verified) = verify_complaint_response_from_signer(
                        &receiver,
                        &committee,
                        &message,
                        &signer,
                        resp,
                    ) else {
                        continue;
                    };
                    responses.push(verified);
                    let try_recover = {
                        let receiver = Arc::clone(&receiver);
                        let message = message.clone();
                        let responses = responses.clone();
                        spawn_blocking(move || receiver.recover(&message, responses)).await
                    };
                    match try_recover {
                        Ok(output) => return Ok((share_index, output)),
                        Err(FastCryptoError::InputTooShort(_)) => continue,
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
                Err(MpcError::ProtocolFailed(format!(
                    "Not enough valid complaint responses for dealer {:?} share {}",
                    dealer, share_index
                )))
            }
        });
        let results: Vec<(ShareIndex, avss::AvssOutput)> =
            futures::future::try_join_all(per_share).await?;
        Ok(results.into_iter().collect())
    }

    fn load_stored_messages(&mut self) -> MpcResult<()> {
        for (dealer, message) in self
            .public_messages_store
            .list_all_dealer_messages()
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            if let Messages::Dkg(msg) = message {
                self.current_dkg_messages.insert(dealer, msg);
            }
        }
        for (dealer, message) in self
            .public_messages_store
            .list_all_rotation_messages()
            .map_err(|e| MpcError::StorageError(e.to_string()))?
        {
            if let Messages::Rotation(msgs) = message {
                self.current_rotation_messages.insert(dealer, msgs);
            }
        }
        Ok(())
    }

    fn prepare_rotation_complain_requests(
        &self,
        dealer: &Address,
        rotation_messages: &RotationMessages,
        epoch: u64,
    ) -> MpcResult<Vec<RotationComplainContext>> {
        let complained_shares: Vec<(ShareIndex, ProtocolComplaint)> = self
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
            return Ok(Vec::new());
        }
        let (nodes, party_id, params) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::KeyRotation);
        complained_shares
            .into_iter()
            .map(|(share_index, complaint)| {
                let message = rotation_messages
                    .get(&share_index)
                    .ok_or_else(|| {
                        MpcError::ProtocolFailed(format!(
                            "No rotation message for share index {}",
                            share_index
                        ))
                    })?
                    .clone();
                let session_id = base_sid.rotation_session_id(dealer, share_index);
                let receiver = avss::Receiver::new(
                    nodes.clone(),
                    party_id,
                    params,
                    session_id.to_vec(),
                    None,
                    self.encryption_key.clone(),
                )?;
                Ok(RotationComplainContext {
                    request: ComplainRequest {
                        dealer: *dealer,
                        share_index: Some(share_index),
                        batch_index: None,
                        complaint,
                        protocol_type: ProtocolTypeIndicator::KeyRotation,
                        epoch,
                    },
                    receiver,
                    message,
                })
            })
            .collect()
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
                    Parameters {
                        t: self.mpc_config.threshold,
                        f: self.mpc_config.max_faulty,
                    },
                    sid.to_vec(),
                    rng,
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
            Messages::Dkg(_)
            | Messages::NonceGeneration(_)
            | Messages::NonceGenerationAvid(_)
            | Messages::AvidNonceRetrieval(_) => {
                panic!("try_sign_rotation_messages called with non-rotation messages")
            }
        };
        let messages_hash = compute_messages_hash(messages);
        if let Some((acked_hash, ack)) = self.rotation_ack_signatures.get(&dealer) {
            if *acked_hash == messages_hash {
                tracing::info!("re-acking identical rotation batch from dealer {dealer}");
                return Ok(ack.clone());
            }
            tracing::warn!(
                "dealer {dealer} sent a rotation batch differing from the one already acked this \
                 epoch (acked {}, got {}); rejecting — equivocation or lost persisted messages",
                hex::encode(<MessageHash as AsRef<[u8; 32]>>::as_ref(acked_hash)),
                hex::encode(<MessageHash as AsRef<[u8; 32]>>::as_ref(&messages_hash)),
            );
            return Err(MpcError::InvalidMessage {
                sender: dealer,
                reason: "Rotation batch differs from the previously acked batch".into(),
            });
        }
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
                Parameters {
                    t: self.mpc_config.threshold,
                    f: self.mpc_config.max_faulty,
                },
                session_id.to_vec(),
                commitment,
                self.encryption_key.clone(),
            )?;
            match receiver.process_message(message, &mut rand::thread_rng())? {
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
        let rotation_message = DealerMessagesHash {
            dealer_address: dealer,
            messages_hash,
        };
        let signature = self
            .signing_key
            .sign(self.mpc_config.epoch, self.address, &rotation_message)
            .signature()
            .clone();
        self.rotation_ack_signatures
            .insert(dealer, (messages_hash, signature.clone()));
        Ok(signature)
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
        let indexed_outputs: Vec<IndexedValue<avss::AvssOutput>> = certified_share_indices
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
        let combined = avss::DkOutput::complete_key_rotation(
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
        complaint_cache: &HashMap<DealerOutputsKey, avss::AvssOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        match certificates.first() {
            Some(CertificateV1::Dkg(_)) | None => {
                self.reconstruct_previous_dkg_output(certificates, complaint_cache)
            }
            Some(CertificateV1::Rotation(_)) => {
                self.reconstruct_previous_rotation_output(certificates, complaint_cache)
            }
            Some(CertificateV1::NonceGeneration { .. }) => {
                unreachable!(
                    "Nonce generation certificates cannot appear as previous certificates for key rotation"
                )
            }
        }
    }

    fn reconstruct_previous_dkg_output(
        &self,
        certificates: &[CertificateV1],
        complaint_cache: &HashMap<DealerOutputsKey, avss::AvssOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        let committee = self.previous_committee.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous committee".into())
        })?;
        let nodes = self.previous_nodes.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous nodes".into())
        })?;
        let output_threshold = self.previous_reconfig_output_threshold.ok_or_else(|| {
            MpcError::InvalidConfig(
                "DKG reconstruction requires previous reconfig's output threshold".into(),
            )
        })?;
        let output_max_faulty = self.previous_reconfig_output_max_faulty.ok_or_else(|| {
            MpcError::InvalidConfig(
                "DKG reconstruction requires previous reconfig's output max_faulty".into(),
            )
        })?;
        let party_id = self.own_party_id(committee)?;
        let encryption_key = self.previous_encryption_key.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("DKG reconstruction requires previous encryption key".into())
        })?;
        let context = DkgReconstructionContext {
            committee,
            nodes,
            party_id,
            encryption_key,
            output_threshold,
            output_max_faulty,
            epoch: self.previous_epoch,
        };
        self.reconstruct_dkg_output(&context, certificates, complaint_cache)
    }

    pub fn reconstruct_current_dkg_output(
        mpc_manager: &Arc<RwLock<Self>>,
        certificates: &[CertificateV1],
        onchain_mpc_key: &[u8],
    ) -> MpcOutputRecoveryOutcome {
        if onchain_mpc_key.is_empty() {
            return MpcOutputRecoveryOutcome::NotApplicable;
        }
        let candidate = {
            let mgr = mpc_manager.read().unwrap();
            let context = DkgReconstructionContext {
                committee: &mgr.committee,
                nodes: &mgr.mpc_config.nodes,
                party_id: mgr.party_id,
                encryption_key: &mgr.encryption_key,
                output_threshold: mgr.mpc_config.threshold,
                output_max_faulty: mgr.mpc_config.max_faulty,
                epoch: mgr.mpc_config.epoch,
            };
            match Self::classify_reconstruction(mgr.reconstruct_dkg_output(
                &context,
                certificates,
                &HashMap::new(),
            )) {
                Ok(output) => output,
                Err(outcome) => return outcome,
            }
        };
        let candidate_key =
            bcs::to_bytes(&candidate.public_key).expect(EXPECT_SERIALIZATION_SUCCESS);
        if candidate_key != onchain_mpc_key {
            return MpcOutputRecoveryOutcome::Suspicious(
                "reconstructed key does not match the on-chain key".into(),
            );
        }
        mpc_manager
            .write()
            .unwrap()
            .set_current_output(candidate.clone());
        MpcOutputRecoveryOutcome::Recovered(candidate)
    }

    pub fn reconstruct_current_rotation_output(
        mpc_manager: &Arc<RwLock<Self>>,
        current_certificates: &[CertificateV1],
        previous_certificates: &[CertificateV1],
        onchain_mpc_key: &[u8],
    ) -> MpcOutputRecoveryOutcome {
        if onchain_mpc_key.is_empty() {
            return MpcOutputRecoveryOutcome::NotApplicable;
        }
        let (current, previous) = {
            let mgr = mpc_manager.read().unwrap();
            let Some(input_threshold) = mgr.previous_reconfig_output_threshold else {
                return MpcOutputRecoveryOutcome::NotApplicable;
            };
            let current_context = RotationReconstructionContext {
                nodes: &mgr.mpc_config.nodes,
                party_id: mgr.party_id,
                encryption_key: &mgr.encryption_key,
                output_threshold: mgr.mpc_config.threshold,
                output_max_faulty: mgr.mpc_config.max_faulty,
                input_threshold,
                epoch: mgr.mpc_config.epoch,
            };
            let current = match Self::classify_reconstruction(mgr.reconstruct_rotation_output(
                &current_context,
                current_certificates,
                &HashMap::new(),
            )) {
                Ok(output) => output,
                Err(outcome) => return outcome,
            };
            let previous = match Self::classify_reconstruction(
                mgr.reconstruct_previous_output(previous_certificates, &HashMap::new()),
            ) {
                Ok(output) => output,
                Err(outcome) => return outcome,
            };
            (current, previous)
        };
        let current_key = bcs::to_bytes(&current.public_key).expect(EXPECT_SERIALIZATION_SUCCESS);
        if current_key != onchain_mpc_key {
            return MpcOutputRecoveryOutcome::Suspicious(
                "reconstructed current key does not match the on-chain key".into(),
            );
        }
        let previous_key = bcs::to_bytes(&previous.public_key).expect(EXPECT_SERIALIZATION_SUCCESS);
        if previous_key != onchain_mpc_key {
            return MpcOutputRecoveryOutcome::Suspicious(
                "reconstructed previous key does not match the on-chain key".into(),
            );
        }
        {
            let mut mgr = mpc_manager.write().unwrap();
            mgr.set_current_output(current.clone());
            mgr.set_previous_output(previous);
        }
        MpcOutputRecoveryOutcome::Recovered(current)
    }

    #[allow(clippy::result_large_err)]
    fn classify_reconstruction(
        result: MpcResult<ReconstructionOutcome>,
    ) -> Result<MpcOutput, MpcOutputRecoveryOutcome> {
        match result {
            Ok(ReconstructionOutcome::Success(output)) => Ok(output),
            Ok(ReconstructionOutcome::NeedsDkgComplaintRecovery { .. })
            | Ok(ReconstructionOutcome::NeedsRotationComplaintRecovery { .. }) => {
                Err(MpcOutputRecoveryOutcome::NotApplicable)
            }
            Err(MpcError::StorageError(_)) | Err(MpcError::NotEnoughApprovals { .. }) => {
                Err(MpcOutputRecoveryOutcome::NotApplicable)
            }
            Err(MpcError::ProtocolFailed(msg)) => Err(MpcOutputRecoveryOutcome::Suspicious(msg)),
            Err(_) => Err(MpcOutputRecoveryOutcome::NotApplicable),
        }
    }

    fn reconstruct_dkg_output(
        &self,
        context: &DkgReconstructionContext<'_>,
        certificates: &[CertificateV1],
        complaint_cache: &HashMap<DealerOutputsKey, avss::AvssOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        let source_session_id = SessionId::new(&self.chain_id, context.epoch, &ProtocolType::Dkg);
        let mut outputs: HashMap<PartyId, avss::AvssOutput> = HashMap::new();
        let mut dealer_weight_sum = 0u32;
        for cert in certificates {
            // This matches the behavior of `run_as_party` during DKG, which also
            // stops at threshold.
            if dealer_weight_sum >= context.output_threshold as u32 {
                break;
            }
            let CertificateV1::Dkg(dkg_cert) = cert else {
                return Err(MpcError::InvalidCertificate(
                    "Mixed certificate types: expected all DKG certificates".into(),
                ));
            };
            let msg = dkg_cert.message();
            let dealer_address = msg.dealer_address;
            let message = self
                .public_messages_store
                .get_dealer_message(context.epoch, &dealer_address)
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
            let dealer_party_id = context
                .committee
                .index_of(&dealer_address)
                .expect("certified dealer must be in committee")
                as PartyId;
            let session_id = source_session_id
                .dealer_session_id(&dealer_address)
                .to_vec();
            if let Some(output) = complaint_cache.get(&DealerOutputsKey::Dkg(dealer_address)) {
                outputs.insert(dealer_party_id, output.clone());
                let dealer_weight = context
                    .nodes
                    .weight_of(dealer_party_id)
                    .expect("party_id must be valid");
                dealer_weight_sum += dealer_weight as u32;
                continue;
            }
            match process_avss_message(
                context.encryption_key,
                context.nodes.clone(),
                context.party_id,
                Parameters {
                    t: context.output_threshold,
                    f: context.output_max_faulty,
                },
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
            let dealer_weight = context
                .nodes
                .weight_of(dealer_party_id)
                .expect("party_id must be valid");
            dealer_weight_sum += dealer_weight as u32;
        }
        if dealer_weight_sum < context.output_threshold as u32 {
            return Err(MpcError::NotEnoughApprovals {
                needed: context.output_threshold as usize,
                got: dealer_weight_sum as usize,
            });
        }
        let dealer_ids: Vec<_> = outputs.keys().copied().collect();
        tracing::info!(
            "reconstruct_dkg (epoch={}): {} dealers (party_ids={:?}), \
             dealer_weight_sum={dealer_weight_sum}, threshold={}",
            context.epoch,
            dealer_ids.len(),
            dealer_ids,
            context.output_threshold,
        );
        let combined_output =
            avss::DkOutput::complete_dkg(context.output_threshold, context.nodes, outputs)
                .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "reconstruct_dkg: result vk={}",
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
            threshold: context.output_threshold,
        }))
    }

    fn reconstruct_previous_rotation_output(
        &self,
        certificates: &[CertificateV1],
        complaint_cache: &HashMap<DealerOutputsKey, avss::AvssOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        let nodes = self.previous_nodes.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("Rotation reconstruction requires previous nodes".into())
        })?;
        let committee = self.previous_committee.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig("Rotation reconstruction requires previous committee".into())
        })?;
        let party_id = self.own_party_id(committee)?;
        let output_threshold = self.previous_reconfig_output_threshold.ok_or_else(|| {
            MpcError::InvalidConfig(
                "Rotation reconstruction requires previous reconfig's output threshold".into(),
            )
        })?;
        let output_max_faulty = self.previous_reconfig_output_max_faulty.ok_or_else(|| {
            MpcError::InvalidConfig(
                "Rotation reconstruction requires previous reconfig's output max_faulty".into(),
            )
        })?;
        let input_threshold = self.previous_reconfig_input_threshold.ok_or_else(|| {
            MpcError::InvalidConfig(
                "Rotation reconstruction requires previous reconfig's input threshold \
                 (no committee found at previous_epoch - 1)"
                    .into(),
            )
        })?;
        let encryption_key = self.previous_encryption_key.as_ref().ok_or_else(|| {
            MpcError::InvalidConfig(
                "Rotation reconstruction requires previous encryption key".into(),
            )
        })?;
        let context = RotationReconstructionContext {
            nodes,
            party_id,
            encryption_key,
            output_threshold,
            output_max_faulty,
            input_threshold,
            epoch: self.previous_epoch,
        };
        self.reconstruct_rotation_output(&context, certificates, complaint_cache)
    }

    fn reconstruct_rotation_output(
        &self,
        context: &RotationReconstructionContext<'_>,
        certificates: &[CertificateV1],
        complaint_cache: &HashMap<DealerOutputsKey, avss::AvssOutput>,
    ) -> MpcResult<ReconstructionOutcome> {
        let source_session_id =
            SessionId::new(&self.chain_id, context.epoch, &ProtocolType::KeyRotation);
        // Each dealer only rotates their own shares from the previous epoch, so share indices
        // are unique across dealers (no duplicates in `certified_share_indices`).
        let mut local_outputs: HashMap<ShareIndex, avss::AvssOutput> = HashMap::new();
        let mut certified_share_indices = Vec::new();
        for cert in certificates {
            let CertificateV1::Rotation(rotation_cert) = cert else {
                return Err(MpcError::InvalidCertificate(
                    "Mixed certificate types: expected all Rotation certificates".into(),
                ));
            };
            let msg = rotation_cert.message();
            let dealer_address = msg.dealer_address;
            let rotation_msgs = self
                .public_messages_store
                .get_rotation_messages(context.epoch, &dealer_address)
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
                        "reconstruct_rotation: complaint cache hit for \
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
                    context.encryption_key,
                    context.nodes.clone(),
                    context.party_id,
                    Parameters {
                        t: context.output_threshold,
                        f: context.output_max_faulty,
                    },
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
        if certified_share_indices.len() < context.input_threshold as usize {
            return Err(MpcError::NotEnoughApprovals {
                needed: context.input_threshold as usize,
                got: certified_share_indices.len(),
            });
        }
        let indexed_outputs: Vec<IndexedValue<avss::AvssOutput>> = certified_share_indices
            .iter()
            .take(context.input_threshold as usize)
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
            "reconstruct_rotation (epoch={}): {} share_indices={:?}, \
             output_threshold={}, input_threshold={}",
            context.epoch,
            used_indices.len(),
            used_indices,
            context.output_threshold,
            context.input_threshold,
        );
        let combined = avss::DkOutput::complete_key_rotation(
            context.input_threshold,
            context.party_id,
            context.nodes,
            &indexed_outputs,
        )
        .expect(EXPECT_THRESHOLD_MET);
        tracing::info!(
            "reconstruct_rotation: result vk={}",
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
            threshold: context.output_threshold,
        }))
    }

    pub async fn fetch_public_mpc_output_from_quorum(
        mpc_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        previous_committee_threshold: u64,
    ) -> MpcResult<PublicMpcOutput> {
        let (previous_committee, previous_nodes, epoch) = {
            let mgr = mpc_manager.read().unwrap();
            let previous_committee = mgr
                .previous_committee
                .clone()
                .expect("key rotation requires previous committee");
            let previous_nodes = mgr.previous_nodes.clone().ok_or_else(|| {
                MpcError::InvalidConfig("previous_nodes required for public-output quorum".into())
            })?;
            (previous_committee, previous_nodes, mgr.previous_epoch)
        };
        let request = GetPublicMpcOutputRequest { epoch };
        let mut futures: FuturesUnordered<_> = previous_committee
            .members()
            .iter()
            .enumerate()
            .map(|(party_id, member)| {
                let addr = member.validator_address();
                let weight = previous_nodes
                    .share_ids_of(party_id as u16)
                    .map(|ids| ids.len() as u64)
                    .unwrap_or(0);
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
        metrics: &Metrics,
    ) -> MpcResult<(MpcOutput, bool)> {
        let (is_member_of_previous_committee, has_previous_key, threshold_opt) = {
            let mgr = mpc_manager.read().unwrap();
            let is_member = mgr
                .previous_committee
                .as_ref()
                .and_then(|c| c.index_of(&mgr.address))
                .is_some();
            (
                is_member,
                mgr.previous_encryption_key.is_some(),
                mgr.previous_reconfig_output_threshold,
            )
        };
        let previous = if is_member_of_previous_committee && has_previous_key {
            let reconstruction_result = async {
                let _retrieve_timer = metrics
                    .mpc_prepare_previous_retrieve_duration_seconds
                    .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                    .start_timer();
                Self::retrieve_missing_previous_messages(
                    mpc_manager,
                    previous_certificates,
                    p2p_channel,
                )
                .await?;
                drop(_retrieve_timer);
                Self::reconstruct_with_complaint_recovery(
                    mpc_manager,
                    previous_certificates,
                    p2p_channel,
                    metrics,
                )
                .await
            }
            .await;
            match reconstruction_result {
                Ok(output) => output,
                Err(e) => {
                    tracing::info!("Reconstruction failed ({e}), falling back to new-member path");
                    let _fetch_timer = metrics
                        .mpc_prepare_previous_fetch_public_output_duration_seconds
                        .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                        .start_timer();
                    Self::fetch_and_build_public_output(mpc_manager, p2p_channel, threshold_opt)
                        .await?
                }
            }
        } else {
            let _fetch_timer = metrics
                .mpc_prepare_previous_fetch_public_output_duration_seconds
                .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                .start_timer();
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
        metrics: &Metrics,
    ) -> MpcResult<MpcOutput> {
        let mut complaint_cache: HashMap<DealerOutputsKey, avss::AvssOutput> = HashMap::new();
        loop {
            let mgr = Arc::clone(mpc_manager);
            let certs = previous_certificates.to_vec();
            let cache_snapshot = complaint_cache.clone();
            let _reconstruct_timer = metrics
                .mpc_prepare_previous_reconstruct_duration_seconds
                .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                .start_timer();
            let outcome = spawn_blocking(move || {
                let mgr = mgr.read().unwrap();
                mgr.reconstruct_previous_output(&certs, &cache_snapshot)
            })
            .await?;
            drop(_reconstruct_timer);
            match outcome {
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
                        mgr.complaints_to_process.insert(
                            ComplaintsToProcessKey::Dkg(dealer_address),
                            ProtocolComplaint::Avss(complaint),
                        );
                        Self::collect_signers_for_dealer(
                            &mgr,
                            previous_certificates,
                            &dealer_address,
                        )
                    };
                    let previous_epoch = mpc_manager.read().unwrap().previous_epoch;
                    metrics
                        .mpc_prepare_previous_complaint_recovery_total
                        .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                        .inc();
                    let _recovery_timer = metrics
                        .mpc_prepare_previous_complaint_recovery_duration_seconds
                        .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                        .start_timer();
                    let recovered = Self::recover_dkg_shares_via_complaint(
                        mpc_manager,
                        &dealer_address,
                        &message,
                        signers,
                        p2p_channel,
                        previous_epoch,
                    )
                    .await?;
                    drop(_recovery_timer);
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
                            ProtocolComplaint::Avss(complaint),
                        );
                        Self::collect_signers_for_dealer(
                            &mgr,
                            previous_certificates,
                            &dealer_address,
                        )
                    };
                    metrics
                        .mpc_prepare_previous_complaint_recovery_total
                        .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                        .inc();
                    let _recovery_timer = metrics
                        .mpc_prepare_previous_complaint_recovery_duration_seconds
                        .with_label_values(&[MPC_LABEL_KEY_ROTATION])
                        .start_timer();
                    let recovered = Self::recover_rotation_shares_via_complaints(
                        mpc_manager,
                        &dealer_address,
                        &rotation_msgs,
                        signers,
                        p2p_channel,
                        previous_epoch,
                    )
                    .await?;
                    drop(_recovery_timer);
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
        Self::retrieve_missing_nonce_messages(mpc_manager, batch_index, certs, p2p_channel).await?;
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
                            ProtocolComplaint::BatchedAvss(complaint),
                        );
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

    async fn retrieve_missing_nonce_messages(
        mpc_manager: &Arc<RwLock<Self>>,
        batch_index: u32,
        certs: &[(Address, hashi_types::move_types::DealerSubmissionV1)],
        p2p_channel: &impl P2PChannel,
    ) -> MpcResult<()> {
        let (certified_dealers, _) = mpc_manager
            .read()
            .unwrap()
            .certified_nonce_dealers_from_certs(certs);
        for (dealer, cert) in certs {
            if !certified_dealers.contains(dealer) {
                continue;
            }
            let expected_hash = sui_sdk_types::Digest::from_bytes(&cert.message.messages_hash)
                .map_err(|e| {
                    MpcError::InvalidCertificate(format!(
                        "malformed nonce message hash for dealer {dealer:?}: {e}"
                    ))
                })?;
            let needs_retrieval = mpc_manager.write().unwrap().needs_nonce_retrieval(
                *dealer,
                batch_index,
                &expected_hash,
            );
            if !needs_retrieval {
                continue;
            }
            let (request, signers) = {
                let mgr = mpc_manager.read().unwrap();
                let members = mgr.committee.members();
                let signers: Vec<Address> = cert
                    .signature
                    .signers_bitmap
                    .iter()
                    .filter_map(|&idx| members.get(idx as usize).map(|m| m.validator_address()))
                    .collect();
                let request = RetrieveMessagesRequest {
                    dealer: *dealer,
                    protocol_type: ProtocolTypeIndicator::NonceGeneration,
                    epoch: mgr.mpc_config.epoch,
                    batch_index: Some(batch_index),
                };
                (request, signers)
            };
            tracing::info!(
                "Nonce message for certified dealer {dealer:?} missing locally during recovery, \
                 retrieving from signers"
            );
            let messages = hedged_retrieve(signers, p2p_channel, &request, expected_hash)
                .await
                .ok_or_else(|| {
                    MpcError::PairwiseCommunicationError(format!(
                        "Could not retrieve nonce message for dealer {dealer:?} from any signer \
                         during recovery"
                    ))
                })?;
            let Messages::NonceGeneration(ref nonce) = messages else {
                return Err(MpcError::ProtocolFailed(format!(
                    "Retrieved non-nonce message for dealer {dealer:?} during recovery"
                )));
            };
            let mut mgr = mpc_manager.write().unwrap();
            let epoch = mgr.mpc_config.epoch;
            mgr.cache_and_persist_nonce_message(epoch, *dealer, nonce)?;
            // Drop any output derived from the previously stored (hash-mismatching)
            // message so reconstruction reprocesses the retrieved certified message.
            mgr.dealer_nonce_outputs.remove(&(batch_index, *dealer));
        }
        Ok(())
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
        let messages = hedged_retrieve(signers, p2p_channel, &request, message.messages_hash)
            .await
            .ok_or_else(|| {
                MpcError::PairwiseCommunicationError(format!(
                    "Could not retrieve previous epoch message for dealer {:?} from any signer",
                    message.dealer_address
                ))
            })?;
        let mut mgr = mpc_manager.write().unwrap();
        let previous_epoch = mgr.previous_epoch;
        match messages {
            Messages::Dkg(ref msg) => {
                mgr.cache_and_persist_dkg_message(previous_epoch, message.dealer_address, msg)?;
            }
            Messages::Rotation(ref msgs) => {
                mgr.cache_and_persist_rotation_messages(
                    previous_epoch,
                    message.dealer_address,
                    msgs,
                )?;
            }
            Messages::NonceGeneration(_)
            | Messages::NonceGenerationAvid(_)
            | Messages::AvidNonceRetrieval(_) => unreachable!(
                "Hash matched previous-epoch certificate but got {:?}",
                std::mem::discriminant(&messages)
            ),
        }
        Ok(())
    }

    fn base_session_id_for_epoch(&self, epoch: u64, protocol_type: &ProtocolType) -> SessionId {
        if epoch == self.mpc_config.epoch {
            self.session_id.clone()
        } else {
            SessionId::new(&self.chain_id, self.previous_epoch, protocol_type)
        }
    }

    fn config_for_epoch(
        &self,
        epoch: u64,
    ) -> MpcResult<(Nodes<EncryptionGroupElement>, u16, Parameters)> {
        if epoch == self.mpc_config.epoch {
            Ok((
                self.mpc_config.nodes.clone(),
                self.party_id,
                Parameters {
                    t: self.mpc_config.threshold,
                    f: self.mpc_config.max_faulty,
                },
            ))
        } else {
            let committee = self.previous_committee.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("No previous committee for cross-epoch complaint".into())
            })?;
            let nodes = self.previous_nodes.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("No previous nodes for cross-epoch complaint".into())
            })?;
            let t = self.previous_reconfig_output_threshold.ok_or_else(|| {
                MpcError::InvalidConfig("No previous threshold for cross-epoch complaint".into())
            })?;
            let f = self.previous_reconfig_output_max_faulty.ok_or_else(|| {
                MpcError::InvalidConfig("No previous max_faulty for cross-epoch complaint".into())
            })?;
            let party_id = self.own_party_id(committee)?;
            Ok((nodes.clone(), party_id, Parameters { t, f }))
        }
    }

    fn committee_for_epoch(&self, epoch: u64) -> MpcResult<&Committee> {
        if epoch == self.mpc_config.epoch {
            Ok(&self.committee)
        } else {
            self.previous_committee.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig("No previous committee for cross-epoch complaint".into())
            })
        }
    }

    fn accuser_party_id(&self, epoch: u64, caller: &Address) -> MpcResult<PartyId> {
        self.committee_for_epoch(epoch)?
            .index_of(caller)
            .map(|i| i as PartyId)
            .ok_or_else(|| MpcError::InvalidMessage {
                sender: *caller,
                reason: "complaint accuser is not a member of the epoch committee".into(),
            })
    }

    fn own_party_id(&self, committee: &Committee) -> MpcResult<PartyId> {
        committee
            .index_of(&self.address)
            .map(|i| i as PartyId)
            .ok_or_else(|| MpcError::InvalidConfig("This node is not in the committee".into()))
    }

    fn encryption_key_for_epoch(
        &self,
        epoch: u64,
    ) -> MpcResult<&PrivateKey<EncryptionGroupElement>> {
        if epoch == self.mpc_config.epoch {
            Ok(&self.encryption_key)
        } else if epoch == self.previous_epoch {
            self.previous_encryption_key.as_ref().ok_or_else(|| {
                MpcError::InvalidConfig(
                    "previous_encryption_key required for previous epoch".into(),
                )
            })
        } else {
            Err(MpcError::InvalidConfig(format!(
                "encryption_key_for_epoch({epoch}): not current ({}) or previous ({})",
                self.mpc_config.epoch, self.previous_epoch,
            )))
        }
    }

    fn get_or_derive_dkg_output(
        &self,
        dealer: &Address,
        message: &avss::Message,
        epoch: u64,
    ) -> MpcResult<avss::AvssOutput> {
        if let Some(output) = self.dealer_outputs.get(&DealerOutputsKey::Dkg(*dealer)) {
            return Ok(output.clone());
        }
        // Cross-epoch fallback: re-derive from message
        let (nodes, party_id, params) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::Dkg);
        let session_id = base_sid.dealer_session_id(dealer);
        match process_avss_message(
            self.encryption_key_for_epoch(epoch)?,
            nodes,
            party_id,
            params,
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
    ) -> MpcResult<avss::AvssOutput> {
        if epoch == self.mpc_config.epoch
            && let Some(output) = self
                .dealer_outputs
                .get(&DealerOutputsKey::Rotation(share_index))
        {
            return Ok(output.clone());
        }
        let (nodes, party_id, params) = self.config_for_epoch(epoch)?;
        let base_sid = self.base_session_id_for_epoch(epoch, &ProtocolType::KeyRotation);
        let session_id = base_sid.rotation_session_id(dealer, share_index);
        match process_avss_message(
            self.encryption_key_for_epoch(epoch)?,
            nodes,
            party_id,
            params,
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
                .current_dkg_messages
                .get(dealer)
                .map(|m| Messages::Dkg(m.clone())),
            ProtocolTypeIndicator::KeyRotation => self
                .current_rotation_messages
                .get(dealer)
                .map(|m| Messages::Rotation(m.clone())),
            ProtocolTypeIndicator::NonceGeneration => {
                let batch_index = batch_index?;
                self.current_nonce_messages
                    .get(&(batch_index, *dealer))
                    .map(|m| Messages::NonceGeneration(m.clone()))
            }
        }
    }

    pub(crate) fn required_nonce_weight(&self) -> u32 {
        let max_faulty = self.mpc_config.max_faulty as u32;
        match self.mpc_config.presignature_derivation_version {
            PresignatureDerivationVersion::Legacy => 2 * max_faulty + 1,
            PresignatureDerivationVersion::PrivacyThreshold => {
                self.mpc_config.nodes.total_weight() as u32 - max_faulty
            }
        }
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

    fn set_current_output(&mut self, output: MpcOutput) {
        self.current_output = Some(output);
    }

    fn set_previous_output(&mut self, output: MpcOutput) {
        self.previous_output = Some(output);
    }
}

pub fn fallback_encryption_public_key() -> PublicKey<EncryptionGroupElement> {
    static FALLBACK_ENCRYPTION_PK: LazyLock<PublicKey<EncryptionGroupElement>> =
        LazyLock::new(|| PublicKey::from(EncryptionGroupElement::hash_to_group_element(b"hashi")));
    FALLBACK_ENCRYPTION_PK.clone()
}

fn verify_complaint_response_from_signer(
    receiver: &avss::Receiver,
    committee: &Committee,
    message: &avss::Message,
    signer: &Address,
    response: avss::ComplaintResponse,
) -> Option<avss::VerifiedComplaintResponse> {
    let Some(responder_id) = committee.index_of(signer).map(|i| i as PartyId) else {
        tracing::warn!(
            "Complaint responder {:?} not in committee; skipping",
            signer
        );
        return None;
    };
    match receiver.verify_complaint_response(message, responder_id, response) {
        Ok(verified) => Some(verified),
        Err(e) => {
            tracing::warn!(
                "Invalid complaint response from {:?}: {}; skipping",
                signer,
                e
            );
            None
        }
    }
}

fn fan_out_complaints<'a, P: P2PChannel + 'a>(
    signers: Vec<Address>,
    p2p_channel: &'a P,
    request: &'a ComplainRequest,
) -> FuturesUnordered<impl Future<Output = (Address, ChannelResult<ComplaintResponse>)> + 'a> {
    signers
        .into_iter()
        .map(move |signer| async move {
            let result = with_timeout_and_retry(|| p2p_channel.complain(&signer, request)).await;
            (signer, result)
        })
        .collect()
}

async fn hedged_retrieve<'a, P: P2PChannel + 'a>(
    mut signers: Vec<Address>,
    p2p_channel: &'a P,
    request: &'a RetrieveMessagesRequest,
    expected_hash: MessageHash,
) -> Option<Messages> {
    signers.shuffle(&mut rand::thread_rng());
    let mut remaining = signers.into_iter();
    let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
    let mut round_size = HEDGED_RETRIEVE_INITIAL_ROUND_SIZE;
    loop {
        for _ in 0..round_size {
            if let Some(signer) = remaining.next() {
                in_flight.push(async move {
                    let result =
                        with_timeout_and_retry(|| p2p_channel.retrieve_messages(&signer, request))
                            .await;
                    (signer, result)
                });
            }
        }
        if in_flight.is_empty() {
            return None;
        }
        let timeout = tokio::time::sleep(HEDGED_RETRIEVE_ROUND_TIMEOUT);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                biased;
                Some((signer, result)) = in_flight.next() => match result {
                    Ok(response) => {
                        if compute_messages_hash(&response.messages) == expected_hash {
                            return Some(response.messages);
                        }
                        tracing::info!(
                            "Hash mismatch from signer {:?} during retrieval",
                            signer
                        );
                    }
                    Err(e) => tracing::info!(
                        "Retrieve from signer {:?} failed: {}",
                        signer,
                        e
                    ),
                },
                _ = &mut timeout => break,
            }
            if in_flight.is_empty() {
                break;
            }
        }
        round_size = round_size.saturating_mul(HEDGED_RETRIEVE_ROUND_GROWTH_FACTOR);
    }
}

fn process_avss_message(
    encryption_key: &PrivateKey<EncryptionGroupElement>,
    nodes: Nodes<EncryptionGroupElement>,
    party_id: u16,
    params: Parameters,
    session_id: Vec<u8>,
    message: &avss::Message,
    commitment: Option<G>,
) -> MpcResult<avss::ProcessedMessage> {
    let commitment_hex = commitment
        .as_ref()
        .map(|c| hex::encode(c.to_byte_array()))
        .unwrap_or_else(|| "None".to_string());
    let session_id_hex = hex::encode(&session_id);
    let total_weight = nodes.total_weight();
    let num_nodes = nodes.num_nodes();
    let receiver = avss::Receiver::new(
        nodes,
        party_id,
        params,
        session_id,
        commitment,
        encryption_key.clone(),
    )?;
    match receiver.process_message(message, &mut rand::thread_rng()) {
        Ok(pm) => Ok(pm),
        Err(e) => {
            tracing::error!(
                "process_avss_message failed: err={e}, \
                 total_weight={total_weight}, num_nodes={num_nodes}, \
                 commitment={commitment_hex}, session_id={session_id_hex}"
            );
            Err(MpcError::from(e))
        }
    }
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
    tracing::info!(
        pre_reduction_total_weight = total_weight,
        threshold,
        max_faulty,
        weight_reduction_allowed_delta,
        lower_bound,
        "build_reduced_nodes: pre-reduction parameters"
    );
    Nodes::prop_reduce(
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

fn consume_certified_nonce_outputs<T>(
    outputs_map: &mut BTreeMap<(u32, Address), T>,
    batch_index: u32,
    certified: &HashSet<Address>,
    mut convert: impl FnMut(&T) -> batch_avss::ReceiverOutput,
) -> (usize, Vec<Address>, Vec<batch_avss::ReceiverOutput>) {
    let pre_filter = outputs_map
        .keys()
        .filter(|(b, _)| *b == batch_index)
        .count();
    let mut dealers = Vec::new();
    let mut outputs = Vec::new();
    outputs_map.retain(|(b, addr), output| {
        if *b != batch_index {
            return true;
        }
        if certified.contains(addr) {
            dealers.push(*addr);
            outputs.push(convert(output));
            true
        } else {
            false
        }
    });
    (pre_filter, dealers, outputs)
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
