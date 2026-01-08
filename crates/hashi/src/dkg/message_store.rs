//! Message store for DKG - handles RPC message processing with its own lock.
//!
//! This is separate from DkgManager to allow RPC handlers to process messages
//! without blocking the protocol execution lock, preventing deadlocks.

use crate::committee::Bls12381PrivateKey;
use crate::committee::Committee;
use crate::dkg::types::ComplainRequest;
use crate::dkg::types::ComplainResponse;
use crate::dkg::types::DkgConfig;
use crate::dkg::types::DkgDealerMessageHash;
use crate::dkg::types::DkgError;
use crate::dkg::types::DkgOutput;
use crate::dkg::types::DkgResult;
use crate::dkg::types::GetPublicDkgOutputRequest;
use crate::dkg::types::GetPublicDkgOutputResponse;
use crate::dkg::types::MpcMessageV1::Dkg;
use crate::dkg::types::MpcMessageV1::Rotation;
use crate::dkg::types::PublicDkgOutput;
use crate::dkg::types::RetrieveMessageRequest;
use crate::dkg::types::RetrieveMessageResponse;
use crate::dkg::types::RetrieveRotationMessagesRequest;
use crate::dkg::types::RetrieveRotationMessagesResponse;
use crate::dkg::types::RotationComplainRequest;
use crate::dkg::types::RotationComplainResponse;
use crate::dkg::types::RotationDealerMessagesHash;
use crate::dkg::types::RotationMessages;
use crate::dkg::types::RotationShareComplaintResponse;
use crate::dkg::types::SendMessageRequest;
use crate::dkg::types::SendMessageResponse;
use crate::dkg::types::SendRotationMessagesRequest;
use crate::dkg::types::SendRotationMessagesResponse;
use crate::dkg::types::SessionId;
use crate::storage::PublicMessagesStore;
use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::ShareIndex;
use std::collections::HashMap;
use sui_sdk_types::Address;

use super::EncryptionGroupElement;
use super::compute_message_hash;
use super::compute_rotation_messages_hash;

/// Message store for DKG - holds all state needed by RPC handlers.
/// This struct has its own RwLock to allow concurrent message processing
/// without blocking protocol execution.
pub struct MessageStore {
    // Immutable configuration
    pub party_id: PartyId,
    pub address: Address,
    pub dkg_config: DkgConfig,
    pub session_id: SessionId,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub signing_key: Bls12381PrivateKey,
    pub committee: Committee,
    pub public_messages_store: Box<dyn PublicMessagesStore>,

    // DKG message storage
    pub dealer_messages: HashMap<Address, avss::Message>,
    pub dealer_outputs: HashMap<Address, avss::PartialOutput>,
    pub message_responses: HashMap<Address, SendMessageResponse>,
    pub complaint_responses: HashMap<Address, complaint::ComplaintResponse<avss::SharesForNode>>,

    // Rotation message storage
    pub rotation_dealer_messages: HashMap<Address, RotationMessages>,
    pub rotation_outputs: HashMap<ShareIndex, avss::PartialOutput>,
    pub rotation_message_responses: HashMap<Address, SendRotationMessagesResponse>,
    pub rotation_complaint_responses: HashMap<Address, Vec<RotationShareComplaintResponse>>,

    // For rotation - needs previous DKG output to verify rotation messages
    pub previous_dkg_output: Option<DkgOutput>,
}

impl MessageStore {
    /// Create a new message store with the given configuration.
    pub fn new(
        party_id: PartyId,
        address: Address,
        dkg_config: DkgConfig,
        session_id: SessionId,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        signing_key: Bls12381PrivateKey,
        committee: Committee,
        public_messages_store: Box<dyn PublicMessagesStore>,
    ) -> Self {
        Self {
            party_id,
            address,
            dkg_config,
            session_id,
            encryption_key,
            signing_key,
            committee,
            public_messages_store,
            dealer_messages: HashMap::new(),
            dealer_outputs: HashMap::new(),
            message_responses: HashMap::new(),
            complaint_responses: HashMap::new(),
            rotation_dealer_messages: HashMap::new(),
            rotation_outputs: HashMap::new(),
            rotation_message_responses: HashMap::new(),
            rotation_complaint_responses: HashMap::new(),
            previous_dkg_output: None,
        }
    }

    /// Set the previous DKG output (needed for rotation message verification).
    pub fn set_previous_dkg_output(&mut self, output: DkgOutput) {
        self.previous_dkg_output = Some(output);
    }

    /// RPC endpoint handler for `SendMessageRequest`
    pub fn handle_send_message_request(
        &mut self,
        sender: Address,
        request: &SendMessageRequest,
    ) -> DkgResult<SendMessageResponse> {
        // Check for equivocation or return cached response
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

        // Store and process the message
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

    /// RPC endpoint handler for `ComplainRequest`
    pub fn handle_complain_request(
        &mut self,
        request: &ComplainRequest,
    ) -> DkgResult<ComplainResponse> {
        let cache_key = request.dealer;
        // Return cached response if available
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

    /// RPC endpoint handler for `SendRotationMessagesRequest`
    pub fn handle_send_rotation_messages_request(
        &mut self,
        sender: Address,
        request: &SendRotationMessagesRequest,
    ) -> DkgResult<SendRotationMessagesResponse> {
        // Check for equivocation or return cached response
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

    /// RPC endpoint handler for `RotationComplainRequest`
    pub fn handle_rotation_complain_request(
        &mut self,
        request: &RotationComplainRequest,
    ) -> DkgResult<RotationComplainResponse> {
        // Check cache first
        if let Some(cached_responses) = self.rotation_complaint_responses.get(&request.dealer) {
            return Ok(RotationComplainResponse {
                responses: cached_responses.clone(),
            });
        }

        let previous = self
            .previous_dkg_output
            .as_ref()
            .ok_or_else(|| DkgError::ProtocolFailed("Rotation not started".to_string()))?;

        let rotation_messages = self
            .rotation_dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| {
                DkgError::NotFound(format!("Rotation messages for dealer {:?}", request.dealer))
            })?;

        let message = rotation_messages.get(request.share_index).ok_or_else(|| {
            DkgError::NotFound(format!(
                "Rotation message for share index {:?}",
                request.share_index
            ))
        })?;

        let rotation_session_id = self
            .session_id
            .rotation_session_id(&request.dealer, request.share_index);

        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            rotation_session_id.to_vec(),
            Some(previous.commitments[&request.share_index]),
            self.encryption_key.clone(),
        );

        let partial_output = self
            .rotation_outputs
            .get(&request.share_index)
            .ok_or_else(|| {
                DkgError::ProtocolFailed(format!(
                    "No rotation output for share index {:?}",
                    request.share_index
                ))
            })?;

        let response = receiver.handle_complaint(message, &request.complaint, partial_output)?;

        let share_response = RotationShareComplaintResponse {
            share_index: request.share_index,
            response,
        };

        // Cache for future requests
        self.rotation_complaint_responses
            .entry(request.dealer)
            .or_default()
            .push(share_response.clone());

        Ok(RotationComplainResponse {
            responses: vec![share_response],
        })
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

    // Internal helper methods

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

    fn try_sign_rotation_messages(
        &mut self,
        previous_dkg_output: &DkgOutput,
        dealer: Address,
        messages: &RotationMessages,
    ) -> DkgResult<BLS12381Signature> {
        // Verify and process each message
        for (&share_index, message) in messages.iter() {
            let rotation_session_id = self.session_id.rotation_session_id(&dealer, share_index);
            let commitment = previous_dkg_output
                .commitments
                .get(&share_index)
                .ok_or_else(|| DkgError::InvalidMessage {
                    sender: dealer,
                    reason: format!("No commitment for share index {:?}", share_index),
                })?;

            let receiver = avss::Receiver::new(
                self.dkg_config.nodes.clone(),
                self.party_id,
                self.dkg_config.threshold,
                rotation_session_id.to_vec(),
                Some(*commitment),
                self.encryption_key.clone(),
            );

            match receiver.process_message(message)? {
                avss::ProcessedMessage::Valid(output) => {
                    self.rotation_outputs.insert(share_index, output);
                }
                avss::ProcessedMessage::Complaint(_) => {
                    return Err(DkgError::InvalidMessage {
                        sender: dealer,
                        reason: format!("Invalid shares for share index {:?}", share_index),
                    });
                }
            }
        }

        // Sign the messages hash
        let messages_hash = compute_rotation_messages_hash(messages);
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

    /// Load stored messages from the public message store.
    pub fn load_stored_messages(&mut self) -> DkgResult<()> {
        let stored = self
            .public_messages_store
            .list_all_dealer_messages()
            .map_err(|e| DkgError::StorageError(e.to_string()))?;
        for (dealer, message) in stored {
            self.dealer_messages.insert(dealer, message);
        }
        Ok(())
    }
}
