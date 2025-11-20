//! Distributed Key Generation (DKG) module

pub mod types;

use crate::storage::PublicMessagesStore;
use crate::types::ValidatorAddress;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::threshold_schnorr::{avss, complaint};

pub use types::{
    AddressToPartyId, Authenticated, ComplainRequest, ComplainResponse, DkgCertificate, DkgConfig,
    DkgError, DkgOutput, DkgResult, EncryptionGroupElement, MessageApproval, MessageHash,
    MessageType, OrderedBroadcastMessage, P2PMessage, RetrieveMessageRequest,
    RetrieveMessageResponse, SendShareRequest, SendShareResponse, SessionContext, SessionId,
    SighashType, SignatureBytes, ValidatorSignature,
};

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";

// DKG protocol
// 1) A dealer sends out a message to all parties containing the encrypted shares and the public keys of the nonces.
// 2) Each party verifies the message and returns a signature. Once sufficient valid signatures are received from the parties, the dealer sends a certificate to Sui (TOB).
// 3) Once sufficient valid certificates are received, a party completes the protocol locally by aggregating the shares from the dealers.
pub struct DkgManager {
    // Immutable during a given session
    pub party_id: PartyId,
    pub address: ValidatorAddress,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub bls_signing_key: crate::bls::Bls12381PrivateKey,
    pub validator_weights: std::collections::HashMap<ValidatorAddress, u16>,
    // Mutable during a given session
    pub dealer_outputs: std::collections::HashMap<ValidatorAddress, avss::ReceiverOutput>,
    pub dealer_messages: std::collections::HashMap<ValidatorAddress, avss::Message>,
    pub share_responses: std::collections::HashMap<ValidatorAddress, SendShareResponse>,
    pub complaints: std::collections::HashMap<ValidatorAddress, complaint::Complaint>,
    pub complaint_responses:
        std::collections::HashMap<ValidatorAddress, complaint::ComplaintResponse>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
}

impl DkgManager {
    pub fn new(
        address: ValidatorAddress,
        dkg_config: DkgConfig,
        session_context: SessionContext,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        bls_signing_key: crate::bls::Bls12381PrivateKey,
        public_message_store: Box<dyn PublicMessagesStore>,
    ) -> Self {
        let party_id = *dkg_config
            .address_to_party_id
            .get(&address)
            .expect("address not found in validator registry");
        let validator_weights: std::collections::HashMap<ValidatorAddress, u16> = dkg_config
            .address_to_party_id
            .iter()
            .map(|(addr, party_id)| {
                let weight = dkg_config.nodes.weight_of(*party_id).unwrap();
                (addr.clone(), weight)
            })
            .collect();
        Self {
            party_id,
            address,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            validator_weights,
            dealer_outputs: std::collections::HashMap::new(),
            dealer_messages: std::collections::HashMap::new(),
            share_responses: std::collections::HashMap::new(),
            complaints: std::collections::HashMap::new(),
            complaint_responses: std::collections::HashMap::new(),
            public_messages_store: public_message_store,
        }
    }

    /// RPC endpoint handler for `SendShareRequest`
    pub fn handle_send_share_request(
        &mut self,
        sender: ValidatorAddress,
        request: &SendShareRequest,
    ) -> DkgResult<SendShareResponse> {
        if let Some(existing_message) = self.dealer_messages.get(&sender) {
            let existing_hash =
                compute_message_hash(&self.session_context, &sender, existing_message)?;
            let incoming_hash =
                compute_message_hash(&self.session_context, &sender, &request.message)?;
            return if existing_hash == incoming_hash {
                Ok(self.share_responses.get(&sender).unwrap().clone())
            } else {
                Err(DkgError::InvalidMessage {
                    sender: sender.clone(),
                    reason: "Dealer sent different messages".to_string(),
                })
            };
        }
        let validator_signature = self.receive_dealer_message(&request.message, sender.clone())?;
        let response = SendShareResponse {
            signature: validator_signature.signature,
        };
        self.share_responses.insert(sender, response.clone());
        Ok(response)
    }

    /// RPC endpoint handler for `RetrieveMessageRequest`
    pub fn handle_retrieve_message_request(
        &self,
        request: &RetrieveMessageRequest,
    ) -> DkgResult<RetrieveMessageResponse> {
        // TODO: Add DoS protection - track retrieval request count per party and rate limit
        let message = self
            .dealer_messages
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("Message not available".to_string()))?;
        Ok(RetrieveMessageResponse {
            message: message.clone(),
        })
    }

    /// RPC endpoint handler for `ComplainRequest`
    pub fn handle_complain_request(
        &mut self,
        request: &ComplainRequest,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<ComplainResponse> {
        let cache_key = request.dealer.clone();
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
        self.dealer_outputs
            .get(&request.dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No shares for dealer".into()))?;
        let dealer_session_id = self.session_context.dealer_session_id(&request.dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None,
            self.encryption_key.clone(),
        );
        let response = receiver.handle_complaint(message, &request.complaint, rng)?;
        self.complaint_responses.insert(cache_key, response.clone());
        Ok(ComplainResponse { response })
    }

    pub async fn run_as_dealer(
        &mut self,
        p2p_channel: &impl crate::communication::P2PChannel,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<()> {
        // TODO: Return early if DKG is already completed (we're a slow dealer)
        let dealer_message = self.create_dealer_message(rng)?;
        let my_signature = self.receive_dealer_message(&dealer_message, self.address.clone())?;
        let mut approvals = vec![my_signature];
        // TODO: Consider sending RPC's in parallel
        // TODO: Add timeout and retries handling when adding RPC layer
        for validator_address in self.dkg_config.address_to_party_id.keys() {
            if validator_address != &self.address {
                let response = match p2p_channel
                    .send_share(
                        validator_address,
                        &SendShareRequest {
                            message: dealer_message.clone(),
                        },
                    )
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::info!("Failed to send share to {:?}: {}", validator_address, e);
                        continue;
                    }
                };
                // TODO: Add cryptographic verification of response.signature
                approvals.push(ValidatorSignature {
                    validator: validator_address.clone(),
                    signature: response.signature,
                });
            }
        }
        let required_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        if has_sufficient_weighted_signatures(&approvals, &self.validator_weights, required_weight)
        {
            let cert = self.create_certificate(&dealer_message, approvals)?;
            // TODO: Add timeout and retries handling when adding RPC layer
            ordered_broadcast_channel
                .publish(OrderedBroadcastMessage::AvssCertificateV1(cert))
                .await
                .map_err(|e| {
                    DkgError::BroadcastError(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    pub async fn run_as_party(
        &mut self,
        p2p_channel: &impl crate::communication::P2PChannel,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.dkg_config.threshold;
        let mut certified_dealers = std::collections::HashMap::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= threshold as u32 {
                break;
            }
            let tob_msg = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| DkgError::BroadcastError(e.to_string()))?;
            if let OrderedBroadcastMessage::AvssCertificateV1(cert) = tob_msg {
                if certified_dealers.contains_key(&cert.dealer) {
                    continue;
                }
                if !self.dealer_messages.contains_key(&cert.dealer) {
                    tracing::info!(
                        "Certificate from dealer {:?} received but message missing, retrieving from signers",
                        cert.dealer
                    );
                    self.retrieve_dealer_message(cert.dealer.clone(), &cert, p2p_channel)
                        .await
                        .map_err(|e| {
                            tracing::error!(
                                "Failed to retrieve message from any signer for dealer {:?}: {}. Certificate exists but message unavailable from all signers.",
                                cert.dealer,
                                e
                            );
                            e
                        })?;
                }
                match validate_certificate(
                    &cert,
                    &self.dkg_config,
                    &self.session_context,
                    &self.validator_weights,
                    &self.dealer_messages,
                ) {
                    Ok(()) => {
                        if self.complaints.contains_key(&cert.dealer) {
                            self.recover_shares_via_complaint(
                                &cert.dealer,
                                cert.signatures.iter().map(|s| &s.validator),
                                p2p_channel,
                            )
                            .await?;
                        }
                        let dealer_weight =
                            self.validator_weights.get(&cert.dealer).ok_or_else(|| {
                                DkgError::ProtocolFailed("Missing dealer weight".parse().unwrap())
                            })?;
                        dealer_weight_sum += *dealer_weight as u32;
                        certified_dealers.insert(cert.dealer.clone(), cert);
                    }
                    Err(e) => {
                        tracing::info!("Invalid certificate from {:?}: {}", cert.dealer, e);
                        continue;
                    }
                }
            }
        }
        let output = self.process_certificates(&certified_dealers)?;
        Ok(output)
    }

    fn create_dealer_message(
        &self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<avss::Message> {
        let dealer_session_id = self.session_context.dealer_session_id(&self.address);
        let dealer = avss::Dealer::new(
            None,
            self.dkg_config.nodes.clone(),
            self.dkg_config.threshold,
            self.dkg_config.max_faulty,
            dealer_session_id.to_vec(),
        )?;
        let message = dealer.create_message(rng)?;
        Ok(message)
    }

    fn receive_dealer_message(
        &mut self,
        message: &avss::Message,
        dealer_address: ValidatorAddress,
    ) -> DkgResult<ValidatorSignature> {
        self.dealer_messages
            .insert(dealer_address.clone(), message.clone());
        self.public_messages_store
            .store_dealer_message(&dealer_address, message)
            .map_err(|e| DkgError::StorageError(e.to_string()))?;
        let dealer_session_id = self.session_context.dealer_session_id(&dealer_address);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None, // commitment: None for initial DKG
            self.encryption_key.clone(),
        );
        let receiver_output = match receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => output,
            avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints.insert(dealer_address.clone(), complaint);
                return Err(DkgError::ProtocolFailed(
                    "Invalid message from dealer".into(),
                ));
            }
        };
        self.dealer_outputs
            .insert(dealer_address.clone(), receiver_output);
        let message_hash = compute_message_hash(&self.session_context, &dealer_address, message)?;
        let signature = self.bls_signing_key.sign(&message_hash);
        Ok(ValidatorSignature {
            validator: self.address.clone(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    fn create_certificate(
        &self,
        message: &avss::Message,
        signatures: Vec<ValidatorSignature>,
    ) -> DkgResult<DkgCertificate> {
        let message_hash = compute_message_hash(&self.session_context, &self.address, message)?;
        Ok(DkgCertificate {
            dealer: self.address.clone(),
            message_hash,
            signatures,
            session_context: self.session_context.clone(),
        })
    }

    fn process_certificates(
        &self,
        certified_dealers: &std::collections::HashMap<ValidatorAddress, DkgCertificate>,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.dkg_config.threshold;
        // TODO: Handle missing messages and invalid shares
        let outputs: std::collections::HashMap<PartyId, avss::ReceiverOutput> = certified_dealers
            .values()
            .map(|cert| {
                let dealer_party_id = self
                    .dkg_config
                    .address_to_party_id
                    .get(&cert.dealer)
                    .ok_or_else(|| {
                        DkgError::ProtocolFailed(format!("Unknown dealer: {:?}", cert.dealer))
                    })?;
                let output = self
                    .dealer_outputs
                    .get(&cert.dealer)
                    .ok_or_else(|| {
                        DkgError::ProtocolFailed(format!(
                            "No dealer output found for dealer: {:?}.",
                            cert.dealer
                        ))
                    })?
                    .clone();
                Ok((*dealer_party_id, output))
            })
            .collect::<Result<_, DkgError>>()?;
        let combined_output =
            avss::ReceiverOutput::complete_dkg(threshold, &self.dkg_config.nodes, outputs)
                .map_err(|e| DkgError::CryptoError(format!("Failed to complete DKG: {}", e)))?;
        Ok(DkgOutput {
            public_key: combined_output.vk,
            key_shares: combined_output.my_shares,
            commitments: combined_output.commitments,
            session_context: self.session_context.clone(),
        })
    }

    async fn retrieve_dealer_message(
        &mut self,
        dealer_address: ValidatorAddress,
        certificate: &DkgCertificate,
        p2p_channel: &impl crate::communication::P2PChannel,
    ) -> DkgResult<()> {
        let request = RetrieveMessageRequest {
            dealer: dealer_address.clone(),
        };
        // TODO: Implement gradual escalation strategy for better network efficiency:
        // - Round 1: Call 1-2 random signers, wait ~2s
        // - Round 2: Call 2-3 more signers, wait ~2s
        // - and so on
        for signer_sig in &certificate.signatures {
            let signer_address = &signer_sig.validator;
            if signer_address == &self.address {
                tracing::error!(
                    "Self in certificate signers but message not available for dealer {:?}.",
                    dealer_address
                );
                return Err(DkgError::ProtocolFailed(
                    "Self in certificate signers but message not available".to_string(),
                ));
            }
            // TODO: Add timeout and retries handling when adding RPC layer
            match p2p_channel.retrieve_message(signer_address, &request).await {
                Ok(response) => {
                    let message_hash = compute_message_hash(
                        &self.session_context,
                        &dealer_address,
                        &response.message,
                    )?;
                    if message_hash != certificate.message_hash {
                        tracing::info!(
                            "Signer {:?} returned message with wrong hash",
                            signer_address
                        );
                        continue;
                    }
                    self.receive_dealer_message(&response.message, dealer_address)?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::info!("Failed to retrieve from signer {:?}: {}", signer_address, e);
                    continue;
                }
            }
        }
        Err(DkgError::PairwiseCommunicationError(
            "Failed to retrieve message from any signer".to_string(),
        ))
    }

    async fn recover_shares_via_complaint(
        &mut self,
        dealer: &ValidatorAddress,
        signers: impl IntoIterator<Item = &ValidatorAddress>,
        p2p_channel: &impl crate::communication::P2PChannel,
    ) -> DkgResult<()> {
        let complaint = self
            .complaints
            .get(dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No complaint for dealer".into()))?
            .clone();
        let complaint_request = ComplainRequest {
            dealer: dealer.clone(),
            complaint: complaint.clone(),
        };
        let dealer_session_id = self.session_context.dealer_session_id(dealer);
        let receiver = avss::Receiver::new(
            self.dkg_config.nodes.clone(),
            self.party_id,
            self.dkg_config.threshold,
            dealer_session_id.to_vec(),
            None,
            self.encryption_key.clone(),
        );
        let message = self.dealer_messages.get(dealer).ok_or_else(|| {
            DkgError::ProtocolFailed(format!("No dealer message found for dealer {:?}", dealer))
        })?;
        let mut responses = Vec::new();
        for signer in signers {
            // TODO: Add timeout and retries handling when adding RPC layer
            let response = p2p_channel.complain(signer, &complaint_request).await?;
            responses.push(response.response);
            match receiver.recover(message, &responses) {
                Ok(receiver_output) => {
                    self.dealer_outputs.insert(dealer.clone(), receiver_output);
                    self.complaints.remove(dealer);
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
}

fn validate_certificate(
    cert: &DkgCertificate,
    dkg_config: &DkgConfig,
    session_context: &SessionContext,
    validator_weights: &std::collections::HashMap<ValidatorAddress, u16>,
    dealer_messages: &std::collections::HashMap<ValidatorAddress, avss::Message>,
) -> DkgResult<()> {
    validate_message_hash(cert, dealer_messages, session_context)?;
    validate_signatures(
        &cert.signatures,
        dkg_config.required_dkg_signatures() as u16,
        validator_weights,
    )?;
    Ok(())
}

fn validate_message_hash(
    cert: &DkgCertificate,
    dealer_messages: &std::collections::HashMap<ValidatorAddress, avss::Message>,
    session_context: &SessionContext,
) -> DkgResult<()> {
    let message = dealer_messages.get(&cert.dealer).ok_or_else(|| {
        DkgError::InvalidCertificate(format!(
            "Dealer message not yet received from {:?}",
            cert.dealer
        ))
    })?;
    let expected_hash = compute_message_hash(session_context, &cert.dealer, message)?;
    if cert.message_hash != expected_hash {
        return Err(DkgError::InvalidCertificate(format!(
            "Message hash mismatch for dealer {:?}",
            cert.dealer
        )));
    }
    Ok(())
}

// TODO: Add cryptographic verification of signatures
fn validate_signatures(
    signatures: &[ValidatorSignature],
    required_weight: u16,
    validator_weights: &std::collections::HashMap<ValidatorAddress, u16>,
) -> DkgResult<()> {
    let mut seen_signers = std::collections::HashSet::new();
    let mut total_weight = 0u32;
    for sig in signatures {
        if !seen_signers.insert(&sig.validator) {
            return Err(DkgError::InvalidCertificate(format!(
                "Duplicate signer: {:?}",
                sig.validator
            )));
        }
        let weight = validator_weights.get(&sig.validator).ok_or_else(|| {
            DkgError::InvalidCertificate(format!("Unknown signer: {:?}", sig.validator))
        })?;
        total_weight += *weight as u32;
    }
    if total_weight < required_weight as u32 {
        return Err(DkgError::InvalidCertificate(format!(
            "Insufficient signature weight: got {}, need {}",
            total_weight, required_weight
        )));
    }
    Ok(())
}

fn compute_total_signature_weight(
    signatures: &[ValidatorSignature],
    validator_weights: &std::collections::HashMap<ValidatorAddress, u16>,
) -> DkgResult<u32> {
    let mut total_weight: u32 = 0;
    for sig in signatures {
        let weight =
            validator_weights
                .get(&sig.validator)
                .ok_or_else(|| DkgError::InvalidMessage {
                    sender: sig.validator.clone(),
                    reason: "Signature from unknown validator".to_string(),
                })?;
        total_weight += *weight as u32;
    }
    Ok(total_weight)
}

fn has_sufficient_weighted_signatures(
    signatures: &[ValidatorSignature],
    validator_weights: &std::collections::HashMap<ValidatorAddress, u16>,
    required_weight: u16,
) -> bool {
    match compute_total_signature_weight(signatures, validator_weights) {
        Ok(total_weight) => total_weight >= required_weight as u32,
        Err(e) => {
            tracing::info!("Error checking signature weights: {}", e);
            false
        }
    }
}

fn compute_message_hash(
    session: &SessionContext,
    dealer_address: &ValidatorAddress,
    message: &avss::Message,
) -> DkgResult<MessageHash> {
    let message_bytes = bcs::to_bytes(message)
        .map_err(|e| DkgError::CryptoError(format!("Failed to serialize message: {}", e)))?;
    let mut hasher = Blake2b256::default();
    let dealer_session_id = session.dealer_session_id(dealer_address);
    hasher.update(dealer_session_id.as_ref());
    // No length prefix is needed for message_bytes because it's the only variable-length
    // input.
    hasher.update(&message_bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::types::ProtocolType;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::Scalar;
    use fastcrypto_tbls::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::random_oracle::RandomOracle;
    use fastcrypto_tbls::threshold_schnorr::avss;

    struct MockPublicMessagesStore;

    impl PublicMessagesStore for MockPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            _dealer: &ValidatorAddress,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_dealer_message(
            &self,
            _dealer: &ValidatorAddress,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(None)
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn create_test_validator(party_id: u16) -> (ValidatorAddress, Node<EncryptionGroupElement>) {
        let private_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_private_key(&private_key);
        let address = ValidatorAddress([party_id as u8; 32]);
        let weight = 1;
        let node = Node {
            id: party_id,
            pk: public_key,
            weight,
        };
        (address, node)
    }

    fn build_nodes_and_registry(
        validators: Vec<(ValidatorAddress, Node<EncryptionGroupElement>)>,
    ) -> (Nodes<EncryptionGroupElement>, AddressToPartyId) {
        let mut node_vec: Vec<_> = validators.iter().map(|(_, node)| node.clone()).collect();
        node_vec.sort_by_key(|n| n.id);
        let nodes = Nodes::new(node_vec).unwrap();
        let address_to_party_id: AddressToPartyId = validators
            .iter()
            .map(|(addr, node)| (addr.clone(), node.id))
            .collect();
        (nodes, address_to_party_id)
    }

    fn create_test_dkg_config(num_validators: u16) -> DkgConfig {
        const THRESHOLD: u16 = 2;
        const MAX_FAULTY: u16 = 1;
        assert!(
            num_validators >= THRESHOLD + 2 * MAX_FAULTY,
            "num_validators ({}) must be >= t+2f = {}",
            num_validators,
            THRESHOLD + 2 * MAX_FAULTY
        );
        let validators = (0..num_validators).map(create_test_validator).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        DkgConfig::new(100, nodes, address_to_party_id, THRESHOLD, MAX_FAULTY).unwrap()
    }

    fn create_test_manager(validator_index: u16, dkg_config: DkgConfig) -> DkgManager {
        let address = ValidatorAddress([validator_index as u8; 32]);
        let session_context = SessionContext::new(
            dkg_config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );
        let encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let bls_signing_key = crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng());
        DkgManager::new(
            address,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            Box::new(MockPublicMessagesStore),
        )
    }

    struct MockP2PChannel {
        managers: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<ValidatorAddress, DkgManager>>,
        >,
        current_sender: ValidatorAddress,
    }

    impl MockP2PChannel {
        fn new(
            managers: std::collections::HashMap<ValidatorAddress, DkgManager>,
            current_sender: ValidatorAddress,
        ) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
                current_sender,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for MockP2PChannel {
        async fn send_share(
            &self,
            recipient: &ValidatorAddress,
            request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::SendFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            let response = manager
                .handle_send_share_request(self.current_sender.clone(), request)
                .map_err(|e| {
                    crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            party: &ValidatorAddress,
            request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            let managers = self.managers.lock().unwrap();
            let manager = managers.get(party).ok_or_else(|| {
                crate::communication::ChannelError::SendFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager
                .handle_retrieve_message_request(request)
                .map_err(|e| {
                    crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
                })?;
            Ok(response)
        }

        async fn complain(
            &self,
            party: &ValidatorAddress,
            request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(party).ok_or_else(|| {
                crate::communication::ChannelError::SendFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let mut rng = rand::thread_rng();
            let response = manager
                .handle_complain_request(request, &mut rng)
                .map_err(|e| {
                    crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
                })?;
            Ok(response)
        }
    }

    struct MockOrderedBroadcastChannel {
        certificates: std::sync::Mutex<std::collections::VecDeque<DkgCertificate>>,
        published: std::sync::Mutex<Vec<OrderedBroadcastMessage>>,
    }

    impl MockOrderedBroadcastChannel {
        fn new(certificates: Vec<DkgCertificate>) -> Self {
            Self {
                certificates: std::sync::Mutex::new(certificates.into()),
                published: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn published_count(&self) -> usize {
            self.published.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::OrderedBroadcastChannel<OrderedBroadcastMessage>
        for MockOrderedBroadcastChannel
    {
        async fn publish(
            &self,
            message: OrderedBroadcastMessage,
        ) -> crate::communication::ChannelResult<()> {
            self.published.lock().unwrap().push(message);
            Ok(())
        }

        async fn receive(
            &mut self,
        ) -> crate::communication::ChannelResult<OrderedBroadcastMessage> {
            let cert = self
                .certificates
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| {
                    crate::communication::ChannelError::SendFailed(
                        "No more certificates".to_string(),
                    )
                })?;
            Ok(OrderedBroadcastMessage::AvssCertificateV1(cert))
        }

        async fn try_receive_timeout(
            &mut self,
            _duration: std::time::Duration,
        ) -> crate::communication::ChannelResult<Option<OrderedBroadcastMessage>> {
            unimplemented!()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(self.certificates.lock().unwrap().len())
        }
    }

    fn create_manager_with_valid_keys(
        validator_index: usize,
        num_validators: usize,
    ) -> (DkgManager, Vec<PrivateKey<EncryptionGroupElement>>) {
        let mut rng = rand::thread_rng();

        // Create shared encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let address = ValidatorAddress([validator_index as u8; 32]);
        let manager = DkgManager::new(
            address,
            config,
            session_context,
            encryption_keys[validator_index].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        (manager, encryption_keys)
    }

    struct FailingP2PChannel {
        error_message: String,
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for FailingP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }

        async fn retrieve_message(
            &self,
            _party: &ValidatorAddress,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }

        async fn complain(
            &self,
            _party: &ValidatorAddress,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }
    }

    struct SucceedingP2PChannel {}

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for SucceedingP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Ok(SendShareResponse {
                signature: Vec::new(),
            })
        }

        async fn retrieve_message(
            &self,
            _party: &ValidatorAddress,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            unimplemented!("SucceedingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &ValidatorAddress,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            unimplemented!("SucceedingP2PChannel does not implement complain")
        }
    }

    struct PartiallyFailingP2PChannel {
        fail_count: std::sync::Arc<std::sync::Mutex<usize>>,
        max_failures: usize,
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for PartiallyFailingP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            let mut count = self.fail_count.lock().unwrap();
            if *count < self.max_failures {
                *count += 1;
                Err(crate::communication::ChannelError::SendFailed(
                    "network error".to_string(),
                ))
            } else {
                Ok(SendShareResponse {
                    signature: Vec::new(),
                })
            }
        }

        async fn retrieve_message(
            &self,
            _party: &ValidatorAddress,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &ValidatorAddress,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement complain")
        }
    }

    struct FailingOrderedBroadcastChannel {
        error_message: String,
        fail_on_publish: bool,
        fail_on_receive: bool,
    }

    #[async_trait::async_trait]
    impl crate::communication::OrderedBroadcastChannel<OrderedBroadcastMessage>
        for FailingOrderedBroadcastChannel
    {
        async fn publish(
            &self,
            _message: OrderedBroadcastMessage,
        ) -> crate::communication::ChannelResult<()> {
            if self.fail_on_publish {
                Err(crate::communication::ChannelError::SendFailed(
                    self.error_message.clone(),
                ))
            } else {
                Ok(())
            }
        }

        async fn receive(
            &mut self,
        ) -> crate::communication::ChannelResult<OrderedBroadcastMessage> {
            if self.fail_on_receive {
                Err(crate::communication::ChannelError::SendFailed(
                    self.error_message.clone(),
                ))
            } else {
                unreachable!()
            }
        }

        async fn try_receive_timeout(
            &mut self,
            _duration: std::time::Duration,
        ) -> crate::communication::ChannelResult<Option<OrderedBroadcastMessage>> {
            unreachable!()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(0)
        }
    }

    #[test]
    fn test_dkg_static_data_creation() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config.clone());

        assert_eq!(manager.party_id, 0);
        assert_eq!(manager.dkg_config.threshold, 2);
        assert_eq!(manager.dkg_config.max_faulty, 1);
        assert_eq!(manager.dkg_config.address_to_party_id.len(), 5);
    }

    #[test]
    fn test_dkg_manager_creation() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config);

        assert!(manager.dealer_outputs.is_empty());
    }

    #[test]
    fn test_create_dealer_message() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config);

        // Should successfully create a dealer message
        let _message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();
    }

    struct InMemoryPublicMessagesStore {
        stored: std::collections::HashMap<ValidatorAddress, avss::Message>,
    }

    impl InMemoryPublicMessagesStore {
        fn new() -> Self {
            Self {
                stored: std::collections::HashMap::new(),
            }
        }
    }

    impl PublicMessagesStore for InMemoryPublicMessagesStore {
        fn store_dealer_message(
            &mut self,
            dealer: &ValidatorAddress,
            message: &avss::Message,
        ) -> anyhow::Result<()> {
            self.stored.insert(dealer.clone(), message.clone());
            Ok(())
        }

        fn get_dealer_message(
            &self,
            dealer: &ValidatorAddress,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(self.stored.get(dealer).cloned())
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
            _dealer: &ValidatorAddress,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Storage failure"))
        }

        fn get_dealer_message(
            &self,
            _dealer: &ValidatorAddress,
        ) -> anyhow::Result<Option<avss::Message>> {
            Ok(None)
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_dealer_receiver_flow() {
        // Create encryption keys for each validator
        let mut rng = rand::thread_rng();
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using the encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 0) with its encryption key
        let dealer_address = ValidatorAddress([0; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            Box::new(MockPublicMessagesStore),
        );
        let message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let dealer_address = dealer_manager.address.clone();

        // Create receiver (party 1) with its encryption key and storage
        let receiver_address = ValidatorAddress([1; 32]);
        let storage = InMemoryPublicMessagesStore::new();
        let mut receiver_manager = DkgManager::new(
            receiver_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            Box::new(storage),
        );

        // Receiver processes the dealer's message
        let signature = receiver_manager
            .receive_dealer_message(&message, dealer_address.clone())
            .unwrap();

        // Verify signature format
        assert_eq!(signature.validator, receiver_manager.address);
        assert_eq!(signature.signature.len(), 96); // BLS signature length

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
        let stored_message = receiver_manager
            .public_messages_store
            .get_dealer_message(&dealer_address)
            .unwrap();
        assert!(
            stored_message.is_some(),
            "Dealer message should be persisted to storage"
        );
    }

    #[test]
    fn test_receive_dealer_message_storage_failure() {
        // Create encryption keys for validators
        let mut rng = rand::thread_rng();
        let encryption_keys: Vec<_> = (0..2)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using the encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let public_key = PublicKey::from_private_key(key);
                let address = ValidatorAddress([i as u8; 32]);
                let node = Node {
                    id: i as u16,
                    pk: public_key,
                    weight: 1,
                };
                (address, node)
            })
            .collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 1, 0).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create dealer (party 0)
        let dealer_address = ValidatorAddress([0; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            Box::new(MockPublicMessagesStore),
        );
        let message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Create receiver with failing storage
        let receiver_address = ValidatorAddress([1; 32]);
        let mut receiver_manager = DkgManager::new(
            receiver_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            Box::new(FailingPublicMessagesStore),
        );

        // Receiver processes the dealer's message - should fail due to storage error
        let result = receiver_manager.receive_dealer_message(&message, dealer_address.clone());

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
    fn test_has_sufficient_weighted_signatures_insufficient() {
        // Create validators with different weights: [5, 3, 2, 1, 1]
        let validators =
            validation_test_utils::create_test_validators_with_weights(&[5, 3, 2, 1, 1]);
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        // threshold=7, max_faulty=2, so required_weight = 9
        let config = DkgConfig::new(100, nodes, address_to_party_id, 7, 2).unwrap();

        // Test case 1: Only validator 0 (weight=5), need 9
        let signatures = vec![ValidatorSignature {
            validator: ValidatorAddress([0; 32]),
            signature: vec![0; 96],
        }];
        assert!(
            !validation_test_utils::test_has_sufficient_weighted_signatures(&signatures, &config)
        );

        // Test case 2: Validators 0 and 2 (weight=5+2=7), need 9
        let signatures = vec![
            ValidatorSignature {
                validator: ValidatorAddress([0; 32]),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: ValidatorAddress([2; 32]),
                signature: vec![0; 96],
            },
        ];
        assert!(
            !validation_test_utils::test_has_sufficient_weighted_signatures(&signatures, &config)
        );

        // Test case 3: Validators 0 and 1 (weight=5+3=8), still need 9
        let signatures = vec![
            ValidatorSignature {
                validator: ValidatorAddress([0; 32]),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: ValidatorAddress([1; 32]),
                signature: vec![0; 96],
            },
        ];
        assert!(
            !validation_test_utils::test_has_sufficient_weighted_signatures(&signatures, &config)
        );

        // Test case 4: Validators 0, 1, and 3 (weight=5+3+1=9), exactly sufficient
        let signatures = vec![
            ValidatorSignature {
                validator: ValidatorAddress([0; 32]),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: ValidatorAddress([1; 32]),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: ValidatorAddress([3; 32]),
                signature: vec![0; 96],
            },
        ];
        assert!(
            validation_test_utils::test_has_sufficient_weighted_signatures(&signatures, &config)
        );
    }

    #[test]
    fn test_create_certificate_success() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config.clone());

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Create enough signatures (threshold + max_faulty = 3 weight needed)
        let required_sigs = (manager.dkg_config.threshold + manager.dkg_config.max_faulty) as usize;
        let signatures: Vec<_> = config
            .address_to_party_id
            .keys()
            .take(required_sigs)
            .map(|addr| ValidatorSignature {
                validator: addr.clone(),
                signature: vec![0; 96],
            })
            .collect();

        let certificate = manager
            .create_certificate(&message, signatures.clone())
            .unwrap();

        assert_eq!(certificate.dealer, manager.address);
        assert_eq!(certificate.signatures.len(), required_sigs);
        assert_eq!(
            certificate.session_context.session_id,
            manager.session_context.session_id
        );
    }

    #[test]
    fn test_create_certificate_weighted_signatures() {
        // Create validators with different weights
        let validators = vec![
            (
                ValidatorAddress([0; 32]),
                Node {
                    id: 0,
                    pk: PublicKey::from_private_key(&PrivateKey::<EncryptionGroupElement>::new(
                        &mut rand::thread_rng(),
                    )),
                    weight: 3, // Heavy weight
                },
            ),
            (
                ValidatorAddress([1; 32]),
                Node {
                    id: 1,
                    pk: PublicKey::from_private_key(&PrivateKey::<EncryptionGroupElement>::new(
                        &mut rand::thread_rng(),
                    )),
                    weight: 1,
                },
            ),
            (
                ValidatorAddress([2; 32]),
                Node {
                    id: 2,
                    pk: PublicKey::from_private_key(&PrivateKey::<EncryptionGroupElement>::new(
                        &mut rand::thread_rng(),
                    )),
                    weight: 1,
                },
            ),
        ];

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        // threshold=3, max_faulty=1, total_weight=5
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 1).unwrap();
        let manager = create_test_manager(0, config.clone());

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Only validator 0 (weight=3), which is less than required (threshold + max_faulty = 4)
        let addr0 = ValidatorAddress([0; 32]);
        let insufficient_sigs = vec![ValidatorSignature {
            validator: addr0.clone(),
            signature: vec![0; 96],
        }];

        // Should not have sufficient weight
        assert!(
            !validation_test_utils::test_has_sufficient_weighted_signatures(
                &insufficient_sigs,
                &config
            )
        );

        // Validator 0 (weight=3) + validator 1 (weight=1) = 4, which meets the requirement
        let addr1 = ValidatorAddress([1; 32]);
        let sufficient_sigs = vec![
            ValidatorSignature {
                validator: addr0.clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: addr1.clone(),
                signature: vec![0; 96],
            },
        ];

        // Should have sufficient weight
        assert!(
            validation_test_utils::test_has_sufficient_weighted_signatures(
                &sufficient_sigs,
                &config
            )
        );

        // create_certificate should succeed now (no weight validation there)
        let result = manager.create_certificate(&message, sufficient_sigs);
        assert!(result.is_ok());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_has_sufficient_weighted_signatures_unknown_validator() {
        let config = create_test_dkg_config(5);

        // Create signatures including one from an unknown validator
        let unknown_validator = ValidatorAddress([99; 32]);
        let known_validator_addr = config.address_to_party_id.keys().next().unwrap();
        let signatures = vec![
            ValidatorSignature {
                validator: known_validator_addr.clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: unknown_validator.clone(),
                signature: vec![0; 96],
            },
        ];

        let validator_weights = validation_test_utils::create_validator_weights(&config);
        let required_weight = config.threshold + config.max_faulty;

        let result =
            has_sufficient_weighted_signatures(&signatures, &validator_weights, required_weight);

        assert!(!result);
        assert!(logs_contain("Error checking signature weights"));
        assert!(logs_contain("Signature from unknown validator"));
    }

    #[test]
    fn test_compute_message_hash_deterministic() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();
        let dealer_address = ValidatorAddress([42; 32]);

        let hash1 =
            compute_message_hash(&manager.session_context, &dealer_address, &message).unwrap();

        let hash2 =
            compute_message_hash(&manager.session_context, &dealer_address, &message).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_message_hash_different_for_different_dealers() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        let hash1 = compute_message_hash(
            &manager.session_context,
            &ValidatorAddress([1; 32]),
            &message,
        )
        .unwrap();

        let hash2 = compute_message_hash(
            &manager.session_context,
            &ValidatorAddress([2; 32]),
            &message,
        )
        .unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_process_certificates_success() {
        // Create 5 validators with different weights
        let mut rng = rand::thread_rng();
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Use different weights: [3, 2, 4, 1, 2] (total = 12)
        let weights = [3, 2, 4, 1, 2];
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = weights[i];
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        // threshold = 3, max_faulty = 1, total_weight = 12
        // Constraint: t + 2f = 3 + 2 = 5 <= 12 ✓
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create threshold (3) dealers - complete_dkg requires exactly t dealer outputs
        // Using validators 0, 1, 4 as dealers (weights 3, 2, 2 respectively)
        let dealer_indices = [0, 1, 4];
        let dealer_managers: Vec<_> = dealer_indices
            .iter()
            .map(|&i| {
                let addr = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    addr.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Create receiver (party 2 with weight=4 - will receive 4 shares!)
        let addr2 = ValidatorAddress([2; 32]);
        let mut receiver_manager = DkgManager::new(
            addr2.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[2].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            Box::new(MockPublicMessagesStore),
        );

        // Each dealer creates a message
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|dm| dm.create_dealer_message(&mut rng).unwrap())
            .collect();

        // Receiver processes all dealer messages and creates certificates
        let mut certificates = std::collections::HashMap::new();
        for (i, message) in dealer_messages.iter().enumerate() {
            let dealer_address = dealer_managers[i].address.clone();

            // Receiver processes the message
            let _sig = receiver_manager.receive_dealer_message(message, dealer_address.clone());

            // Create a certificate (in practice, would collect signatures from other validators)
            // Need threshold + max_faulty = 3 + 1 = 4 weighted signatures
            // Using validators with weights: 0(3) + 1(2) = 5 weight, which is > 4 ✓
            let addr0 = ValidatorAddress([0; 32]);
            let addr1 = ValidatorAddress([1; 32]);
            let mock_signatures = vec![
                ValidatorSignature {
                    validator: addr0.clone(), // weight=3
                    signature: vec![0; 96],
                },
                ValidatorSignature {
                    validator: addr1.clone(), // weight=2
                    signature: vec![0; 96],
                },
            ];

            // Dealer creates their own certificate
            let cert = dealer_managers[i]
                .create_certificate(message, mock_signatures)
                .unwrap();
            certificates.insert(dealer_address, cert);
        }

        // Process certificates to complete DKG
        let dkg_output = receiver_manager
            .process_certificates(&certificates)
            .unwrap();

        // Verify output structure
        // Receiver has weight=4, so should receive 4 shares
        assert_eq!(dkg_output.key_shares.shares.len(), 4);
        assert!(!dkg_output.commitments.is_empty());
        assert_eq!(
            dkg_output.session_context.session_id,
            session_context.session_id
        );
    }

    #[test]
    fn test_process_certificates_missing_dealer_output() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config.clone());

        // Create certificates for dealers we haven't received messages from
        let addr0 = &ValidatorAddress([0; 32]);
        let addr1 = &ValidatorAddress([1; 32]);

        let mock_signatures = vec![ValidatorSignature {
            validator: addr0.clone(),
            signature: vec![0; 96],
        }];

        let cert0 = DkgCertificate {
            dealer: addr0.clone(),
            message_hash: [0; 32],
            signatures: mock_signatures.clone(),
            session_context: manager.session_context.clone(),
        };
        let cert1 = DkgCertificate {
            dealer: addr1.clone(),
            message_hash: [0; 32],
            signatures: mock_signatures,
            session_context: manager.session_context.clone(),
        };

        let mut certificates = std::collections::HashMap::new();
        certificates.insert(cert0.dealer.clone(), cert0);
        certificates.insert(cert1.dealer.clone(), cert1);

        let result = manager.process_certificates(&certificates);
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
        let weights = [1, 1, 1, 2, 2];
        let num_validators = weights.len();

        // Create encryption keys and BLS keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = weights[i];
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        // Total weight = 7, threshold = 3, max_faulty = 1
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    address.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Phase 1: Pre-create all dealer messages
        let dealer_messages: Vec<_> = managers
            .iter()
            .map(|mgr| mgr.create_dealer_message(&mut rng).unwrap())
            .collect();

        // Phase 2: Pre-compute all signatures and certificates
        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = ValidatorAddress([dealer_idx as u8; 32]);

            // Collect signatures from all validators
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr.clone())
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate
            let cert = managers[dealer_idx]
                .create_certificate(message, signatures)
                .unwrap();
            certificates.push(cert);
        }

        // Phase 3: Test run_as_dealer() and run_as_party() for validator 0 with mocked channels
        // Remove validator 0 from managers (it will call run_dkg)
        let mut test_manager = managers.remove(0);

        // Create mock P2P channel with remaining managers (validators 1-4)
        let other_managers: std::collections::HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (ValidatorAddress([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, ValidatorAddress([0; 32]));

        // Pre-populate validator 0's manager with dealer outputs from all validators (including itself)
        for (j, message) in dealer_messages.iter().enumerate() {
            test_manager
                .receive_dealer_message(message, ValidatorAddress([j as u8; 32]))
                .unwrap();
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

        // Verify the session context matches
        assert_eq!(
            output.session_context.session_id, session_context.session_id,
            "Output should have correct session ID"
        );

        // Verify all certificates were consumed from the TOB channel (only threshold needed)
        use crate::communication::OrderedBroadcastChannel;
        assert_eq!(
            mock_tob.pending_messages(),
            Some(other_certificates_len - config.threshold as usize),
            "TOB should have consumed exactly threshold certificates"
        );

        // Verify that other validators (in the mock P2P channel) received and processed validator 0's dealer message
        let other_managers = mock_p2p.managers.lock().unwrap();
        let addr0 = ValidatorAddress([0; 32]);
        for j in 1..num_validators {
            let addr_j = ValidatorAddress([j as u8; 32]);
            let other_mgr = other_managers.get(&addr_j).unwrap();
            assert!(
                other_mgr.dealer_outputs.contains_key(&addr0),
                "Validator {} should have dealer output from validator 0",
                j
            );
        }
    }

    #[tokio::test]
    async fn test_run_as_dealer_success() {
        let mut rng = rand::thread_rng();
        let num_validators = 5;

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create manager for validator 0
        let addr0 = ValidatorAddress([0; 32]);
        let mut test_manager = DkgManager::new(
            addr0.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create managers for other validators
        let other_managers: std::collections::HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = ValidatorAddress([i as u8; 32]);
                let manager = DkgManager::new(
                    addr.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, ValidatorAddress([0; 32]));
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Call run_as_dealer()
        let result = test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;

        // Verify success
        assert!(result.is_ok());

        // Verify own dealer output is stored
        let addr0 = ValidatorAddress([0; 32]);
        assert!(test_manager.dealer_outputs.contains_key(&addr0));

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let addr = ValidatorAddress([i as u8; 32]);
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
        let threshold = 2;

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    address.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Pre-create dealer messages and certificates for threshold validators
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(threshold as usize)
            .map(|mgr| mgr.create_dealer_message(&mut rng).unwrap())
            .collect();

        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = ValidatorAddress([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr.clone())
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate
            let cert = managers[dealer_idx]
                .create_certificate(message, signatures)
                .unwrap();
            certificates.push(cert);
        }

        // Create mock TOB with threshold certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates.clone());

        // Call run_as_party() for validator 0
        let mut test_manager = managers.remove(0);
        let other_managers: std::collections::HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (ValidatorAddress([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, ValidatorAddress([0; 32]));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify output structure
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), num_validators); // total weight = 5
        assert_eq!(
            output.session_context.session_id,
            session_context.session_id
        );

        // Verify TOB consumed exactly threshold certificates
        use crate::communication::OrderedBroadcastChannel;
        assert_eq!(mock_tob.pending_messages(), Some(0));
    }

    #[tokio::test]
    async fn test_run_as_party_recovers_shares_via_complaint() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer 0 with normal message
        let (dealer_0_addr, dealer_0_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let dealer_0_message = dealer_0_mgr
            .dealer_messages
            .get(&dealer_0_addr)
            .unwrap()
            .clone();

        // Create dealer 1 with cheating message (corrupts party 2's shares)
        let (dealer_1_addr, _) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);
        let dealer_1_message = create_cheating_message(
            &dealer_1_addr,
            &config,
            &session_context,
            2, // Corrupt shares for party 2
            &mut rng,
        );

        // Create party 2 manager (will have complaint for dealer 1)
        let (party_addr, mut party_manager) =
            create_manager_at_index(2, &config, &session_context, &encryption_keys, &mut rng);

        // Party 2 successfully processes dealer 0's message
        party_manager
            .receive_dealer_message(&dealer_0_message, dealer_0_addr.clone())
            .unwrap();

        // Party 2 fails on dealer 1's cheating message and creates complaint
        let result = party_manager.receive_dealer_message(&dealer_1_message, dealer_1_addr.clone());
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_1_addr));

        // Create other parties who can successfully process dealer 1's message
        let mut other_managers = std::collections::HashMap::new();
        for party_id in [0, 1, 3, 4] {
            let (addr, mut mgr) = create_manager_at_index(
                party_id,
                &config,
                &session_context,
                &encryption_keys,
                &mut rng,
            );
            // They successfully process dealer 1's cheating message
            mgr.receive_dealer_message(&dealer_1_message, dealer_1_addr.clone())
                .unwrap();
            other_managers.insert(addr, mgr);
        }

        // Create certificates with signers (excluding party 2 who has complaint)
        let cert_0 = create_certificate_with_signers(
            &dealer_0_addr,
            &dealer_0_message,
            &session_context,
            vec![
                ValidatorAddress([0; 32]),
                ValidatorAddress([1; 32]),
                ValidatorAddress([3; 32]),
            ],
        );
        let cert_1 = create_certificate_with_signers(
            &dealer_1_addr,
            &dealer_1_message,
            &session_context,
            vec![
                ValidatorAddress([0; 32]),
                ValidatorAddress([1; 32]),
                ValidatorAddress([3; 32]),
            ],
        );

        let certificates = vec![cert_0, cert_1];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);
        let mock_p2p = MockP2PChannel::new(other_managers, party_addr.clone());

        // Verify complaint exists before run_as_party
        assert!(party_manager.complaints.contains_key(&dealer_1_addr));

        // Run as party - should recover shares via complaint
        let output = party_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify complaint was resolved
        assert!(
            !party_manager.complaints.contains_key(&dealer_1_addr),
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
    async fn test_run_as_party_skips_invalid_certificates() {
        // Test that run_as_party() skips invalid certificates and continues collecting valid ones
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let threshold = 3;

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());
        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    address.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Create threshold valid certificates + some invalid ones
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(threshold as usize)
            .map(|mgr| mgr.create_dealer_message(&mut rng).unwrap())
            .collect();

        let mut valid_certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = ValidatorAddress([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr.clone())
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate
            let cert = managers[dealer_idx]
                .create_certificate(message, signatures)
                .unwrap();
            valid_certificates.push(cert);
        }

        // Create invalid certificate with wrong message hash
        let invalid_dealer_msg = managers[3].create_dealer_message(&mut rng).unwrap();
        let dealer_addr_3 = ValidatorAddress([3; 32]);

        let mut invalid_signatures = Vec::new();
        for manager in managers.iter_mut() {
            let sig = manager
                .receive_dealer_message(&invalid_dealer_msg, dealer_addr_3.clone())
                .unwrap();
            invalid_signatures.push(sig);
        }

        let mut invalid_cert = managers[3]
            .create_certificate(&invalid_dealer_msg, invalid_signatures)
            .unwrap();
        // Make it invalid by corrupting the message hash
        invalid_cert.message_hash = [99; 32]; // Wrong hash

        // Mix valid and invalid certificates in TOB
        // Order: valid[0], invalid, valid[1], valid[2]
        let all_certificates = vec![
            valid_certificates[0].clone(),
            invalid_cert,
            valid_certificates[1].clone(),
            valid_certificates[2].clone(),
        ];

        let mut mock_tob = MockOrderedBroadcastChannel::new(all_certificates);

        // Call run_as_party() for validator 0
        let mut test_manager = managers.remove(0);
        let other_managers: std::collections::HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (ValidatorAddress([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, ValidatorAddress([0; 32]));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify it succeeded by collecting the 3 valid certificates
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), num_validators); // total weight = 5
        assert_eq!(
            output.session_context.session_id,
            session_context.session_id
        );

        // Verify TOB consumed all certificates (3 valid + 1 invalid)
        use crate::communication::OrderedBroadcastChannel;
        assert_eq!(
            mock_tob.pending_messages(),
            Some(0),
            "TOB should have consumed all certificates"
        );
    }

    #[tokio::test]
    async fn test_run_as_party_requires_different_dealers() {
        // Test that having t certificates from a single dealer is not sufficient
        let mut rng = rand::thread_rng();
        let num_validators = 5;
        let threshold = 2;

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    address.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Create dealer messages from 2 dealers
        let dealer_messages: Vec<_> = managers
            .iter()
            .take(2)
            .map(|mgr| mgr.create_dealer_message(&mut rng).unwrap())
            .collect();

        // Create certificates
        let mut certificates = Vec::new();
        for (dealer_idx, message) in dealer_messages.iter().enumerate() {
            let dealer_addr = ValidatorAddress([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr.clone())
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate
            let cert = managers[dealer_idx]
                .create_certificate(message, signatures)
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
        let other_managers: std::collections::HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| {
                let addr_idx = if idx < 2 { idx } else { idx + 1 };
                (ValidatorAddress([addr_idx as u8; 32]), mgr)
            })
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, ValidatorAddress([2; 32]));
        let output = test_manager
            .run_as_party(&mock_p2p, &mut mock_tob)
            .await
            .unwrap();

        // Verify it correctly waited for 2 different dealers
        assert_eq!(output.key_shares.shares.len(), 1); // weight = 1
        assert_eq!(output.commitments.len(), num_validators); // total weight = 5

        // Verify TOB consumed all 3 messages (not just the first 2)
        use crate::communication::OrderedBroadcastChannel;
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
        assert!(logs_contain("Failed to send share"));
        assert!(logs_contain("network error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_tob_publish_error() {
        let mut rng = rand::thread_rng();
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let succeeding_p2p = SucceedingP2PChannel {};

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
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 7);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        let partially_failing_p2p = PartiallyFailingP2PChannel {
            fail_count: std::sync::Arc::new(std::sync::Mutex::new(0)),
            max_failures: 1, // Fail 1 out of 6, get 5 signatures
        };

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
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Fail too many validators
        let partially_failing_p2p = PartiallyFailingP2PChannel {
            fail_count: std::sync::Arc::new(std::sync::Mutex::new(0)),
            max_failures: 3, // Fail 3 out of 4, only 1 succeeds
        };

        let result = test_manager
            .run_as_dealer(&partially_failing_p2p, &mut mock_tob, &mut rng)
            .await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        // Verify logging occurred for the 3 failures
        assert!(logs_contain("Failed to send share"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_includes_own_signature() {
        let mut rng = rand::thread_rng();
        let num_validators = 5;

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create manager for validator 0 (the dealer)
        let dealer_addr = ValidatorAddress([0; 32]);
        let mut test_manager = DkgManager::new(
            dealer_addr.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create managers for other validators
        let other_managers: std::collections::HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = ValidatorAddress([i as u8; 32]);
                let manager = DkgManager::new(
                    addr.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, dealer_addr.clone());
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
        let cert = match &published[0] {
            OrderedBroadcastMessage::AvssCertificateV1(cert) => cert,
            _ => panic!("Expected AvssCertificateV1"),
        };

        // Verify the dealer's own signature is included
        assert!(
            cert.signatures
                .iter()
                .any(|sig| sig.validator == dealer_addr),
            "Dealer's own signature must be included in the certificate"
        );

        // Verify the dealer is the first signer
        assert_eq!(
            cert.signatures[0].validator, dealer_addr,
            "Dealer should be the first signer"
        );

        // Verify all signatures are from distinct validators
        let signers: std::collections::HashSet<_> =
            cert.signatures.iter().map(|sig| &sig.validator).collect();
        assert_eq!(
            signers.len(),
            cert.signatures.len(),
            "All signatures should be from distinct validators"
        );
    }

    #[tokio::test]
    async fn test_run_as_party_tob_receive_error() {
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "receive timeout".to_string(),
            fail_on_publish: false,
            fail_on_receive: true,
        };

        let mock_p2p =
            MockP2PChannel::new(std::collections::HashMap::new(), ValidatorAddress([0; 32]));
        let result = test_manager.run_as_party(&mock_p2p, &mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::BroadcastError(_)));
        assert!(err.to_string().contains("receive timeout"));
    }

    struct WeightBasedTestSetup {
        config: DkgConfig,
        session_context: SessionContext,
        dealer_messages: Vec<(ValidatorAddress, avss::Message)>,
        certificates: Vec<DkgCertificate>,
        encryption_keys: Vec<PrivateKey<EncryptionGroupElement>>,
        weights: Vec<u16>,
    }

    fn setup_weight_based_test(
        weights: Vec<u16>,
        threshold: u16,
        num_dealers: Option<usize>,
    ) -> WeightBasedTestSetup {
        let mut rng = rand::thread_rng();
        let num_validators = weights.len();

        // Create encryption keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators with specified weights
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = weights[i];
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, threshold, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer managers (either all validators or specified subset)
        let dealer_count = num_dealers.unwrap_or(num_validators);
        let dealer_managers: Vec<_> = (0..dealer_count)
            .map(|i| {
                let addr = ValidatorAddress([i as u8; 32]);
                DkgManager::new(
                    addr.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    crate::bls::Bls12381PrivateKey::generate(&mut rng),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Generate dealer messages once and store them
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|manager| {
                let message = manager.create_dealer_message(&mut rng).unwrap();
                (manager.address.clone(), message)
            })
            .collect();

        // Create certificates from the stored messages
        let certificates: Vec<_> = dealer_messages
            .iter()
            .map(|(dealer_addr, message)| {
                create_test_certificate(dealer_addr, message, &config, &session_context, &weights)
            })
            .collect();

        WeightBasedTestSetup {
            config,
            session_context,
            dealer_messages,
            certificates,
            encryption_keys,
            weights,
        }
    }

    // Create a test certificate with minimal valid signatures
    fn create_test_certificate(
        dealer_addr: &ValidatorAddress,
        message: &avss::Message,
        config: &DkgConfig,
        session_context: &SessionContext,
        weights: &[u16],
    ) -> DkgCertificate {
        let message_hash = compute_message_hash(session_context, dealer_addr, message).unwrap();

        // Create minimal valid signatures to pass validation
        let dkg_required = config.required_dkg_signatures() as u16;
        let mut dkg_sigs = vec![];
        let mut weight_sum = 0u16;

        // Add signatures from validators until we meet the required weight
        for (i, w) in weights.iter().enumerate() {
            let signer_addr = ValidatorAddress([i as u8; 32]);
            let sig = types::ValidatorSignature {
                validator: signer_addr,
                signature: vec![0u8; 64], // Dummy signature
            };
            dkg_sigs.push(sig);
            weight_sum += w;

            if weight_sum >= dkg_required {
                break;
            }
        }

        DkgCertificate {
            dealer: dealer_addr.clone(),
            message_hash,
            signatures: dkg_sigs,
            session_context: session_context.clone(),
        }
    }

    // Helper to create and setup a party manager for testing
    async fn setup_party_and_run(
        test_setup: &WeightBasedTestSetup,
        party_index: usize,
    ) -> (DkgResult<DkgOutput>, MockOrderedBroadcastChannel) {
        let mut rng = rand::thread_rng();
        let party_addr = ValidatorAddress([party_index as u8; 32]);

        let mut party_manager = DkgManager::new(
            party_addr.clone(),
            test_setup.config.clone(),
            test_setup.session_context.clone(),
            test_setup.encryption_keys[party_index].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Pre-process the dealer messages so validation passes
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = party_manager.receive_dealer_message(message, dealer_addr.clone());
        }

        // Create mock TOB with certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(test_setup.certificates.clone());

        // Run party collection
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr.clone());
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

        (result, mock_tob)
    }

    #[tokio::test]
    async fn test_run_as_party_weight_based_collection() {
        // Test that run_as_party stops collecting when dealer_weight_sum >= threshold
        // Use weights [1, 1, 1, 2, 2] (total = 7)
        // With threshold=3, we need dealers with total weight >= 3
        // This ensures we get exactly 3 dealers (1+1+1=3) to satisfy both weight and AVSS requirements
        let test_setup = setup_weight_based_test(vec![1, 1, 1, 2, 2], 3, None);
        let (result, mock_tob) = setup_party_and_run(&test_setup, 0).await;

        assert!(result.is_ok());

        // Key verification: Check how many certificates were consumed
        // BTreeMap ordering of addresses: [0,0,0,...], [1,1,1,...], [2,2,2,...], etc
        // Weights: addr0=1, addr1=1, addr2=1, addr3=2, addr4=2
        // Should consume addr0 (weight 1) + addr1 (weight 1) + addr2 (weight 1) = total weight 3 >= threshold
        use crate::communication::OrderedBroadcastChannel;
        let remaining = mock_tob.pending_messages().unwrap();
        assert_eq!(
            remaining, 2,
            "Should consume exactly 3 certificates to reach weight threshold of 3"
        );

        // Verify the output
        let output = result.unwrap();
        assert_eq!(
            output.key_shares.shares.len(),
            test_setup.weights[0] as usize
        ); // Party 0 has weight 1
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
        // Use weights [1, 1, 1, 1, 1] (all equal)
        // Need exactly 3 dealers to reach threshold
        let test_setup = setup_weight_based_test(vec![1, 1, 1, 1, 1], 3, None);
        let (result, mock_tob) = setup_party_and_run(&test_setup, 0).await;

        assert!(result.is_ok());

        // Should consume exactly 3 certificates (weight 1+1+1 = 3)
        use crate::communication::OrderedBroadcastChannel;
        let remaining = mock_tob.pending_messages().unwrap();
        assert_eq!(
            remaining, 2,
            "Should consume exactly 3 certificates to reach threshold"
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
        let mut rng = rand::thread_rng();
        let party_addr = ValidatorAddress([0; 32]);
        let mut party_manager = DkgManager::new(
            party_addr.clone(),
            test_setup.config.clone(),
            test_setup.session_context.clone(),
            test_setup.encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Pre-process the dealer messages
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = party_manager.receive_dealer_message(message, dealer_addr.clone());
        }

        // Create mock TOB with the modified certificates (including duplicates)
        let mut mock_tob = MockOrderedBroadcastChannel::new(modified_certificates);

        // Run party collection
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr.clone());
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;
        assert!(result.is_ok());

        // Verify behavior:
        // Should process: dealer0 (weight 1), skip dealer0 duplicate,
        //                dealer1 (weight 1), skip dealer1 duplicate,
        //                dealer2 (weight 1) - now we have weight 3 >= threshold
        // Should NOT process: dealer3 (since we already have enough weight)
        use crate::communication::OrderedBroadcastChannel;
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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create 3 dealers with their messages
        let (dealer1_addr, dealer1_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let (dealer2_addr, dealer2_mgr) =
            create_dealer_with_message(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let (party_addr, mut party_manager) =
            create_manager_at_index(3, &config, &session_context, &encryption_keys, &mut rng);

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

        // Create certificates using the test helper which creates minimal valid signatures
        let cert1 = create_test_certificate(
            &dealer1_addr,
            &msg1,
            &config,
            &session_context,
            &[1, 1, 1, 1, 1],
        );
        let cert2 = create_test_certificate(
            &dealer2_addr,
            &msg2,
            &config,
            &session_context,
            &[1, 1, 1, 1, 1],
        );

        // Create mock P2P channel with dealers that have messages
        let mut dealers = std::collections::HashMap::new();
        dealers.insert(dealer1_addr.clone(), dealer1_mgr);
        dealers.insert(dealer2_addr.clone(), dealer2_mgr);
        let mock_p2p = MockP2PChannel::new(dealers, party_addr.clone());

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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create 3 dealers with their messages
        let (dealer1_addr, dealer1_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let (dealer2_addr, _dealer2_mgr) =
            create_dealer_with_message(1, &config, &session_context, &encryption_keys, &mut rng);
        let (dealer3_addr, dealer3_mgr) =
            create_dealer_with_message(2, &config, &session_context, &encryption_keys, &mut rng);

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let (party_addr, mut party_manager) =
            create_manager_at_index(3, &config, &session_context, &encryption_keys, &mut rng);

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

        // Create certificates for all three dealers
        let cert1 = create_test_certificate(
            &dealer1_addr,
            &msg1,
            &config,
            &session_context,
            &[1, 1, 1, 1, 1],
        );
        let cert2 = create_test_certificate(
            &dealer2_addr,
            &msg2,
            &config,
            &session_context,
            &[1, 1, 1, 1, 1],
        );
        let cert3 = create_test_certificate(
            &dealer3_addr,
            &msg3,
            &config,
            &session_context,
            &[1, 1, 1, 1, 1],
        );

        // Create mock P2P channel with only dealer1 and dealer3 (dealer2 is missing)
        // So retrieval of dealer2's message will fail
        let mut dealers = std::collections::HashMap::new();
        dealers.insert(dealer1_addr.clone(), dealer1_mgr);
        dealers.insert(dealer3_addr.clone(), dealer3_mgr);
        let mock_p2p = MockP2PChannel::new(dealers, party_addr.clone());

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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer 0 with a message - recovery will fail
        let (dealer0_addr, dealer0_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let dealer0_message = dealer0_mgr
            .dealer_messages
            .get(&dealer0_addr)
            .unwrap()
            .clone();

        // Create dealer 1 - would be processed if we continued
        let (dealer1_addr, dealer1_mgr) =
            create_dealer_with_message(1, &config, &session_context, &encryption_keys, &mut rng);
        let dealer1_message = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();

        // Create party manager (validator 4)
        let (party_addr, mut party_manager) =
            create_manager_at_index(4, &config, &session_context, &encryption_keys, &mut rng);

        // Setup complaint for dealer 0 (recovery will fail - no responders in P2P)
        let complaint = create_complaint_for_dealer(
            &dealer0_message,
            4, // party_id
            &config,
            &session_context,
            &dealer0_addr,
            &mut rng,
        );
        setup_party_with_complaint(
            &mut party_manager,
            &dealer0_addr,
            &dealer0_message,
            complaint,
        );

        // Create certificates
        let cert0 = create_certificate_with_signers(
            &dealer0_addr,
            &dealer0_message,
            &session_context,
            vec![
                ValidatorAddress([0; 32]),
                ValidatorAddress([1; 32]),
                ValidatorAddress([2; 32]),
            ],
        );
        let cert1 = create_certificate_with_signers(
            &dealer1_addr,
            &dealer1_message,
            &session_context,
            vec![
                ValidatorAddress([1; 32]),
                ValidatorAddress([2; 32]),
                ValidatorAddress([3; 32]),
            ],
        );

        // Create mock P2P with no responders (recovery will fail)
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr.clone());

        // Create mock TOB with both certificates
        let certificates = vec![cert0, cert1];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);

        // Run as party - should ABORT on dealer0 recovery failure
        let result = party_manager.run_as_party(&mock_p2p, &mut mock_tob).await;

        // Should fail with BroadcastError (P2P call failed)
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::BroadcastError(_)),
            "Expected BroadcastError, got: {:?}",
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
            party_manager.complaints.contains_key(&dealer0_addr),
            "Complaint should remain after recovery failure"
        );
    }

    #[tokio::test]
    async fn test_handle_send_share_request() {
        // Test that handle_send_share_request works with the new request/response types
        let mut rng = rand::thread_rng();

        // Create shared encryption keys
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 1) with its encryption key
        let dealer_address = ValidatorAddress([1; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Create receiver (party 0) with its encryption key
        let receiver_address = ValidatorAddress([0; 32]);
        let mut receiver_manager = DkgManager::new(
            receiver_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Dealer creates a message
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Create a request as if dealer sent it to receiver
        let request = SendShareRequest {
            message: dealer_message.clone(),
        };

        // Receiver handles the request
        let response = receiver_manager
            .handle_send_share_request(dealer_address.clone(), &request)
            .unwrap();

        assert_eq!(response.signature.len(), 96); // BLS signature size
    }

    #[tokio::test]
    async fn test_handle_retrieve_message_request_success() {
        let mut rng = rand::thread_rng();

        // Create shared encryption keys
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 0)
        let dealer_address = ValidatorAddress([0; 32]);
        let mut dealer_manager = DkgManager::new(
            dealer_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Dealer creates and processes its own message (stores in dealer_messages)
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        dealer_manager
            .receive_dealer_message(&dealer_message, dealer_address.clone())
            .unwrap();

        // Party requests the dealer's message
        let request = RetrieveMessageRequest {
            dealer: dealer_address.clone(),
        };
        let response = dealer_manager
            .handle_retrieve_message_request(&request)
            .unwrap();

        let expected_hash =
            compute_message_hash(&session_context, &dealer_address, &dealer_message).unwrap();
        let received_hash =
            compute_message_hash(&session_context, &dealer_address, &response.message).unwrap();
        assert_eq!(received_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_handle_retrieve_message_request_message_not_available() {
        let mut rng = rand::thread_rng();

        // Create shared encryption keys
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 0) but don't create/process any message
        let dealer_address = ValidatorAddress([0; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Party requests the dealer's message
        let request = RetrieveMessageRequest {
            dealer: dealer_address.clone(),
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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);
        let (dealer_address, _dealer_message, complaint) = create_dealer_message_and_complaint(
            &config,
            &session_context,
            &encryption_keys,
            &mut rng,
        );

        // Create manager (party 1) without any dealer messages
        let mut manager = DkgManager::new(
            ValidatorAddress([1; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        let request = ComplainRequest {
            dealer: dealer_address,
            complaint,
        };

        // Manager has no message from this dealer
        let result = manager.handle_complain_request(&request, &mut rng);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No message from dealer"));
    }

    #[test]
    fn test_handle_complain_request_no_shares_for_dealer() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);
        let (dealer_address, dealer_message, complaint) = create_dealer_message_and_complaint(
            &config,
            &session_context,
            &encryption_keys,
            &mut rng,
        );

        // Create manager that has the message but NOT dealer_output
        let mut manager = DkgManager::new(
            ValidatorAddress([1; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Manually insert message without processing (so no dealer_output)
        manager
            .dealer_messages
            .insert(dealer_address.clone(), dealer_message.clone());

        let request = ComplainRequest {
            dealer: dealer_address,
            complaint,
        };

        // Manager has message but no dealer_output
        let result = manager.handle_complain_request(&request, &mut rng);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
        assert!(err.to_string().contains("No shares for dealer"));
    }

    #[test]
    fn test_handle_complain_request_caches_response() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer (party 0)
        let (dealer_addr, _dealer_manager) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, &mut rng);

        // Create a cheating dealer message with corrupted shares for party 1
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 processes the corrupted message and gets a complaint
        let dealer_session_id = session_context.dealer_session_id(&dealer_addr);
        let receiver1 = avss::Receiver::new(
            config.nodes.clone(),
            1,
            config.threshold,
            dealer_session_id.to_vec(),
            None,
            encryption_keys[1].clone(),
        );

        let result = receiver1.process_message(&cheating_message);
        let complaint = match result {
            Ok(avss::ProcessedMessage::Complaint(c)) => c,
            Ok(_) => panic!("Expected complaint but got valid shares"),
            Err(e) => panic!("Processing failed with error: {:?}", e),
        };

        // Party 2 processes the SAME cheating message
        // Party 2's shares are valid (not corrupted) so it gets valid output
        let (_party2_addr, mut party2_manager) =
            create_manager_at_index(2, &config, &session_context, &encryption_keys, &mut rng);

        // Set up party 2 with the cheating message
        party2_manager
            .receive_dealer_message(&cheating_message, dealer_addr.clone())
            .unwrap();

        let request = ComplainRequest {
            dealer: dealer_addr.clone(),
            complaint: complaint.clone(),
        };

        // First call - should compute and cache
        let response1 = party2_manager
            .handle_complain_request(&request, &mut rng)
            .unwrap();

        // Verify cache contains the response
        assert_eq!(party2_manager.complaint_responses.len(), 1);
        assert!(
            party2_manager
                .complaint_responses
                .contains_key(&dealer_addr)
        );

        // Second call - should return cached response
        let response2 = party2_manager
            .handle_complain_request(&request, &mut rng)
            .unwrap();

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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _dealer_manager) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, &mut rng);
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr.clone());
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_addr));

        // Create exactly threshold (2) parties that can respond
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let (addr, mut mgr) = create_manager_at_index(
                party_id,
                &config,
                &session_context,
                &encryption_keys,
                &mut rng,
            );
            mgr.receive_dealer_message(&cheating_message, dealer_addr.clone())
                .unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers
            .iter()
            .map(|(addr, _)| addr.clone())
            .collect();

        let managers_map: std::collections::HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        // Recover with exactly threshold signers
        // Tests incremental recovery: receiver.recover() returns InputTooShort after first response,
        // continues to collect second response, then succeeds
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.iter(), &mock_p2p)
            .await;

        assert!(
            result.is_ok(),
            "Recovery should succeed: {:?}",
            result.err()
        );
        assert!(party_manager.dealer_outputs.contains_key(&dealer_addr));
        assert!(
            !party_manager.complaints.contains_key(&dealer_addr),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_complaint_for_dealer() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create manager without any complaints
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create a dealer address that has no complaint
        let dealer_addr = ValidatorAddress([0; 32]);

        // Create a minimal certificate
        let cert = DkgCertificate {
            dealer: dealer_addr.clone(),
            message_hash: [0u8; 32],
            signatures: vec![],
            session_context: session_context.clone(),
        };

        // Create empty mock P2P channel
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr);

        // Call recover_shares_via_complaint - should fail because no complaint exists
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                cert.signatures.iter().map(|s| &s.validator),
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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with a message
        let (dealer_addr, dealer_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let dealer_message = dealer_mgr
            .dealer_messages
            .get(&dealer_addr)
            .unwrap()
            .clone();

        // Create party manager with a complaint
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create and setup complaint for dealer
        let complaint = create_complaint_for_dealer(
            &dealer_message,
            1, // party_id
            &config,
            &session_context,
            &dealer_addr,
            &mut rng,
        );
        setup_party_with_complaint(&mut party_manager, &dealer_addr, &dealer_message, complaint);

        // Create certificate with a signer that doesn't exist in mock P2P
        let signer_addresses = vec![ValidatorAddress([99; 32])]; // This validator doesn't exist
        let cert = create_certificate_with_signers(
            &dealer_addr,
            &dealer_message,
            &session_context,
            signer_addresses,
        );

        // Create empty mock P2P channel (no responders)
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr);

        // Call recover_shares_via_complaint - should fail because P2P call fails
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                cert.signatures.iter().map(|s| &s.validator),
                &mock_p2p,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::BroadcastError(_)),
            "Expected BroadcastError, got: {:?}",
            err
        );
        assert!(err.to_string().contains("Party"));
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_insufficient_signers() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _dealer_manager) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, &mut rng);
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr.clone());
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_addr));

        // Create only 1 other party that can respond (threshold is 2, so insufficient)
        let mut other_managers = vec![];
        for party_id in 2..3 {
            let (addr, mut mgr) = create_manager_at_index(
                party_id,
                &config,
                &session_context,
                &encryption_keys,
                &mut rng,
            );
            mgr.receive_dealer_message(&cheating_message, dealer_addr.clone())
                .unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers
            .iter()
            .map(|(addr, _)| addr.clone())
            .collect();

        let managers_map: std::collections::HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr.clone());

        // Attempt recovery with insufficient signers
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.iter(), &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );
        assert!(
            err.to_string()
                .contains("Not enough valid complaint responses"),
            "Error message should indicate insufficient responses, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_dealer_message() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, &mut rng);
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr.clone());
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_addr));

        // Remove the dealer message to simulate the edge case
        party_manager.dealer_messages.remove(&dealer_addr);

        // Create mock P2P (empty is fine since we should fail before contacting anyone)
        let mock_p2p = MockP2PChannel::new(std::collections::HashMap::new(), party_addr);

        // Try to recover - should fail because dealer message is missing
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                [ValidatorAddress([2; 32])].iter(),
                &mock_p2p,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::ProtocolFailed(_)),
            "Expected ProtocolFailed, got: {:?}",
            err
        );
        assert!(
            err.to_string().contains("No dealer message found"),
            "Error should mention missing dealer message, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_crypto_error() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, &mut rng);
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr.clone());
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_addr));

        // Create other parties that can create valid responses
        let mut other_managers = vec![];
        for party_id in 2..4 {
            let (addr, mut mgr) = create_manager_at_index(
                party_id,
                &config,
                &session_context,
                &encryption_keys,
                &mut rng,
            );
            mgr.receive_dealer_message(&cheating_message, dealer_addr.clone())
                .unwrap();
            other_managers.push((addr, mgr));
        }

        let signer_addresses: Vec<_> = other_managers
            .iter()
            .map(|(addr, _)| addr.clone())
            .collect();

        let managers_map: std::collections::HashMap<_, _> = other_managers.into_iter().collect();
        let mock_p2p = MockP2PChannel::new(managers_map, party_addr);

        // Replace party_manager's stored message with a different one to cause crypto mismatch
        // The responses will be for the original message, but recovery will try to use them with this new message
        let different_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            2, // Different corruption
            &mut rng,
        );
        party_manager
            .dealer_messages
            .insert(dealer_addr.clone(), different_message);

        // Attempt recovery - should fail with CryptoError because message doesn't match responses
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.iter(), &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DkgError::CryptoError(_)),
            "Expected CryptoError, got: {:?}",
            err
        );
    }

    #[test]
    fn test_receive_dealer_message_stores_message_even_on_complaint() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer message
        let (dealer_addr, dealer_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let dealer_message = dealer_mgr
            .dealer_messages
            .get(&dealer_addr)
            .unwrap()
            .clone();

        // Create party that will create a complaint (using wrong encryption key)
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let mut party_manager = DkgManager::new(
            ValidatorAddress([1; 32]),
            config.clone(),
            session_context.clone(),
            wrong_key, // Wrong key causes complaint
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
            Box::new(MockPublicMessagesStore),
        );

        // Process dealer message - should create complaint and return error
        let result = party_manager.receive_dealer_message(&dealer_message, dealer_addr.clone());

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid message from dealer")
        );

        assert!(
            party_manager.dealer_messages.contains_key(&dealer_addr),
            "Dealer message should be stored even when complaint is created"
        );
        assert!(
            party_manager.complaints.contains_key(&dealer_addr),
            "Complaint should be stored"
        );
        assert!(
            !party_manager.dealer_outputs.contains_key(&dealer_addr),
            "Dealer output should NOT be stored when complaint is created"
        );
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_success() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer (party 0) with its message
        let (dealer_address, dealer_manager) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);

        // Create party (party 1) that will request the message
        let (party_address, mut party_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create a certificate for the dealer's message
        let message_hash = compute_message_hash(
            &session_context,
            &dealer_address,
            dealer_manager.dealer_messages.get(&dealer_address).unwrap(),
        )
        .unwrap();
        let cert = DkgCertificate {
            dealer: dealer_address.clone(),
            message_hash,
            signatures: vec![ValidatorSignature {
                validator: dealer_address.clone(),
                signature: vec![0u8; 64],
            }],
            session_context: session_context.clone(),
        };

        // Create mock P2P channel with the dealer (who also signed the cert)
        let mut dealers = std::collections::HashMap::new();
        dealers.insert(dealer_address.clone(), dealer_manager);
        let mock_p2p = MockP2PChannel::new(dealers, party_address.clone());

        // Party requests dealer's share from certificate signers
        let result = party_manager
            .retrieve_dealer_message(dealer_address.clone(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        assert!(party_manager.dealer_messages.contains_key(&dealer_address));
        assert!(party_manager.dealer_outputs.contains_key(&dealer_address));
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_propagates_processing_error() {
        // Tests that errors from receive_dealer_message() are properly propagated
        let mut rng = rand::thread_rng();

        // Create two separate configs with different encryption keys
        // Dealer will create message for config1, party will try to process with config2
        let (config_1, session_context, encryption_keys_1) =
            create_test_config_and_encrption_keys(&mut rng);
        let (config_2, _, encryption_keys_2) = create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with config_1
        let (dealer_address, dealer_manager) = create_dealer_with_message(
            0,
            &config_1,
            &session_context,
            &encryption_keys_1,
            &mut rng,
        );

        // Create party with config_2 (incompatible encryption key)
        let (party_address, mut party_manager) =
            create_manager_at_index(1, &config_2, &session_context, &encryption_keys_2, &mut rng);

        // Create a certificate for the dealer's message
        let message_hash = compute_message_hash(
            &session_context,
            &dealer_address,
            dealer_manager.dealer_messages.get(&dealer_address).unwrap(),
        )
        .unwrap();
        let cert = DkgCertificate {
            dealer: dealer_address.clone(),
            message_hash,
            signatures: vec![ValidatorSignature {
                validator: dealer_address.clone(),
                signature: vec![0u8; 64],
            }],
            session_context: session_context.clone(),
        };

        // Create mock P2P channel
        let mut dealers = std::collections::HashMap::new();
        dealers.insert(dealer_address.clone(), dealer_manager);
        let mock_p2p = MockP2PChannel::new(dealers, party_address.clone());

        // Party requests dealer's share - should fail during message processing (incompatible keys)
        let result = party_manager
            .retrieve_dealer_message(dealer_address.clone(), &cert, &mock_p2p)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::ProtocolFailed(_)));
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_retries_multiple_signers() {
        // Tests that retrieve_dealer_message retries with next signer if first fails
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message
        let (dealer_addr, dealer_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);

        // Create party that will request
        let (party_addr, mut party_mgr) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create certificate with two signers: offline signer first, then dealer
        let offline_signer_addr = ValidatorAddress([99; 32]); // Not in mock P2P
        let cert = create_certificate_with_signers(
            &dealer_addr,
            dealer_mgr.dealer_messages.get(&dealer_addr).unwrap(),
            &session_context,
            vec![offline_signer_addr, dealer_addr.clone()], // Try offline first, then dealer
        );

        // MockP2PChannel: only include dealer (offline signer not included)
        let mut managers = std::collections::HashMap::new();
        managers.insert(dealer_addr.clone(), dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr.clone());

        // Should succeed by trying second signer after first fails
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr.clone(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        assert!(party_mgr.dealer_messages.contains_key(&dealer_addr));
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_aborts_when_self_in_signers() {
        // Tests that retrieve_dealer_message aborts with error when requesting party is in signer list
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message
        let (dealer_addr, dealer_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);

        // Create party that will request (party 1)
        let (party_addr, mut party_mgr) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create certificate with signers including the requesting party
        // This is an invalid state - party shouldn't be retrieving a message it signed for
        let cert = create_certificate_with_signers(
            &dealer_addr,
            dealer_mgr.dealer_messages.get(&dealer_addr).unwrap(),
            &session_context,
            vec![party_addr.clone(), dealer_addr.clone()], // Party in signer list
        );

        // MockP2PChannel: include dealer
        let mut managers = std::collections::HashMap::new();
        managers.insert(dealer_addr.clone(), dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr.clone());

        // Should abort with ProtocolFailed error due to invariant violation
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr.clone(), &cert, &mock_p2p)
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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message
        let (dealer_addr, dealer_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);

        // Create party that will request
        let (party_addr, mut party_mgr) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, &mut rng);

        // Create certificate with multiple offline signers
        let cert = create_certificate_with_signers(
            &dealer_addr,
            dealer_mgr.dealer_messages.get(&dealer_addr).unwrap(),
            &session_context,
            vec![ValidatorAddress([98; 32]), ValidatorAddress([99; 32])], // All offline
        );

        // MockP2PChannel: empty (no signers available)
        let managers = std::collections::HashMap::new();
        let mock_p2p = MockP2PChannel::new(managers, party_addr.clone());

        // Should fail because all signers are offline
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr.clone(), &cert, &mock_p2p)
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
        let (config, session_context, encryption_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer A with message MA
        let (dealer_a_addr, dealer_a_mgr) =
            create_dealer_with_message(0, &config, &session_context, &encryption_keys, &mut rng);
        let message_a = dealer_a_mgr
            .dealer_messages
            .get(&dealer_a_addr)
            .unwrap()
            .clone();

        // Create dealer B with different message MB
        let (dealer_b_addr, dealer_b_mgr) =
            create_dealer_with_message(1, &config, &session_context, &encryption_keys, &mut rng);
        let message_b = dealer_b_mgr
            .dealer_messages
            .get(&dealer_b_addr)
            .unwrap()
            .clone();

        // Create party that will request
        let (party_addr, mut party_mgr) =
            create_manager_at_index(2, &config, &session_context, &encryption_keys, &mut rng);

        // Create Byzantine signer that has WRONG message stored for dealer A
        // (It has dealer B's message stored under dealer A's key.)
        let byzantine_signer_addr = ValidatorAddress([3; 32]);
        let mut byzantine_signer =
            create_manager_at_index(3, &config, &session_context, &encryption_keys, &mut rng).1;
        // Byzantine: store dealer B's message under dealer A's address
        byzantine_signer
            .dealer_messages
            .insert(dealer_a_addr.clone(), message_b.clone());

        // Create valid certificate for dealer A with correct hash
        let cert = create_certificate_with_signers(
            &dealer_a_addr,
            &message_a,
            &session_context,
            vec![byzantine_signer_addr.clone(), dealer_a_addr.clone()],
        );

        // MockP2PChannel: has Byzantine signer and real dealer A
        let mut managers = std::collections::HashMap::new();
        managers.insert(byzantine_signer_addr, byzantine_signer);
        managers.insert(dealer_a_addr.clone(), dealer_a_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr.clone());

        // Party requests dealer A's message
        // 1. Tries Byzantine signer first -> returns message B
        // 2. Computes hash(message B) != hash(message A) -> rejects, continues
        // 3. Tries real dealer A -> returns message A -> hash matches -> success
        let result = party_mgr
            .retrieve_dealer_message(dealer_a_addr.clone(), &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        // Should have dealer A's correct message (from second signer)
        assert!(party_mgr.dealer_messages.contains_key(&dealer_a_addr));
    }

    fn create_test_config_and_encrption_keys(
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (
        DkgConfig,
        SessionContext,
        Vec<PrivateKey<EncryptionGroupElement>>,
    ) {
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let party_id = i as u16;
                let weight = 1;
                let node = Node {
                    id: party_id,
                    pk: public_key,
                    weight,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        (config, session_context, encryption_keys)
    }

    fn create_manager_at_index(
        index: u8,
        config: &DkgConfig,
        session_context: &SessionContext,
        encryption_keys: &[PrivateKey<EncryptionGroupElement>],
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (ValidatorAddress, DkgManager) {
        let address = ValidatorAddress([index; 32]);
        let manager = DkgManager::new(
            address.clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[index as usize].clone(),
            crate::bls::Bls12381PrivateKey::generate(rng),
            Box::new(MockPublicMessagesStore),
        );
        (address, manager)
    }

    fn create_dealer_with_message(
        index: u8,
        config: &DkgConfig,
        session_context: &SessionContext,
        encryption_keys: &[PrivateKey<EncryptionGroupElement>],
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (ValidatorAddress, DkgManager) {
        let (address, mut manager) =
            create_manager_at_index(index, config, session_context, encryption_keys, rng);
        let dealer_message = manager.create_dealer_message(rng).unwrap();
        manager
            .receive_dealer_message(&dealer_message, address.clone())
            .unwrap();
        (address, manager)
    }

    fn create_certificate_with_signers(
        dealer_address: &ValidatorAddress,
        message: &avss::Message,
        session_context: &SessionContext,
        signer_addresses: Vec<ValidatorAddress>,
    ) -> DkgCertificate {
        let message_hash = compute_message_hash(session_context, dealer_address, message).unwrap();
        DkgCertificate {
            dealer: dealer_address.clone(),
            message_hash,
            signatures: signer_addresses
                .iter()
                .map(|addr| ValidatorSignature {
                    validator: addr.clone(),
                    signature: vec![0u8; 64],
                })
                .collect(),
            session_context: session_context.clone(),
        }
    }

    fn create_complaint_for_dealer(
        dealer_message: &avss::Message,
        party_id: u16,
        config: &DkgConfig,
        session_context: &SessionContext,
        dealer_address: &ValidatorAddress,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> complaint::Complaint {
        let dealer_session_id = session_context.dealer_session_id(dealer_address);
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
        dealer_address: &ValidatorAddress,
        config: &DkgConfig,
        session_context: &SessionContext,
        corrupt_party_id: u16,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> avss::Message {
        use fastcrypto::groups::secp256k1::ProjectivePoint;
        type S = <ProjectivePoint as fastcrypto::groups::GroupElement>::ScalarType;

        let dealer_session_id = session_context.dealer_session_id(dealer_address);

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
            RandomOracle::new(&Hex::encode(dealer_session_id.digest)).extend("encryption");
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

    fn create_dealer_message_and_complaint(
        config: &DkgConfig,
        session_context: &SessionContext,
        encryption_keys: &[PrivateKey<EncryptionGroupElement>],
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (ValidatorAddress, avss::Message, complaint::Complaint) {
        let (dealer_address, dealer_manager) =
            create_manager_at_index(0, config, session_context, encryption_keys, rng);
        let dealer_message = dealer_manager.create_dealer_message(rng).unwrap();
        // Create complaint from party 1 using wrong encryption key
        let complaint = create_complaint_for_dealer(
            &dealer_message,
            1,
            config,
            session_context,
            &dealer_address,
            rng,
        );
        (dealer_address, dealer_message, complaint)
    }

    fn setup_party_with_complaint(
        party_manager: &mut DkgManager,
        dealer_address: &ValidatorAddress,
        dealer_message: &avss::Message,
        complaint: complaint::Complaint,
    ) {
        party_manager
            .complaints
            .insert(dealer_address.clone(), complaint);
        party_manager
            .dealer_messages
            .insert(dealer_address.clone(), dealer_message.clone());
    }

    fn create_handle_send_share_test_setup(
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (ValidatorAddress, DkgManager, ValidatorAddress, DkgManager) {
        let (config, session_context, encryption_keys) = create_test_config_and_encrption_keys(rng);
        let (dealer_address, dealer_manager) =
            create_manager_at_index(1, &config, &session_context, &encryption_keys, rng);
        let (receiver_address, receiver_manager) =
            create_manager_at_index(0, &config, &session_context, &encryption_keys, rng);
        (
            dealer_address,
            dealer_manager,
            receiver_address,
            receiver_manager,
        )
    }

    #[tokio::test]
    async fn test_handle_send_share_request_idempotent() {
        // Test that same request returns cached response (idempotent)
        let mut rng = rand::thread_rng();
        let (dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_share_test_setup(&mut rng);

        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let request = SendShareRequest {
            message: dealer_message.clone(),
        };

        // First request
        let response1 = receiver_manager
            .handle_send_share_request(dealer_address.clone(), &request)
            .unwrap();

        // Second request with same message - should return cached response
        let response2 = receiver_manager
            .handle_send_share_request(dealer_address.clone(), &request)
            .unwrap();

        // Responses should be identical (same signature bytes)
        assert_eq!(response1.signature, response2.signature);
    }

    #[tokio::test]
    async fn test_handle_send_share_request_equivocation() {
        // Test that different message from same dealer triggers error
        let mut rng = rand::thread_rng();
        let (dealer_address, dealer_manager, _receiver_address, mut receiver_manager) =
            create_handle_send_share_test_setup(&mut rng);

        // First message from dealer
        let dealer_message1 = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let request1 = SendShareRequest {
            message: dealer_message1.clone(),
        };

        // Process first request successfully
        let response1 = receiver_manager
            .handle_send_share_request(dealer_address.clone(), &request1)
            .unwrap();
        assert_eq!(response1.signature.len(), 96);

        // Second DIFFERENT message from same dealer (equivocation)
        let dealer_message2 = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let request2 = SendShareRequest {
            message: dealer_message2.clone(),
        };

        // Should return error
        let result = receiver_manager.handle_send_share_request(dealer_address.clone(), &request2);
        assert!(result.is_err());

        match result.unwrap_err() {
            DkgError::InvalidMessage { sender, reason } => {
                assert_eq!(sender, dealer_address);
                assert!(reason.contains("different messages"));
            }
            _ => panic!("Expected InvalidMessage error"),
        }
    }

    mod validation_test_utils {
        use super::*;
        use fastcrypto_tbls::nodes::Node;

        pub fn create_test_validators_with_weights(
            weights: &[u16],
        ) -> Vec<(ValidatorAddress, Node<EncryptionGroupElement>)> {
            weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| {
                    let private_key =
                        PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
                    let public_key = PublicKey::from_private_key(&private_key);
                    let address = ValidatorAddress([i as u8; 32]);
                    let party_id = i as u16;
                    let node = Node {
                        id: party_id,
                        pk: public_key,
                        weight,
                    };
                    (address, node)
                })
                .collect()
        }

        pub fn create_test_config_with_weights(
            weights: &[u16],
            threshold: u16,
            max_faulty: u16,
        ) -> DkgConfig {
            let validators = create_test_validators_with_weights(weights);
            let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
            DkgConfig::new(100, nodes, address_to_party_id, threshold, max_faulty).unwrap()
        }

        pub fn create_validator_weights(
            config: &DkgConfig,
        ) -> std::collections::HashMap<ValidatorAddress, u16> {
            config
                .address_to_party_id
                .iter()
                .map(|(addr, party_id)| {
                    let weight = config.nodes.weight_of(*party_id).unwrap();
                    (addr.clone(), weight)
                })
                .collect()
        }

        pub fn test_has_sufficient_weighted_signatures(
            signatures: &[ValidatorSignature],
            config: &DkgConfig,
        ) -> bool {
            let validator_weights = create_validator_weights(config);
            let required_weight = config.threshold + config.max_faulty;
            has_sufficient_weighted_signatures(signatures, &validator_weights, required_weight)
        }

        pub fn create_test_signatures(
            validator_indices: &[usize],
            _config: &DkgConfig,
        ) -> Vec<ValidatorSignature> {
            validator_indices
                .iter()
                .map(|&i| {
                    let address = ValidatorAddress([i as u8; 32]);
                    ValidatorSignature {
                        validator: address,
                        signature: vec![0u8; 96], // Dummy BLS signature
                    }
                })
                .collect()
        }
    }

    mod test_validate_signature_set {
        use super::validation_test_utils::*;
        use super::*;

        #[test]
        fn test_valid_signatures_sufficient_weight() {
            let weights = vec![3, 2, 4, 1, 2]; // total = 12
            let config = create_test_config_with_weights(&weights, 3, 1);
            let validator_weights = create_validator_weights(&config);

            // Signatures from validators 0, 2 (weights 3 + 4 = 7)
            let signatures = create_test_signatures(&[0, 2], &config);

            let result = validate_signatures(
                &signatures,
                7, // require exactly 7
                &validator_weights,
            );
            assert!(result.is_ok());
        }

        #[test]
        fn test_duplicate_signer() {
            let weights = vec![3, 2, 4];
            let config = create_test_config_with_weights(&weights, 2, 1);
            let validator_weights = create_validator_weights(&config);

            // Duplicate validator 0
            let signatures = vec![
                ValidatorSignature {
                    validator: ValidatorAddress([0; 32]),
                    signature: vec![0u8; 96],
                },
                ValidatorSignature {
                    validator: ValidatorAddress([0; 32]),
                    signature: vec![0u8; 96],
                },
            ];

            let result = validate_signatures(&signatures, 5, &validator_weights);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Duplicate signer"));
        }

        #[test]
        fn test_unknown_signer() {
            let weights = vec![3, 2, 4];
            let config = create_test_config_with_weights(&weights, 2, 1);
            let validator_weights = create_validator_weights(&config);

            // Validator 99 doesn't exist
            let signatures = vec![ValidatorSignature {
                validator: ValidatorAddress([99; 32]),
                signature: vec![0u8; 96],
            }];

            let result = validate_signatures(&signatures, 1, &validator_weights);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Unknown signer"));
        }

        #[test]
        fn test_insufficient_weight() {
            let weights = vec![3, 2, 4];
            let config = create_test_config_with_weights(&weights, 2, 1);
            let validator_weights = create_validator_weights(&config);

            // Signatures from validators 0, 1 (weights 3 + 2 = 5)
            let signatures = create_test_signatures(&[0, 1], &config);

            let result = validate_signatures(
                &signatures,
                6, // require 6, but only have 5
                &validator_weights,
            );
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("Insufficient"));
            assert!(err_msg.contains("got 5, need 6"));
        }
    }

    mod test_validate_message_hash {
        use super::validation_test_utils::*;
        use super::*;

        #[test]
        fn test_valid_message_hash() {
            let config = create_test_config_with_weights(&[1, 1, 1, 1, 1], 2, 1); // Need 5 validators for t=2, f=1
            let session_context =
                SessionContext::new(100, ProtocolType::DkgKeyGeneration, "test".to_string());

            // Create a dealer message
            let mut rng = rand::thread_rng();
            let manager = create_test_manager(0, config);
            let dealer_message = manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Compute correct hash
            let message_hash =
                compute_message_hash(&session_context, &dealer_addr, &dealer_message).unwrap();

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash,
                signatures: vec![],
                session_context: session_context.clone(),
            };

            let mut dealer_messages = std::collections::HashMap::new();
            dealer_messages.insert(dealer_addr, dealer_message);

            let result = validate_message_hash(&cert, &dealer_messages, &session_context);
            assert!(result.is_ok());
        }

        #[test]
        fn test_dealer_message_not_received() {
            let _config = create_test_config_with_weights(&[1, 1, 1, 1, 1], 2, 1); // Need 5 validators for t=2, f=1
            let session_context =
                SessionContext::new(100, ProtocolType::DkgKeyGeneration, "test".to_string());
            let dealer_addr = ValidatorAddress([0; 32]);

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash: [0; 32],
                signatures: vec![],
                session_context: session_context.clone(),
            };

            let dealer_messages = std::collections::HashMap::new(); // Empty - message not received

            let result = validate_message_hash(&cert, &dealer_messages, &session_context);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Dealer message not yet received")
            );
        }

        #[test]
        fn test_message_hash_mismatch() {
            let config = create_test_config_with_weights(&[1, 1, 1, 1, 1], 2, 1); // Need 5 validators for t=2, f=1
            let session_context =
                SessionContext::new(100, ProtocolType::DkgKeyGeneration, "test".to_string());

            let mut rng = rand::thread_rng();
            let manager = create_test_manager(0, config);
            let dealer_message = manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Create cert with wrong hash
            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash: [99; 32], // Wrong hash
                signatures: vec![],
                session_context: session_context.clone(),
            };

            let mut dealer_messages = std::collections::HashMap::new();
            dealer_messages.insert(dealer_addr, dealer_message);

            let result = validate_message_hash(&cert, &dealer_messages, &session_context);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Message hash mismatch")
            );
        }
    }

    mod test_validate_certificate {
        use super::validation_test_utils::*;
        use super::*;

        fn create_valid_cert_and_data() -> (
            DkgCertificate,
            DkgManager,
            std::collections::HashMap<ValidatorAddress, avss::Message>,
        ) {
            let weights = vec![2, 2, 2, 2, 2]; // 5 validators
            let config = create_test_config_with_weights(&weights, 3, 1);

            let mut rng = rand::thread_rng();
            let temp_manager = create_test_manager(0, config.clone());
            let dealer_message = temp_manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Create the final manager that we'll return
            let manager = create_test_manager(0, config.clone());
            let session_context = &manager.session_context;

            let message_hash =
                compute_message_hash(session_context, &dealer_addr, &dealer_message).unwrap();

            // Create sufficient signatures (4 validators with weight 2 each = 8)
            // DKG requires t+f = 4
            let dkg_sigs = create_test_signatures(&[0, 1, 2, 3], &config); // weight = 8 >= 4

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash,
                signatures: dkg_sigs,
                session_context: session_context.clone(),
            };

            let mut dealer_messages = std::collections::HashMap::new();
            dealer_messages.insert(dealer_addr, dealer_message);

            (cert, manager, dealer_messages)
        }

        #[test]
        fn test_valid_certificate() {
            let (cert, manager, dealer_messages) = create_valid_cert_and_data();
            let validator_weights =
                validation_test_utils::create_validator_weights(&manager.dkg_config);
            let result = validate_certificate(
                &cert,
                &manager.dkg_config,
                &manager.session_context,
                &validator_weights,
                &dealer_messages,
            );
            assert!(result.is_ok());
        }

        #[test]
        fn test_session_id_mismatch() {
            // This test verifies that a certificate created with a different session context
            // (and thus different message hash) is properly rejected
            let config = create_test_config_with_weights(&[1, 1, 1, 1, 1], 2, 1);
            let dealer_addr = ValidatorAddress([0; 32]);

            // Create a minimal dealer message using actual dealer (to get valid message structure)
            let manager = create_test_manager(0, config.clone());
            let mut rng = rand::thread_rng();
            let dealer = avss::Dealer::new(
                None,
                manager.dkg_config.nodes.clone(),
                manager.dkg_config.threshold,
                manager.dkg_config.max_faulty,
                vec![1, 2, 3], // Dummy session ID
            )
            .unwrap();
            let dealer_message = dealer.create_message(&mut rng).unwrap();

            // Create certificate with hash computed using WRONG session context
            let wrong_session_context =
                SessionContext::new(200, ProtocolType::DkgKeyGeneration, "test".to_string());
            let wrong_hash =
                compute_message_hash(&wrong_session_context, &dealer_addr, &dealer_message)
                    .unwrap();

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash: wrong_hash, // Hash computed with wrong session
                signatures: vec![],
                session_context: wrong_session_context, // Doesn't matter what we put here
            };

            // Create manager with CORRECT session for validation
            let correct_manager = create_test_manager(0, config);

            let mut dealer_messages = std::collections::HashMap::new();
            dealer_messages.insert(dealer_addr, dealer_message);

            // Validation should fail because the hash was computed with a different session
            let validator_weights =
                validation_test_utils::create_validator_weights(&correct_manager.dkg_config);
            let result = validate_certificate(
                &cert,
                &correct_manager.dkg_config,
                &correct_manager.session_context,
                &validator_weights,
                &dealer_messages,
            );
            assert!(
                result.is_err(),
                "Expected validation to fail but it succeeded"
            );
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains("Message hash mismatch"),
                "Expected 'Message hash mismatch' but got: {}",
                error_msg
            );
        }

        #[test]
        fn test_invalid_dkg_signatures() {
            let (mut cert, manager, dealer_messages) = create_valid_cert_and_data();

            // Empty DKG signatures - insufficient weight
            cert.signatures = vec![];

            let validator_weights = create_validator_weights(&manager.dkg_config);
            let result = validate_certificate(
                &cert,
                &manager.dkg_config,
                &manager.session_context,
                &validator_weights,
                &dealer_messages,
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Insufficient signature weight")
            );
        }

        #[test]
        fn test_invalid_message_hash() {
            let (mut cert, manager, dealer_messages) = create_valid_cert_and_data();

            // Wrong message hash
            cert.message_hash = [99; 32];

            let validator_weights = create_validator_weights(&manager.dkg_config);
            let result = validate_certificate(
                &cert,
                &manager.dkg_config,
                &manager.session_context,
                &validator_weights,
                &dealer_messages,
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Message hash mismatch")
            );
        }
    }
}
