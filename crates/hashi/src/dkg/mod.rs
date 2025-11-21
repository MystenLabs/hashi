//! Distributed Key Generation (DKG) module

pub mod types;

use crate::bls::{BlsCommittee, BlsCommitteeMember, BlsSignatureAggregator, Certificate};
use crate::dkg::types::DkgMessage;
use crate::storage::PublicMessagesStore;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::threshold_schnorr::{avss, complaint};
use std::collections::HashMap;
use sui_sdk_types::Address;
pub use types::{
    AddressToPartyId, Authenticated, ComplainRequest, ComplainResponse, DkgConfig, DkgError,
    DkgOutput, DkgResult, EncryptionGroupElement, MessageApproval, MessageHash, MessageType,
    OrderedBroadcastMessage, RetrieveMessageRequest, RetrieveMessageResponse, SendShareRequest,
    SendShareResponse, SessionContext, SessionId, SighashType, SignatureBytes, ValidatorSignature,
};

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";

// DKG protocol
// 1) A dealer sends out a message to all parties containing the encrypted shares and the public keys of the nonces.
// 2) Each party verifies the message and returns a signature. Once sufficient valid signatures are received from the parties, the dealer sends a certificate to Sui (TOB).
// 3) Once sufficient valid certificates are received, a party completes the protocol locally by aggregating the shares from the dealers.
pub struct DkgManager {
    // Immutable during a given session
    pub party_id: PartyId,
    pub address: Address,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub bls_signing_key: crate::bls::Bls12381PrivateKey,
    pub bls_committee: BlsCommittee,
    // Mutable during a given session
    pub dealer_outputs: HashMap<Address, avss::PartialOutput>,
    pub dealer_messages: HashMap<Address, avss::Message>,
    pub share_responses: HashMap<Address, SendShareResponse>,
    pub complaints: HashMap<Address, complaint::Complaint>,
    pub complaint_responses: HashMap<Address, complaint::ComplaintResponse<avss::SharesForNode>>,
    pub public_messages_store: Box<dyn PublicMessagesStore>,
}

impl DkgManager {
    pub fn new(
        address: Address,
        dkg_config: DkgConfig,
        session_context: SessionContext,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        bls_signing_key: crate::bls::Bls12381PrivateKey,
        bls_public_keys: HashMap<Address, BLS12381PublicKey>,
        public_message_store: Box<dyn PublicMessagesStore>,
    ) -> Self {
        let party_id = *dkg_config
            .address_to_party_id
            .get(&address)
            .expect("address not found in validator registry");
        let bls_committee = create_bls_committee(&dkg_config, &bls_public_keys);
        Self {
            party_id,
            address,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            bls_committee,
            dealer_outputs: HashMap::new(),
            dealer_messages: HashMap::new(),
            share_responses: HashMap::new(),
            complaints: HashMap::new(),
            complaint_responses: HashMap::new(),
            public_messages_store: public_message_store,
        }
    }

    /// RPC endpoint handler for `SendShareRequest`
    pub fn handle_send_share_request(
        &mut self,
        sender: Address,
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
                    sender,
                    reason: "Dealer sent different messages".to_string(),
                })
            };
        }
        let signature = self.receive_dealer_message(&request.message, sender)?;
        let response = SendShareResponse { signature };
        self.share_responses.insert(sender, response.clone());
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
            .ok_or_else(|| DkgError::ProtocolFailed("Message not available".to_string()))?;
        Ok(RetrieveMessageResponse {
            message: message.clone(),
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
        let dealer_session_id = self.session_context.dealer_session_id(&request.dealer);
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
        let my_signature = self.receive_dealer_message(&dealer_message, self.address)?;
        let message_hash =
            compute_message_hash(&self.session_context, &self.address, &dealer_message)?;
        let mut aggregator = BlsSignatureAggregator::new(
            &self.bls_committee,
            DkgMessage {
                dealer_address: self.address,
                session_context: self.session_context.clone(),
                message_hash,
            },
        );
        aggregator
            .add_signature(my_signature.signature)
            .map_err(|e| DkgError::CryptoError(format!("Failed to add signature: {}", e)))?;

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

                // The signature is verified in the call to `add_signature`
                if let Err(e) = aggregator.add_signature(response.signature.signature) {
                    tracing::info!("Invalid signature from {:?}: {}", validator_address, e)
                }
            }
        }

        let required_weight = self.dkg_config.threshold + self.dkg_config.max_faulty;
        if aggregator.weight() >= required_weight as u64 {
            let cert = aggregator.finish().map_err(|e| {
                DkgError::CryptoError(format!("Failed to aggregate signatures: {}", e))
            })?;
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
        let mut certified_dealers = HashMap::new();
        let mut dealer_weight_sum = 0u32;
        loop {
            if dealer_weight_sum >= self.dkg_config.threshold as u32 {
                break;
            }
            let tob_msg = ordered_broadcast_channel
                .receive()
                .await
                .map_err(|e| DkgError::BroadcastError(e.to_string()))?;
            if let OrderedBroadcastMessage::AvssCertificateV1(cert) = tob_msg {
                let dealer = cert.message.dealer_address;
                if certified_dealers.contains_key(&dealer) {
                    continue;
                }
                if !self.dealer_messages.contains_key(&dealer) {
                    tracing::info!(
                        "Certificate from dealer {:?} received but message missing, retrieving from signers",
                        &dealer
                    );
                    self.retrieve_dealer_message(dealer, &cert, p2p_channel)
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
                match self.validate_certificate(&cert) {
                    Ok(()) => {
                        if self.complaints.contains_key(&cert.message.dealer_address) {
                            self.recover_shares_via_complaint(
                                &cert.message.dealer_address,
                                cert.signers(&self.bls_committee).map_err(|_| {
                                    DkgError::InvalidCertificate(
                                        "Invalid certificate for committee".parse().unwrap(),
                                    )
                                })?,
                                p2p_channel,
                            )
                            .await?;
                        }
                        let dealer_weight =
                            self.bls_committee.weight_of(&dealer).map_err(|_| {
                                DkgError::ProtocolFailed("Missing dealer weight".parse().unwrap())
                            })?;
                        dealer_weight_sum += dealer_weight as u32;
                        certified_dealers.insert(dealer, cert);
                    }
                    Err(e) => {
                        tracing::info!("Invalid certificate from {:?}: {}", &dealer, e);
                        continue;
                    }
                }
            }
        }
        self.process_certificates(&certified_dealers)
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
        dealer_address: Address,
    ) -> DkgResult<ValidatorSignature> {
        self.dealer_messages.insert(dealer_address, message.clone());
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
        let partial_output = match receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => output,
            avss::ProcessedMessage::Complaint(complaint) => {
                self.complaints.insert(dealer_address, complaint);
                return Err(DkgError::ProtocolFailed(
                    "Invalid message from dealer".into(),
                ));
            }
        };
        self.dealer_outputs.insert(dealer_address, partial_output);
        self.dealer_messages.insert(dealer_address, message.clone());
        self.public_messages_store
            .store_dealer_message(&dealer_address, message)
            .map_err(|e| DkgError::StorageError(e.to_string()))?;
        let message_hash = compute_message_hash(&self.session_context, &dealer_address, message)?;
        let signature = self.bls_signing_key.sign(
            self.dkg_config.epoch,
            self.address,
            &DkgMessage {
                dealer_address,
                session_context: self.session_context.clone(),
                message_hash,
            },
        );
        Ok(ValidatorSignature {
            validator: self.address,
            signature,
        })
    }

    fn process_certificates(
        &self,
        certified_dealers: &HashMap<Address, Certificate<DkgMessage>>,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.dkg_config.threshold;
        // TODO: Handle missing messages and invalid shares
        let outputs: HashMap<PartyId, avss::PartialOutput> = certified_dealers
            .keys()
            .map(|dealer| {
                let dealer_party_id =
                    self.dkg_config
                        .address_to_party_id
                        .get(dealer)
                        .ok_or_else(|| {
                            DkgError::ProtocolFailed(format!("Unknown dealer: {:?}", dealer))
                        })?;
                let output = self
                    .dealer_outputs
                    .get(dealer)
                    .ok_or_else(|| {
                        DkgError::ProtocolFailed(format!(
                            "No dealer output found for dealer: {:?}.",
                            dealer
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
        dealer_address: Address,
        certificate: &Certificate<DkgMessage>,
        p2p_channel: &impl crate::communication::P2PChannel,
    ) -> DkgResult<()> {
        let request = RetrieveMessageRequest {
            dealer: dealer_address,
        };
        // TODO: Implement gradual escalation strategy for better network efficiency:
        // - Round 1: Call 1-2 random signers, wait ~2s
        // - Round 2: Call 2-3 more signers, wait ~2s
        // - and so on
        if certificate
            .is_signer(&self.address, &self.bls_committee)
            .map_err(|e| DkgError::CryptoError(e.to_string()))?
        {
            tracing::error!(
                "Self in certificate signers but message not available for dealer {:?}.",
                dealer_address
            );
            return Err(DkgError::ProtocolFailed(
                "Self in certificate signers but message not available".to_string(),
            ));
        }
        let signers = certificate.signers(&self.bls_committee).map_err(|_| {
            DkgError::ProtocolFailed(
                "Certificate does not match the current epoch or committee".to_string(),
            )
        })?;
        for signer_address in signers {
            if signer_address == self.address {
                tracing::error!(
                    "Self in certificate signers but message not available for dealer {:?}.",
                    dealer_address
                );
                return Err(DkgError::ProtocolFailed(
                    "Self in certificate signers but message not available".to_string(),
                ));
            }
            // TODO: Add timeout and retries handling when adding RPC layer
            match p2p_channel
                .retrieve_message(&signer_address, &request)
                .await
            {
                Ok(response) => {
                    let message_hash = compute_message_hash(
                        &self.session_context,
                        &dealer_address,
                        &response.message,
                    )?;
                    if message_hash != certificate.message.message_hash {
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
        dealer: &Address,
        signers: impl IntoIterator<Item = Address>,
        p2p_channel: &impl crate::communication::P2PChannel,
    ) -> DkgResult<()> {
        let complaint = self
            .complaints
            .get(dealer)
            .ok_or_else(|| DkgError::ProtocolFailed("No complaint for dealer".into()))?
            .clone();
        let complaint_request = ComplainRequest {
            dealer: *dealer,
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
            let response = p2p_channel.complain(&signer, &complaint_request).await?;
            responses.push(response.response);
            match receiver.recover(message, responses.clone()) {
                Ok(partial_output) => {
                    self.dealer_outputs.insert(*dealer, partial_output);
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

    fn validate_certificate(&self, cert: &Certificate<DkgMessage>) -> DkgResult<()> {
        let dealer = cert.message.dealer_address;
        let message = self.dealer_messages.get(&dealer).ok_or_else(|| {
            DkgError::InvalidCertificate(format!(
                "Dealer message not yet received from {:?}",
                dealer
            ))
        })?;
        let expected_hash = compute_message_hash(&self.session_context, &dealer, message)?;
        if cert.message.message_hash != expected_hash {
            return Err(DkgError::InvalidCertificate(format!(
                "Message hash mismatch for dealer {:?}",
                dealer
            )));
        }

        self.bls_committee
            .verify_signature(cert)
            .map_err(|e| DkgError::CryptoError(format!("Failed to verify certificate: {}", e)))
    }
}

fn create_bls_committee(
    dkg_config: &DkgConfig,
    public_keys: &HashMap<Address, BLS12381PublicKey>,
) -> BlsCommittee {
    let sorted_by_party_id: std::collections::BTreeMap<u16, Address> = dkg_config
        .address_to_party_id
        .iter()
        .map(|(addr, &party_id)| (party_id, *addr))
        .collect();
    let committee: Vec<BlsCommitteeMember> = sorted_by_party_id
        .into_iter()
        .map(|(party_id, validator_address)| {
            BlsCommitteeMember::new(
                validator_address,
                public_keys.get(&validator_address).unwrap().clone(),
                dkg_config.nodes.weight_of(party_id).unwrap() as u64,
            )
        })
        .collect();
    BlsCommittee::new(committee, dkg_config.epoch)
}

fn compute_message_hash(
    session: &SessionContext,
    dealer_address: &Address,
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
            _dealer: &Address,
            _message: &avss::Message,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_dealer_message(&self, _dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
            Ok(None)
        }

        fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn create_test_validator(party_id: u16) -> (Address, Node<EncryptionGroupElement>) {
        let private_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_private_key(&private_key);
        let address = Address::new([party_id as u8; 32]);
        let weight = 1;
        let node = Node {
            id: party_id,
            pk: public_key,
            weight,
        };
        (address, node)
    }

    fn build_nodes_and_registry(
        validators: Vec<(Address, Node<EncryptionGroupElement>)>,
    ) -> (Nodes<EncryptionGroupElement>, AddressToPartyId) {
        let mut node_vec: Vec<_> = validators.iter().map(|(_, node)| node.clone()).collect();
        node_vec.sort_by_key(|n| n.id);
        let nodes = Nodes::new(node_vec).unwrap();
        let address_to_party_id: AddressToPartyId = validators
            .iter()
            .map(|(addr, node)| (*addr, node.id))
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

    fn create_test_bls_keys(dkg_config: &DkgConfig) -> HashMap<Address, BLS12381PublicKey> {
        dkg_config
            .address_to_party_id
            .keys()
            .map(|addr| {
                let sk = crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng());
                (*addr, sk.public_key())
            })
            .collect()
    }

    fn create_test_certificate(
        config: &DkgConfig,
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
        dealer_message: &avss::Message,
        dealer_address: Address,
        session_context: &SessionContext,
        validator_signatures: Vec<ValidatorSignature>,
    ) -> DkgResult<Certificate<DkgMessage>> {
        // Compute message hash
        let message_hash = compute_message_hash(session_context, &dealer_address, dealer_message)?;

        // Create DkgMessage
        let dkg_message = DkgMessage {
            dealer_address,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create BLS committee
        let bls_committee = create_bls_committee(config, bls_public_keys);

        // Create aggregator
        let mut aggregator = crate::bls::BlsSignatureAggregator::new(&bls_committee, dkg_message);

        // Add all signatures
        for validator_sig in validator_signatures {
            aggregator
                .add_signature(validator_sig.signature)
                .map_err(|e| DkgError::CryptoError(e.to_string()))?;
        }

        // Finish and return certificate
        aggregator
            .finish()
            .map_err(|e| DkgError::CryptoError(e.to_string()))
    }

    fn create_test_manager(validator_index: u16, dkg_config: DkgConfig) -> DkgManager {
        let address = Address::new([validator_index as u8; 32]);
        let session_context = SessionContext::new(
            dkg_config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );
        let encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let bls_signing_key = crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let bls_public_keys = create_test_bls_keys(&dkg_config);
        DkgManager::new(
            address,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            bls_public_keys,
            Box::new(MockPublicMessagesStore),
        )
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
    impl crate::communication::P2PChannel for MockP2PChannel {
        async fn send_share(
            &self,
            recipient: &Address,
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
                .handle_send_share_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            party: &Address,
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
            party: &Address,
            request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(party).ok_or_else(|| {
                crate::communication::ChannelError::SendFailed(format!(
                    "Party {:?} not found",
                    party
                ))
            })?;
            let response = manager.handle_complain_request(request).map_err(|e| {
                crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
            })?;
            Ok(response)
        }
    }

    struct MockOrderedBroadcastChannel {
        certificates: std::sync::Mutex<std::collections::VecDeque<Certificate<DkgMessage>>>,
        published: std::sync::Mutex<Vec<OrderedBroadcastMessage>>,
    }

    impl MockOrderedBroadcastChannel {
        fn new(certificates: Vec<Certificate<DkgMessage>>) -> Self {
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

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        let address = Address::new([validator_index as u8; 32]);
        let manager = DkgManager::new(
            address,
            config,
            session_context,
            encryption_keys[validator_index].clone(),
            bls_keys[validator_index].clone(),
            bls_public_keys,
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
            _recipient: &Address,
            _request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            Err(crate::communication::ChannelError::SendFailed(
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
    impl crate::communication::P2PChannel for SucceedingP2PChannel {
        async fn send_share(
            &self,
            recipient: &Address,
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
                .handle_send_share_request(self.current_sender, request)
                .map_err(|e| {
                    crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
                })?;
            Ok(response)
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            unimplemented!("SucceedingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            unimplemented!("SucceedingP2PChannel does not implement complain")
        }
    }

    struct PartiallyFailingP2PChannel {
        managers: std::sync::Arc<std::sync::Mutex<HashMap<Address, DkgManager>>>,
        current_sender: Address,
        fail_count: std::sync::Arc<std::sync::Mutex<usize>>,
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
                fail_count: std::sync::Arc::new(std::sync::Mutex::new(0)),
                max_failures,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for PartiallyFailingP2PChannel {
        async fn send_share(
            &self,
            recipient: &Address,
            request: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            let mut count = self.fail_count.lock().unwrap();
            if *count < self.max_failures {
                *count += 1;
                Err(crate::communication::ChannelError::SendFailed(
                    "network error".to_string(),
                ))
            } else {
                drop(count); // Release the lock before calling manager
                let mut managers = self.managers.lock().unwrap();
                let manager = managers.get_mut(recipient).ok_or_else(|| {
                    crate::communication::ChannelError::SendFailed(format!(
                        "Recipient {:?} not found",
                        recipient
                    ))
                })?;
                let response = manager
                    .handle_send_share_request(self.current_sender, request)
                    .map_err(|e| {
                        crate::communication::ChannelError::SendFailed(format!(
                            "Handler failed: {}",
                            e
                        ))
                    })?;
                Ok(response)
            }
        }

        async fn retrieve_message(
            &self,
            _party: &Address,
            _request: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            _party: &Address,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            unimplemented!("PartiallyFailingP2PChannel does not implement complain")
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
    impl crate::communication::P2PChannel for PreCollectedP2PChannel {
        async fn send_share(
            &self,
            _: &Address,
            _: &SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement send_share")
        }

        async fn retrieve_message(
            &self,
            _: &Address,
            _: &RetrieveMessageRequest,
        ) -> crate::communication::ChannelResult<RetrieveMessageResponse> {
            unimplemented!("PreCollectedP2PChannel does not implement retrieve_message")
        }

        async fn complain(
            &self,
            party: &Address,
            _request: &ComplainRequest,
        ) -> crate::communication::ChannelResult<ComplainResponse> {
            self.responses
                .lock()
                .unwrap()
                .get(party)
                .cloned()
                .ok_or_else(|| crate::communication::ChannelError::SendFailed("No response".into()))
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
    //
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
                let address = Address::new([i as u8; 32]);
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
        let dealer_address = Address::new([0; 32]);
        let bls_public_keys = create_test_bls_keys(&config);
        let dealer_manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );
        let message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let dealer_address = dealer_manager.address;

        // Create receiver (party 1) with its encryption key and storage
        let receiver_address = Address::new([1; 32]);
        let storage = InMemoryPublicMessagesStore::new();
        let mut receiver_manager = DkgManager::new(
            receiver_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            bls_public_keys,
            Box::new(storage),
        );

        // Receiver processes the dealer's message
        let signature = receiver_manager
            .receive_dealer_message(&message, dealer_address)
            .unwrap();

        // Verify signature format
        assert_eq!(signature.validator, receiver_manager.address);

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
                let address = Address::new([i as u8; 32]);
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

        let bls_public_keys = create_test_bls_keys(&config);

        // Create dealer (party 0)
        let dealer_address = Address::new([0; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );
        let message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Create receiver with failing storage
        let receiver_address = Address::new([1; 32]);
        let mut receiver_manager = DkgManager::new(
            receiver_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rand::thread_rng()),
            bls_public_keys,
            Box::new(FailingPublicMessagesStore),
        );

        // Receiver processes the dealer's message - should fail due to storage error
        let result = receiver_manager.receive_dealer_message(&message, dealer_address);

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
    fn test_compute_message_hash_deterministic() {
        let config = create_test_dkg_config(5);
        let manager = create_test_manager(0, config);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();
        let dealer_address = Address::new([42; 32]);

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

        let hash1 =
            compute_message_hash(&manager.session_context, &Address::new([1; 32]), &message)
                .unwrap();

        let hash2 =
            compute_message_hash(&manager.session_context, &Address::new([2; 32]), &message)
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
                let address = Address::new([i as u8; 32]);
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

        // Generate BLS key pairs for all validators (indexed by validator index 0-4)
        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Map each address to its corresponding BLS public key
        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i as usize].public_key())
            })
            .collect();

        // Create threshold (3) dealers - complete_dkg requires exactly t dealer outputs
        // Using validators 0, 1, 4 as dealers (weights 3, 2, 2 respectively)
        let dealer_indices = [0, 1, 4];
        let mut dealer_managers: Vec<_> = dealer_indices
            .iter()
            .map(|&i| {
                let addr = Address::new([i as u8; 32]);
                DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Create receiver (party 2 with weight=4 - will receive 4 shares!)
        let addr2 = Address::new([2; 32]);
        let mut receiver_manager = DkgManager::new(
            addr2,
            config.clone(),
            session_context.clone(),
            encryption_keys[2].clone(),
            bls_keys[2].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Each dealer creates a message
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|dm| dm.create_dealer_message(&mut rng).unwrap())
            .collect();

        // Receiver processes all dealer messages and creates certificates
        let mut certificates = HashMap::new();
        for (i, message) in dealer_messages.iter().enumerate() {
            let dealer_address = dealer_managers[i].address;

            // Receiver processes the message
            let _sig = receiver_manager.receive_dealer_message(message, dealer_address);

            // Create a certificate by collecting signatures from other validators
            // Need threshold + max_faulty = 3 + 1 = 4 weighted signatures
            // Using validators 0 and 1 with weights 3 and 2 respectively (total = 5 > 4)
            let validator_signatures = vec![
                // Validator 0 (weight=3) signs
                dealer_managers[0]
                    .receive_dealer_message(message, dealer_address)
                    .unwrap(),
                // Validator 1 (weight=2) signs
                dealer_managers[1]
                    .receive_dealer_message(message, dealer_address)
                    .unwrap(),
            ];

            // Create certificate using helper
            let cert = create_test_certificate(
                &config,
                &bls_public_keys,
                message,
                dealer_address,
                &session_context,
                validator_signatures,
            )
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
        let mut rng = rand::thread_rng();

        // Create encryption keys that will match the config
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
                let node = Node {
                    id: i as u16,
                    pk: public_key,
                    weight: 1,
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

        // Generate BLS keys
        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create a receiver manager (will not receive dealer messages)
        let receiver_manager = DkgManager::new(
            Address::new([0; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create dealers with matching encryption keys
        let dealer_addr0 = Address::new([1; 32]);
        let dealer_addr1 = Address::new([2; 32]);

        let dealer0 = DkgManager::new(
            dealer_addr0,
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            bls_keys[1].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        let dealer1 = DkgManager::new(
            dealer_addr1,
            config.clone(),
            session_context.clone(),
            encryption_keys[2].clone(),
            bls_keys[2].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        let message0 = dealer0.create_dealer_message(&mut rng).unwrap();
        let message1 = dealer1.create_dealer_message(&mut rng).unwrap();

        // Create a validator to sign the dealer messages
        let validator_addr = Address::new([3; 32]);
        let mut validator = DkgManager::new(
            validator_addr,
            config.clone(),
            session_context.clone(),
            encryption_keys[3].clone(),
            bls_keys[3].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create certificates (using actual BLS signatures from validator)
        let sig0 = validator
            .receive_dealer_message(&message0, dealer_addr0)
            .unwrap();
        let cert0 = create_test_certificate(
            &config,
            &bls_public_keys,
            &message0,
            dealer_addr0,
            &session_context,
            vec![sig0],
        )
        .unwrap();

        let sig1 = validator
            .receive_dealer_message(&message1, dealer_addr1)
            .unwrap();
        let cert1 = create_test_certificate(
            &config,
            &bls_public_keys,
            &message1,
            dealer_addr1,
            &session_context,
            vec![sig1],
        )
        .unwrap();

        let mut certificates = HashMap::new();
        certificates.insert(dealer_addr0, cert0);
        certificates.insert(dealer_addr1, cert1);

        // Process certificates should fail because receiver never processed the dealer messages
        let result = receiver_manager.process_certificates(&certificates);
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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = Address::new([i as u8; 32]);
                DkgManager::new(
                    address,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
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
            let dealer_addr = Address::new([dealer_idx as u8; 32]);

            // Collect signatures from all validators
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr)
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(
                &config,
                &bls_public_keys,
                message,
                dealer_addr,
                &session_context,
                signatures,
            )
            .unwrap();
            certificates.push(cert);
        }

        // Phase 3: Test run_as_dealer() and run_as_party() for validator 0 with mocked channels
        // Remove validator 0 from managers (it will call run_dkg)
        let mut test_manager = managers.remove(0);

        // Create mock P2P channel with remaining managers (validators 1-4)
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (Address::new([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, Address::new([0; 32]));

        // Pre-populate validator 0's manager with dealer outputs from all validators (including itself)
        for (j, message) in dealer_messages.iter().enumerate() {
            test_manager
                .receive_dealer_message(message, Address::new([j as u8; 32]))
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
        let addr0 = Address::new([0; 32]);
        for j in 1..num_validators {
            let addr_j = Address::new([j as u8; 32]);
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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create manager for validator 0
        let addr0 = Address::new([0; 32]);
        let mut test_manager = DkgManager::new(
            addr0,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create managers for other validators
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let manager = DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers, Address::new([0; 32]));
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Call run_as_dealer()
        let result = test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;

        // Verify success
        assert!(result.is_ok());

        // Verify own dealer output is stored
        let addr0 = Address::new([0; 32]);
        assert!(test_manager.dealer_outputs.contains_key(&addr0));

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let addr = Address::new([i as u8; 32]);
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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = Address::new([i as u8; 32]);
                DkgManager::new(
                    address,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
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
            let dealer_addr = Address::new([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr)
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(
                &config,
                &bls_public_keys,
                message,
                dealer_addr,
                &session_context,
                signatures,
            )
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
            .map(|(idx, mgr)| (Address::new([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, Address::new([0; 32]));
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer 0 with normal message
        let (dealer_0_addr, dealer_0_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let dealer_0_message = dealer_0_mgr
            .dealer_messages
            .get(&dealer_0_addr)
            .unwrap()
            .clone();
        let dealer_0_message_hash =
            compute_message_hash(&session_context, &dealer_0_addr, &dealer_0_message).unwrap();
        let dealer_0_dkg_message = DkgMessage {
            dealer_address: dealer_0_addr,
            session_context: session_context.clone(),
            message_hash: dealer_0_message_hash,
        };

        // Create dealer 1 with cheating message (corrupts party 2's shares)
        let (dealer_1_addr, _) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let dealer_1_message = create_cheating_message(
            &dealer_1_addr,
            &config,
            &session_context,
            2, // Corrupt shares for party 2
            &mut rng,
        );
        let dealer_1_message_hash =
            compute_message_hash(&session_context, &dealer_1_addr, &dealer_1_message).unwrap();
        let dealer_1_dkg_message = DkgMessage {
            dealer_address: dealer_1_addr,
            session_context: session_context.clone(),
            message_hash: dealer_1_message_hash,
        };

        // Create party 2 manager (will have complaint for dealer 1)
        let (party_addr, mut party_manager) = create_manager_at_index(
            2,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Party 2 successfully processes dealer 0's message
        party_manager
            .receive_dealer_message(&dealer_0_message, dealer_0_addr)
            .unwrap();

        // Party 2 fails on dealer 1's cheating message and creates complaint
        let result = party_manager.receive_dealer_message(&dealer_1_message, dealer_1_addr);
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_1_addr));

        // Create other parties who can successfully process dealer 1's message
        let mut other_managers = HashMap::new();
        for party_id in [0, 1, 3, 4] {
            let (addr, mut mgr) = create_manager_at_index(
                party_id,
                &config,
                &session_context,
                &encryption_keys,
                &bls_keys,
                &bls_public_keys,
            );
            // They successfully process dealer 1's cheating message
            mgr.receive_dealer_message(&dealer_1_message, dealer_1_addr)
                .unwrap();
            other_managers.insert(addr, mgr);
        }

        // Create certificates with signers (excluding party 2 who has complaint)
        let cert_0 = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_0_addr,
            &dealer_0_message,
            &session_context,
            [
                (0usize, Address::new([0; 32])),
                (1, Address::new([1; 32])),
                (3, Address::new([3; 32])),
            ]
            .iter()
            .map(|(i, a)| ValidatorSignature {
                validator: *a,
                signature: bls_keys[*i].sign(config.epoch, *a, &dealer_0_dkg_message),
            })
            .collect(),
        )
        .unwrap();

        let cert_1 = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_1_addr,
            &dealer_1_message,
            &session_context,
            [
                (0usize, Address::new([0; 32])),
                (1, Address::new([1; 32])),
                (3, Address::new([3; 32])),
            ]
            .iter()
            .map(|(i, a)| ValidatorSignature {
                validator: *a,
                signature: bls_keys[*i].sign(config.epoch, *a, &dealer_1_dkg_message),
            })
            .collect(),
        )
        .unwrap();

        let certificates = vec![cert_0, cert_1];
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates);
        let mock_p2p = MockP2PChannel::new(other_managers, party_addr);

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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = Address::new([i as u8; 32]);
                DkgManager::new(
                    address,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
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
            let dealer_addr = Address::new([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr)
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(
                &config,
                &bls_public_keys,
                message,
                dealer_addr,
                &session_context,
                signatures,
            )
            .unwrap();
            valid_certificates.push(cert);
        }

        // Create invalid certificate with wrong message hash
        let invalid_dealer_msg = managers[3].create_dealer_message(&mut rng).unwrap();
        let dealer_addr_3 = Address::new([3; 32]);

        let mut invalid_signatures = Vec::new();
        for manager in managers.iter_mut() {
            let sig = manager
                .receive_dealer_message(&invalid_dealer_msg, dealer_addr_3)
                .unwrap();
            invalid_signatures.push(sig);
        }

        // Create a valid certificate but with corrupted message hash
        let mut invalid_cert = create_test_certificate(
            &config,
            &bls_public_keys,
            &invalid_dealer_msg,
            dealer_addr_3,
            &session_context,
            invalid_signatures,
        )
        .unwrap();
        // Make it invalid by corrupting the message hash in the DkgMessage
        invalid_cert.message.message_hash = [99; 32]; // Wrong hash

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
        let other_managers: HashMap<_, _> = managers
            .into_iter()
            .enumerate()
            .map(|(idx, mgr)| (Address::new([(idx + 1) as u8; 32]), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, Address::new([0; 32]));
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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = Address::new([i as u8; 32]);
                DkgManager::new(
                    address,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
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
            let dealer_addr = Address::new([dealer_idx as u8; 32]);

            // All validators process dealer messages
            let mut signatures = Vec::new();
            for manager in managers.iter_mut() {
                let sig = manager
                    .receive_dealer_message(message, dealer_addr)
                    .unwrap();
                signatures.push(sig);
            }

            // Create certificate using helper
            let cert = create_test_certificate(
                &config,
                &bls_public_keys,
                message,
                dealer_addr,
                &session_context,
                signatures,
            )
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
                (Address::new([addr_idx as u8; 32]), mgr)
            })
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers, Address::new([2; 32]));
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
                let address = Address::new([i as u8; 32]);
                let node = Node {
                    id: i as u16,
                    pk: public_key,
                    weight: 1,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create test manager (validator 0)
        let mut test_manager = DkgManager::new(
            Address::new([0; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create managers for validators 1-4 to respond with valid signatures
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let manager = DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        let succeeding_p2p = SucceedingP2PChannel::new(other_managers, Address::new([0; 32]));

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
        let num_validators = 7;

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
                let address = Address::new([i as u8; 32]);
                let node = Node {
                    id: i as u16,
                    pk: public_key,
                    weight: 1,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 4, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        let mut test_manager = DkgManager::new(
            Address::new([0; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let manager = DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        let partially_failing_p2p = PartiallyFailingP2PChannel::new(
            other_managers,
            Address::new([0; 32]),
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
        let num_validators = 5;

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
                let address = Address::new([i as u8; 32]);
                let node = Node {
                    id: i as u16,
                    pk: public_key,
                    weight: 1,
                };
                (address, node)
            })
            .collect();

        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        let mut test_manager = DkgManager::new(
            Address::new([0; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let manager = DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                );
                (addr, manager)
            })
            .collect();

        // Fail too many validators - fail 3 out of 4, only 1 succeeds
        let partially_failing_p2p =
            PartiallyFailingP2PChannel::new(other_managers, Address::new([0; 32]), 3);

        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

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
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create manager for validator 0 (the dealer)
        let dealer_addr = Address::new([0; 32]);
        let mut test_manager = DkgManager::new(
            dealer_addr,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create managers for other validators
        let other_managers: HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let manager = DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                );
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
        let cert = match &published[0] {
            OrderedBroadcastMessage::AvssCertificateV1(cert) => cert,
            _ => panic!("Expected AvssCertificateV1"),
        };

        // Create BLS committee to verify signatures
        let bls_committee = create_bls_committee(&config, &bls_public_keys);

        // Get the list of signers from the certificate
        let signers = cert
            .signers(&bls_committee)
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
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "receive timeout".to_string(),
            fail_on_publish: false,
            fail_on_receive: true,
        };

        let mock_p2p = MockP2PChannel::new(HashMap::new(), Address::new([0; 32]));
        let result = test_manager.run_as_party(&mock_p2p, &mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DkgError::BroadcastError(_)));
        assert!(err.to_string().contains("receive timeout"));
    }
    //
    struct WeightBasedTestSetup {
        config: DkgConfig,
        session_context: SessionContext,
        dealer_messages: Vec<(Address, avss::Message)>,
        certificates: Vec<Certificate<DkgMessage>>,
        encryption_keys: Vec<PrivateKey<EncryptionGroupElement>>,
        bls_keys: Vec<crate::bls::Bls12381PrivateKey>,
        bls_public_keys: HashMap<Address, BLS12381PublicKey>,
        weights: Vec<u16>,
    }
    //
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

        // Create BLS keys for all validators
        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validators with specified weights
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..num_validators)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create dealer managers (either all validators or specified subset)
        let dealer_count = num_dealers.unwrap_or(num_validators);
        let dealer_managers: Vec<_> = (0..dealer_count)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                DkgManager::new(
                    addr,
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                    bls_public_keys.clone(),
                    Box::new(MockPublicMessagesStore),
                )
            })
            .collect();

        // Generate dealer messages once and store them
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|manager| {
                let message = manager.create_dealer_message(&mut rng).unwrap();
                (manager.address, message)
            })
            .collect();

        // Create certificates from the stored messages
        let certificates: Vec<_> = dealer_messages
            .iter()
            .map(|(dealer_addr, message)| {
                create_weight_based_test_certificate(
                    dealer_addr,
                    message,
                    &config,
                    &session_context,
                    &weights,
                    &bls_keys,
                    &bls_public_keys,
                )
            })
            .collect();

        WeightBasedTestSetup {
            config,
            session_context,
            dealer_messages,
            certificates,
            encryption_keys,
            bls_keys,
            bls_public_keys,
            weights,
        }
    }

    // Create a test certificate with minimal valid signatures for weight-based tests
    fn create_weight_based_test_certificate(
        dealer_addr: &Address,
        message: &avss::Message,
        config: &DkgConfig,
        session_context: &SessionContext,
        weights: &[u16],
        bls_keys: &[crate::bls::Bls12381PrivateKey],
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
    ) -> Certificate<DkgMessage> {
        let message_hash = compute_message_hash(session_context, dealer_addr, message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: *dealer_addr,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create BLS committee
        let bls_committee = create_bls_committee(config, bls_public_keys);
        let mut aggregator =
            crate::bls::BlsSignatureAggregator::new(&bls_committee, dkg_message.clone());

        // Add signatures from validators until we meet the required weight
        let dkg_required = config.threshold;
        let mut weight_sum = 0u16;

        for (i, w) in weights.iter().enumerate() {
            let signer_addr = Address::new([i as u8; 32]);
            let signature = bls_keys[i].sign(config.epoch, signer_addr, &dkg_message);
            aggregator.add_signature(signature).unwrap();
            weight_sum += w;

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
        let party_addr = Address::new([party_index as u8; 32]);

        let mut party_manager = DkgManager::new(
            party_addr,
            test_setup.config.clone(),
            test_setup.session_context.clone(),
            test_setup.encryption_keys[party_index].clone(),
            test_setup.bls_keys[party_index].clone(),
            test_setup.bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Pre-process the dealer messages so validation passes
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = party_manager.receive_dealer_message(message, *dealer_addr);
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
        let party_addr = Address::new([0; 32]);
        let mut party_manager = DkgManager::new(
            party_addr,
            test_setup.config.clone(),
            test_setup.session_context.clone(),
            test_setup.encryption_keys[0].clone(),
            test_setup.bls_keys[0].clone(),
            test_setup.bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Pre-process the dealer messages
        for (dealer_addr, message) in &test_setup.dealer_messages {
            let _ = party_manager.receive_dealer_message(message, *dealer_addr);
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create 3 dealers with their messages
        let (dealer1_addr, dealer1_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let (dealer2_addr, dealer2_mgr) = create_dealer_with_message(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let (party_addr, mut party_manager) = create_manager_at_index(
            3,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

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

        // Create validator signatures for certificates
        let validator_signatures_1: Vec<ValidatorSignature> = (0..3)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let message_hash =
                    compute_message_hash(&session_context, &dealer1_addr, &msg1).unwrap();
                let dkg_message = DkgMessage {
                    dealer_address: dealer1_addr,
                    session_context: session_context.clone(),
                    message_hash,
                };
                let signature = bls_keys[i].sign(config.epoch, addr, &dkg_message);
                ValidatorSignature {
                    validator: addr,
                    signature,
                }
            })
            .collect();

        let validator_signatures_2: Vec<ValidatorSignature> = (0..3)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                let message_hash =
                    compute_message_hash(&session_context, &dealer2_addr, &msg2).unwrap();
                let dkg_message = DkgMessage {
                    dealer_address: dealer2_addr,
                    session_context: session_context.clone(),
                    message_hash,
                };
                let signature = bls_keys[i].sign(config.epoch, addr, &dkg_message);
                ValidatorSignature {
                    validator: addr,
                    signature,
                }
            })
            .collect();

        // Create certificates using the test helper
        let cert1 = create_test_certificate(
            &config,
            &bls_public_keys,
            &msg1,
            dealer1_addr,
            &session_context,
            validator_signatures_1,
        )
        .unwrap();
        let cert2 = create_test_certificate(
            &config,
            &bls_public_keys,
            &msg2,
            dealer2_addr,
            &session_context,
            validator_signatures_2,
        )
        .unwrap();

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create 3 dealers with their messages
        let (dealer1_addr, dealer1_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let (dealer2_addr, _dealer2_mgr) = create_dealer_with_message(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let (dealer3_addr, dealer3_mgr) = create_dealer_with_message(
            2,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party (validator 3) WITHOUT pre-processing dealer messages
        let (party_addr, mut party_manager) = create_manager_at_index(
            3,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

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

        // Helper to create validator signatures
        let create_sigs = |dealer_addr: Address, msg: &avss::Message| -> Vec<ValidatorSignature> {
            (0..3)
                .map(|i| {
                    let addr = Address::new([i as u8; 32]);
                    let message_hash =
                        compute_message_hash(&session_context, &dealer_addr, msg).unwrap();
                    let dkg_message = DkgMessage {
                        dealer_address: dealer_addr,
                        session_context: session_context.clone(),
                        message_hash,
                    };
                    let signature = bls_keys[i].sign(config.epoch, addr, &dkg_message);
                    ValidatorSignature {
                        validator: addr,
                        signature,
                    }
                })
                .collect()
        };

        // Create certificates for all three dealers
        let cert1 = create_test_certificate(
            &config,
            &bls_public_keys,
            &msg1,
            dealer1_addr,
            &session_context,
            create_sigs(dealer1_addr, &msg1),
        )
        .unwrap();
        let cert2 = create_test_certificate(
            &config,
            &bls_public_keys,
            &msg2,
            dealer2_addr,
            &session_context,
            create_sigs(dealer2_addr, &msg2),
        )
        .unwrap();
        let cert3 = create_test_certificate(
            &config,
            &bls_public_keys,
            &msg3,
            dealer3_addr,
            &session_context,
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer 0 with a message - recovery will fail
        let (dealer0_addr, dealer0_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let dealer0_message = dealer0_mgr
            .dealer_messages
            .get(&dealer0_addr)
            .unwrap()
            .clone();
        let dealer0_message_hash =
            compute_message_hash(&session_context, &dealer0_addr, &dealer0_message).unwrap();
        let dealer0_dkg_message = DkgMessage {
            dealer_address: dealer0_addr,
            session_context: session_context.clone(),
            message_hash: dealer0_message_hash,
        };

        // Create dealer 1 - would be processed if we continued
        let (dealer1_addr, dealer1_mgr) = create_dealer_with_message(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let dealer1_message = dealer1_mgr
            .dealer_messages
            .get(&dealer1_addr)
            .unwrap()
            .clone();
        let dealer1_message_hash =
            compute_message_hash(&session_context, &dealer1_addr, &dealer1_message).unwrap();
        let dealer1_dkg_message = DkgMessage {
            dealer_address: dealer1_addr,
            session_context: session_context.clone(),
            message_hash: dealer1_message_hash,
        };

        // Create party manager (validator 4)
        let (party_addr, mut party_manager) = create_manager_at_index(
            4,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

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

        // Create certificates with signers (excluding party 2 who has complaint)
        let cert0 = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer0_addr,
            &dealer0_message,
            &session_context,
            [
                (0usize, Address::new([0; 32])),
                (1, Address::new([1; 32])),
                (3, Address::new([3; 32])),
            ]
            .iter()
            .map(|(i, a)| ValidatorSignature {
                validator: *a,
                signature: bls_keys[*i].sign(config.epoch, *a, &dealer0_dkg_message),
            })
            .collect(),
        )
        .unwrap();
        let cert1 = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer1_addr,
            &dealer1_message,
            &session_context,
            [
                (0usize, Address::new([0; 32])),
                (1, Address::new([1; 32])),
                (3, Address::new([3; 32])),
            ]
            .iter()
            .map(|(i, a)| ValidatorSignature {
                validator: *a,
                signature: bls_keys[*i].sign(config.epoch, *a, &dealer1_dkg_message),
            })
            .collect(),
        )
        .unwrap();

        // Create mock P2P with no responders (recovery will fail)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

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

    // TODO: Is this needed anywhere?
    #[allow(unused)]
    async fn test_handle_send_share_request() {
        // Test that handle_send_share_request works with the new request/response types
        let mut rng = rand::thread_rng();

        // Create shared encryption keys
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create dealer (party 1) with its encryption key
        let dealer_address = Address::new([1; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            bls_keys[1].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Create receiver (party 0) with its encryption key
        let receiver_address = Address::new([0; 32]);
        let mut receiver_manager = DkgManager::new(
            receiver_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
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
            .handle_send_share_request(dealer_address, &request)
            .unwrap();

        // Verify we got a valid BLS signature from the receiver
        assert_eq!(response.signature.validator, receiver_address);
    }

    #[tokio::test]
    async fn test_handle_retrieve_message_request_success() {
        let mut rng = rand::thread_rng();

        // Create shared encryption keys
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create dealer (party 0)
        let dealer_address = Address::new([0; 32]);
        let mut dealer_manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Dealer creates and processes its own message (stores in dealer_messages)
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        dealer_manager
            .receive_dealer_message(&dealer_message, dealer_address)
            .unwrap();

        // Party requests the dealer's message
        let request = RetrieveMessageRequest {
            dealer: dealer_address,
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

        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validators using shared encryption public keys
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        // Create dealer (party 0) but don't create/process any message
        let dealer_address = Address::new([0; 32]);
        let dealer_manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);
        let (dealer_address, _dealer_message, complaint) = create_dealer_message_and_complaint(
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create manager (party 1) without any dealer messages
        let mut manager = DkgManager::new(
            dealer_address,
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            bls_keys[1].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);
        let (dealer_address, dealer_message, complaint) = create_dealer_message_and_complaint(
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create manager that has the message but NOT dealer_output
        let mut manager = DkgManager::new(
            Address::new([1; 32]),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            bls_keys[1].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer (party 0)
        let (dealer_addr, _dealer_manager) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

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
        let (_party2_addr, mut party2_manager) = create_manager_at_index(
            2,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Set up party 2 with the cheating message
        party2_manager
            .receive_dealer_message(&cheating_message, dealer_addr)
            .unwrap();

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _dealer_manager) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr);
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
                &bls_keys,
                &bls_public_keys,
            );
            mgr.receive_dealer_message(&cheating_message, dealer_addr)
                .unwrap();
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
            !party_manager.complaints.contains_key(&dealer_addr),
            "Complaint should be cleared after successful recovery"
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_complaint_for_dealer() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create manager without any complaints
        let (party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Create a dealer address that has no complaint
        let (dealer_addr, dealer_manager) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        let dealer_message = dealer_manager.dealer_messages.get(&dealer_addr).unwrap();
        let message_hash =
            compute_message_hash(&session_context, &dealer_addr, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: dealer_addr,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create a minimal certificate
        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_addr,
            dealer_message,
            &session_context,
            [(1usize, party_addr)]
                .iter()
                .map(|(i, a)| ValidatorSignature {
                    validator: *a,
                    signature: bls_keys[*i].sign(config.epoch, *a, &dkg_message),
                })
                .collect(),
        )
        .unwrap();

        // Create empty mock P2P channel
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Call recover_shares_via_complaint - should fail because no complaint exists
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                cert.signers(&party_manager.bls_committee).unwrap(),
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with a message
        let (dealer_addr, dealer_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let dealer_message = dealer_mgr
            .dealer_messages
            .get(&dealer_addr)
            .unwrap()
            .clone();

        // Create party manager with a complaint
        let (party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

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
        let signer_addresses = vec![Address::new([99; 32])]; // This validator doesn't exist

        // Create empty mock P2P channel (no responders)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Call recover_shares_via_complaint - should fail because P2P call fails
        let result = party_manager
            .recover_shares_via_complaint(&dealer_addr, signer_addresses.into_iter(), &mock_p2p)
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _dealer_manager) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr);
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
                &bls_keys,
                &bls_public_keys,
            );
            mgr.receive_dealer_message(&cheating_message, dealer_addr)
                .unwrap();
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
            err.to_string()
                .contains("Not enough valid complaint responses"),
            "Error message should indicate insufficient responses, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_recover_shares_via_complaint_no_dealer_message() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with cheating message
        let (dealer_addr, _) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let cheating_message = create_cheating_message(
            &dealer_addr,
            &config,
            &session_context,
            1, // Corrupt shares for party 1
            &mut rng,
        );

        // Party 1 receives corrupted message and creates complaint
        let (party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let result = party_manager.receive_dealer_message(&cheating_message, dealer_addr);
        assert!(result.is_err());
        assert!(party_manager.complaints.contains_key(&dealer_addr));

        // Remove the dealer message to simulate the edge case
        party_manager.dealer_messages.remove(&dealer_addr);

        // Create mock P2P (empty is fine since we should fail before contacting anyone)
        let mock_p2p = MockP2PChannel::new(HashMap::new(), party_addr);

        // Try to recover - should fail because dealer message is missing
        let result = party_manager
            .recover_shares_via_complaint(
                &dealer_addr,
                [Address::new([2; 32])].into_iter(),
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
        // This test triggers a genuine crypto error by providing complaint responses
        // from parties whose IDs are not in the receiver's nodes configuration.
        // When receiver.recover() calls total_weight_of() with invalid party IDs,
        // it returns a FastCryptoError that gets wrapped as CryptoError.

        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer and cheating message
        let (dealer_addr, _) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let dealer_message =
            create_cheating_message(&dealer_addr, &config, &session_context, 1, &mut rng);

        // Create responders 3 and 4 who successfully process the dealer message
        let (addr3, mut mgr3) = create_manager_at_index(
            3,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        mgr3.receive_dealer_message(&dealer_message, dealer_addr)
            .unwrap();

        let (addr4, mut mgr4) = create_manager_at_index(
            4,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        mgr4.receive_dealer_message(&dealer_message, dealer_addr)
            .unwrap();

        // Party 1 complains
        let (_party_addr, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        party_manager
            .receive_dealer_message(&dealer_message, dealer_addr)
            .unwrap_err();
        party_manager
            .dealer_messages
            .insert(dealer_addr, dealer_message);

        // Pre-collect complaint responses from parties 3 and 4
        let complaint = party_manager.complaints.get(&dealer_addr).unwrap().clone();
        let request = ComplainRequest {
            dealer: dealer_addr,
            complaint,
        };

        let resp3 = mgr3.handle_complain_request(&request).unwrap();
        let resp4 = mgr4.handle_complain_request(&request).unwrap();

        let responses = std::collections::HashMap::from([(addr3, resp3), (addr4, resp4)]);

        // Modify party_manager's config to exclude parties 3 and 4
        // This makes their responses invalid (party IDs not in the nodes list)
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

    #[test]
    fn test_receive_dealer_message_stores_message_even_on_complaint() {
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer message
        let (dealer_addr, dealer_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let dealer_message = dealer_mgr
            .dealer_messages
            .get(&dealer_addr)
            .unwrap()
            .clone();

        // Create party that will create a complaint (using wrong encryption key)
        let wrong_key = PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let mut party_manager = DkgManager::new(
            Address::new([1; 32]),
            config.clone(),
            session_context.clone(),
            wrong_key, // Wrong key causes complaint
            bls_keys[0].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Process dealer message - should create complaint and return error
        let result = party_manager.receive_dealer_message(&dealer_message, dealer_addr);

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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer (party 0) with its message
        let (dealer_address, dealer_manager) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party (party 1) that will request the message
        let (party_address, mut party_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Get dealer's message for certificate creation
        let dealer_message = dealer_manager.dealer_messages.get(&dealer_address).unwrap();

        // Create DkgMessage and validator signatures
        let message_hash =
            compute_message_hash(&session_context, &dealer_address, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address,
            session_context: session_context.clone(),
            message_hash,
        };

        // Dealer signs its own message
        let dealer_signature =
            bls_keys[0].sign(session_context.epoch, dealer_address, &dkg_message);
        let validator_signatures = vec![ValidatorSignature {
            validator: dealer_address,
            signature: dealer_signature,
        }];

        // Create certificate with dealer's signature
        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_address,
            dealer_message,
            &session_context,
            validator_signatures,
        )
        .unwrap();

        // Create mock P2P channel with the dealer (who also signed the cert)
        let mut dealers = HashMap::new();
        dealers.insert(dealer_address, dealer_manager);
        let mock_p2p = MockP2PChannel::new(dealers, party_address);

        // Party requests dealer's share from certificate signers
        let result = party_manager
            .retrieve_dealer_message(dealer_address, &cert, &mock_p2p)
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
        let (config_1, session_context, encryption_keys_1, bls_keys_1, bls_public_keys_1) =
            create_test_config_and_encrption_keys(&mut rng);
        let (config_2, _, encryption_keys_2, bls_keys_2, bls_public_keys_2) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with config_1
        let (dealer_address, dealer_manager) = create_dealer_with_message(
            0,
            &config_1,
            &session_context,
            &encryption_keys_1,
            &bls_keys_1,
            &bls_public_keys_1,
            &mut rng,
        );

        // Create party with config_2 (incompatible encryption key)
        let (party_address, mut party_manager) = create_manager_at_index(
            1,
            &config_2,
            &session_context,
            &encryption_keys_2,
            &bls_keys_2,
            &bls_public_keys_2,
        );

        // Get dealer's message for certificate creation
        let dealer_message = dealer_manager.dealer_messages.get(&dealer_address).unwrap();

        // Create DkgMessage and validator signatures
        let message_hash =
            compute_message_hash(&session_context, &dealer_address, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address,
            session_context: session_context.clone(),
            message_hash,
        };

        // Dealer signs its own message using config_1 BLS keys
        let dealer_signature =
            bls_keys_1[0].sign(session_context.epoch, dealer_address, &dkg_message);
        let validator_signatures = vec![ValidatorSignature {
            validator: dealer_address,
            signature: dealer_signature,
        }];

        // Create certificate with dealer's signature using config_1
        let cert = create_certificate_with_signers(
            &config_1,
            &bls_public_keys_1,
            &dealer_address,
            dealer_message,
            &session_context,
            validator_signatures,
        )
        .unwrap();

        // Create mock P2P channel
        let mut dealers = HashMap::new();
        dealers.insert(dealer_address, dealer_manager);
        let mock_p2p = MockP2PChannel::new(dealers, party_address);

        // Party requests dealer's share - should fail during certificate validation or message processing
        // (incompatible keys - config mismatch)
        let result = party_manager
            .retrieve_dealer_message(dealer_address, &cert, &mock_p2p)
            .await;

        // Should fail - either during certificate validation (CryptoError) or message processing (ProtocolFailed)
        assert!(
            result.is_err(),
            "Expected error due to incompatible configs"
        );
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_retries_multiple_signers() {
        // Tests that retrieve_dealer_message retries with next signer if first fails
        let mut rng = rand::thread_rng();
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message (validator 0)
        let (dealer_addr, dealer_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party that will request (validator 2)
        let (party_addr, mut party_mgr) = create_manager_at_index(
            2,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash =
            compute_message_hash(&session_context, &dealer_addr, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: dealer_addr,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create certificate with two signers: validator 1 (not in P2P) and dealer (validator 0)
        // Validator 1 signs first, then validator 0
        let validator_1_addr = Address::new([1; 32]);
        let validator_1_signature =
            bls_keys[1].sign(session_context.epoch, validator_1_addr, &dkg_message);
        let dealer_signature = bls_keys[0].sign(session_context.epoch, dealer_addr, &dkg_message);

        let validator_signatures = vec![
            ValidatorSignature {
                validator: validator_1_addr,
                signature: validator_1_signature,
            },
            ValidatorSignature {
                validator: dealer_addr,
                signature: dealer_signature,
            },
        ];

        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_addr,
            dealer_message,
            &session_context,
            validator_signatures,
        )
        .unwrap();

        // MockP2PChannel: only include dealer (validator 1 not included)
        let mut managers = HashMap::new();
        managers.insert(dealer_addr, dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        // Should succeed by trying validator 1 (fails), then dealer (succeeds)
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr, &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        assert!(party_mgr.dealer_messages.contains_key(&dealer_addr));
    }

    #[tokio::test]
    async fn test_retrieve_dealer_message_aborts_when_self_in_signers() {
        // Tests that retrieve_dealer_message aborts with error when requesting party is in signer list
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message (validator 0)
        let (dealer_addr, dealer_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party that will request (party 1)
        let (party_addr, mut party_mgr) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash =
            compute_message_hash(&session_context, &dealer_addr, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: dealer_addr,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create certificate with signers including the requesting party
        // This is an invalid state - party shouldn't be retrieving a message it signed for
        let party_signature = bls_keys[1].sign(session_context.epoch, party_addr, &dkg_message);
        let dealer_signature = bls_keys[0].sign(session_context.epoch, dealer_addr, &dkg_message);

        let validator_signatures = vec![
            ValidatorSignature {
                validator: party_addr,
                signature: party_signature,
            },
            ValidatorSignature {
                validator: dealer_addr,
                signature: dealer_signature,
            },
        ];

        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_addr,
            dealer_message,
            &session_context,
            validator_signatures,
        )
        .unwrap();

        // MockP2PChannel: include dealer
        let mut managers = HashMap::new();
        managers.insert(dealer_addr, dealer_mgr);
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        // Should abort with ProtocolFailed error due to invariant violation
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr, &cert, &mock_p2p)
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer with message (validator 0)
        let (dealer_addr, dealer_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );

        // Create party that will request (validator 1)
        let (party_addr, mut party_mgr) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Get dealer's message for certificate creation
        let dealer_message = dealer_mgr.dealer_messages.get(&dealer_addr).unwrap();

        // Create DkgMessage
        let message_hash =
            compute_message_hash(&session_context, &dealer_addr, dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: dealer_addr,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create certificate with signers 2 and 3 (both will be offline in P2P)
        let signer_2_addr = Address::new([2; 32]);
        let signer_3_addr = Address::new([3; 32]);
        let signer_2_signature =
            bls_keys[2].sign(session_context.epoch, signer_2_addr, &dkg_message);
        let signer_3_signature =
            bls_keys[3].sign(session_context.epoch, signer_3_addr, &dkg_message);

        let validator_signatures = vec![
            ValidatorSignature {
                validator: signer_2_addr,
                signature: signer_2_signature,
            },
            ValidatorSignature {
                validator: signer_3_addr,
                signature: signer_3_signature,
            },
        ];

        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_addr,
            dealer_message,
            &session_context,
            validator_signatures,
        )
        .unwrap();

        // MockP2PChannel: empty (no signers available)
        let managers = HashMap::new();
        let mock_p2p = MockP2PChannel::new(managers, party_addr);

        // Should fail because all signers are offline
        let result = party_mgr
            .retrieve_dealer_message(dealer_addr, &cert, &mock_p2p)
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
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(&mut rng);

        // Create dealer A with message MA
        let (dealer_a_addr, dealer_a_mgr) = create_dealer_with_message(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let message_a = dealer_a_mgr
            .dealer_messages
            .get(&dealer_a_addr)
            .unwrap()
            .clone();

        // Create dealer B with different message MB
        let (dealer_b_addr, dealer_b_mgr) = create_dealer_with_message(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
            &mut rng,
        );
        let message_b = dealer_b_mgr
            .dealer_messages
            .get(&dealer_b_addr)
            .unwrap()
            .clone();

        // Create party that will request
        let (party_addr, mut party_mgr) = create_manager_at_index(
            2,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );

        // Create Byzantine signer that has WRONG message stored for dealer A
        // (It has dealer B's message stored under dealer A's key.)
        let byzantine_signer_addr = Address::new([3; 32]);
        let mut byzantine_signer = create_manager_at_index(
            3,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        )
        .1;
        // Byzantine: store dealer B's message under dealer A's address
        byzantine_signer
            .dealer_messages
            .insert(dealer_a_addr, message_b.clone());

        // Create DkgMessage for dealer A
        let message_hash_a =
            compute_message_hash(&session_context, &dealer_a_addr, &message_a).unwrap();
        let dkg_message = DkgMessage {
            dealer_address: dealer_a_addr,
            session_context: session_context.clone(),
            message_hash: message_hash_a,
        };

        // Create valid certificate for dealer A with correct hash, signed by Byzantine signer and dealer A
        let byzantine_signature =
            bls_keys[3].sign(session_context.epoch, byzantine_signer_addr, &dkg_message);
        let dealer_a_signature =
            bls_keys[0].sign(session_context.epoch, dealer_a_addr, &dkg_message);

        let validator_signatures = vec![
            ValidatorSignature {
                validator: byzantine_signer_addr,
                signature: byzantine_signature,
            },
            ValidatorSignature {
                validator: dealer_a_addr,
                signature: dealer_a_signature,
            },
        ];

        let cert = create_certificate_with_signers(
            &config,
            &bls_public_keys,
            &dealer_a_addr,
            &message_a,
            &session_context,
            validator_signatures,
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
            .retrieve_dealer_message(dealer_a_addr, &cert, &mock_p2p)
            .await;

        assert!(result.is_ok());
        // Should have dealer A's correct message (from second signer)
        assert!(party_mgr.dealer_messages.contains_key(&dealer_a_addr));
    }
    //
    type TestConfigAndKeys = (
        DkgConfig,
        SessionContext,
        Vec<PrivateKey<EncryptionGroupElement>>,
        Vec<crate::bls::Bls12381PrivateKey>,
        HashMap<Address, BLS12381PublicKey>,
    );

    fn create_test_config_and_encrption_keys(
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> TestConfigAndKeys {
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(rng))
            .collect();

        let bls_keys: Vec<_> = (0..5)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(rng))
            .collect();

        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key = PublicKey::from_private_key(private_key);
                let address = Address::new([i as u8; 32]);
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

        // Create BLS public keys map with deterministic ordering
        let bls_public_keys: HashMap<_, _> = (0..5)
            .map(|i| {
                let addr = Address::new([i as u8; 32]);
                (addr, bls_keys[i].public_key())
            })
            .collect();

        (
            config,
            session_context,
            encryption_keys,
            bls_keys,
            bls_public_keys,
        )
    }

    fn create_manager_at_index(
        index: u8,
        config: &DkgConfig,
        session_context: &SessionContext,
        encryption_keys: &[PrivateKey<EncryptionGroupElement>],
        bls_keys: &[crate::bls::Bls12381PrivateKey],
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
    ) -> (Address, DkgManager) {
        let address = Address::new([index; 32]);
        let manager = DkgManager::new(
            address,
            config.clone(),
            session_context.clone(),
            encryption_keys[index as usize].clone(),
            bls_keys[index as usize].clone(),
            bls_public_keys.clone(),
            Box::new(MockPublicMessagesStore),
        );
        (address, manager)
    }

    fn create_dealer_with_message(
        index: u8,
        config: &DkgConfig,
        session_context: &SessionContext,
        encryption_keys: &[PrivateKey<EncryptionGroupElement>],
        bls_keys: &[crate::bls::Bls12381PrivateKey],
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (Address, DkgManager) {
        let (address, mut manager) = create_manager_at_index(
            index,
            config,
            session_context,
            encryption_keys,
            bls_keys,
            bls_public_keys,
        );
        let dealer_message = manager.create_dealer_message(rng).unwrap();
        manager
            .receive_dealer_message(&dealer_message, address)
            .unwrap();
        (address, manager)
    }

    fn create_certificate_with_signers(
        config: &DkgConfig,
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
        dealer_address: &Address,
        message: &avss::Message,
        session_context: &SessionContext,
        signer_signatures: Vec<ValidatorSignature>,
    ) -> DkgResult<Certificate<DkgMessage>> {
        let message_hash = compute_message_hash(session_context, dealer_address, message)?;
        let dkg_message = DkgMessage {
            dealer_address: *dealer_address,
            session_context: session_context.clone(),
            message_hash,
        };

        let bls_committee = create_bls_committee(config, bls_public_keys);
        let mut aggregator = crate::bls::BlsSignatureAggregator::new(&bls_committee, dkg_message);

        for validator_sig in signer_signatures {
            aggregator
                .add_signature(validator_sig.signature)
                .map_err(|e| DkgError::CryptoError(e.to_string()))?;
        }
        aggregator
            .finish()
            .map_err(|e| DkgError::CryptoError(e.to_string()))
    }

    fn create_complaint_for_dealer(
        dealer_message: &avss::Message,
        party_id: u16,
        config: &DkgConfig,
        session_context: &SessionContext,
        dealer_address: &Address,
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
        dealer_address: &Address,
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
        bls_keys: &[crate::bls::Bls12381PrivateKey],
        bls_public_keys: &HashMap<Address, BLS12381PublicKey>,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (Address, avss::Message, complaint::Complaint) {
        let (dealer_address, dealer_manager) = create_manager_at_index(
            0,
            config,
            session_context,
            encryption_keys,
            bls_keys,
            bls_public_keys,
        );
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
        dealer_address: &Address,
        dealer_message: &avss::Message,
        complaint: complaint::Complaint,
    ) {
        party_manager.complaints.insert(*dealer_address, complaint);
        party_manager
            .dealer_messages
            .insert(*dealer_address, dealer_message.clone());
    }

    fn create_handle_send_share_test_setup(
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (Address, DkgManager, Address, DkgManager) {
        let (config, session_context, encryption_keys, bls_keys, bls_public_keys) =
            create_test_config_and_encrption_keys(rng);
        let (dealer_address, dealer_manager) = create_manager_at_index(
            1,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
        let (receiver_address, receiver_manager) = create_manager_at_index(
            0,
            &config,
            &session_context,
            &encryption_keys,
            &bls_keys,
            &bls_public_keys,
        );
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
            .handle_send_share_request(dealer_address, &request)
            .unwrap();

        // Second request with same message - should return cached response
        let response2 = receiver_manager
            .handle_send_share_request(dealer_address, &request)
            .unwrap();

        // Responses should be identical (same validator)
        assert_eq!(response1.signature.validator, response2.signature.validator);
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
            .handle_send_share_request(dealer_address, &request1)
            .unwrap();
        assert_eq!(response1.signature.validator, receiver_manager.address);

        // Second DIFFERENT message from same dealer (equivocation)
        let dealer_message2 = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let request2 = SendShareRequest {
            message: dealer_message2.clone(),
        };

        // Should return error
        let result = receiver_manager.handle_send_share_request(dealer_address, &request2);
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
    async fn test_committee_ordering_consistency_across_independent_construction() {
        // This test verifies that validators who construct their configs independently
        // (simulating production) can still verify each other's signatures.

        let mut rng = rand::thread_rng();
        let num_validators = 5;

        // Create shared validator data
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();
        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        // Create validator registry in a specific order
        let validator_data: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = Address::new([i as u8; 32]);
                let party_id = i as u16;
                let encryption_pk = PublicKey::from_private_key(&encryption_keys[i]);
                let bls_pk = bls_keys[i].public_key();
                let weight = 1;
                (address, party_id, encryption_pk, bls_pk, weight)
            })
            .collect();

        let epoch = 100;
        let threshold = 2;
        let max_faulty = 1;
        let session_context = SessionContext::new(
            epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        let construct_config = |data: &[(
            Address,
            u16,
            PublicKey<EncryptionGroupElement>,
            BLS12381PublicKey,
            u16,
        )]| {
            // Build nodes and address_to_party_id from scratch (not cloning!)
            let mut nodes_vec = Vec::new();
            let mut address_to_party_id = HashMap::new();
            let mut bls_public_keys = HashMap::new();

            for (addr, party_id, enc_pk, bls_pk, weight) in data {
                let node = Node {
                    id: *party_id,
                    pk: enc_pk.clone(),
                    weight: *weight,
                };
                nodes_vec.push(node);
                address_to_party_id.insert(*addr, *party_id);
                bls_public_keys.insert(*addr, bls_pk.clone());
            }

            let nodes = Nodes::new(nodes_vec).unwrap();
            let config =
                DkgConfig::new(epoch, nodes, address_to_party_id, threshold, max_faulty).unwrap();
            (config, bls_public_keys)
        };

        // Validator 0 constructs config independently
        let (config0, bls_public_keys0) = construct_config(&validator_data);
        let manager0 = DkgManager::new(
            Address::new([0; 32]),
            config0.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
            bls_public_keys0.clone(),
            Box::new(MockPublicMessagesStore),
        );

        // Validator 1 constructs config independently with REVERSED insertion order
        // FLAKINESS: Reversing insertion order doesn't guarantee different HashMap iteration
        // order due to HashMap's internal randomization. However, it increases the likelihood
        // that the two HashMaps will have different iteration orders, which is what we want
        // to test.
        let mut validator_data_reversed = validator_data.clone();
        validator_data_reversed.reverse();
        let (config1, bls_public_keys1) = construct_config(&validator_data_reversed);
        let mut manager1 = DkgManager::new(
            Address::new([1; 32]),
            config1,
            session_context.clone(),
            encryption_keys[1].clone(),
            bls_keys[1].clone(),
            bls_public_keys1,
            Box::new(MockPublicMessagesStore),
        );

        // Validator 0 creates a dealer message
        let dealer_message = manager0.create_dealer_message(&mut rng).unwrap();
        let dealer_address = Address::new([0; 32]);

        // Collect signatures from all validators
        let message_hash =
            compute_message_hash(&session_context, &dealer_address, &dealer_message).unwrap();
        let dkg_message = DkgMessage {
            dealer_address,
            session_context: session_context.clone(),
            message_hash,
        };

        // Create certificate using validator 0's committee
        let bls_committee0 = create_bls_committee(&config0, &bls_public_keys0);
        let mut aggregator =
            crate::bls::BlsSignatureAggregator::new(&bls_committee0, dkg_message.clone());

        // Add signatures from validators 0, 1, 2 (threshold is 2, so this is enough)
        for (i, key) in bls_keys.iter().enumerate().take(3) {
            let sig = key.sign(epoch, Address::new([i as u8; 32]), &dkg_message);
            aggregator.add_signature(sig).unwrap();
        }

        let certificate = aggregator.finish().unwrap();

        // Validator 1 needs to receive the dealer message first
        manager1
            .receive_dealer_message(&dealer_message, dealer_address)
            .unwrap();

        let result = manager1.validate_certificate(&certificate);
        assert!(
            result.is_ok(),
            "Validator with independently constructed config should verify certificate. \
             This fails without deterministic committee ordering! Error: {:?}",
            result.err()
        );
    }
}
