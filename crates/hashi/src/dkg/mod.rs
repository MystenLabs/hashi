//! Distributed Key Generation (DKG) module for Hashi bridge

pub mod interfaces;
pub mod types;

use crate::types::ValidatorAddress;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::threshold_schnorr::avss;
use std::collections::BTreeMap;
use sui_crypto::Signer;

pub use types::{
    DkgCertificate, DkgConfig, DkgError, DkgOutput, DkgResult, EncryptionGroupElement,
    MessageApproval, MessageHash, MessageType, OrderedBroadcastMessage, P2PMessage, SessionContext,
    SessionId, SighashType, SignatureBytes, ValidatorInfo, ValidatorSignature,
};

pub struct DkgStaticData {
    pub validator_info: ValidatorInfo,
    pub nodes: Nodes<EncryptionGroupElement>,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub encryption_key: PrivateKey<EncryptionGroupElement>,
    pub bls_signing_key: crate::bls::Bls12381PrivateKey,
    pub receiver: avss::Receiver,
    pub validator_weights: BTreeMap<ValidatorAddress, u16>,
}

#[derive(Clone, Debug)]
pub struct DkgRuntimeState {
    pub dealer_outputs: BTreeMap<ValidatorAddress, avss::ReceiverOutput>,
    pub dealer_messages: BTreeMap<ValidatorAddress, avss::Message>,
}

impl DkgStaticData {
    pub fn new(
        validator_info: ValidatorInfo,
        dkg_config: DkgConfig,
        session_context: SessionContext,
        encryption_key: PrivateKey<EncryptionGroupElement>,
        bls_signing_key: crate::bls::Bls12381PrivateKey,
    ) -> DkgResult<Self> {
        let nodes = create_nodes(&dkg_config.validators);
        let session_id = session_context.session_id.to_vec();
        let receiver = avss::Receiver::new(
            nodes.clone(),
            validator_info.party_id,
            dkg_config.threshold,
            session_id,
            None, // commitment: None for initial DKG
            encryption_key.clone(),
        );
        let validator_weights: BTreeMap<_, _> = dkg_config
            .validators
            .iter()
            .map(|v| (v.address.clone(), v.weight))
            .collect();
        Ok(Self {
            validator_info,
            nodes,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            receiver,
            validator_weights,
        })
    }
}

pub struct DkgManager {
    pub static_data: DkgStaticData,
    pub runtime_state: DkgRuntimeState,
}

struct SignatureCollectionState {
    signatures: Vec<ValidatorSignature>,
    is_cert_published: bool,
}

impl DkgManager {
    pub fn new(static_data: DkgStaticData) -> Self {
        Self {
            static_data,
            runtime_state: DkgRuntimeState {
                dealer_outputs: BTreeMap::new(),
                dealer_messages: BTreeMap::new(),
            },
        }
    }

    pub fn create_dealer_message(
        &self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<avss::Message> {
        let dealer = avss::Dealer::new(
            None,
            self.static_data.nodes.clone(),
            self.static_data.dkg_config.threshold,
            self.static_data.dkg_config.max_faulty,
            self.static_data.session_context.session_id.to_vec(),
        )?;
        let message = dealer.create_message(rng)?;
        Ok(message)
    }

    pub fn receive_dealer_message(
        &mut self,
        message: &avss::Message,
        dealer_address: ValidatorAddress,
    ) -> DkgResult<ValidatorSignature> {
        let receiver_output = match self.static_data.receiver.process_message(message)? {
            avss::ProcessedMessage::Valid(output) => output,
            // TODO: Add compliant handling
            avss::ProcessedMessage::Complaint(_) => {
                return Err(DkgError::ProtocolFailed(
                    "Invalid message from dealer".into(),
                ));
            }
        };
        self.runtime_state
            .dealer_outputs
            .insert(dealer_address.clone(), receiver_output);
        self.runtime_state
            .dealer_messages
            .insert(dealer_address.clone(), message.clone());
        let message_hash =
            compute_message_hash(message, &dealer_address, &self.static_data.session_context)?;
        let signature = self.static_data.bls_signing_key.sign(&message_hash);
        Ok(ValidatorSignature {
            validator: self.static_data.validator_info.address.clone(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    pub fn create_certificate(
        &self,
        message: &avss::Message,
        signatures: Vec<ValidatorSignature>,
    ) -> DkgResult<DkgCertificate> {
        let total_weight =
            compute_total_signature_weight(&signatures, &self.static_data.validator_weights)?;
        let weight_lower_bound =
            self.static_data.dkg_config.threshold + self.static_data.dkg_config.max_faulty;
        if total_weight < weight_lower_bound {
            return Err(DkgError::ProtocolFailed(format!(
                "Insufficient weighted signatures: got {}, need {}",
                total_weight, weight_lower_bound
            )));
        }
        let message_hash = compute_message_hash(
            message,
            &self.static_data.validator_info.address,
            &self.static_data.session_context,
        )?;
        Ok(DkgCertificate {
            dealer: self.static_data.validator_info.address.clone(),
            message_hash,
            data_availability_signatures: signatures.clone(),
            dkg_signatures: signatures,
            session_context: self.static_data.session_context.clone(),
        })
    }

    pub fn process_certificates(&self, certificates: &[DkgCertificate]) -> DkgResult<DkgOutput> {
        let threshold = self.static_data.dkg_config.threshold;
        if certificates.len() != threshold as usize {
            return Err(DkgError::ProtocolFailed(format!(
                "Expected {} certificates, got {}",
                threshold,
                certificates.len()
            )));
        }
        // TODO: Handle missing messages and invalid shares
        let mut outputs = Vec::new();
        for cert in certificates {
            let output = self
                .runtime_state
                .dealer_outputs
                .get(&cert.dealer)
                .ok_or_else(|| {
                    DkgError::ProtocolFailed(format!(
                        "No dealer output found for dealer: {:?}.",
                        cert.dealer
                    ))
                })?;
            outputs.push(output.clone());
        }
        let combined = avss::ReceiverOutput::complete_dkg(threshold, outputs)
            .map_err(|e| DkgError::CryptoError(format!("Failed to complete DKG: {}", e)))?;
        Ok(DkgOutput {
            public_key: combined.vk,
            key_shares: combined.my_shares,
            commitments: combined.commitments,
            session_context: self.static_data.session_context.clone(),
        })
    }

    pub async fn run_dkg(
        &mut self,
        p2p_channel: &mut impl crate::communication::P2PChannel<P2PMessage>,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.static_data.dkg_config.threshold;
        let max_faulty = self.static_data.dkg_config.max_faulty;
        let required_sigs = threshold + max_faulty;
        let my_address = self.static_data.validator_info.address.clone();
        let session_id = self.static_data.session_context.session_id;

        let dealer_message = self.create_dealer_message(rng)?;
        let my_message_hash = compute_message_hash(
            &dealer_message,
            &my_address,
            &self.static_data.session_context,
        )?;
        p2p_channel
            .broadcast(P2PMessage::ShareV1 {
                session_id,
                sender: my_address.clone(),
                message: Box::new(dealer_message.clone()),
            })
            .await
            .map_err(|e| DkgError::ProtocolFailed(format!("Failed to broadcast share: {}", e)))?;
        self.receive_dealer_message(&dealer_message, my_address.clone())?;

        let mut sig_state = SignatureCollectionState {
            signatures: Vec::new(),
            is_cert_published: false,
        };
        let mut certificates = Vec::new();
        loop {
            let have_all_dealer_messages = certificates.iter().all(|cert: &DkgCertificate| {
                self.runtime_state.dealer_outputs.contains_key(&cert.dealer)
            });
            if certificates.len() >= threshold as usize && have_all_dealer_messages {
                break;
            }
            // TODO: Validate message sender is as claimed
            tokio::select! {
                p2p_result = p2p_channel.receive() => {
                    let p2p_msg = p2p_result.map_err(|e| {
                        DkgError::ProtocolFailed(format!("P2P channel error: {}", e))
                    })?;
                    match p2p_msg.message {
                        P2PMessage::ShareV1 {
                            sender,
                            message,
                            session_id: msg_session_id,
                        } if msg_session_id == session_id => {
                            self.handle_incoming_share(
                                p2p_channel,
                                sender,
                                &p2p_msg.sender,
                                &message,
                                session_id,
                            )
                            .await?;
                        }
                        P2PMessage::DkgSignatureV1 {
                            dealer,
                            message_hash,
                            signature,
                            signer,
                            session_id: msg_session_id,
                        } if msg_session_id == session_id
                            && dealer == my_address
                            && message_hash == my_message_hash =>
                        {
                            self.handle_signature_for_my_message(
                                ordered_broadcast_channel,
                                &dealer_message,
                                signer,
                                signature,
                                required_sigs,
                                &mut sig_state,
                            )
                            .await?;
                        }
                        // TODO: Handle error responses to our dealer message for n-(t+f+1) error counting
                        _ => {
                        }
                    }
                }
                tob_result = ordered_broadcast_channel.receive() => {
                    let tob_msg = tob_result.map_err(|e| {
                        DkgError::ProtocolFailed(format!("TOB channel error: {}", e))
                    })?;
                    if let OrderedBroadcastMessage::CertificateV1(cert) = tob_msg.message {
                        // TODO: Validate certificate signatures
                        // TODO: Check session_id matches
                        certificates.push(cert);
                    }
                }
            }
            // TODO: Handle case where we receive n-(t+f+1) error responses (too slow, abort)
        }
        let output = self.process_certificates(&certificates)?;
        Ok(output)
    }

    /// TODO: Send error response if validation fails
    async fn handle_incoming_share(
        &mut self,
        p2p_channel: &mut impl crate::communication::P2PChannel<P2PMessage>,
        sender: ValidatorAddress,
        authenticated_sender: &ValidatorAddress,
        message: &avss::Message,
        session_id: SessionId,
    ) -> DkgResult<()> {
        match self.receive_dealer_message(message, sender.clone()) {
            Ok(sig) => {
                p2p_channel
                    .send_to(
                        &sender,
                        P2PMessage::DkgSignatureV1 {
                            session_id,
                            signer: self.static_data.validator_info.address.clone(),
                            dealer: sender.clone(),
                            message_hash: compute_message_hash(
                                message,
                                authenticated_sender,
                                &self.static_data.session_context,
                            )?,
                            signature: sig.signature,
                        },
                    )
                    .await
                    .map_err(|e| {
                        DkgError::ProtocolFailed(format!("Failed to send signature: {}", e))
                    })?;
            }
            Err(_) => {
                // TODO: Send error response to dealer
            }
        }
        Ok(())
    }

    async fn handle_signature_for_my_message(
        &self,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
        dealer_message: &avss::Message,
        signer: ValidatorAddress,
        signature: SignatureBytes,
        required_sigs: u16,
        signature_collection_state: &mut SignatureCollectionState,
    ) -> DkgResult<()> {
        signature_collection_state
            .signatures
            .push(ValidatorSignature {
                validator: signer,
                signature,
            });
        if !signature_collection_state.is_cert_published
            && signature_collection_state.signatures.len() >= required_sigs as usize
        {
            let cert = self.create_certificate(
                dealer_message,
                signature_collection_state.signatures.clone(),
            )?;
            ordered_broadcast_channel
                .publish(OrderedBroadcastMessage::CertificateV1(cert))
                .await
                .map_err(|e| {
                    DkgError::ProtocolFailed(format!("Failed to publish certificate: {}", e))
                })?;
            signature_collection_state.is_cert_published = true;
        }
        Ok(())
    }
}

fn create_nodes(validators: &[ValidatorInfo]) -> Nodes<EncryptionGroupElement> {
    let nodes: Vec<_> = validators
        .iter()
        .map(|v| Node {
            id: v.party_id,
            pk: v.ecies_public_key.clone(),
            weight: v.weight,
        })
        .collect();
    Nodes::new(nodes).expect("Failed to create nodes")
}

fn compute_total_signature_weight(
    signatures: &[ValidatorSignature],
    validator_weights: &BTreeMap<ValidatorAddress, u16>,
) -> DkgResult<u16> {
    let mut total_weight: u16 = 0;
    for sig in signatures {
        let weight = validator_weights.get(&sig.validator).ok_or_else(|| {
            DkgError::ProtocolFailed(format!(
                "Signature from unknown validator: {:?}",
                sig.validator
            ))
        })?;
        total_weight += weight;
    }
    Ok(total_weight)
}

fn compute_message_hash(
    message: &avss::Message,
    dealer_address: &ValidatorAddress,
    session: &SessionContext,
) -> DkgResult<MessageHash> {
    let message_bytes = bcs::to_bytes(message)
        .map_err(|e| DkgError::CryptoError(format!("Failed to serialize message: {}", e)))?;
    let mut hasher = Blake2b256::default();
    // No length prefix is needed for message_bytes because it's the only variable-length
    // input.
    hasher.update(&message_bytes);
    hasher.update(dealer_address.0);
    hasher.update(session.session_id.as_ref());
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::{OrderedBroadcastChannel, P2PChannel};
    use crate::dkg::types::ProtocolType;

    fn create_test_validator(party_id: u16) -> ValidatorInfo {
        let private_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let public_key = fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(&private_key);

        ValidatorInfo {
            address: ValidatorAddress([party_id as u8; 32]),
            party_id,
            weight: 1,
            ecies_public_key: public_key,
        }
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
        let validators: Vec<_> = (0..num_validators).map(create_test_validator).collect();
        DkgConfig::new(100, validators, THRESHOLD, MAX_FAULTY).unwrap()
    }

    fn create_test_static_data(validator_index: u16, dkg_config: DkgConfig) -> DkgStaticData {
        let validator_info = dkg_config.validators[validator_index as usize].clone();
        let session_context = SessionContext::new(
            dkg_config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );
        let encryption_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let bls_signing_key = crate::bls::Bls12381PrivateKey::generate(rand::thread_rng());
        DkgStaticData::new(
            validator_info,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
        )
        .unwrap()
    }

    #[test]
    fn test_dkg_static_data_creation() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());

        assert_eq!(static_data.validator_info.party_id, 0);
        assert_eq!(static_data.dkg_config.threshold, 2);
        assert_eq!(static_data.dkg_config.max_faulty, 1);
        assert_eq!(static_data.dkg_config.validators.len(), 5);
    }

    #[test]
    fn test_dkg_manager_creation() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        assert!(manager.runtime_state.dealer_outputs.is_empty());
    }

    #[test]
    fn test_create_dealer_message() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        // Should successfully create a dealer message
        let _message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();
    }

    #[test]
    fn test_dealer_receiver_flow() {
        // Create encryption keys for each validator
        let mut rng = rand::thread_rng();
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        // Create validators using the encryption public keys
        let validators: Vec<_> = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                ValidatorInfo {
                    address: ValidatorAddress([i as u8; 32]),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                }
            })
            .collect();

        let config = DkgConfig::new(100, validators, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 0) with its encryption key
        let dealer_static = DkgStaticData::new(
            config.validators[0].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(rand::thread_rng()),
        )
        .unwrap();

        let dealer_manager = DkgManager::new(dealer_static);
        let message = dealer_manager.create_dealer_message(&mut rng).unwrap();
        let dealer_address = dealer_manager.static_data.validator_info.address.clone();

        // Create receiver (party 1) with its encryption key
        let receiver_static = DkgStaticData::new(
            config.validators[1].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(rand::thread_rng()),
        )
        .unwrap();

        let mut receiver_manager = DkgManager::new(receiver_static);

        // Receiver processes the dealer's message
        let signature = receiver_manager
            .receive_dealer_message(&message, dealer_address.clone())
            .unwrap();

        // Verify signature format
        assert_eq!(
            signature.validator,
            receiver_manager.static_data.validator_info.address
        );
        assert_eq!(signature.signature.len(), 96); // BLS signature length

        // Verify receiver output was stored
        assert!(
            receiver_manager
                .runtime_state
                .dealer_outputs
                .contains_key(&dealer_address)
        );

        // Verify dealer message was stored for signature recovery
        assert!(
            receiver_manager
                .runtime_state
                .dealer_messages
                .contains_key(&dealer_address)
        );
    }

    #[test]
    fn test_create_certificate_insufficient_signatures() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Only 2 signatures with weight=1 each, need threshold + max_faulty = 3
        let signatures = vec![
            ValidatorSignature {
                validator: config.validators[0].address.clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: config.validators[1].address.clone(),
                signature: vec![0; 96],
            },
        ];

        let result = manager.create_certificate(&message, signatures);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient weighted signatures")
        );
    }

    #[test]
    fn test_create_certificate_success() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Create enough signatures (threshold + max_faulty = 3 weight needed)
        let required_sigs = (manager.static_data.dkg_config.threshold
            + manager.static_data.dkg_config.max_faulty) as usize;
        let signatures: Vec<_> = (0..required_sigs)
            .map(|i| ValidatorSignature {
                validator: config.validators[i].address.clone(),
                signature: vec![0; 96],
            })
            .collect();

        let certificate = manager
            .create_certificate(&message, signatures.clone())
            .unwrap();

        assert_eq!(
            certificate.dealer,
            manager.static_data.validator_info.address
        );
        assert_eq!(certificate.dkg_signatures.len(), required_sigs);
        assert_eq!(
            certificate.data_availability_signatures.len(),
            required_sigs
        );
        assert_eq!(
            certificate.session_context.session_id,
            manager.static_data.session_context.session_id
        );
    }

    #[test]
    fn test_create_certificate_weighted_signatures() {
        // Create validators with different weights
        let validators: Vec<_> = vec![
            ValidatorInfo {
                address: ValidatorAddress([0; 32]),
                party_id: 0,
                weight: 3, // Heavy weight
                ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                    &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                ),
            },
            ValidatorInfo {
                address: ValidatorAddress([1; 32]),
                party_id: 1,
                weight: 1,
                ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                    &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                ),
            },
            ValidatorInfo {
                address: ValidatorAddress([2; 32]),
                party_id: 2,
                weight: 1,
                ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                    &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                ),
            },
        ];

        // threshold=3, max_faulty=1, total_weight=5
        let config = DkgConfig::new(100, validators, 3, 1).unwrap();
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Only validator 0 (weight=3), which is less than required (threshold + max_faulty = 4)
        let insufficient_sigs = vec![ValidatorSignature {
            validator: config.validators[0].address.clone(),
            signature: vec![0; 96],
        }];

        let result = manager.create_certificate(&message, insufficient_sigs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient weighted signatures")
        );

        // Validator 0 (weight=3) + validator 1 (weight=1) = 4, which meets the requirement
        let sufficient_sigs = vec![
            ValidatorSignature {
                validator: config.validators[0].address.clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: config.validators[1].address.clone(),
                signature: vec![0; 96],
            },
        ];

        let result = manager.create_certificate(&message, sufficient_sigs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_certificate_unknown_validator() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Create signatures including one from an unknown validator
        let unknown_validator = ValidatorAddress([99; 32]);
        let signatures = vec![
            ValidatorSignature {
                validator: config.validators[0].address.clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: unknown_validator.clone(),
                signature: vec![0; 96],
            },
        ];

        let result = manager.create_certificate(&message, signatures);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Signature from unknown validator")
        );
    }

    #[test]
    fn test_compute_message_hash_deterministic() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();
        let dealer_address = ValidatorAddress([42; 32]);

        let hash1 = compute_message_hash(
            &message,
            &dealer_address,
            &manager.static_data.session_context,
        )
        .unwrap();

        let hash2 = compute_message_hash(
            &message,
            &dealer_address,
            &manager.static_data.session_context,
        )
        .unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_message_hash_different_for_different_dealers() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        let hash1 = compute_message_hash(
            &message,
            &ValidatorAddress([1; 32]),
            &manager.static_data.session_context,
        )
        .unwrap();

        let hash2 = compute_message_hash(
            &message,
            &ValidatorAddress([2; 32]),
            &manager.static_data.session_context,
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
        let validators: Vec<_> = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                ValidatorInfo {
                    address: ValidatorAddress([i as u8; 32]),
                    party_id: i as u16,
                    weight: weights[i],
                    ecies_public_key: public_key,
                }
            })
            .collect();

        // threshold = 3, max_faulty = 1, total_weight = 12
        // Constraint: t + 2f = 3 + 2 = 5 <= 12 ✓
        let config = DkgConfig::new(100, validators, 3, 1).unwrap();
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
                let static_data = DkgStaticData::new(
                    config.validators[i].clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    crate::bls::Bls12381PrivateKey::generate(rand::thread_rng()),
                )
                .unwrap();
                DkgManager::new(static_data)
            })
            .collect();

        // Create receiver (party 2 with weight=4 - will receive 4 shares!)
        let receiver_static = DkgStaticData::new(
            config.validators[2].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[2].clone(),
            crate::bls::Bls12381PrivateKey::generate(rand::thread_rng()),
        )
        .unwrap();
        let mut receiver_manager = DkgManager::new(receiver_static);

        // Each dealer creates a message
        let dealer_messages: Vec<_> = dealer_managers
            .iter()
            .map(|dm| dm.create_dealer_message(&mut rng).unwrap())
            .collect();

        // Receiver processes all dealer messages and creates certificates
        let mut certificates = Vec::new();
        for (i, message) in dealer_messages.iter().enumerate() {
            let dealer_address = dealer_managers[i]
                .static_data
                .validator_info
                .address
                .clone();

            // Receiver processes the message
            let _sig = receiver_manager
                .receive_dealer_message(message, dealer_address.clone())
                .unwrap();

            // Create a certificate (in practice, would collect signatures from other validators)
            // Need threshold + max_faulty = 3 + 1 = 4 weighted signatures
            // Using validators with weights: 0(3) + 1(2) = 5 weight, which is > 4 ✓
            let mock_signatures = vec![
                ValidatorSignature {
                    validator: config.validators[0].address.clone(), // weight=3
                    signature: vec![0; 96],
                },
                ValidatorSignature {
                    validator: config.validators[1].address.clone(), // weight=2
                    signature: vec![0; 96],
                },
            ];

            // Dealer creates their own certificate
            let cert = dealer_managers[i]
                .create_certificate(message, mock_signatures)
                .unwrap();
            certificates.push(cert);
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
    fn test_process_certificates_insufficient_count() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        // Only 1 certificate, but threshold is 2
        let certificates = vec![];

        let result = manager.process_certificates(&certificates);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected 2 certificates, got 0")
        );
    }

    #[test]
    fn test_process_certificates_missing_dealer_output() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        // Create certificates for dealers we haven't received messages from
        let mock_signatures = vec![ValidatorSignature {
            validator: config.validators[0].address.clone(),
            signature: vec![0; 96],
        }];

        let certificates = vec![
            DkgCertificate {
                dealer: config.validators[0].address.clone(),
                message_hash: [0; 32],
                data_availability_signatures: mock_signatures.clone(),
                dkg_signatures: mock_signatures.clone(),
                session_context: manager.static_data.session_context.clone(),
            },
            DkgCertificate {
                dealer: config.validators[1].address.clone(),
                message_hash: [0; 32],
                data_availability_signatures: mock_signatures.clone(),
                dkg_signatures: mock_signatures,
                session_context: manager.static_data.session_context.clone(),
            },
        ];

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
    async fn test_handle_incoming_share_valid() {
        // Setup: Create two validators - dealer and receiver
        let mut rng = rand::thread_rng();
        let encryption_keys: Vec<_> = (0..5)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let validators: Vec<_> = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                ValidatorInfo {
                    address: ValidatorAddress([i as u8; 32]),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                }
            })
            .collect();

        let config = DkgConfig::new(100, validators.clone(), 2, 1).unwrap();

        // Dealer (validator 0) creates a share message
        let dealer_static_data = DkgStaticData::new(
            validators[0].clone(),
            config.clone(),
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string()),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let dealer_manager = DkgManager::new(dealer_static_data);
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Receiver (validator 1) receives the share
        let receiver_static_data = DkgStaticData::new(
            validators[1].clone(),
            config.clone(),
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string()),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let mut receiver_manager = DkgManager::new(receiver_static_data);

        // Setup P2P channels
        let mut channels = crate::communication::InMemoryP2PChannels::new_network(
            validators.iter().map(|v| v.address.clone()).collect(),
        );
        let mut receiver_channel = channels.remove(&validators[1].address).unwrap();

        // Test: handle_incoming_share should send a signature back
        receiver_manager
            .handle_incoming_share(
                &mut receiver_channel,
                validators[0].address.clone(),
                &validators[0].address,
                &dealer_message,
                receiver_manager.static_data.session_context.session_id,
            )
            .await
            .unwrap();

        // Verify: Check that a signature was sent back to the dealer
        let mut dealer_channel = channels.remove(&validators[0].address).unwrap();
        let received = dealer_channel.receive().await.unwrap();
        match received.message {
            P2PMessage::DkgSignatureV1 {
                signer,
                dealer,
                session_id,
                ..
            } => {
                assert_eq!(signer, validators[1].address);
                assert_eq!(dealer, validators[0].address);
                assert_eq!(
                    session_id,
                    receiver_manager.static_data.session_context.session_id
                );
            }
            _ => panic!("Expected DkgSignatureV1 message"),
        }
    }

    #[tokio::test]
    async fn test_handle_signature_for_my_message_below_threshold() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);
        let dealer_message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Setup ordered broadcast channel
        let mut tob_channels = crate::communication::InMemoryOrderedBroadcastChannel::new_network(
            config
                .validators
                .iter()
                .map(|v| v.address.clone())
                .collect(),
        );
        let mut tob_channel = tob_channels.remove(&config.validators[0].address).unwrap();

        // Create state
        let mut state = SignatureCollectionState {
            signatures: Vec::new(),
            is_cert_published: false,
        };
        let required_sigs = 3; // threshold + max_faulty

        // Add 2 signatures (below threshold of 3)
        for i in 0..2 {
            manager
                .handle_signature_for_my_message(
                    &mut tob_channel,
                    &dealer_message,
                    config.validators[i].address.clone(),
                    vec![0; 96],
                    required_sigs,
                    &mut state,
                )
                .await
                .unwrap();
        }

        // Verify: No certificate published yet
        assert_eq!(state.signatures.len(), 2);
        assert!(!state.is_cert_published);
        assert_eq!(tob_channel.pending_messages().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_handle_signature_for_my_message_reaches_threshold() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);
        let dealer_message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Setup ordered broadcast channel
        let mut tob_channels = crate::communication::InMemoryOrderedBroadcastChannel::new_network(
            config
                .validators
                .iter()
                .map(|v| v.address.clone())
                .collect(),
        );
        let mut tob_channel = tob_channels.remove(&config.validators[0].address).unwrap();

        // Create state
        let mut state = SignatureCollectionState {
            signatures: Vec::new(),
            is_cert_published: false,
        };
        let required_sigs = 3;

        // Add exactly 3 signatures (reaches threshold)
        for i in 0..3 {
            manager
                .handle_signature_for_my_message(
                    &mut tob_channel,
                    &dealer_message,
                    config.validators[i].address.clone(),
                    vec![0; 96],
                    required_sigs,
                    &mut state,
                )
                .await
                .unwrap();
        }

        // Verify: Certificate was published
        assert_eq!(state.signatures.len(), 3);
        assert!(state.is_cert_published);
        assert_eq!(tob_channel.pending_messages().unwrap(), 1);

        // Verify the published message is a certificate
        let published = tob_channel.receive().await.unwrap();
        match published.message {
            OrderedBroadcastMessage::CertificateV1(cert) => {
                assert_eq!(cert.dealer, manager.static_data.validator_info.address);
                assert_eq!(cert.dkg_signatures.len(), 3);
            }
            _ => panic!("Expected CertificateV1 message"),
        }
    }

    #[tokio::test]
    async fn test_handle_signature_for_my_message_no_duplicate_cert() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);
        let dealer_message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Setup ordered broadcast channel
        let mut tob_channels = crate::communication::InMemoryOrderedBroadcastChannel::new_network(
            config
                .validators
                .iter()
                .map(|v| v.address.clone())
                .collect(),
        );
        let mut tob_channel = tob_channels.remove(&config.validators[0].address).unwrap();

        // Create state
        let mut state = SignatureCollectionState {
            signatures: Vec::new(),
            is_cert_published: false,
        };
        let required_sigs = 3;

        // Add 4 signatures (exceeds threshold)
        for i in 0..4 {
            manager
                .handle_signature_for_my_message(
                    &mut tob_channel,
                    &dealer_message,
                    config.validators[i].address.clone(),
                    vec![0; 96],
                    required_sigs,
                    &mut state,
                )
                .await
                .unwrap();
        }

        // Verify: Only one certificate was published (no duplicate)
        assert_eq!(state.signatures.len(), 4);
        assert!(state.is_cert_published);
        assert_eq!(tob_channel.pending_messages().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_run_dkg_weighted_validators() {
        // Test DKG with weighted validators: [3, 2, 4, 1, 2]
        let mut rng = rand::thread_rng();
        let weights = [3, 2, 4, 1, 2];
        let num_validators = weights.len();

        // Create encryption keys and validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let validators: Vec<_> = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                ValidatorInfo {
                    address: ValidatorAddress([i as u8; 32]),
                    party_id: i as u16,
                    weight: weights[i],
                    ecies_public_key: public_key,
                }
            })
            .collect();

        // Total weight = 12, threshold = 3, max_faulty = 1
        let config = DkgConfig::new(100, validators.clone(), 3, 1).unwrap();

        // Create DKG managers for each validator
        let managers: Vec<_> = validators
            .iter()
            .enumerate()
            .map(|(i, validator)| {
                let static_data = DkgStaticData::new(
                    validator.clone(),
                    config.clone(),
                    SessionContext::new(
                        100,
                        ProtocolType::DkgKeyGeneration,
                        "testchain".to_string(),
                    ),
                    encryption_keys[i].clone(),
                    crate::bls::Bls12381PrivateKey::generate(&mut rng),
                )
                .unwrap();
                DkgManager::new(static_data)
            })
            .collect();

        // Setup channels
        let mut p2p_channels = crate::communication::InMemoryP2PChannels::new_network(
            validators.iter().map(|v| v.address.clone()).collect(),
        );
        let mut tob_channels = crate::communication::InMemoryOrderedBroadcastChannel::new_network(
            validators.iter().map(|v| v.address.clone()).collect(),
        );

        // Run DKG for all validators concurrently
        let mut tasks = Vec::new();
        for (i, mut manager) in managers.into_iter().enumerate() {
            let mut p2p = p2p_channels.remove(&validators[i].address).unwrap();
            let mut tob = tob_channels.remove(&validators[i].address).unwrap();

            let task = tokio::spawn(async move {
                use rand::SeedableRng;
                let mut rng = rand::rngs::StdRng::from_entropy();
                manager.run_dkg(&mut p2p, &mut tob, &mut rng).await
            });
            tasks.push(task);
        }

        // Wait for all validators to complete DKG
        let mut outputs = Vec::new();
        for task in tasks {
            outputs.push(task.await.unwrap().unwrap());
        }

        // Verify all validators produced valid outputs
        assert_eq!(outputs.len(), num_validators);

        // All validators should have the same public key
        let first_pk = &outputs[0].public_key;
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(&output.public_key, first_pk);
            // Each validator should receive shares proportional to their weight
            assert_eq!(output.key_shares.shares.len(), weights[i] as usize);
        }
    }
}
