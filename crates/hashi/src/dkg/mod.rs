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
    Authenticated, DkgCertificate, DkgConfig, DkgError, DkgOutput, DkgResult,
    EncryptionGroupElement, MessageApproval, MessageHash, MessageType, OrderedBroadcastMessage,
    P2PMessage, SendShareRequest, SendShareResponse, SessionContext, SessionId, SighashType,
    SignatureBytes, ValidatorInfo, ValidatorSignature,
};

const ERR_SEND_SHARE_FAILED: &str = "Failed to send share";
const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";
const ERR_TOB_RECEIVE_FAILED: &str = "TOB channel error";

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

    pub fn handle_send_share_request(
        &mut self,
        request: SendShareRequest,
    ) -> DkgResult<SendShareResponse> {
        let dealer = request.dealer.clone();
        let validator_signature = self.receive_dealer_message(&request.message, dealer.clone())?;
        Ok(SendShareResponse {
            signer: validator_signature.validator,
            message_hash: compute_message_hash(
                &request.message,
                &dealer,
                &self.static_data.session_context,
            )?,
            signature: validator_signature.signature,
        })
    }

    pub async fn run_as_dealer(
        &mut self,
        p2p_channel: &impl crate::communication::P2PChannel,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<()> {
        let threshold = self.static_data.dkg_config.threshold;
        let max_faulty = self.static_data.dkg_config.max_faulty;
        let required_sigs = threshold + max_faulty;
        let my_address = self.static_data.validator_info.address.clone();
        let session_id = self.static_data.session_context.session_id;
        let dealer_message = self.create_dealer_message(rng)?;
        self.receive_dealer_message(&dealer_message, my_address.clone())?;
        let mut signatures = Vec::new();
        // TODO: Consider sending RPC's in parallel
        for validator in &self.static_data.dkg_config.validators {
            if validator.address != my_address {
                let response = p2p_channel
                    .send_share(
                        &validator.address,
                        SendShareRequest {
                            session_id,
                            dealer: my_address.clone(),
                            message: Box::new(dealer_message.clone()),
                        },
                    )
                    .await
                    .map_err(|e| {
                        DkgError::ProtocolFailed(format!("{}: {}", ERR_SEND_SHARE_FAILED, e))
                    })?;
                signatures.push(ValidatorSignature {
                    validator: response.signer,
                    signature: response.signature,
                });
            }
        }
        if signatures.len() >= required_sigs as usize {
            let cert = self.create_certificate(&dealer_message, signatures)?;
            ordered_broadcast_channel
                .publish(OrderedBroadcastMessage::CertificateV1(cert))
                .await
                .map_err(|e| {
                    DkgError::ProtocolFailed(format!("{}: {}", ERR_PUBLISH_CERT_FAILED, e))
                })?;
        }
        Ok(())
    }

    pub async fn run_as_party(
        &mut self,
        ordered_broadcast_channel: &mut impl crate::communication::OrderedBroadcastChannel<
            OrderedBroadcastMessage,
        >,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.static_data.dkg_config.threshold;
        let mut certificates = Vec::new();
        loop {
            let have_all_dealer_messages = certificates.iter().all(|cert: &DkgCertificate| {
                self.runtime_state.dealer_outputs.contains_key(&cert.dealer)
            });
            if certificates.len() >= threshold as usize && have_all_dealer_messages {
                break;
            }
            let tob_msg = ordered_broadcast_channel.receive().await.map_err(|e| {
                DkgError::ProtocolFailed(format!("{}: {}", ERR_TOB_RECEIVE_FAILED, e))
            })?;
            if let OrderedBroadcastMessage::CertificateV1(cert) = tob_msg.message {
                // TODO: Validate certificate signatures and check session_id matches
                certificates.push(cert);
            }
        }
        let output = self.process_certificates(&certificates)?;
        Ok(output)
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

    struct MockP2PChannel {
        managers: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<ValidatorAddress, DkgManager>>,
        >,
    }

    impl MockP2PChannel {
        fn new(managers: std::collections::HashMap<ValidatorAddress, DkgManager>) -> Self {
            Self {
                managers: std::sync::Arc::new(std::sync::Mutex::new(managers)),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for MockP2PChannel {
        async fn send_share(
            &self,
            recipient: &ValidatorAddress,
            request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            let mut managers = self.managers.lock().unwrap();
            let manager = managers.get_mut(recipient).ok_or_else(|| {
                crate::communication::ChannelError::SendFailed(format!(
                    "Recipient {:?} not found",
                    recipient
                ))
            })?;
            manager.handle_send_share_request(request).map_err(|e| {
                crate::communication::ChannelError::SendFailed(format!("Handler failed: {}", e))
            })
        }
    }

    struct MockOrderedBroadcastChannel {
        certificates: std::sync::Mutex<std::collections::VecDeque<DkgCertificate>>,
    }

    impl MockOrderedBroadcastChannel {
        fn new(certificates: Vec<DkgCertificate>) -> Self {
            Self {
                certificates: std::sync::Mutex::new(certificates.into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::communication::OrderedBroadcastChannel<OrderedBroadcastMessage>
        for MockOrderedBroadcastChannel
    {
        async fn publish(
            &self,
            _message: OrderedBroadcastMessage,
        ) -> crate::communication::ChannelResult<()> {
            Ok(())
        }

        async fn receive(
            &mut self,
        ) -> crate::communication::ChannelResult<
            crate::communication::AuthenticatedMessage<OrderedBroadcastMessage>,
        > {
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
            Ok(crate::communication::AuthenticatedMessage {
                sender: cert.dealer.clone(),
                message: OrderedBroadcastMessage::CertificateV1(cert),
            })
        }

        async fn try_receive_timeout(
            &mut self,
            _duration: std::time::Duration,
        ) -> crate::communication::ChannelResult<
            Option<crate::communication::AuthenticatedMessage<OrderedBroadcastMessage>>,
        > {
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
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let static_data = DkgStaticData::new(
            validators[validator_index].clone(),
            config,
            session_context,
            encryption_keys[validator_index].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();

        (DkgManager::new(static_data), encryption_keys)
    }

    struct FailingP2PChannel {
        error_message: String,
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for FailingP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Err(crate::communication::ChannelError::SendFailed(
                self.error_message.clone(),
            ))
        }
    }

    struct SucceedingP2PChannel {
        sender_address: ValidatorAddress,
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for SucceedingP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Ok(SendShareResponse {
                signer: self.sender_address.clone(),
                message_hash: [0u8; 32],
                signature: Vec::new(),
            })
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
        ) -> crate::communication::ChannelResult<
            crate::communication::AuthenticatedMessage<OrderedBroadcastMessage>,
        > {
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
        ) -> crate::communication::ChannelResult<
            Option<crate::communication::AuthenticatedMessage<OrderedBroadcastMessage>>,
        > {
            unreachable!()
        }

        fn pending_messages(&self) -> Option<usize> {
            Some(0)
        }
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
    async fn test_run_dkg() {
        let mut rng = rand::thread_rng();
        let weights = [3, 2, 4, 1, 2];
        let num_validators = weights.len();

        // Create encryption keys and BLS keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
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
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = validators
            .iter()
            .enumerate()
            .map(|(i, validator)| {
                let static_data = DkgStaticData::new(
                    validator.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                DkgManager::new(static_data)
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
            let dealer_addr = validators[dealer_idx].address.clone();

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
            .map(|(idx, mgr)| (validators[idx + 1].address.clone(), mgr))
            .collect();
        let mock_p2p = MockP2PChannel::new(other_managers);

        // Pre-populate validator 0's manager with dealer outputs from validators 1-4
        for j in 1..num_validators {
            test_manager
                .receive_dealer_message(&dealer_messages[j], validators[j].address.clone())
                .unwrap();
        }

        // Create mock ordered broadcast channel with all certificates
        let mut mock_tob = MockOrderedBroadcastChannel::new(certificates.clone());

        // Call run_as_dealer() and run_as_party() for validator 0
        test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await
            .unwrap();
        let output = test_manager.run_as_party(&mut mock_tob).await.unwrap();

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
            Some(certificates.len() - config.threshold as usize),
            "TOB should have consumed exactly threshold certificates"
        );

        // Verify that other validators (in the mock P2P channel) received and processed validator 0's dealer message
        let other_managers = mock_p2p.managers.lock().unwrap();
        for j in 1..num_validators {
            let other_mgr = other_managers.get(&validators[j].address).unwrap();
            assert!(
                other_mgr
                    .runtime_state
                    .dealer_outputs
                    .contains_key(&validators[0].address),
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
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create manager for validator 0
        let static_data = DkgStaticData::new(
            validators[0].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            bls_keys[0].clone(),
        )
        .unwrap();
        let mut test_manager = DkgManager::new(static_data);

        // Create managers for other validators
        let other_managers: std::collections::HashMap<_, _> = (1..num_validators)
            .map(|i| {
                let static_data = DkgStaticData::new(
                    validators[i].clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                (validators[i].address.clone(), DkgManager::new(static_data))
            })
            .collect();

        let mock_p2p = MockP2PChannel::new(other_managers);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Call run_as_dealer()
        let result = test_manager
            .run_as_dealer(&mock_p2p, &mut mock_tob, &mut rng)
            .await;

        // Verify success
        assert!(result.is_ok());

        // Verify own dealer output is stored
        assert!(
            test_manager
                .runtime_state
                .dealer_outputs
                .contains_key(&validators[0].address)
        );

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let other_mgr = other_managers.get(&validators[i].address).unwrap();
            assert!(
                other_mgr
                    .runtime_state
                    .dealer_outputs
                    .contains_key(&validators[0].address),
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

        let config = DkgConfig::new(100, validators.clone(), threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = validators
            .iter()
            .enumerate()
            .map(|(i, validator)| {
                let static_data = DkgStaticData::new(
                    validator.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                DkgManager::new(static_data)
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
            let dealer_addr = validators[dealer_idx].address.clone();

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
        let output = test_manager.run_as_party(&mut mock_tob).await.unwrap();

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

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(ERR_SEND_SHARE_FAILED));
        assert!(err.to_string().contains("network error"));
    }

    #[tokio::test]
    async fn test_run_as_dealer_tob_publish_error() {
        let mut rng = rand::thread_rng();
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let succeeding_p2p = SucceedingP2PChannel {
            sender_address: test_manager.static_data.validator_info.address.clone(),
        };

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
    async fn test_run_as_party_tob_receive_error() {
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);

        let mut failing_tob = FailingOrderedBroadcastChannel {
            error_message: "receive timeout".to_string(),
            fail_on_publish: false,
            fail_on_receive: true,
        };

        let result = test_manager.run_as_party(&mut failing_tob).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(ERR_TOB_RECEIVE_FAILED));
        assert!(err.to_string().contains("receive timeout"));
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

        // Create dealer (party 1) with its encryption key
        let dealer_data = DkgStaticData::new(
            config.validators[1].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let dealer_manager = DkgManager::new(dealer_data);

        // Create receiver (party 0) with its encryption key
        let receiver_data = DkgStaticData::new(
            config.validators[0].clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let mut receiver_manager = DkgManager::new(receiver_data);

        // Dealer creates a message
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Create a request as if dealer sent it to receiver
        let sender = config.validators[1].address.clone();
        let request = SendShareRequest {
            session_id: session_context.session_id,
            dealer: sender.clone(),
            message: Box::new(dealer_message.clone()),
        };

        // Receiver handles the request
        let response = receiver_manager.handle_send_share_request(request).unwrap();

        // Verify response
        assert_eq!(
            response.signer,
            receiver_manager.static_data.validator_info.address
        );
        assert_eq!(response.signature.len(), 96); // BLS signature size
        // message_hash should match what we computed
        let expected_hash =
            compute_message_hash(&dealer_message, &sender, &session_context).unwrap();
        assert_eq!(response.message_hash, expected_hash);
    }
}
