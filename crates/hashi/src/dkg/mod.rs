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
    SignatureBytes, ValidatorEntry, ValidatorInfo, ValidatorRegistry, ValidatorSignature,
};

const ERR_PUBLISH_CERT_FAILED: &str = "Failed to publish certificate";
const ERR_TOB_RECEIVE_FAILED: &str = "TOB channel error";

#[derive(Debug, Clone, Copy)]
enum SignatureSetType {
    DataAvailability,
    Dkg,
}

impl std::fmt::Display for SignatureSetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataAvailability => write!(f, "data availability"),
            Self::Dkg => write!(f, "DKG"),
        }
    }
}

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
        let nodes = create_nodes(&dkg_config.validator_registry);
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
            .validator_registry
            .iter()
            .map(|(addr, v)| (addr.clone(), v.weight))
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

    pub fn process_certificates(
        &self,
        validator_to_certificate: &std::collections::HashMap<ValidatorAddress, DkgCertificate>,
    ) -> DkgResult<DkgOutput> {
        let threshold = self.static_data.dkg_config.threshold;
        if validator_to_certificate.len() != threshold as usize {
            return Err(DkgError::ProtocolFailed(format!(
                "Expected {} certificates, got {}",
                threshold,
                validator_to_certificate.len()
            )));
        }
        // TODO: Handle missing messages and invalid shares
        let mut outputs = Vec::new();
        for cert in validator_to_certificate.values() {
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
        if request.session_id != self.static_data.session_context.session_id {
            return Err(DkgError::InvalidMessage {
                sender: request.dealer.clone(),
                reason: format!(
                    "Session ID mismatch: expected {:?}, got {:?}",
                    self.static_data.session_context.session_id, request.session_id
                ),
            });
        }
        let validator_signature =
            self.receive_dealer_message(&request.message, request.dealer.clone())?;
        Ok(SendShareResponse {
            signer: validator_signature.validator,
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
        // TODO: Add timeout handling when adding RPC layer
        for validator_address in self.static_data.dkg_config.validator_registry.keys() {
            if validator_address != &my_address {
                let response = match p2p_channel
                    .send_share(
                        validator_address,
                        SendShareRequest {
                            session_id,
                            dealer: my_address.clone(),
                            message: Box::new(dealer_message.clone()),
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
                if &response.signer != validator_address {
                    tracing::info!(
                        "Response signer mismatch: expected {:?}, got {:?}",
                        validator_address,
                        response.signer
                    );
                    continue;
                }
                // TODO: Add cryptographic verification of response.signature
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
        let mut validator_to_certificate = std::collections::HashMap::new();
        loop {
            if validator_to_certificate.len() == threshold as usize {
                break;
            }
            let tob_msg = ordered_broadcast_channel.receive().await.map_err(|e| {
                DkgError::ProtocolFailed(format!("{}: {}", ERR_TOB_RECEIVE_FAILED, e))
            })?;
            if let OrderedBroadcastMessage::CertificateV1(cert) = tob_msg.message {
                match validate_certificate(
                    &cert,
                    &self.static_data,
                    &self.runtime_state.dealer_messages,
                ) {
                    Ok(()) => {
                        validator_to_certificate.insert(cert.dealer.clone(), cert);
                    }
                    Err(e) => {
                        tracing::info!("Invalid certificate from {:?}: {}", cert.dealer, e);
                        continue;
                    }
                }
            }
        }
        let output = self.process_certificates(&validator_to_certificate)?;
        Ok(output)
    }
}

fn validate_certificate(
    cert: &DkgCertificate,
    static_data: &DkgStaticData,
    dealer_messages: &BTreeMap<ValidatorAddress, avss::Message>,
) -> DkgResult<()> {
    if cert.session_context.session_id != static_data.session_context.session_id {
        return Err(DkgError::InvalidCertificate(format!(
            "Session ID mismatch: expected {:?}, got {:?}",
            static_data.session_context.session_id, cert.session_context.session_id
        )));
    }
    if !static_data
        .dkg_config
        .validator_registry
        .contains_key(&cert.dealer)
    {
        return Err(DkgError::InvalidCertificate(format!(
            "Unknown dealer: {:?}",
            cert.dealer
        )));
    }
    validate_signature_set(
        &cert.data_availability_signatures,
        SignatureSetType::DataAvailability,
        static_data
            .dkg_config
            .required_data_availability_signatures() as u16,
        &static_data.validator_weights,
    )?;
    validate_signature_set(
        &cert.dkg_signatures,
        SignatureSetType::Dkg,
        static_data.dkg_config.required_dkg_signatures() as u16,
        &static_data.validator_weights,
    )?;
    validate_message_hash(cert, dealer_messages, &static_data.session_context)?;
    Ok(())
}

fn validate_message_hash(
    cert: &DkgCertificate,
    dealer_messages: &BTreeMap<ValidatorAddress, avss::Message>,
    session_context: &SessionContext,
) -> DkgResult<()> {
    let message = dealer_messages.get(&cert.dealer).ok_or_else(|| {
        DkgError::InvalidCertificate(format!(
            "Dealer message not yet received from {:?}",
            cert.dealer
        ))
    })?;
    let expected_hash = compute_message_hash(message, &cert.dealer, session_context)?;
    if cert.message_hash != expected_hash {
        return Err(DkgError::InvalidCertificate(format!(
            "Message hash mismatch for dealer {:?}",
            cert.dealer
        )));
    }
    Ok(())
}

fn validate_signature_set(
    signatures: &[ValidatorSignature],
    signature_type: SignatureSetType,
    required_weight: u16,
    validator_weights: &BTreeMap<ValidatorAddress, u16>,
) -> DkgResult<()> {
    let mut seen_signers = std::collections::HashSet::new();
    let mut total_weight = 0u16;
    for sig in signatures {
        if !seen_signers.insert(&sig.validator) {
            return Err(DkgError::InvalidCertificate(format!(
                "Duplicate signer in {}: {:?}",
                signature_type, sig.validator
            )));
        }
        let weight = validator_weights.get(&sig.validator).ok_or_else(|| {
            DkgError::InvalidCertificate(format!(
                "Unknown signer in {}: {:?}",
                signature_type, sig.validator
            ))
        })?;
        total_weight = total_weight
            .checked_add(*weight)
            .ok_or_else(|| DkgError::ProtocolFailed("Signature weight overflow".to_string()))?;
    }
    if total_weight < required_weight {
        return Err(DkgError::InvalidCertificate(format!(
            "Insufficient {} signature weight: got {}, need {}",
            signature_type, total_weight, required_weight
        )));
    }
    Ok(())
}

fn create_nodes(validators: &ValidatorRegistry) -> Nodes<EncryptionGroupElement> {
    let nodes: Vec<_> = validators
        .values()
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
        let weight =
            validator_weights
                .get(&sig.validator)
                .ok_or_else(|| DkgError::InvalidMessage {
                    sender: sig.validator.clone(),
                    reason: "Signature from unknown validator".to_string(),
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

    fn create_test_validator(party_id: u16) -> ValidatorEntry {
        let private_key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let public_key = fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(&private_key);
        let address = ValidatorAddress([party_id as u8; 32]);
        let info = ValidatorInfo {
            address: address.clone(),
            party_id,
            weight: 1,
            ecies_public_key: public_key,
        };
        (address, info)
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
        DkgConfig::new(100, validators, THRESHOLD, MAX_FAULTY).unwrap()
    }

    fn create_test_static_data(validator_index: u16, dkg_config: DkgConfig) -> DkgStaticData {
        let validator_address = ValidatorAddress([validator_index as u8; 32]);
        let validator_info = dkg_config
            .validator_registry
            .get(&validator_address)
            .expect("validator not found")
            .clone();
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
        let validators: ValidatorRegistry = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators.clone(), 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        let validator_address = ValidatorAddress([validator_index as u8; 32]);
        let static_data = DkgStaticData::new(
            validators.get(&validator_address).unwrap().clone(),
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

    struct SucceedingP2PChannel {}

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for SucceedingP2PChannel {
        async fn send_share(
            &self,
            recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Ok(SendShareResponse {
                signer: recipient.clone(),
                signature: Vec::new(),
            })
        }
    }

    struct WrongSignerP2PChannel {
        wrong_signer: ValidatorAddress,
    }

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for WrongSignerP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            Ok(SendShareResponse {
                signer: self.wrong_signer.clone(),
                signature: Vec::new(),
            })
        }
    }

    struct UnknownValidatorP2PChannel {}

    #[async_trait::async_trait]
    impl crate::communication::P2PChannel for UnknownValidatorP2PChannel {
        async fn send_share(
            &self,
            _recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            // Return an address that's not in the validator registry
            Ok(SendShareResponse {
                signer: ValidatorAddress([99; 32]),
                signature: Vec::new(),
            })
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
            recipient: &ValidatorAddress,
            _request: SendShareRequest,
        ) -> crate::communication::ChannelResult<SendShareResponse> {
            let mut count = self.fail_count.lock().unwrap();
            if *count < self.max_failures {
                *count += 1;
                Err(crate::communication::ChannelError::SendFailed(
                    "network error".to_string(),
                ))
            } else {
                Ok(SendShareResponse {
                    signer: recipient.clone(),
                    signature: Vec::new(),
                })
            }
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
        assert_eq!(static_data.dkg_config.validator_registry.len(), 5);
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
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 0) with its encryption key
        let dealer_address = ValidatorAddress([0; 32]);
        let dealer_static = DkgStaticData::new(
            config
                .validator_registry
                .get(&dealer_address)
                .unwrap()
                .clone(),
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
        let receiver_address = ValidatorAddress([1; 32]);
        let receiver_static = DkgStaticData::new(
            config
                .validator_registry
                .get(&receiver_address)
                .unwrap()
                .clone(),
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
        let signatures: Vec<_> = config
            .validator_registry
            .values()
            .take(2)
            .map(|v| ValidatorSignature {
                validator: v.address.clone(),
                signature: vec![0; 96],
            })
            .collect();

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
        let signatures: Vec<_> = config
            .validator_registry
            .values()
            .take(required_sigs)
            .map(|v| ValidatorSignature {
                validator: v.address.clone(),
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
        let validators = vec![
            (
                ValidatorAddress([0; 32]),
                ValidatorInfo {
                    address: ValidatorAddress([0; 32]),
                    party_id: 0,
                    weight: 3, // Heavy weight
                    ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                        &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                    ),
                },
            ),
            (
                ValidatorAddress([1; 32]),
                ValidatorInfo {
                    address: ValidatorAddress([1; 32]),
                    party_id: 1,
                    weight: 1,
                    ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                        &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                    ),
                },
            ),
            (
                ValidatorAddress([2; 32]),
                ValidatorInfo {
                    address: ValidatorAddress([2; 32]),
                    party_id: 2,
                    weight: 1,
                    ecies_public_key: fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(
                        &PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng()),
                    ),
                },
            ),
        ]
        .into_iter()
        .collect();

        // threshold=3, max_faulty=1, total_weight=5
        let config = DkgConfig::new(100, validators, 3, 1).unwrap();
        let static_data = create_test_static_data(0, config.clone());
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Only validator 0 (weight=3), which is less than required (threshold + max_faulty = 4)
        let addr0 = ValidatorAddress([0; 32]);
        let insufficient_sigs = vec![ValidatorSignature {
            validator: config
                .validator_registry
                .get(&addr0)
                .unwrap()
                .address
                .clone(),
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
        let addr1 = ValidatorAddress([1; 32]);
        let sufficient_sigs = vec![
            ValidatorSignature {
                validator: config
                    .validator_registry
                    .get(&addr0)
                    .unwrap()
                    .address
                    .clone(),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: config
                    .validator_registry
                    .get(&addr1)
                    .unwrap()
                    .address
                    .clone(),
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
        let known_validator = config.validator_registry.values().next().unwrap();
        let signatures = vec![
            ValidatorSignature {
                validator: known_validator.address.clone(),
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
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: weights[i],
                    ecies_public_key: public_key,
                };
                (address, info)
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
                let addr = ValidatorAddress([i as u8; 32]);
                let static_data = DkgStaticData::new(
                    config.validator_registry.get(&addr).unwrap().clone(),
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
        let addr2 = ValidatorAddress([2; 32]);
        let receiver_static = DkgStaticData::new(
            config.validator_registry.get(&addr2).unwrap().clone(),
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
        let mut certificates = std::collections::HashMap::new();
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
            let addr0 = &ValidatorAddress([0; 32]);
            let addr1 = &ValidatorAddress([1; 32]);
            let mock_signatures = vec![
                ValidatorSignature {
                    validator: config
                        .validator_registry
                        .get(addr0)
                        .unwrap()
                        .address
                        .clone(), // weight=3
                    signature: vec![0; 96],
                },
                ValidatorSignature {
                    validator: config
                        .validator_registry
                        .get(addr1)
                        .unwrap()
                        .address
                        .clone(), // weight=2
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
    fn test_process_certificates_insufficient_count() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        // Only 0 certificates, but threshold is 2
        let certificates = std::collections::HashMap::new();

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
        let addr0 = &ValidatorAddress([0; 32]);
        let addr1 = &ValidatorAddress([1; 32]);

        let mock_signatures = vec![ValidatorSignature {
            validator: config
                .validator_registry
                .get(addr0)
                .unwrap()
                .address
                .clone(),
            signature: vec![0; 96],
        }];

        let cert0 = DkgCertificate {
            dealer: config
                .validator_registry
                .get(addr0)
                .unwrap()
                .address
                .clone(),
            message_hash: [0; 32],
            data_availability_signatures: mock_signatures.clone(),
            dkg_signatures: mock_signatures.clone(),
            session_context: manager.static_data.session_context.clone(),
        };
        let cert1 = DkgCertificate {
            dealer: config
                .validator_registry
                .get(addr1)
                .unwrap()
                .address
                .clone(),
            message_hash: [0; 32],
            data_availability_signatures: mock_signatures.clone(),
            dkg_signatures: mock_signatures,
            session_context: manager.static_data.session_context.clone(),
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
        let weights = [3, 2, 4, 1, 2];
        let num_validators = weights.len();

        // Create encryption keys and BLS keys for all validators
        let encryption_keys: Vec<_> = (0..num_validators)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();

        let bls_keys: Vec<_> = (0..num_validators)
            .map(|_| crate::bls::Bls12381PrivateKey::generate(&mut rng))
            .collect();

        let validators: ValidatorRegistry = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: weights[i],
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        // Total weight = 12, threshold = 3, max_faulty = 1
        let config = DkgConfig::new(100, validators, 3, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                let validator = config.validator_registry.get(&address).unwrap();
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
        let mock_p2p = MockP2PChannel::new(other_managers);

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
                other_mgr.runtime_state.dealer_outputs.contains_key(&addr0),
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
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, 2, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create manager for validator 0
        let addr0 = &ValidatorAddress([0; 32]);
        let static_data = DkgStaticData::new(
            config.validator_registry.get(addr0).unwrap().clone(),
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
                let addr = ValidatorAddress([i as u8; 32]);
                let validator_info = config.validator_registry.get(&addr).unwrap();
                let static_data = DkgStaticData::new(
                    validator_info.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                (addr, DkgManager::new(static_data))
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
        let addr0 = ValidatorAddress([0; 32]);
        assert!(
            test_manager
                .runtime_state
                .dealer_outputs
                .contains_key(&addr0)
        );

        // Verify other validators received dealer message via P2P
        let other_managers = mock_p2p.managers.lock().unwrap();
        for i in 1..num_validators {
            let addr = ValidatorAddress([i as u8; 32]);
            let other_mgr = other_managers.get(&addr).unwrap();
            assert!(
                other_mgr.runtime_state.dealer_outputs.contains_key(&addr0),
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
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                let validator_info = config.validator_registry.get(&address).unwrap();
                let static_data = DkgStaticData::new(
                    validator_info.clone(),
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
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());
        let wrong_session_context =
            SessionContext::new(200, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                let validator_info = config.validator_registry.get(&address).unwrap();
                let static_data = DkgStaticData::new(
                    validator_info.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                DkgManager::new(static_data)
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

        // Create invalid certificates with wrong session ID
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
        // Make it invalid by changing session context
        invalid_cert.session_context = wrong_session_context.clone();

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
        let output = test_manager.run_as_party(&mut mock_tob).await.unwrap();

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
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, threshold, 1).unwrap();
        let session_context =
            SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testchain".to_string());

        // Create all managers
        let mut managers: Vec<_> = (0..num_validators)
            .map(|i| {
                let address = ValidatorAddress([i as u8; 32]);
                let validator_info = config.validator_registry.get(&address).unwrap();
                let static_data = DkgStaticData::new(
                    validator_info.clone(),
                    config.clone(),
                    session_context.clone(),
                    encryption_keys[i].clone(),
                    bls_keys[i].clone(),
                )
                .unwrap();
                DkgManager::new(static_data)
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
        let output = test_manager.run_as_party(&mut mock_tob).await.unwrap();

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
    #[tracing_test::traced_test]
    async fn test_run_as_dealer_signer_mismatch_rejected() {
        let mut rng = rand::thread_rng();
        let (mut test_manager, _) = create_manager_with_valid_keys(0, 5);
        let mut mock_tob = MockOrderedBroadcastChannel::new(Vec::new());

        // Use wrong signer - always returns dealer's address instead of recipient's
        let wrong_signer = test_manager.static_data.validator_info.address.clone();
        let wrong_signer_p2p = WrongSignerP2PChannel { wrong_signer };

        let result = test_manager
            .run_as_dealer(&wrong_signer_p2p, &mut mock_tob, &mut rng)
            .await;

        assert!(result.is_ok());
        assert_eq!(mock_tob.published_count(), 0);
        assert!(logs_contain("Response signer mismatch"));
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
        let validators = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, private_key)| {
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 1) with its encryption key
        let dealer_address = ValidatorAddress([1; 32]);
        let dealer_data = DkgStaticData::new(
            config
                .validator_registry
                .get(&dealer_address)
                .unwrap()
                .clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let dealer_manager = DkgManager::new(dealer_data);

        // Create receiver (party 0) with its encryption key
        let receiver_address = ValidatorAddress([0; 32]);
        let receiver_data = DkgStaticData::new(
            config
                .validator_registry
                .get(&receiver_address)
                .unwrap()
                .clone(),
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
        let sender = dealer_address.clone();
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
    }

    #[tokio::test]
    async fn test_handle_send_share_request_session_id_mismatch() {
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
                let public_key =
                    fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(private_key);
                let address = ValidatorAddress([i as u8; 32]);
                let info = ValidatorInfo {
                    address: address.clone(),
                    party_id: i as u16,
                    weight: 1,
                    ecies_public_key: public_key,
                };
                (address, info)
            })
            .collect();

        let config = DkgConfig::new(100, validators, 2, 1).unwrap();
        let session_context = SessionContext::new(
            config.epoch,
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );

        // Create dealer (party 1) with its encryption key
        let dealer_address = ValidatorAddress([1; 32]);
        let dealer_data = DkgStaticData::new(
            config
                .validator_registry
                .get(&dealer_address)
                .unwrap()
                .clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[1].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let dealer_manager = DkgManager::new(dealer_data);

        // Create receiver (party 0) with its encryption key
        let receiver_address = ValidatorAddress([0; 32]);
        let receiver_data = DkgStaticData::new(
            config
                .validator_registry
                .get(&receiver_address)
                .unwrap()
                .clone(),
            config.clone(),
            session_context.clone(),
            encryption_keys[0].clone(),
            crate::bls::Bls12381PrivateKey::generate(&mut rng),
        )
        .unwrap();
        let mut receiver_manager = DkgManager::new(receiver_data);

        // Dealer creates a message
        let dealer_message = dealer_manager.create_dealer_message(&mut rng).unwrap();

        // Create a request with WRONG session_id (different epoch)
        let wrong_session_context = SessionContext::new(
            999, // Wrong epoch
            ProtocolType::DkgKeyGeneration,
            "testchain".to_string(),
        );
        let request = SendShareRequest {
            session_id: wrong_session_context.session_id,
            dealer: dealer_address.clone(),
            message: Box::new(dealer_message.clone()),
        };

        // Receiver handles the request - should fail
        let result = receiver_manager.handle_send_share_request(request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Session ID mismatch"));
    }

    mod validation_test_utils {
        use super::*;

        pub fn create_test_validators_with_weights(weights: &[u16]) -> ValidatorRegistry {
            weights
                .iter()
                .enumerate()
                .map(|(i, &weight)| {
                    let private_key =
                        PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
                    let public_key =
                        fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(&private_key);
                    let address = ValidatorAddress([i as u8; 32]);
                    let info = ValidatorInfo {
                        address: address.clone(),
                        party_id: i as u16,
                        weight,
                        ecies_public_key: public_key,
                    };
                    (address, info)
                })
                .collect()
        }

        pub fn create_test_config_with_weights(
            weights: &[u16],
            threshold: u16,
            max_faulty: u16,
        ) -> DkgConfig {
            let validators = create_test_validators_with_weights(weights);
            DkgConfig::new(100, validators, threshold, max_faulty).unwrap()
        }

        pub fn create_validator_weights(config: &DkgConfig) -> BTreeMap<ValidatorAddress, u16> {
            config
                .validator_registry
                .iter()
                .map(|(addr, info)| (addr.clone(), info.weight))
                .collect()
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

            let result = validate_signature_set(
                &signatures,
                SignatureSetType::DataAvailability,
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

            let result =
                validate_signature_set(&signatures, SignatureSetType::Dkg, 5, &validator_weights);
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

            let result = validate_signature_set(
                &signatures,
                SignatureSetType::DataAvailability,
                1,
                &validator_weights,
            );
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

            let result = validate_signature_set(
                &signatures,
                SignatureSetType::Dkg,
                6, // require 6, but only have 5
                &validator_weights,
            );
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("Insufficient"));
            assert!(err_msg.contains("got 5, need 6"));
        }

        #[test]
        fn test_signature_weight_overflow() {
            let mut validator_weights = BTreeMap::new();
            let addr0 = ValidatorAddress([0; 32]);
            let addr1 = ValidatorAddress([1; 32]);
            validator_weights.insert(addr0.clone(), u16::MAX);
            validator_weights.insert(addr1.clone(), 1);

            // Create signatures from both validators (will cause overflow: u16::MAX + 1)
            let signatures = vec![
                ValidatorSignature {
                    validator: addr0,
                    signature: vec![0u8; 96],
                },
                ValidatorSignature {
                    validator: addr1,
                    signature: vec![0u8; 96],
                },
            ];

            let result = validate_signature_set(
                &signatures,
                SignatureSetType::DataAvailability,
                1,
                &validator_weights,
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Signature weight overflow")
            );
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
            let static_data = create_test_static_data(0, config);
            let manager = DkgManager::new(static_data);
            let dealer_message = manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Compute correct hash
            let message_hash =
                compute_message_hash(&dealer_message, &dealer_addr, &session_context).unwrap();

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash,
                data_availability_signatures: vec![],
                dkg_signatures: vec![],
                session_context: session_context.clone(),
            };

            let mut dealer_messages = BTreeMap::new();
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
                data_availability_signatures: vec![],
                dkg_signatures: vec![],
                session_context: session_context.clone(),
            };

            let dealer_messages = BTreeMap::new(); // Empty - message not received

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
            let static_data = create_test_static_data(0, config);
            let manager = DkgManager::new(static_data);
            let dealer_message = manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Create cert with wrong hash
            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash: [99; 32], // Wrong hash
                data_availability_signatures: vec![],
                dkg_signatures: vec![],
                session_context: session_context.clone(),
            };

            let mut dealer_messages = BTreeMap::new();
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
            DkgStaticData,
            BTreeMap<ValidatorAddress, avss::Message>,
        ) {
            let weights = vec![2, 2, 2, 2, 2]; // 5 validators
            let config = create_test_config_with_weights(&weights, 3, 1);

            let mut rng = rand::thread_rng();
            let temp_static_data = create_test_static_data(0, config.clone());
            let temp_manager = DkgManager::new(temp_static_data);
            let dealer_message = temp_manager.create_dealer_message(&mut rng).unwrap();
            let dealer_addr = ValidatorAddress([0; 32]);

            // Create the final static_data that we'll return
            let static_data = create_test_static_data(0, config.clone());
            let session_context = &static_data.session_context;

            let message_hash =
                compute_message_hash(&dealer_message, &dealer_addr, session_context).unwrap();

            // Create sufficient signatures (4 validators with weight 2 each = 8)
            // DA requires 2f+1 = 3, DKG requires t+f = 4
            let da_sigs = create_test_signatures(&[0, 1, 2], &config); // weight = 6 >= 3
            let dkg_sigs = create_test_signatures(&[0, 1, 2, 3], &config); // weight = 8 >= 4

            let cert = DkgCertificate {
                dealer: dealer_addr.clone(),
                message_hash,
                data_availability_signatures: da_sigs,
                dkg_signatures: dkg_sigs,
                session_context: session_context.clone(),
            };

            let mut dealer_messages = BTreeMap::new();
            dealer_messages.insert(dealer_addr, dealer_message);

            (cert, static_data, dealer_messages)
        }

        #[test]
        fn test_valid_certificate() {
            let (cert, static_data, dealer_messages) = create_valid_cert_and_data();
            let result = validate_certificate(&cert, &static_data, &dealer_messages);
            assert!(result.is_ok());
        }

        #[test]
        fn test_session_id_mismatch() {
            let (mut cert, static_data, dealer_messages) = create_valid_cert_and_data();

            // Change session ID
            cert.session_context = SessionContext::new(
                200, // Different epoch
                ProtocolType::DkgKeyGeneration,
                "test".to_string(),
            );

            let result = validate_certificate(&cert, &static_data, &dealer_messages);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Session ID mismatch")
            );
        }

        #[test]
        fn test_unknown_dealer() {
            let (mut cert, static_data, dealer_messages) = create_valid_cert_and_data();

            // Set dealer to unknown address
            cert.dealer = ValidatorAddress([99; 32]);

            let result = validate_certificate(&cert, &static_data, &dealer_messages);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Unknown dealer"));
        }

        #[test]
        fn test_invalid_da_signatures() {
            let (mut cert, static_data, dealer_messages) = create_valid_cert_and_data();

            // Empty DA signatures - insufficient weight
            cert.data_availability_signatures = vec![];

            let result = validate_certificate(&cert, &static_data, &dealer_messages);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Insufficient data availability signature weight")
            );
        }

        #[test]
        fn test_invalid_dkg_signatures() {
            let (mut cert, static_data, dealer_messages) = create_valid_cert_and_data();

            // Empty DKG signatures - insufficient weight
            cert.dkg_signatures = vec![];

            let result = validate_certificate(&cert, &static_data, &dealer_messages);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Insufficient DKG signature weight")
            );
        }

        #[test]
        fn test_invalid_message_hash() {
            let (mut cert, static_data, dealer_messages) = create_valid_cert_and_data();

            // Wrong message hash
            cert.message_hash = [99; 32];

            let result = validate_certificate(&cert, &static_data, &dealer_messages);
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
