//! Distributed Key Generation (DKG) module for Hashi bridge

pub mod interfaces;
pub mod types;

use crate::types::ValidatorAddress;
use fastcrypto::groups::Scalar;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use std::collections::BTreeMap;
use sui_crypto::Signer;

pub use types::{
    DkgCertificate, DkgConfig, DkgError, DkgOutput, DkgResult, MessageApproval, MessageHash,
    MessageType, OrderedBroadcastMessage, P2PMessage, SessionContext, SessionId, SighashType,
    SignatureBytes, ValidatorInfo, ValidatorSignature,
};

pub struct DkgStaticData {
    pub validator_info: ValidatorInfo,
    pub nodes: Nodes<RistrettoPoint>,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub encryption_key: PrivateKey<RistrettoPoint>,
    pub bls_signing_key: crate::bls::Bls12381PrivateKey,
    pub receiver: avss::Receiver,
}

#[derive(Clone, Debug)]
pub struct DkgRuntimeState {
    pub dealer_outputs: BTreeMap<ValidatorAddress, avss::ReceiverOutput>,
}

impl DkgStaticData {
    pub fn new(
        validator_info: ValidatorInfo,
        dkg_config: DkgConfig,
        session_context: SessionContext,
        encryption_key: PrivateKey<RistrettoPoint>,
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
        Ok(Self {
            validator_info,
            nodes,
            dkg_config,
            session_context,
            encryption_key,
            bls_signing_key,
            receiver,
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
            },
        }
    }

    pub fn create_dealer_message(
        &self,
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> DkgResult<avss::Message> {
        let secret = S::rand(rng);
        let dealer = avss::Dealer::new(
            Some(secret),
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
            avss::ProcessedMessage::Complaint(_) => {
                return Err(DkgError::ProtocolFailed(
                    "Invalid message from dealer".into(),
                ));
            }
        };
        self.runtime_state
            .dealer_outputs
            .insert(dealer_address.clone(), receiver_output);
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
        let required_num_of_signatures = (self.static_data.dkg_config.threshold
            + self.static_data.dkg_config.max_faulty)
            as usize;
        if signatures.len() < required_num_of_signatures {
            return Err(DkgError::ProtocolFailed(format!(
                "Insufficient signatures: got {}, need {}",
                signatures.len(),
                required_num_of_signatures
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

    /// TODO: Verify certificates, aggregate outputs, and create final DKG output
    pub fn process_certificates(&self, _certificates: &[DkgCertificate]) -> DkgResult<DkgOutput> {
        unimplemented!(
            "process_certificates should use fastcrypto's ReceiverOutput aggregation that does not seem to exist yet"
        )
    }
}

fn create_nodes(validators: &[ValidatorInfo]) -> Nodes<RistrettoPoint> {
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

fn compute_message_hash(
    message: &avss::Message,
    dealer_address: &ValidatorAddress,
    session: &SessionContext,
) -> DkgResult<MessageHash> {
    let message_bytes = bcs::to_bytes(message)
        .map_err(|e| DkgError::CryptoError(format!("Failed to serialize message: {}", e)))?;
    let mut hasher = Blake2b256::default();
    hasher.update(&message_bytes);
    hasher.update(dealer_address.0);
    hasher.update(session.session_id.as_ref());
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::types::ProtocolType;

    fn create_test_validator(party_id: u16) -> ValidatorInfo {
        let private_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
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
        let encryption_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
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
            .map(|_| PrivateKey::<RistrettoPoint>::new(&mut rng))
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
    }

    #[test]
    fn test_create_certificate_insufficient_signatures() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Only 2 signatures, need threshold + max_faulty = 3
        let signatures = vec![
            ValidatorSignature {
                validator: ValidatorAddress([1; 32]),
                signature: vec![0; 96],
            },
            ValidatorSignature {
                validator: ValidatorAddress([2; 32]),
                signature: vec![0; 96],
            },
        ];

        let result = manager.create_certificate(&message, signatures);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient signatures")
        );
    }

    #[test]
    fn test_create_certificate_success() {
        let config = create_test_dkg_config(5);
        let static_data = create_test_static_data(0, config);
        let manager = DkgManager::new(static_data);

        let message = manager
            .create_dealer_message(&mut rand::thread_rng())
            .unwrap();

        // Create enough signatures (threshold + max_faulty)
        let required_sigs = (manager.static_data.dkg_config.threshold
            + manager.static_data.dkg_config.max_faulty) as usize;
        let signatures: Vec<_> = (0..required_sigs)
            .map(|i| ValidatorSignature {
                validator: ValidatorAddress([i as u8; 32]),
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
}
