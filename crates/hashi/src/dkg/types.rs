//! Core types for the DKG protocol

use crate::bls::{CommitteeSignature, MemberSignature};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::Digest;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::{
    nodes::PartyId,
    polynomial::Eval,
    random_oracle::RandomOracle,
    threshold_schnorr::{G, avss, complaint},
};
use serde::{Deserialize, Serialize};
use sui_sdk_types::Address;

pub type EncryptionGroupElement = fastcrypto::groups::ristretto255::RistrettoPoint;
pub type Secp256k1Point = fastcrypto::groups::secp256k1::ProjectivePoint;
pub type MessageHash = [u8; 32];
pub type AddressToPartyId = std::collections::HashMap<Address, PartyId>;

pub struct SessionId([u8; 64]);

// Domain separation constants for RandomOracle
const DOMAIN_HASHI: &str =
    "754526047e6e997e6c348e7c3491c57b79e22c3efab204b9f0e72c85249c5959::hashi";
const DOMAIN_DKG: &str = "dkg";
const DOMAIN_ROTATION: &str = "rotation";
const DOMAIN_NONCE: &str = "nonce";
const DOMAIN_SIGNING: &str = "signing";
const DOMAIN_DEALER: &str = "dealer";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgConfig {
    pub epoch: u64,
    pub nodes: Nodes<EncryptionGroupElement>,
    pub address_to_party_id: AddressToPartyId,
    /// Threshold for signing (t)
    pub threshold: u16,
    /// Maximum number of faulty validators (f)
    pub max_faulty: u16,
}

impl DkgConfig {
    pub fn new(
        epoch: u64,
        nodes: Nodes<EncryptionGroupElement>,
        address_to_party_id: AddressToPartyId,
        threshold: u16,
        max_faulty: u16,
    ) -> Result<Self, DkgError> {
        if threshold <= max_faulty {
            return Err(DkgError::InvalidThreshold(
                "threshold must be greater than max_faulty".into(),
            ));
        }
        let total_weight = nodes.total_weight();
        if threshold + 2 * max_faulty > total_weight {
            return Err(DkgError::InvalidThreshold(format!(
                "t + 2f ({}) must be <= total weight ({})",
                threshold + 2 * max_faulty,
                total_weight
            )));
        }
        Ok(Self {
            epoch,
            address_to_party_id,
            nodes,
            threshold,
            max_faulty,
        })
    }

    pub fn total_weight(&self) -> u16 {
        self.nodes.total_weight()
    }
}

/// Helper struct for unique serialization.
#[derive(Serialize)]
struct SessionIdInputs {
    epoch: u64,
    nonce_id: Option<u32>,
    message_hash: Option<[u8; 32]>,
}

impl SessionId {
    pub fn new(epoch: u64, protocol_type: &ProtocolType, chain_id: &str) -> Self {
        let oracle = base_oracle(protocol_type);
        let input = match protocol_type {
            ProtocolType::DkgKeyGeneration | ProtocolType::KeyRotation => SessionIdInputs {
                epoch,
                nonce_id: None,
                message_hash: None,
            },
            ProtocolType::NonceGeneration(nonce_id) => SessionIdInputs {
                epoch,
                nonce_id: Some(*nonce_id),
                message_hash: None,
            },
            ProtocolType::Signing { message_hash } => SessionIdInputs {
                epoch,
                nonce_id: None,
                message_hash: Some(*message_hash),
            },
        };
        oracle.evaluate(&input)
    }

    /// Sub-session ID for a specific dealer, derived from the session ID
    pub fn dealer_session_id(&self, dealer: &Address) -> SessionId {
        let oracle = RandomOracle::new(self.0.to_vec());
        oracle.evaluate(&dealer)
    }

    fn base_oracle(protocol_type: &ProtocolType) -> RandomOracle {
        let oracle = RandomOracle::new(DOMAIN_HASHI);
        match protocol_type {
            ProtocolType::DkgKeyGeneration => oracle.extend(DOMAIN_DKG),
            ProtocolType::KeyRotation => oracle.extend(DOMAIN_ROTATION),
            ProtocolType::NonceGeneration(_) => oracle.extend(DOMAIN_NONCE),
            ProtocolType::Signing { .. } => oracle.extend(DOMAIN_SIGNING),
        }
    }
}

// Unique MPC protocol instance identifier (per epoch).
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolType {
    DkgKeyGeneration,
    KeyRotation,
    NonceGeneration { batch_index: u32 },
    Signing { message_hash: MessageHash },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub public_key: Secp256k1Point,
    pub key_shares: avss::SharesForNode,
    pub commitments: Vec<Eval<G>>,
    pub session_context: SessionContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub message: avss::Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub signature: ValidatorSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveMessageRequest {
    pub dealer: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveMessageResponse {
    pub message: avss::Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplainRequest {
    pub dealer: Address,
    pub complaint: complaint::Complaint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplainResponse {
    pub response: complaint::ComplaintResponse<avss::SharesForNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSignature {
    // TODO: remove since it's implictly known to the caller
    pub validator: Address,
    pub signature: MemberSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgDealerMessageHash {
    pub dealer_address: Address,
    pub message_hash: MessageHash,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MpcMessageV1 {
    Dkg(DkgDealerMessageHash),
}

pub type Certificate = CommitteeSignature<MpcMessageV1>;

pub type DkgResult<T> = Result<T, DkgError>;

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    #[error("Not enough participants: expected {expected}, got {got}")]
    NotEnoughParticipants { expected: usize, got: usize },

    #[error("Invalid message from {sender}: {reason}")]
    InvalidMessage { sender: Address, reason: String },

    #[error("Invalid message type: {0}")]
    InvalidMessageType(String),

    #[error("Protocol timeout after {seconds} seconds")]
    Timeout { seconds: u64 },

    #[error("Not enough approvals: need {needed}, got {got}")]
    NotEnoughApprovals { needed: usize, got: usize },

    #[error("Certificate verification failed: {0}")]
    InvalidCertificate(String),

    #[error("Broadcast channel error: {0}")]
    BroadcastError(String),

    #[error("Pairwise communication error: {0}")]
    PairwiseCommunicationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Protocol failed: {0}")]
    ProtocolFailed(String),
}

impl From<FastCryptoError> for DkgError {
    fn from(e: FastCryptoError) -> Self {
        DkgError::CryptoError(e.to_string())
    }
}

impl From<crate::communication::ChannelError> for DkgError {
    fn from(e: crate::communication::ChannelError) -> Self {
        DkgError::BroadcastError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
    use fastcrypto_tbls::nodes::Node;

    impl MpcMessageV1 {
        pub fn as_dkg_message(&self) -> &DkgDealerMessageHash {
            match self {
                MpcMessageV1::Dkg(msg) => msg,
            }
        }

        pub fn as_mut_dkg_message(&mut self) -> &mut DkgDealerMessageHash {
            match self {
                MpcMessageV1::Dkg(msg) => msg,
            }
        }
    }

    fn create_test_validator(
        party_id: u16,
        weight: u16,
    ) -> (Address, Node<EncryptionGroupElement>) {
        let private_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_private_key(&private_key);
        let address = Address::new([party_id as u8; 32]);
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

    #[test]
    fn test_dkg_config_valid_equal_weight() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 2);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.epoch, 100);
        assert_eq!(config.threshold, 3);
        assert_eq!(config.max_faulty, 2);
        assert_eq!(config.total_weight(), 7);
    }

    #[test]
    fn test_dkg_config_valid_weighted() {
        let validators = vec![
            create_test_validator(0, 3),
            create_test_validator(1, 2),
            create_test_validator(2, 2),
            create_test_validator(3, 1),
            create_test_validator(4, 1),
        ];
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(42, nodes, address_to_party_id, 5, 2);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.total_weight(), 9);
    }

    #[test]
    fn test_dkg_config_threshold_too_low() {
        let validators = (0..5).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 2);
        assert!(config.is_err());
        match config.unwrap_err() {
            DkgError::InvalidThreshold(msg) => {
                assert!(msg.contains("threshold must be greater than max_faulty"));
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_dkg_config_threshold_equals_faulty() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 3);
        assert!(config.is_err());
        match config.unwrap_err() {
            DkgError::InvalidThreshold(msg) => {
                assert!(msg.contains("threshold must be greater than max_faulty"));
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_dkg_config_byzantine_constraint_violated() {
        let validators = (0..5).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 4, 2);
        assert!(config.is_err());
        match config.unwrap_err() {
            DkgError::InvalidThreshold(msg) => {
                assert!(msg.contains("t + 2f (8) must be <= total weight (5)"));
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_dkg_config_minimum_validators() {
        let validators = (0..3).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 2, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_dkg_config_single_validator() {
        let validators = vec![create_test_validator(0, 1)];
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 1, 0);
        assert!(config.is_ok());
    }

    #[test]
    #[should_panic(expected = "InvalidInput")]
    fn test_dkg_config_zero_weight_sum() {
        // Nodes::new() will fail when trying to create nodes with zero weights
        // This is the expected behavior - invalid node configuration is caught early
        let validators = vec![create_test_validator(0, 0), create_test_validator(1, 0)];
        let (_nodes, _address_to_party_id) = build_nodes_and_registry(validators);
    }

    #[test]
    fn test_optimal_byzantine_tolerance() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let (nodes, address_to_party_id) = build_nodes_and_registry(validators);
        let config = DkgConfig::new(100, nodes, address_to_party_id, 3, 2);
        assert!(config.is_ok());
    }

    #[test]
    fn test_session_context_deterministic_serialization() {
        let epoch = 100;
        let protocol_type = ProtocolType::DkgKeyGeneration;
        let chain_id = "testnet".to_string();

        let ctx1 = SessionContext::new(epoch, protocol_type.clone(), chain_id.clone());
        let ctx2 = SessionContext::new(epoch, protocol_type, chain_id);

        assert_eq!(ctx1.session_id, ctx2.session_id);
    }

    #[test]
    fn test_session_id_different_for_different_protocols() {
        let epoch = 100;
        let chain_id = "testnet".to_string();

        let dkg_ctx = SessionContext::new(epoch, ProtocolType::DkgKeyGeneration, chain_id.clone());
        let rotation_ctx = SessionContext::new(epoch, ProtocolType::KeyRotation, chain_id.clone());
        let nonce_ctx =
            SessionContext::new(epoch, ProtocolType::NonceGeneration(1), chain_id.clone());

        assert_ne!(dkg_ctx.session_id, rotation_ctx.session_id);
        assert_ne!(dkg_ctx.session_id, nonce_ctx.session_id);
        assert_ne!(rotation_ctx.session_id, nonce_ctx.session_id);
    }

    #[test]
    fn test_session_id_different_chains() {
        let epoch = 100;
        let protocol_type = ProtocolType::DkgKeyGeneration;
        let mainnet_ctx = SessionContext::new(epoch, protocol_type.clone(), "mainnet".to_string());
        let testnet_ctx = SessionContext::new(epoch, protocol_type, "testnet".to_string());

        assert_ne!(mainnet_ctx.session_id, testnet_ctx.session_id);
    }

    #[test]
    fn test_dealer_session_serialization() {
        let ctx = SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testnet".to_string());
        let dealer1 = Address::new([1; 32]);
        let dealer2 = Address::new([2; 32]);
        let dealer1_session = ctx.dealer_session_id(&dealer1);
        let dealer2_session = ctx.dealer_session_id(&dealer2);

        // Different dealers should have different sub-session IDs
        assert_ne!(dealer1_session, dealer2_session);

        // Same dealer should produce same session ID
        let dealer1_session2 = ctx.dealer_session_id(&dealer1);
        assert_eq!(dealer1_session, dealer1_session2);
    }
}
