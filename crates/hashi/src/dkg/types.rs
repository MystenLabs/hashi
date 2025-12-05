//! Core types for the DKG protocol

use crate::bls::{BLS12381Signature, CommitteeSignature, MemberSignature};
use fastcrypto::error::FastCryptoError;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::{
    nodes::PartyId,
    polynomial::Eval,
    random_oracle::RandomOracle,
    threshold_schnorr::{G, avss, complaint},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sui_sdk_types::Address;

pub type EncryptionGroupElement = fastcrypto::groups::ristretto255::RistrettoPoint;
pub type Secp256k1Point = fastcrypto::groups::secp256k1::ProjectivePoint;
pub type MessageHash = [u8; 32];
pub type AddressToPartyId = std::collections::HashMap<Address, PartyId>;

// Domain separation constants for RandomOracle
const DOMAIN_HASHI: &str =
    "754526047e6e997e6c348e7c3491c57b79e22c3efab204b9f0e72c85249c5959::hashi";

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

    pub fn from_committee_set(
        committee_set: &crate::onchain::types::CommitteeSet,
    ) -> Result<Self, DkgError> {
        let committee = committee_set
            .committees
            .get(&committee_set.epoch)
            .ok_or_else(|| DkgError::InvalidConfig("no committee for current epoch".into()))?;
        let members_with_keys: Vec<_> = committee
            .members()
            .iter()
            .filter_map(|member| {
                let addr = member.validator_address();
                let member_info = committee_set.members.get(&addr)?;
                let encryption_pk = member_info.encryption_public_key.as_ref()?;
                Some((addr, member.weight(), encryption_pk.clone()))
            })
            .sorted_by_key(|(addr, _, _)| *addr)
            .collect();
        let mut nodes_vec = Vec::with_capacity(members_with_keys.len());
        let mut address_to_party_id = AddressToPartyId::new();
        for (id, (validator_address, weight, encryption_pk)) in members_with_keys.iter().enumerate()
        {
            nodes_vec.push(Node {
                id: id as u16,
                pk: encryption_pk.clone(),
                weight: *weight as u16,
            });
            address_to_party_id.insert(*validator_address, id as u16);
        }
        let nodes = Nodes::new(nodes_vec).map_err(|e| DkgError::CryptoError(e.to_string()))?;
        let total_weight = nodes.total_weight();
        let max_faulty = (total_weight - 1) / 3;
        let threshold = max_faulty + 1;
        Self::new(
            committee_set.epoch,
            nodes,
            address_to_party_id,
            threshold,
            max_faulty,
        )
    }

    pub fn total_weight(&self) -> u16 {
        self.nodes.total_weight()
    }
}

// Unique identifier for a session of MPC protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId([u8; 64]);

// Unique MPC protocol instance identifier (per epoch & chain).
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolType {
    DkgKeyGeneration,
    KeyRotation,
    NonceGeneration { batch_index: u32 },
    Signing { message_hash: MessageHash },
}

impl SessionId {
    pub fn new(chain_id: &str, epoch: u64, protocol_identifer: &ProtocolType) -> Self {
        let oracle = RandomOracle::new(DOMAIN_HASHI);
        SessionId(oracle.evaluate(&(chain_id, epoch, protocol_identifer)))
    }

    pub fn dealer_session_id(&self, dealer: &Address) -> SessionId {
        let oracle = RandomOracle::new(&hex::encode(self.0));
        SessionId(oracle.evaluate(&dealer))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub public_key: Secp256k1Point,
    pub key_shares: avss::SharesForNode,
    pub commitments: Vec<Eval<G>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub message: avss::Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub signature: BLS12381Signature,
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
    // TODO: Remove since it's implicitly known to the caller
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
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    #[error("Not enough participants: expected {expected}, got {got}")]
    NotEnoughParticipants { expected: usize, got: usize },

    #[error("Invalid message from {sender}: {reason}")]
    InvalidMessage { sender: Address, reason: String },

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
    use crate::bls::{BlsCommittee, BlsCommitteeMember};
    use crate::onchain::types::{CommitteeSet, MemberInfo};
    use fastcrypto::bls12381::min_pk::BLS12381KeyPair;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::traits::KeyPair;
    use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
    use fastcrypto_tbls::nodes::Node;
    use std::collections::BTreeMap;

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

        let sid1 = SessionId::new(&chain_id, epoch, &protocol_type);
        let sid2 = SessionId::new(&chain_id, epoch, &protocol_type);

        assert_eq!(sid1, sid2);
    }

    #[test]
    fn test_session_id_different_for_different_protocols() {
        let epoch = 100;
        let chain_id = "testnet".to_string();

        let dkg_sid = SessionId::new(&chain_id, epoch, &ProtocolType::DkgKeyGeneration);
        let rotation_sid = SessionId::new(&chain_id, epoch, &ProtocolType::KeyRotation);
        let nonce_sid = SessionId::new(
            &chain_id,
            epoch,
            &ProtocolType::NonceGeneration { batch_index: 1 },
        );

        assert_ne!(dkg_sid, rotation_sid);
        assert_ne!(dkg_sid, nonce_sid);
        assert_ne!(rotation_sid, nonce_sid);
    }

    #[test]
    fn test_session_id_different_chains() {
        let epoch = 100;
        let protocol_type = ProtocolType::DkgKeyGeneration;
        let mainnet_id = SessionId::new("mainnet", epoch, &protocol_type);
        let testnet_id = SessionId::new("testnet", epoch, &protocol_type);

        assert_ne!(testnet_id, mainnet_id);
    }

    #[test]
    fn test_dealer_session_serialization() {
        let sid = SessionId::new("testnet", 100, &ProtocolType::DkgKeyGeneration);
        let dealer1 = Address::new([1; 32]);
        let dealer2 = Address::new([2; 32]);
        let dealer1_session = sid.dealer_session_id(&dealer1);
        let dealer2_session = sid.dealer_session_id(&dealer2);

        // Different dealers should have different sub-session IDs
        assert_ne!(dealer1_session, dealer2_session);

        // Same dealer should produce same session ID
        let dealer1_session2 = sid.dealer_session_id(&dealer1);
        assert_eq!(dealer1_session, dealer1_session2);
    }

    fn create_test_member_info(id: u8) -> MemberInfo {
        let encryption_private_key =
            PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let encryption_public_key = PublicKey::from_private_key(&encryption_private_key);
        let bls_keypair = BLS12381KeyPair::generate(&mut rand::thread_rng());
        MemberInfo {
            validator_address: Address::new([id; 32]),
            operator_address: Address::new([id; 32]),
            next_epoch_public_key: bls_keypair.public().clone(),
            https_address: None,
            tls_public_key: None,
            encryption_public_key: Some(encryption_public_key),
        }
    }

    fn create_test_committee_member(id: u8, weight: u64) -> BlsCommitteeMember {
        let bls_keypair = BLS12381KeyPair::generate(&mut rand::thread_rng());
        BlsCommitteeMember::new(Address::new([id; 32]), bls_keypair.public().clone(), weight)
    }

    fn create_test_committee_set(member_weights: &[(u8, u64)], epoch: u64) -> CommitteeSet {
        let members: BTreeMap<Address, MemberInfo> = member_weights
            .iter()
            .map(|(id, _)| {
                let addr = Address::new([*id; 32]);
                (addr, create_test_member_info(*id))
            })
            .collect();
        let committee_members: Vec<BlsCommitteeMember> = member_weights
            .iter()
            .map(|(id, weight)| create_test_committee_member(*id, *weight))
            .collect();
        let committee = BlsCommittee::new(committee_members, epoch);
        let mut committees = BTreeMap::new();
        committees.insert(epoch, committee);
        CommitteeSet {
            members_id: Address::new([0; 32]),
            members,
            epoch,
            committees_id: Address::new([1; 32]),
            committees,
        }
    }

    #[test]
    fn test_from_committee_set_basic() {
        let committee_set = create_test_committee_set(
            &[(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1)],
            42,
        );
        let config = DkgConfig::from_committee_set(&committee_set).unwrap();

        assert_eq!(config.epoch, 42);
        assert_eq!(config.total_weight(), 7);
        // max_faulty = (7-1)/3 = 2, threshold = 2+1 = 3
        assert_eq!(config.max_faulty, 2);
        assert_eq!(config.threshold, 3);
    }

    #[test]
    fn test_from_committee_set_deterministic_party_ids() {
        // Create members in reverse order
        let committee_set = create_test_committee_set(&[(3, 1), (2, 1), (1, 1), (0, 1)], 1);
        let config = DkgConfig::from_committee_set(&committee_set).unwrap();

        // Party IDs should be assigned by sorted address order
        assert_eq!(
            config.address_to_party_id.get(&Address::new([0; 32])),
            Some(&0)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([1; 32])),
            Some(&1)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([2; 32])),
            Some(&2)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([3; 32])),
            Some(&3)
        );
    }

    #[test]
    fn test_from_committee_set_weighted() {
        let committee_set = create_test_committee_set(&[(0, 3), (1, 2), (2, 2), (3, 1), (4, 1)], 1);
        let config = DkgConfig::from_committee_set(&committee_set).unwrap();

        assert_eq!(config.total_weight(), 9);
        // max_faulty = (9-1)/3 = 2, threshold = 2+1 = 3
        assert_eq!(config.max_faulty, 2);
        assert_eq!(config.threshold, 3);
    }

    #[test]
    fn test_from_committee_set_skips_missing_encryption_key() {
        let mut committee_set = create_test_committee_set(&[(0, 1), (1, 1), (2, 1), (3, 1)], 1);
        // Remove encryption key from one member
        committee_set
            .members
            .get_mut(&Address::new([0; 32]))
            .unwrap()
            .encryption_public_key = None;

        // Should succeed but skip the member without encryption key
        let config = DkgConfig::from_committee_set(&committee_set).unwrap();
        assert_eq!(config.total_weight(), 3); // Only 3 members included
        assert!(
            config
                .address_to_party_id
                .get(&Address::new([0; 32]))
                .is_none()
        );
        assert!(
            config
                .address_to_party_id
                .get(&Address::new([1; 32]))
                .is_some()
        );
    }

    #[test]
    fn test_from_committee_set_no_committee_for_epoch() {
        let mut committee_set = create_test_committee_set(&[(0, 1), (1, 1), (2, 1), (3, 1)], 1);
        // Change epoch to one without a committee
        committee_set.epoch = 999;

        let result = DkgConfig::from_committee_set(&committee_set);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no committee for current epoch"));
    }
}
