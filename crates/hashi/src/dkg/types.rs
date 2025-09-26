//! Core types for the DKG protocol

use fastcrypto::error::FastCryptoError;
use fastcrypto_tbls::{
    ecies_v1::PublicKey,
    nodes::PartyId,
    polynomial::Eval,
    threshold_schnorr::{G, avss},
};

type EG = fastcrypto::groups::ristretto255::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ValidatorId(pub [u8; 32]);

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: ValidatorId,
    pub party_id: PartyId,
    pub weight: u16,
    pub ecies_public_key: PublicKey<EG>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgConfig {
    pub epoch: u64,
    pub validators: Vec<ValidatorInfo>,
    /// Threshold for signing (t)
    pub threshold: u16,
    /// Maximum number of faulty validators (f)
    pub max_faulty: u16,
}

impl DkgConfig {
    pub fn new(
        epoch: u64,
        validators: Vec<ValidatorInfo>,
        threshold: u16,
        max_faulty: u16,
    ) -> Result<Self, DkgError> {
        if threshold <= max_faulty {
            return Err(DkgError::InvalidThreshold(
                "threshold must be greater than max_faulty".into(),
            ));
        }
        let total_weight: u16 = validators.iter().map(|v| v.weight).sum();
        if threshold + 2 * max_faulty > total_weight {
            return Err(DkgError::InvalidThreshold(format!(
                "t + 2f ({}) must be <= total weight ({})",
                threshold + 2 * max_faulty,
                total_weight
            )));
        }
        Ok(Self {
            epoch,
            validators,
            threshold,
            max_faulty,
        })
    }

    pub fn total_weight(&self) -> u16 {
        self.validators.iter().map(|v| v.weight).sum()
    }

    pub fn get_validator(&self, id: &ValidatorId) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| v.id == *id)
    }
}

/// Unique session context for a DKG protocol instance
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionContext {
    pub epoch: u64,
    pub protocol_type: ProtocolType,
    /// Attempt number
    pub round: u32,
    /// Random nonce for uniqueness (in the case of multiple networks)
    pub nonce: [u8; 16],
}

impl SessionContext {
    pub fn new(epoch: u64, protocol_type: ProtocolType, round: u32) -> Self {
        use rand::Rng;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill(&mut nonce);
        Self {
            epoch,
            protocol_type,
            round,
            nonce,
        }
    }

    /// Convert to bytes for use in `fastcrypto` (as sid parameter)
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SessionContext serialization should not fail")
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolType {
    DkgKeyGeneration,
    DkgKeyRotation,
    NonceGeneration(u32),
    Signing([u8; 32]), // transaction hash
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub public_key: G,
    pub key_shares: avss::SharesForNode,
    pub commitments: Vec<Eval<G>>,
    pub session_context: SessionContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DkgMessage {
    Share {
        sender: ValidatorId,
        message: Box<avss::Message>,
    },
    Approval(MessageApproval),
    Certificate(DkgCertificate),
    Complaint {
        accuser: ValidatorId,
        complaint_bytes: Vec<u8>,
    },
    ComplaintResponse {
        responder: ValidatorId,
        response_bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageApproval {
    pub message_hash: [u8; 32],
    pub approver: ValidatorId,
    // TODO: Will be replaced with proper signature type when certificate management is implemented.
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgCertificate {
    pub message_hash: [u8; 32],
    pub approvals: Vec<MessageApproval>,
    pub message_type: MessageType,
    pub session_context: SessionContext,
    pub sender: ValidatorId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType {
    DkgShare,
    Complaint,
    ComplaintResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgProtocolState {
    pub received_messages: BTreeMap<ValidatorId, avss::Message>,
    pub processed_shares: BTreeMap<ValidatorId, avss::SharesForNode>,
    pub processed_commitments: BTreeMap<ValidatorId, Vec<Eval<G>>>,
    pub complaints: Vec<Vec<u8>>,
    pub complaint_responses: Vec<Vec<u8>>,
    pub certificates: Vec<DkgCertificate>,
}

pub type DkgResult<T> = Result<T, DkgError>;

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    #[error("Not enough participants: expected {expected}, got {got}")]
    NotEnoughParticipants { expected: usize, got: usize },

    #[error("Invalid message from {sender}: {reason}")]
    InvalidMessage { sender: ValidatorId, reason: String },

    #[error("Protocol timeout after {seconds} seconds")]
    Timeout { seconds: u64 },

    #[error("Not enough approvals: need {needed}, got {got}")]
    NotEnoughApprovals { needed: usize, got: usize },

    #[error("Certificate verification failed: {0}")]
    InvalidCertificate(String),

    #[error("Broadcast channel error: {0}")]
    BroadcastError(String),

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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator(party_id: u16, weight: u16) -> ValidatorInfo {
        use fastcrypto::groups::ristretto255::RistrettoPoint;
        use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};

        let private_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_private_key(&private_key);
        ValidatorInfo {
            id: ValidatorId([party_id as u8; 32]),
            party_id,
            weight,
            ecies_public_key: public_key,
        }
    }

    #[test]
    fn test_dkg_config_valid_equal_weight() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators, 3, 2);
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
        let config = DkgConfig::new(42, validators, 5, 2);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.total_weight(), 9);
    }

    #[test]
    fn test_dkg_config_threshold_too_low() {
        let validators = (0..5).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators, 2, 2);
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
        let config = DkgConfig::new(100, validators, 3, 3);
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
        let config = DkgConfig::new(100, validators, 4, 2);
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
        let config = DkgConfig::new(100, validators, 2, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_dkg_config_single_validator() {
        let validators = vec![create_test_validator(0, 1)];
        let config = DkgConfig::new(100, validators, 1, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_dkg_config_zero_weight_sum() {
        let validators = vec![create_test_validator(0, 0), create_test_validator(1, 0)];
        let config = DkgConfig::new(100, validators, 1, 0);
        assert!(config.is_err());
    }

    #[test]
    fn test_dkg_config_get_validator() {
        let validators = (0..3).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators, 2, 0).unwrap();

        // Test finding existing validator
        let validator_id = ValidatorId([0; 32]);
        let validator = config.get_validator(&validator_id);
        assert!(validator.is_some());
        assert_eq!(validator.unwrap().party_id, 0);

        // Test finding non-existent validator
        let unknown_id = ValidatorId([99; 32]);
        assert!(config.get_validator(&unknown_id).is_none());
    }

    #[test]
    fn test_optimal_byzantine_tolerance() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators, 3, 2);
        assert!(config.is_ok());
    }
}
