//! Core types for the DKG protocol

use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::Digest;
use fastcrypto_tbls::{
    ecies_v1::PublicKey,
    nodes::PartyId,
    polynomial::Eval,
    random_oracle::RandomOracle,
    threshold_schnorr::{G, avss, complaint},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

type EG = fastcrypto::groups::ristretto255::RistrettoPoint;

pub type MessageHash = [u8; 32];
pub type SignatureBytes = Vec<u8>;
pub type SessionId = Digest<64>;

// Domain separation constants for RandomOracle
const DOMAIN_HASHI: &str = "hashi";
const DOMAIN_DKG: &str = "dkg";
const DOMAIN_SHARE: &str = "share";
const DOMAIN_ROTATION: &str = "rotation";
const DOMAIN_NONCE: &str = "nonce";
const DOMAIN_GENERATION: &str = "generation";
const DOMAIN_SIGNING: &str = "signing";
const DOMAIN_DEALER: &str = "dealer";

fn evaluate_oracle<T: serde::Serialize>(oracle: &RandomOracle, input: &T) -> SessionId {
    Digest::new(oracle.evaluate(input))
}

fn base_oracle(protocol_type: &ProtocolType) -> RandomOracle {
    match protocol_type {
        ProtocolType::DkgKeyGeneration => RandomOracle::new(DOMAIN_HASHI).extend(DOMAIN_DKG),
        ProtocolType::DkgShareRotation => RandomOracle::new(DOMAIN_HASHI)
            .extend(DOMAIN_SHARE)
            .extend(DOMAIN_ROTATION),
        ProtocolType::NonceGeneration(_) => RandomOracle::new(DOMAIN_HASHI)
            .extend(DOMAIN_NONCE)
            .extend(DOMAIN_GENERATION),
        ProtocolType::Signing { .. } => RandomOracle::new(DOMAIN_HASHI).extend(DOMAIN_SIGNING),
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ValidatorAddress(pub [u8; 32]);

impl fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: ValidatorAddress,
    /// Index in the validator set
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

    pub fn required_data_availability_signatures(&self) -> usize {
        (2 * self.max_faulty + 1) as usize
    }

    pub fn required_dkg_signatures(&self) -> usize {
        (self.threshold + self.max_faulty) as usize
    }
}

/// Unique deterministic session context for a DKG protocol instance
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionContext {
    pub epoch: u64,
    pub protocol_type: ProtocolType,
    pub chain_id: String,
}

/// Inputs for session ID generation
#[derive(Serialize)]
struct SessionIdInputs {
    epoch: u64,
    nonce_id: Option<u32>,
    message_hash: Option<[u8; 32]>,
    sighash_type: Option<u8>,
    derivation_indexes: Option<Vec<u32>>,
}

impl SessionContext {
    pub fn new(epoch: u64, protocol_type: ProtocolType, chain_id: String) -> Self {
        Self {
            epoch,
            protocol_type,
            chain_id,
        }
    }

    pub fn session_id(&self) -> SessionId {
        let oracle = base_oracle(&self.protocol_type).extend(&self.chain_id);
        let input = match &self.protocol_type {
            ProtocolType::DkgKeyGeneration | ProtocolType::DkgShareRotation => SessionIdInputs {
                epoch: self.epoch,
                nonce_id: None,
                message_hash: None,
                sighash_type: None,
                derivation_indexes: None,
            },
            ProtocolType::NonceGeneration(nonce_id) => SessionIdInputs {
                epoch: self.epoch,
                nonce_id: Some(*nonce_id),
                message_hash: None,
                sighash_type: None,
                derivation_indexes: None,
            },
            ProtocolType::Signing {
                message_hash,
                sighash_type,
                derivation_indexes,
            } => SessionIdInputs {
                epoch: self.epoch,
                nonce_id: None,
                message_hash: Some(*message_hash),
                sighash_type: Some(*sighash_type as u8),
                derivation_indexes: derivation_indexes.clone(),
            },
        };
        evaluate_oracle(&oracle, &input)
    }

    /// Sub-session ID for a specific dealer, derived from the session ID
    pub fn dealer_session_id(&self, dealer: &ValidatorAddress) -> SessionId {
        let oracle = RandomOracle::new(DOMAIN_HASHI).extend(DOMAIN_DEALER);
        evaluate_oracle(&oracle, &(self.session_id(), dealer.0))
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolType {
    DkgKeyGeneration,
    DkgShareRotation,
    NonceGeneration(u32),
    Signing {
        message_hash: MessageHash,
        sighash_type: SighashType,
        /// Derivation path indexes for each UTXO being signed
        /// None means using the root key (no derivation)
        derivation_indexes: Option<Vec<u32>>,
    },
}

#[derive(Clone, Copy, Debug, Default, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum SighashType {
    #[default]
    All = 0x01,
    None = 0x02,
    Single = 0x03,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub public_key: G,
    pub key_shares: avss::SharesForNode,
    pub commitments: Vec<Eval<G>>,
    pub session_context: SessionContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    ShareV1 {
        session_id: SessionId,
        sender: ValidatorAddress,
        message: Box<avss::Message>,
    },
    ComplaintV1 {
        session_id: SessionId,
        accuser: ValidatorAddress,
        complaint: complaint::Complaint,
    },
    ComplaintResponseV1 {
        session_id: SessionId,
        responder: ValidatorAddress,
        response: complaint::ComplaintResponse,
    },
    ApprovalV1(MessageApproval),
    DataAvailabilitySignatureV1 {
        session_id: SessionId,
        signer: ValidatorAddress,
        dealer: ValidatorAddress,
        message_hash: MessageHash,
        signature: SignatureBytes,
    },
    DkgSignatureV1 {
        session_id: SessionId,
        signer: ValidatorAddress,
        dealer: ValidatorAddress,
        message_hash: MessageHash,
        signature: SignatureBytes,
    },
    ShareRequestV1 {
        session_id: SessionId,
        requester: ValidatorAddress,
        dealer: ValidatorAddress,
        message_hash: MessageHash,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OrderedBroadcastMessage {
    CertificateV1(DkgCertificate),
    PresignatureV1 {
        sender: ValidatorAddress,
        session_context: SessionContext,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageApproval {
    pub message_hash: MessageHash,
    pub approver: ValidatorAddress,
    // TODO: Will be replaced with proper signature type when certificate management is implemented.
    pub signature: SignatureBytes,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator: ValidatorAddress,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgCertificate {
    pub dealer: ValidatorAddress,
    pub message_hash: MessageHash,
    pub data_availability_signatures: Vec<ValidatorSignature>,
    pub dkg_signatures: Vec<ValidatorSignature>,
    pub session_context: SessionContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType {
    DkgShare,
    Complaint,
    ComplaintResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgProtocolState {
    pub received_messages: BTreeMap<ValidatorAddress, avss::Message>,
    pub processed_shares: BTreeMap<ValidatorAddress, avss::SharesForNode>,
    pub processed_commitments: BTreeMap<ValidatorAddress, Vec<Eval<G>>>,
    pub complaints: Vec<complaint::Complaint>,
    pub complaint_responses: Vec<complaint::ComplaintResponse>,
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
    InvalidMessage {
        sender: ValidatorAddress,
        reason: String,
    },

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
            address: ValidatorAddress([party_id as u8; 32]),
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
    fn test_optimal_byzantine_tolerance() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators, 3, 2);
        assert!(config.is_ok());
    }

    #[test]
    fn test_required_data_availability_signatures() {
        let validators: Vec<ValidatorInfo> = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let config = DkgConfig::new(100, validators.clone(), 3, 2).unwrap();

        assert_eq!(config.required_data_availability_signatures(), 5);
    }

    #[test]
    fn test_required_dkg_signatures() {
        let validators: Vec<ValidatorInfo> = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let config1 = DkgConfig::new(100, validators.clone(), 3, 2).unwrap();

        assert_eq!(config1.required_dkg_signatures(), 5);
    }

    #[test]
    fn test_session_context_deterministic_serialization() {
        let epoch = 100;
        let protocol_type = ProtocolType::DkgKeyGeneration;
        let chain_id = "testnet".to_string();
        let ctx1 = SessionContext {
            epoch,
            protocol_type: protocol_type.clone(),
            chain_id: chain_id.clone(),
        };
        let ctx2 = SessionContext {
            epoch,
            protocol_type,
            chain_id,
        };

        assert_eq!(ctx1.session_id(), ctx2.session_id());
    }

    #[test]
    fn test_session_id_different_for_different_protocols() {
        let epoch = 100;
        let chain_id = "testnet".to_string();

        let dkg_ctx = SessionContext::new(epoch, ProtocolType::DkgKeyGeneration, chain_id.clone());
        let rotation_ctx =
            SessionContext::new(epoch, ProtocolType::DkgShareRotation, chain_id.clone());
        let nonce_ctx =
            SessionContext::new(epoch, ProtocolType::NonceGeneration(1), chain_id.clone());

        assert_ne!(dkg_ctx.session_id(), rotation_ctx.session_id());
        assert_ne!(dkg_ctx.session_id(), nonce_ctx.session_id());
        assert_ne!(rotation_ctx.session_id(), nonce_ctx.session_id());
    }

    #[test]
    fn test_session_id_different_chains() {
        let epoch = 100;
        let protocol_type = ProtocolType::DkgKeyGeneration;
        let mainnet_ctx = SessionContext::new(epoch, protocol_type.clone(), "mainnet".to_string());
        let testnet_ctx = SessionContext::new(epoch, protocol_type, "testnet".to_string());

        assert_ne!(mainnet_ctx.session_id(), testnet_ctx.session_id());
    }

    #[test]
    fn test_dealer_session_serialization() {
        let ctx = SessionContext::new(100, ProtocolType::DkgKeyGeneration, "testnet".to_string());
        let dealer1 = ValidatorAddress([1; 32]);
        let dealer2 = ValidatorAddress([2; 32]);
        let dealer1_session = ctx.dealer_session_id(&dealer1);
        let dealer2_session = ctx.dealer_session_id(&dealer2);

        // Different dealers should have different sub-session IDs
        assert_ne!(dealer1_session, dealer2_session);

        // Same dealer should produce same session ID
        let dealer1_session2 = ctx.dealer_session_id(&dealer1);
        assert_eq!(dealer1_session, dealer1_session2);
    }
}
