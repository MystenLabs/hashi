//! Core types for the DKG protocol

use fastcrypto::error::FastCryptoError;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::ShareIndex;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::Committee;
use hashi_types::committee::SignedMessage;
use hashi_types::move_types::CertifiedMessage;
use hashi_types::move_types::DkgDealerMessageHashV1;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;

pub type EncryptionGroupElement = fastcrypto::groups::ristretto255::RistrettoPoint;
pub type MessageHash = Digest;

// Domain separation constants for RandomOracle
const DOMAIN_HASHI: &str =
    "754526047e6e997e6c348e7c3491c57b79e22c3efab204b9f0e72c85249c5959::hashi";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgConfig {
    pub epoch: u64,
    pub nodes: Nodes<EncryptionGroupElement>,
    /// Threshold for signing (t)
    pub threshold: u16,
    /// Maximum number of faulty validators (f)
    pub max_faulty: u16,
}

impl DkgConfig {
    pub fn new(
        epoch: u64,
        nodes: Nodes<EncryptionGroupElement>,
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
            nodes,
            threshold,
            max_faulty,
        })
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

    pub fn rotation_session_id(&self, dealer: &Address, share_index: ShareIndex) -> SessionId {
        let oracle = RandomOracle::new(&hex::encode(self.0));
        SessionId(oracle.evaluate(&(dealer, share_index.get())))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub public_key: G,
    pub key_shares: avss::SharesForNode,
    pub commitments: BTreeMap<ShareIndex, G>,
    pub threshold: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicDkgOutput {
    pub public_key: G,
    pub commitments: BTreeMap<ShareIndex, G>,
}

impl PublicDkgOutput {
    pub fn from_dkg_output(output: &DkgOutput) -> Self {
        Self {
            public_key: output.public_key,
            commitments: output.commitments.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPublicDkgOutputRequest {
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPublicDkgOutputResponse {
    pub output: PublicDkgOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationMessages {
    messages: BTreeMap<ShareIndex, avss::Message>,
}

impl RotationMessages {
    pub fn new(messages: BTreeMap<ShareIndex, avss::Message>) -> Self {
        Self { messages }
    }

    pub fn get(&self, share_index: ShareIndex) -> Option<&avss::Message> {
        self.messages.get(&share_index)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ShareIndex, &avss::Message)> {
        self.messages.iter()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendRotationMessagesRequest {
    pub messages: RotationMessages,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendRotationMessagesResponse {
    pub signature: BLS12381Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveRotationMessagesRequest {
    pub dealer: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveRotationMessagesResponse {
    pub messages: RotationMessages,
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
pub struct RotationComplainRequest {
    pub dealer: Address,
    pub share_index: ShareIndex,
    pub complaint: complaint::Complaint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationShareComplaintResponse {
    pub share_index: ShareIndex,
    pub response: complaint::ComplaintResponse<avss::SharesForNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationComplainResponse {
    pub responses: Vec<RotationShareComplaintResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgDealerMessageHash {
    pub dealer_address: Address,
    pub message_hash: MessageHash,
}

impl DkgDealerMessageHash {
    pub fn from_onchain_cert(
        cert: &CertifiedMessage<DkgDealerMessageHashV1>,
        epoch: u64,
        committee: &Committee,
        threshold: u64,
    ) -> Result<DkgCertificate, DkgError> {
        let hash_bytes: [u8; 32] =
            cert.message
                .message_hash
                .as_slice()
                .try_into()
                .map_err(|_| DkgError::InvalidMessage {
                    sender: cert.message.dealer_address,
                    reason: "invalid message_hash length".into(),
                })?;

        let message = Self {
            dealer_address: cert.message.dealer_address,
            message_hash: hash_bytes.into(),
        };
        SignedMessage::try_from_parts(
            epoch,
            message,
            &cert.signature.signature,
            &cert.signature.signers_bitmap,
            committee,
            threshold,
        )
        .map_err(|e| DkgError::InvalidCertificate(e.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationDealerMessagesHash {
    pub dealer_address: Address,
    pub messages_hash: MessageHash,
}

pub type DkgCertificate = SignedMessage<DkgDealerMessageHash>;
pub type RotationCertificate = SignedMessage<RotationDealerMessagesHash>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum CertificateV1 {
    Dkg(DkgCertificate),
    Rotation(RotationCertificate),
}

impl CertificateV1 {
    pub fn epoch(&self) -> u64 {
        match self {
            CertificateV1::Dkg(cert) => cert.epoch(),
            CertificateV1::Rotation(cert) => cert.epoch(),
        }
    }

    pub fn signature_bytes(&self) -> &[u8] {
        match self {
            CertificateV1::Dkg(cert) => cert.signature_bytes(),
            CertificateV1::Rotation(cert) => cert.signature_bytes(),
        }
    }

    pub fn signers_bitmap_bytes(&self) -> &[u8] {
        match self {
            CertificateV1::Dkg(cert) => cert.signers_bitmap_bytes(),
            CertificateV1::Rotation(cert) => cert.signers_bitmap_bytes(),
        }
    }

    pub fn signers(
        &self,
        committee: &Committee,
    ) -> Result<Vec<Address>, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) => cert.signers(committee),
            CertificateV1::Rotation(cert) => cert.signers(committee),
        }
    }

    pub fn weight(&self, committee: &Committee) -> Result<u64, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) => cert.weight(committee),
            CertificateV1::Rotation(cert) => cert.weight(committee),
        }
    }

    pub fn is_signer(
        &self,
        address: &Address,
        committee: &Committee,
    ) -> Result<bool, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) => cert.is_signer(address, committee),
            CertificateV1::Rotation(cert) => cert.is_signer(address, committee),
        }
    }

    pub fn dkg_message_hash(&self) -> Option<&DkgDealerMessageHash> {
        match self {
            CertificateV1::Dkg(cert) => Some(cert.message()),
            CertificateV1::Rotation(_) => None,
        }
    }

    pub fn rotation_message_hash(&self) -> Option<&RotationDealerMessagesHash> {
        match self {
            CertificateV1::Dkg(_) => None,
            CertificateV1::Rotation(cert) => Some(cert.message()),
        }
    }
}

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

    #[error("Not found: {0}")]
    NotFound(String),

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
    use fastcrypto_tbls::nodes::Node;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use hashi_types::move_types::CommitteeSignature as MoveCommitteeSignature;
    use std::num::NonZeroU16;

    impl RotationMessages {
        pub fn insert(&mut self, share_index: ShareIndex, message: avss::Message) {
            self.messages.insert(share_index, message);
        }

        pub fn keys(&self) -> impl Iterator<Item = &ShareIndex> {
            self.messages.keys()
        }
    }

    fn create_test_validator(
        party_id: u16,
        weight: u16,
    ) -> (Address, Node<EncryptionGroupElement>) {
        let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let public_key = EncryptionPublicKey::from_private_key(&private_key);
        let address = Address::new([party_id as u8; 32]);
        let node = Node {
            id: party_id,
            pk: public_key,
            weight,
        };
        (address, node)
    }

    fn build_nodes(
        validators: Vec<(Address, Node<EncryptionGroupElement>)>,
    ) -> Nodes<EncryptionGroupElement> {
        let mut node_vec: Vec<_> = validators.iter().map(|(_, node)| node.clone()).collect();
        node_vec.sort_by_key(|n| n.id);
        Nodes::new(node_vec).unwrap()
    }

    #[test]
    fn test_dkg_config_threshold_too_low() {
        let validators = (0..5).map(|i| create_test_validator(i, 1)).collect();
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 2, 2);
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
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 3, 3);
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
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 4, 2);
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
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 2, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_dkg_config_single_validator() {
        let validators = vec![create_test_validator(0, 1)];
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 1, 0);
        assert!(config.is_ok());
    }

    #[test]
    #[should_panic(expected = "InvalidInput")]
    fn test_dkg_config_zero_weight_sum() {
        // Nodes::new() will fail when trying to create nodes with zero weights
        // This is the expected behavior - invalid node configuration is caught early
        let validators = vec![create_test_validator(0, 0), create_test_validator(1, 0)];
        let _nodes = build_nodes(validators);
    }

    #[test]
    fn test_optimal_byzantine_tolerance() {
        let validators = (0..7).map(|i| create_test_validator(i, 1)).collect();
        let nodes = build_nodes(validators);
        let config = DkgConfig::new(100, nodes, 3, 2);
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

    #[test]
    fn test_rotation_session_id() {
        let sid = SessionId::new("testnet", 100, &ProtocolType::KeyRotation);
        let dealer = Address::new([1; 32]);
        let share1 = NonZeroU16::new(1).unwrap();
        let share2 = NonZeroU16::new(2).unwrap();

        // Different share indices should have different session IDs
        let session_d1_s1 = sid.rotation_session_id(&dealer, share1);
        let session_d1_s2 = sid.rotation_session_id(&dealer, share2);
        assert_ne!(session_d1_s1, session_d1_s2);
    }

    #[test]
    fn test_from_onchain_cert_success() {
        let mut rng = rand::thread_rng();
        let epoch = 100u64;
        let threshold = 2u64;

        // Create committee with 3 members
        let signing_keys: Vec<_> = (0..3)
            .map(|_| Bls12381PrivateKey::generate(&mut rng))
            .collect();
        let encryption_keys: Vec<_> = (0..3)
            .map(|_| EncryptionPrivateKey::new(&mut rng))
            .collect();
        let members: Vec<_> = (0..3)
            .map(|i| {
                CommitteeMember::new(
                    Address::new([i as u8; 32]),
                    signing_keys[i].public_key(),
                    EncryptionPublicKey::from_private_key(&encryption_keys[i]),
                    1,
                )
            })
            .collect();
        let committee = Committee::new(members, epoch);

        // Create a DkgDealerMessageHash
        let dealer_address = Address::new([0u8; 32]);
        let message_hash: [u8; 32] = [42u8; 32];
        let dkg_message = DkgDealerMessageHash {
            dealer_address,
            message_hash: message_hash.into(),
        };

        // Sign with committee members to create a valid certificate
        let mut aggregator = BlsSignatureAggregator::new(&committee, dkg_message.clone());
        for (i, key) in signing_keys.iter().enumerate() {
            let addr = Address::new([i as u8; 32]);
            let sig = key.sign(epoch, addr, &dkg_message);
            aggregator.add_signature(sig).unwrap();
        }
        let signed_message = aggregator.finish().unwrap();

        // Convert to on-chain format
        let onchain_cert = CertifiedMessage {
            message: DkgDealerMessageHashV1 {
                dealer_address,
                message_hash: message_hash.to_vec(),
            },
            signature: MoveCommitteeSignature {
                epoch,
                signature: signed_message.signature_bytes().to_vec(),
                signers_bitmap: signed_message.signers_bitmap_bytes().to_vec(),
            },
            stake_support: 3,
        };

        // Parse back using from_onchain_cert
        let result =
            DkgDealerMessageHash::from_onchain_cert(&onchain_cert, epoch, &committee, threshold);
        assert!(
            result.is_ok(),
            "Should parse valid certificate: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.message().dealer_address, dealer_address);
        assert_eq!(
            <MessageHash as AsRef<[u8; 32]>>::as_ref(&parsed.message().message_hash),
            &message_hash
        );
    }

    #[test]
    fn test_from_onchain_cert_invalid_hash_length() {
        let mut rng = rand::thread_rng();
        let epoch = 100u64;
        let threshold = 1u64;

        // Create minimal committee
        let signing_key = Bls12381PrivateKey::generate(&mut rng);
        let encryption_key = EncryptionPrivateKey::new(&mut rng);
        let member = CommitteeMember::new(
            Address::new([0u8; 32]),
            signing_key.public_key(),
            EncryptionPublicKey::from_private_key(&encryption_key),
            1,
        );
        let committee = Committee::new(vec![member], epoch);

        // Create certificate with invalid hash length (not 32 bytes)
        let onchain_cert = CertifiedMessage {
            message: DkgDealerMessageHashV1 {
                dealer_address: Address::new([0u8; 32]),
                message_hash: vec![1, 2, 3], // Invalid: only 3 bytes
            },
            signature: MoveCommitteeSignature {
                epoch,
                signature: vec![],
                signers_bitmap: vec![],
            },
            stake_support: 0,
        };

        let result =
            DkgDealerMessageHash::from_onchain_cert(&onchain_cert, epoch, &committee, threshold);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid message_hash length"),
            "Error should mention invalid hash length: {}",
            err
        );
    }
}
