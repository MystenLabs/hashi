// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto_tbls::ecies_v1::Ciphertext;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::threshold_schnorr::Certificate;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::VerifiedCertificate;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::ShareIndex;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::Committee;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::SignedMessage;
use hashi_types::move_types::DealerSubmissionV1;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;

pub type EncryptionGroupElement = fastcrypto::groups::ristretto255::RistrettoPoint;
pub type MessageHash = Digest;
pub type RotationMessages = BTreeMap<ShareIndex, avss::Message>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceMessage {
    pub batch_index: u32,
    pub message: batch_avss::Message,
}

pub type AvidConfirmCertificate = SignedMessage<DealerMessagesHash>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidNonceMessage {
    pub batch_index: u32,
    pub kind: AvidNonceMessageKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum AvidNonceMessageKind {
    Optimistic(batch_avss_avid::AvssMessage),
    Dispersal {
        dispersal: batch_avss_avid::Dispersal,
        confirm_cert: AvidConfirmCertificate,
    },
    Echo {
        dealer: Address,
        echo: batch_avss_avid::Echo,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidNonceRetrievalMessage {
    pub common: Option<batch_avss_avid::AvssCommonMessage>,
    pub echo: Option<batch_avss_avid::Echo>,
    pub avid_vote: Option<batch_avss_avid::AvidVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidRoundState {
    pub common: batch_avss_avid::AvssCommonMessage,
    pub own_ciphertext: Ciphertext,
}

pub(crate) type HeldAvidEchoes = (batch_avss_avid::AvidVote, Vec<(Address, Messages)>);

// Domain separation constants for RandomOracle
const DOMAIN_HASHI: &str =
    "754526047e6e997e6c348e7c3491c57b79e22c3efab204b9f0e72c85249c5959::hashi";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NonceGenerationProtocol {
    #[default]
    Vanilla,
    Avid,
}

impl NonceGenerationProtocol {
    pub fn from_onchain(value: u16) -> MpcResult<Self> {
        match value {
            0 => Ok(Self::Vanilla),
            1 => Ok(Self::Avid),
            other => Err(MpcError::InvalidConfig(format!(
                "unknown mpc_nonce_generation_protocol: {other}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresignatureDerivationVersion {
    #[default]
    Legacy,
    PrivacyThreshold,
}

impl PresignatureDerivationVersion {
    pub fn from_activation_epoch(epoch: u64, activation_epoch: u64) -> Self {
        if epoch < activation_epoch {
            Self::Legacy
        } else {
            Self::PrivacyThreshold
        }
    }

    pub fn use_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcConfig {
    pub epoch: u64,
    pub nodes: Nodes<EncryptionGroupElement>,
    /// Threshold for signing (t)
    pub threshold: u16,
    /// Maximum number of faulty validators (f)
    pub max_faulty: u16,
    pub nonce_generation_protocol: NonceGenerationProtocol,
    pub presignature_derivation_version: PresignatureDerivationVersion,
    pub nonce_accumulation_window_ms: u64,
}

impl MpcConfig {
    pub fn new(
        epoch: u64,
        nodes: Nodes<EncryptionGroupElement>,
        threshold: u16,
        max_faulty: u16,
        nonce_generation_protocol: NonceGenerationProtocol,
        presignature_derivation_version: PresignatureDerivationVersion,
        nonce_accumulation_window_ms: u64,
    ) -> Self {
        Self {
            epoch,
            nodes,
            threshold,
            max_faulty,
            nonce_generation_protocol,
            presignature_derivation_version,
            nonce_accumulation_window_ms,
        }
    }
}

pub struct NonceCollectionWindow {
    required_weight: u32,
    window_ms: u64,
    weight: u32,
    state: NonceCollectionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonceCollectionState {
    Floor,
    Window { cutoff_ms: u64 },
    Closed { cutoff_ms: Option<u64> },
}

pub struct NonceCertAdmission {
    timestamp_ms: u64,
}

impl NonceCollectionWindow {
    pub fn new(required_weight: u32, window_ms: u64) -> Self {
        Self {
            required_weight,
            window_ms,
            weight: 0,
            state: NonceCollectionState::Floor,
        }
    }

    pub fn closed(&self) -> bool {
        matches!(self.state, NonceCollectionState::Closed { .. })
    }

    pub fn floor_reached(&self) -> bool {
        !matches!(self.state, NonceCollectionState::Floor)
    }

    pub fn weight(&self) -> u32 {
        self.weight
    }

    pub fn cutoff_ms(&self) -> Option<u64> {
        match self.state {
            NonceCollectionState::Window { cutoff_ms } => Some(cutoff_ms),
            NonceCollectionState::Closed { cutoff_ms } => cutoff_ms,
            NonceCollectionState::Floor => None,
        }
    }

    pub fn try_admit(&mut self, timestamp_ms: u64) -> Option<NonceCertAdmission> {
        match self.state {
            NonceCollectionState::Floor => Some(NonceCertAdmission { timestamp_ms }),
            NonceCollectionState::Window { cutoff_ms } => {
                if timestamp_ms > cutoff_ms {
                    self.state = NonceCollectionState::Closed {
                        cutoff_ms: Some(cutoff_ms),
                    };
                    None
                } else {
                    Some(NonceCertAdmission { timestamp_ms })
                }
            }
            NonceCollectionState::Closed { .. } => None,
        }
    }

    pub fn record(&mut self, admission: NonceCertAdmission, reduced_weight: u32) {
        self.weight += reduced_weight;
        if matches!(self.state, NonceCollectionState::Floor) && self.weight >= self.required_weight
        {
            self.state = if self.window_ms == 0 {
                NonceCollectionState::Closed { cutoff_ms: None }
            } else {
                NonceCollectionState::Window {
                    cutoff_ms: admission.timestamp_ms.saturating_add(self.window_ms),
                }
            };
        }
    }
}

// Unique identifier for a session of MPC protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId([u8; 64]);

// Unique MPC protocol instance identifier (per epoch & chain).
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolType {
    Dkg,
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

    pub fn nonce_dealer_session_id(
        chain_id: &str,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> SessionId {
        let base = Self::new(
            chain_id,
            epoch,
            &ProtocolType::NonceGeneration { batch_index },
        );
        base.dealer_session_id(dealer)
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
pub struct MpcOutput {
    pub public_key: G,
    pub key_shares: avss::SharesForNode,
    pub commitments: BTreeMap<ShareIndex, G>,
    pub threshold: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMpcOutput {
    pub public_key: G,
    pub commitments: BTreeMap<ShareIndex, G>,
}

impl PublicMpcOutput {
    pub fn from_mpc_output(output: &MpcOutput) -> Self {
        Self {
            public_key: output.public_key,
            commitments: output.commitments.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPublicMpcOutputRequest {
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPublicMpcOutputResponse {
    pub output: PublicMpcOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Messages {
    Dkg(avss::Message),
    Rotation(RotationMessages),
    NonceGeneration(NonceMessage),
    NonceGenerationAvid(AvidNonceMessage),
    AvidNonceRetrieval(AvidNonceRetrievalMessage),
}

impl Messages {
    pub fn protocol_type(&self) -> ProtocolTypeIndicator {
        match self {
            Messages::Dkg(_) => ProtocolTypeIndicator::Dkg,
            Messages::Rotation(_) => ProtocolTypeIndicator::KeyRotation,
            Messages::NonceGeneration(_) => ProtocolTypeIndicator::NonceGeneration,
            Messages::NonceGenerationAvid(_) => ProtocolTypeIndicator::NonceGeneration,
            Messages::AvidNonceRetrieval(_) => ProtocolTypeIndicator::NonceGeneration,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessagesRequest {
    pub messages: Messages,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessagesResponse {
    pub signature: BLS12381Signature,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ProtocolTypeIndicator {
    Dkg,
    KeyRotation,
    NonceGeneration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveMessagesRequest {
    pub dealer: Address,
    pub protocol_type: ProtocolTypeIndicator,
    pub epoch: u64,
    pub batch_index: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveMessagesResponse {
    pub messages: Messages,
}

#[allow(clippy::large_enum_variant)]
pub enum ReconstructionOutcome {
    Success(MpcOutput),
    NeedsDkgComplaintRecovery {
        dealer_address: Address,
        complaint: avss::Complaint,
        message: avss::Message,
    },
    NeedsRotationComplaintRecovery {
        dealer_address: Address,
        share_index: ShareIndex,
        complaint: avss::Complaint,
        message: avss::Message,
    },
}

pub enum MpcOutputRecoveryOutcome {
    Recovered(MpcOutput),
    NotApplicable,
    Suspicious(String),
}

pub(crate) struct DkgReconstructionContext<'a> {
    pub committee: &'a Committee,
    pub nodes: &'a Nodes<EncryptionGroupElement>,
    pub party_id: PartyId,
    pub encryption_key: &'a PrivateKey<EncryptionGroupElement>,
    pub output_threshold: u16,
    pub output_max_faulty: u16,
    pub epoch: u64,
}

pub(crate) struct RotationReconstructionContext<'a> {
    pub nodes: &'a Nodes<EncryptionGroupElement>,
    pub party_id: PartyId,
    pub encryption_key: &'a PrivateKey<EncryptionGroupElement>,
    pub output_threshold: u16,
    pub output_max_faulty: u16,
    pub input_threshold: u16,
    pub epoch: u64,
}

#[allow(clippy::large_enum_variant)]
pub enum NonceReconstructionOutcome {
    Success(Vec<batch_avss::ReceiverOutput>),
    NeedsComplaintRecovery {
        dealer_address: Address,
        complaint: complaint::Complaint,
        batch_index: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProtocolComplaint {
    Avss(avss::Complaint),
    BatchedAvss(complaint::Complaint),
    AvidReveal(batch_avss_avid::AvssComplaint),
    AvidBlame {
        complaint: batch_avss_avid::AvidComplaint,
        vote_cert: DealerCertificate,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplainRequest {
    pub dealer: Address,
    pub share_index: Option<ShareIndex>, // Only for key rotation
    pub batch_index: Option<u32>,        // Only for nonce generation
    pub complaint: ProtocolComplaint,
    pub protocol_type: ProtocolTypeIndicator,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ComplaintResponse {
    Dkg(avss::ComplaintResponse),
    Rotation(avss::ComplaintResponse),
    NonceGeneration(complaint::ComplaintResponse<batch_avss::SharesForNode>),
    NonceGenerationAvid(batch_avss_avid::ComplaintResponse),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealerMessagesHash {
    pub dealer_address: Address,
    pub messages_hash: MessageHash,
}

impl hashi_types::intent::IntentMessage for DealerMessagesHash {
    const INTENT: hashi_types::intent::Intent = hashi_types::intent::Intent::DealerMessagesHash;
}

impl DealerMessagesHash {
    pub fn from_onchain_cert(
        cert: &DealerSubmissionV1,
        epoch: u64,
    ) -> Result<DealerCertificate, MpcError> {
        let hash_bytes: [u8; 32] =
            cert.message
                .messages_hash
                .as_slice()
                .try_into()
                .map_err(|_| MpcError::InvalidMessage {
                    sender: cert.message.dealer_address,
                    reason: "invalid messages_hash length".into(),
                })?;

        let message = Self {
            dealer_address: cert.message.dealer_address,
            messages_hash: hash_bytes.into(),
        };
        let signed_message = SignedMessage::new(
            epoch,
            message,
            &cert.signature.signature,
            &cert.signature.signers_bitmap,
        )
        .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?;
        Ok(signed_message)
    }
}

pub type DealerCertificate = SignedMessage<DealerMessagesHash>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum CertificateV1 {
    Dkg(DealerCertificate),
    Rotation(DealerCertificate),
    NonceGeneration {
        batch_index: u32,
        cert: DealerCertificate,
        timestamp_ms: u64,
    },
}

impl CertificateV1 {
    pub fn new(
        protocol_type: hashi_types::move_types::ProtocolType,
        batch_index: Option<u32>,
        cert: DealerCertificate,
        timestamp_ms: u64,
    ) -> Self {
        match protocol_type {
            hashi_types::move_types::ProtocolType::Dkg => CertificateV1::Dkg(cert),
            hashi_types::move_types::ProtocolType::KeyRotation => CertificateV1::Rotation(cert),
            hashi_types::move_types::ProtocolType::NonceGeneration => {
                CertificateV1::NonceGeneration {
                    batch_index: batch_index.expect("batch_index required for NonceGeneration"),
                    cert,
                    timestamp_ms,
                }
            }
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.epoch(),
            CertificateV1::NonceGeneration { cert, .. } => cert.epoch(),
        }
    }

    pub fn dealer_address(&self) -> Address {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => {
                cert.message().dealer_address
            }
            CertificateV1::NonceGeneration { cert, .. } => cert.message().dealer_address,
        }
    }

    pub fn signature_bytes(&self) -> &[u8] {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.signature_bytes(),
            CertificateV1::NonceGeneration { cert, .. } => cert.signature_bytes(),
        }
    }

    pub fn signers_bitmap_bytes(&self) -> &[u8] {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.signers_bitmap_bytes(),
            CertificateV1::NonceGeneration { cert, .. } => cert.signers_bitmap_bytes(),
        }
    }

    pub fn signers(
        &self,
        committee: &Committee,
    ) -> Result<Vec<Address>, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.signers(committee),
            CertificateV1::NonceGeneration { cert, .. } => cert.signers(committee),
        }
    }

    pub fn weight(&self, committee: &Committee) -> Result<u64, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.weight(committee),
            CertificateV1::NonceGeneration { cert, .. } => cert.weight(committee),
        }
    }

    pub fn is_signer(
        &self,
        address: &Address,
        committee: &Committee,
    ) -> Result<bool, sui_crypto::SignatureError> {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => {
                cert.is_signer(address, committee)
            }
            CertificateV1::NonceGeneration { cert, .. } => cert.is_signer(address, committee),
        }
    }

    pub fn message(&self) -> &DealerMessagesHash {
        match self {
            CertificateV1::Dkg(cert) | CertificateV1::Rotation(cert) => cert.message(),
            CertificateV1::NonceGeneration { cert, .. } => cert.message(),
        }
    }

    pub fn protocol_type(&self) -> ProtocolType {
        match self {
            CertificateV1::Dkg(_) => ProtocolType::Dkg,
            CertificateV1::Rotation(_) => ProtocolType::KeyRotation,
            CertificateV1::NonceGeneration { batch_index, .. } => ProtocolType::NonceGeneration {
                batch_index: *batch_index,
            },
        }
    }
}

pub(crate) fn hash_avid_vote(vote: &batch_avss_avid::AvidVote) -> MessageHash {
    let bytes = bcs::to_bytes(vote).expect("AvidVote is serializable");
    MessageHash::from(Blake2b256::digest(&bytes).digest)
}

#[derive(Clone)]
pub struct AvidCertificate<P> {
    dealer_cert: DealerCertificate,
    payload: P,
    committee: Arc<Committee>,
    signers: BTreeSet<PartyId>,
}

pub(crate) type VerifiedAvidVoteCert =
    VerifiedCertificate<AvidCertificate<batch_avss_avid::AvidVote>>;

impl<P: Clone> Certificate for AvidCertificate<P> {
    type Payload = P;

    fn signers(&self) -> &BTreeSet<PartyId> {
        &self.signers
    }

    fn payload(&self) -> &P {
        &self.payload
    }

    fn verify(&self) -> FastCryptoResult<()> {
        // Constructors pin `payload` to `dealer_cert`, so the committee signature over the
        // dealer cert authenticates `payload` too.
        self.committee
            .verify_signature(&self.dealer_cert)
            .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
    }
}

impl AvidCertificate<batch_avss_avid::AvssVote> {
    pub fn confirm(dealer_cert: DealerCertificate, committee: Arc<Committee>) -> MpcResult<Self> {
        let payload = batch_avss_avid::AvssVote {
            common_message_hash: to_fastcrypto_digest(&dealer_cert.message().messages_hash),
        };
        let signers = resolve_signers(&dealer_cert, &committee)?;
        Ok(Self {
            dealer_cert,
            payload,
            committee,
            signers,
        })
    }
}

impl AvidCertificate<batch_avss_avid::AvidVote> {
    pub fn vote(
        dealer_cert: DealerCertificate,
        vote: batch_avss_avid::AvidVote,
        committee: Arc<Committee>,
    ) -> MpcResult<Self> {
        if hash_avid_vote(&vote) != dealer_cert.message().messages_hash {
            return Err(MpcError::InvalidCertificate(
                "AvidVote does not match the certified messages_hash".into(),
            ));
        }
        let signers = resolve_signers(&dealer_cert, &committee)?;
        Ok(Self {
            dealer_cert,
            payload: vote,
            committee,
            signers,
        })
    }
}

fn to_fastcrypto_digest(h: &MessageHash) -> fastcrypto::hash::Digest<32> {
    fastcrypto::hash::Digest::new(*<MessageHash as AsRef<[u8; 32]>>::as_ref(h))
}

fn resolve_signers(
    dealer_cert: &DealerCertificate,
    committee: &Committee,
) -> MpcResult<BTreeSet<PartyId>> {
    dealer_cert
        .signers(committee)
        .map_err(|e| MpcError::InvalidCertificate(e.to_string()))?
        .iter()
        .map(|addr| {
            committee
                .index_of(addr)
                .map(|i| i as PartyId)
                .ok_or_else(|| {
                    MpcError::InvalidCertificate(format!("signer {addr} not in committee"))
                })
        })
        .collect()
}

pub type MpcResult<T> = Result<T, MpcError>;

#[derive(Clone, Debug, thiserror::Error)]
pub enum MpcError {
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

    #[error("Not ready: {0}")]
    NotReady(String),

    #[error("Protocol failed: {0}")]
    ProtocolFailed(String),
}

impl From<FastCryptoError> for MpcError {
    fn from(e: FastCryptoError) -> Self {
        MpcError::CryptoError(e.to_string())
    }
}

impl From<crate::communication::ChannelError> for MpcError {
    fn from(e: crate::communication::ChannelError) -> Self {
        MpcError::BroadcastError(e.to_string())
    }
}

pub struct DealerFlowData {
    pub request: SendMessagesRequest,
    pub recipients: Vec<Address>,
    pub messages_hash: DealerMessagesHash,
    pub my_signature: MemberSignature,
    pub required_reduced_weight: u16,
    pub committee: Committee,
    pub reduced_weights: HashMap<Address, u16>,
}

pub(crate) struct AvidDealerFlowData {
    pub(crate) builder: batch_avss_avid::AvssMessageBuilder,
    pub(crate) confirm_target: DealerMessagesHash,
    pub(crate) my_signature: MemberSignature,
    /// Per-recipient optimistic messages, excluding the dealer's own.
    pub(crate) recipient_messages: Vec<(Address, Messages)>,
    pub(crate) committee: Committee,
    pub(crate) reduced_weights: HashMap<Address, u16>,
    pub(crate) total_reduced_weight: u32,
    /// `W − f` in reduced weight.
    pub(crate) vote_quorum_weight: u32,
}

pub(crate) struct RotationComplainContext {
    pub(crate) request: ComplainRequest,
    pub(crate) receiver: avss::Receiver,
    pub(crate) message: avss::Message,
}

impl RotationComplainContext {
    pub(crate) fn share_index(&self) -> ShareIndex {
        self.request
            .share_index
            .expect("rotation complaint context always carries share_index")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DealerOutputsKey {
    Dkg(Address),
    Rotation(ShareIndex),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComplaintsToProcessKey {
    Dkg(Address),
    Rotation(Address, ShareIndex),
    NonceGeneration { batch_index: u32, dealer: Address },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageResponsesKey {
    Dkg { sender: Address },
    Rotation { sender: Address },
    NonceGeneration { batch_index: u32, sender: Address },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComplaintResponsesKey {
    Dkg {
        dealer: Address,
    },
    Rotation {
        dealer: Address,
        share_index: ShareIndex,
    },
    NonceGeneration {
        batch_index: u32,
        dealer: Address,
    },
}

#[derive(Clone, Debug)]
pub struct PartialSigningOutput {
    pub public_nonce: G,
    pub partial_sigs: Vec<Eval<S>>,
}

#[derive(Clone, Debug)]
pub struct GetPartialSignaturesRequest {
    pub signing_ids: Vec<Address>,
}

#[derive(Clone, Debug)]
pub struct GetPartialSignaturesResponse {
    pub partial_sigs: BTreeMap<Address, Vec<Eval<S>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Invalid message from {sender}: {reason}")]
    InvalidMessage { sender: Address, reason: String },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Signing timed out: collected {collected} partial sigs, need {threshold}")]
    Timeout { collected: usize, threshold: u16 },

    #[error(
        "Too many invalid partial signatures to recover: collected {collected}, threshold {threshold}"
    )]
    TooManyInvalidSignatures { collected: usize, threshold: u16 },

    #[error("Presignature pool exhausted, new batch not yet available")]
    PoolExhausted,
}

pub type SigningResult<T> = Result<T, SigningError>;

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
    use hashi_types::move_types::DealerMessagesHashV1;
    use std::num::NonZeroU16;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct StubAvssCert {
        voters: BTreeSet<PartyId>,
        vote: batch_avss_avid::AvssVote,
    }
    impl Certificate for StubAvssCert {
        type Payload = batch_avss_avid::AvssVote;
        fn signers(&self) -> &BTreeSet<PartyId> {
            &self.voters
        }
        fn payload(&self) -> &batch_avss_avid::AvssVote {
            &self.vote
        }
        fn verify(&self) -> FastCryptoResult<()> {
            Ok(())
        }
    }

    fn test_committee(n: usize, epoch: u64) -> (Committee, Vec<Bls12381PrivateKey>) {
        let mut rng = rand::thread_rng();
        let signing_keys: Vec<_> = (0..n)
            .map(|_| Bls12381PrivateKey::generate(&mut rng))
            .collect();
        let members: Vec<_> = (0..n)
            .map(|i| {
                let enc = EncryptionPrivateKey::new(&mut rng);
                CommitteeMember::new(
                    Address::new([i as u8; 32]),
                    signing_keys[i].public_key(),
                    EncryptionPublicKey::from_private_key(&enc),
                    1,
                )
            })
            .collect();
        let committee = Committee::new(members, epoch, 3334u16, 0u16, 3333u16, 0);
        (committee, signing_keys)
    }

    fn dealer_cert(
        committee: &Committee,
        keys: &[Bls12381PrivateKey],
        signer_indices: &[usize],
        epoch: u64,
        messages_hash: MessageHash,
    ) -> DealerCertificate {
        let message = DealerMessagesHash {
            dealer_address: Address::new([0u8; 32]),
            messages_hash,
        };
        let mut aggregator = BlsSignatureAggregator::new(committee, message.clone());
        for &i in signer_indices {
            let sig = keys[i].sign(epoch, Address::new([i as u8; 32]), &message);
            aggregator.add_signature(sig).unwrap();
        }
        aggregator.finish().unwrap()
    }

    fn mint_avid_vote(voters: &[u16]) -> batch_avss_avid::AvidVote {
        use fastcrypto_tbls::ecies_v1;
        use fastcrypto_tbls::threshold_schnorr::Parameters;
        let (t, f, n, batch) = (3u16, 3u16, 10u16, 3u16);
        let mut rng = rand::thread_rng();
        let sks: Vec<_> = (0..n)
            .map(|_| ecies_v1::PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: ecies_v1::PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect(),
        )
        .unwrap();
        let sid = b"avid cert test".to_vec();
        let params = Parameters { t, f };
        let dealer =
            batch_avss_avid::Dealer::new(nodes.clone(), 0, params, sid.clone(), batch).unwrap();
        let builder = dealer.create_avss_messages(&mut rng).unwrap();
        let own_message = builder.message_for(0).unwrap();
        let cert = StubAvssCert {
            voters: voters.iter().copied().collect(),
            vote: batch_avss_avid::AvssVote {
                common_message_hash: own_message.common.hash(),
            },
        };
        let messages = dealer.create_avid_messages(&builder, cert).unwrap();
        let avid_message = messages.message_for(0).unwrap();
        let receiver =
            batch_avss_avid::Receiver::new(nodes, 0, 0, params, sid, sks[0].clone(), batch)
                .unwrap();
        let (_, _, verified_common) = receiver.process_avss_message(&own_message).unwrap();
        let (_, avid_vote) = receiver
            .process_avid_message(&verified_common, avid_message)
            .unwrap();
        avid_vote
    }

    #[test]
    fn avid_confirm_certificate_reconstructs_payload_and_verifies() {
        let epoch = 5;
        let (committee, keys) = test_committee(3, epoch);
        let h_v: [u8; 32] = [42u8; 32];
        let signed = dealer_cert(&committee, &keys, &[0, 1, 2], epoch, h_v.into());
        let committee = Arc::new(committee);

        let cert = AvidCertificate::confirm(signed.clone(), committee).unwrap();

        assert_eq!(cert.signers(), &BTreeSet::from([0u16, 1, 2]));
        assert_eq!(cert.payload().common_message_hash.digest, h_v);
        assert!(cert.verify().is_ok());
        assert!(cert.into_verified().is_ok());

        let (other, _) = test_committee(3, epoch);
        let bad = AvidCertificate::confirm(signed, Arc::new(other)).unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn avid_vote_certificate_hash_pins_the_payload() {
        let epoch = 7;
        let avid_vote = mint_avid_vote(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let (committee, keys) = test_committee(3, epoch);
        let good = dealer_cert(
            &committee,
            &keys,
            &[0, 1, 2],
            epoch,
            hash_avid_vote(&avid_vote),
        );
        let wrong = dealer_cert(&committee, &keys, &[0, 1, 2], epoch, [0u8; 32].into());
        let committee = Arc::new(committee);

        let cert = AvidCertificate::vote(good, avid_vote.clone(), committee.clone()).unwrap();
        assert!(cert.verify().is_ok());
        assert!(cert.into_verified().is_ok());
        assert_eq!(
            bcs::to_bytes(cert.payload()).unwrap(),
            bcs::to_bytes(&avid_vote).unwrap(),
        );

        assert!(AvidCertificate::vote(wrong, avid_vote, committee).is_err());
    }

    #[test]
    fn process_avid_message_accepts_a_real_confirm_cert() {
        use fastcrypto_tbls::ecies_v1;
        use fastcrypto_tbls::threshold_schnorr::Parameters;
        let (t, f, n, batch, epoch) = (3u16, 3u16, 10u16, 3u16, 9u64);
        let mut rng = rand::thread_rng();

        let sks: Vec<_> = (0..n)
            .map(|_| PrivateKey::<EncryptionGroupElement>::new(&mut rng))
            .collect();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: ecies_v1::PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect(),
        )
        .unwrap();
        let (committee, keys) = test_committee(n as usize, epoch);

        let sid = b"avid confirm integration".to_vec();
        let params = Parameters { t, f };
        let dealer =
            batch_avss_avid::Dealer::new(nodes.clone(), 0, params, sid.clone(), batch).unwrap();
        let builder = dealer.create_avss_messages(&mut rng).unwrap();
        let own_message = builder.message_for(0).unwrap();

        // A real Confirm cert
        let h_v = MessageHash::from(own_message.common.hash().digest);
        let confirmers: Vec<usize> = (0..=7).collect();
        let signed = dealer_cert(&committee, &keys, &confirmers, epoch, h_v);
        let confirm_cert = AvidCertificate::confirm(signed, Arc::new(committee)).unwrap();
        assert!(confirm_cert.verify().is_ok());

        // Disperse with the real cert
        let messages = dealer.create_avid_messages(&builder, confirm_cert).unwrap();
        let receiver =
            batch_avss_avid::Receiver::new(nodes, 0, 0, params, sid, sks[0].clone(), batch)
                .unwrap();
        let (_, _, verified_common) = receiver.process_avss_message(&own_message).unwrap();
        let processed =
            receiver.process_avid_message(&verified_common, messages.message_for(0).unwrap());
        assert!(processed.is_ok());
    }

    #[test]
    fn vote_certificate_binds_the_pending_set() {
        let epoch = 11;
        // Two valid dispersals with different recipient sets
        let vote_89 = mint_avid_vote(&[0, 1, 2, 3, 4, 5, 6, 7]); // recipients {8, 9}
        let vote_79 = mint_avid_vote(&[0, 1, 2, 3, 4, 5, 6, 8]); // recipients {7, 9}

        assert_ne!(hash_avid_vote(&vote_89), hash_avid_vote(&vote_79));

        let (committee, keys) = test_committee(3, epoch);
        let signed = dealer_cert(
            &committee,
            &keys,
            &[0, 1, 2],
            epoch,
            hash_avid_vote(&vote_89),
        );
        assert!(AvidCertificate::vote(signed, vote_79, Arc::new(committee)).is_err());
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
    #[should_panic(expected = "InvalidInput")]
    fn test_dkg_config_zero_weight_sum() {
        // Nodes::new() will fail when trying to create nodes with zero weights
        // This is the expected behavior - invalid node configuration is caught early
        let validators = vec![create_test_validator(0, 0), create_test_validator(1, 0)];
        let _nodes = build_nodes(validators);
    }

    #[test]
    fn test_session_context_deterministic_serialization() {
        let epoch = 100;
        let protocol_type = ProtocolType::Dkg;
        let chain_id = "testnet".to_string();

        let sid1 = SessionId::new(&chain_id, epoch, &protocol_type);
        let sid2 = SessionId::new(&chain_id, epoch, &protocol_type);

        assert_eq!(sid1, sid2);
    }

    #[test]
    fn test_session_id_different_for_different_protocols() {
        let epoch = 100;
        let chain_id = "testnet".to_string();

        let dkg_sid = SessionId::new(&chain_id, epoch, &ProtocolType::Dkg);
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
        let protocol_type = ProtocolType::Dkg;
        let mainnet_id = SessionId::new("mainnet", epoch, &protocol_type);
        let testnet_id = SessionId::new("testnet", epoch, &protocol_type);

        assert_ne!(testnet_id, mainnet_id);
    }

    #[test]
    fn test_dealer_session_serialization() {
        let sid = SessionId::new("testnet", 100, &ProtocolType::Dkg);
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
        let committee = Committee::new(members, epoch, 3334u16, 0u16, 3333u16, 0);

        // Create a DealerMessagesHash
        let dealer_address = Address::new([0u8; 32]);
        let messages_hash: [u8; 32] = [42u8; 32];
        let dkg_message = DealerMessagesHash {
            dealer_address,
            messages_hash: messages_hash.into(),
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
        let onchain_cert = DealerSubmissionV1 {
            message: DealerMessagesHashV1 {
                dealer_address,
                messages_hash: messages_hash.to_vec(),
            },
            signature: MoveCommitteeSignature {
                epoch,
                signature: signed_message.signature_bytes().to_vec(),
                signers_bitmap: signed_message.signers_bitmap_bytes().to_vec(),
            },
        };

        // Parse back using from_onchain_cert
        let result = DealerMessagesHash::from_onchain_cert(&onchain_cert, epoch);
        assert!(
            result.is_ok(),
            "Should parse valid certificate: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.message().dealer_address, dealer_address);
        assert_eq!(
            <MessageHash as AsRef<[u8; 32]>>::as_ref(&parsed.message().messages_hash),
            &messages_hash
        );
    }

    #[test]
    fn test_from_onchain_cert_invalid_hash_length() {
        let epoch = 100u64;

        // Create certificate with invalid hash length (not 32 bytes)
        let onchain_cert = DealerSubmissionV1 {
            message: DealerMessagesHashV1 {
                dealer_address: Address::new([0u8; 32]),
                messages_hash: vec![1, 2, 3], // Invalid: only 3 bytes
            },
            signature: MoveCommitteeSignature {
                epoch,
                signature: vec![],
                signers_bitmap: vec![],
            },
        };

        let result = DealerMessagesHash::from_onchain_cert(&onchain_cert, epoch);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid messages_hash length"),
            "Error should mention invalid hash length: {}",
            err
        );
    }

    #[test]
    fn test_nonce_generation_protocol_from_onchain() {
        assert_eq!(
            NonceGenerationProtocol::from_onchain(0).unwrap(),
            NonceGenerationProtocol::Vanilla
        );
        assert_eq!(
            NonceGenerationProtocol::from_onchain(1).unwrap(),
            NonceGenerationProtocol::Avid
        );
        assert!(NonceGenerationProtocol::from_onchain(2).is_err());
        assert!(NonceGenerationProtocol::from_onchain(u16::MAX).is_err());
        assert_eq!(
            NonceGenerationProtocol::default(),
            NonceGenerationProtocol::Vanilla
        );
    }

    #[test]
    fn presignature_derivation_version_from_activation_epoch() {
        use PresignatureDerivationVersion::*;
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(4, 5),
            Legacy
        );
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(5, 5),
            PrivacyThreshold
        );
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(6, 5),
            PrivacyThreshold
        );
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(0, 0),
            PrivacyThreshold
        );
        // The absent-key default: never activates.
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(u64::MAX, u64::MAX),
            PrivacyThreshold
        );
        assert_eq!(
            PresignatureDerivationVersion::from_activation_epoch(u64::MAX - 1, u64::MAX),
            Legacy
        );
        assert!(Legacy.use_legacy());
        assert!(!PrivacyThreshold.use_legacy());
        assert_eq!(PresignatureDerivationVersion::default(), Legacy);
    }

    #[test]
    fn nonce_collection_window_zero_is_floor_rule_verbatim() {
        let mut window = NonceCollectionWindow::new(10, 0);
        let admission = window.try_admit(100).unwrap();
        window.record(admission, 6);
        assert!(!window.closed());
        let admission = window.try_admit(100).unwrap();
        window.record(admission, 4);
        assert!(window.closed());
        assert_eq!(window.cutoff_ms(), None);
        assert!(window.try_admit(100).is_none());
    }

    #[test]
    fn nonce_collection_window_admits_through_cutoff_and_closes_after() {
        let mut window = NonceCollectionWindow::new(10, 700);
        let admission = window.try_admit(100).unwrap();
        window.record(admission, 6);
        let admission = window.try_admit(200).unwrap();
        window.record(admission, 4);
        assert!(!window.closed());
        assert_eq!(window.cutoff_ms(), Some(900));
        let admission = window.try_admit(900).unwrap();
        window.record(admission, 3);
        assert!(window.try_admit(901).is_none());
        assert!(window.closed());
        assert_eq!(window.cutoff_ms(), Some(900));
        assert!(window.floor_reached());
        assert!(window.try_admit(500).is_none());
    }

    #[test]
    fn nonce_collection_window_cutoff_uses_crossing_stamp_not_later_ones() {
        let mut window = NonceCollectionWindow::new(5, 700);
        let admission = window.try_admit(1_000).unwrap();
        window.record(admission, 5);
        assert_eq!(window.cutoff_ms(), Some(1_700));
        let admission = window.try_admit(1_600).unwrap();
        window.record(admission, 2);
        assert_eq!(window.cutoff_ms(), Some(1_700));
    }

    #[test]
    fn nonce_collection_window_unrecorded_admission_leaves_state_unchanged() {
        let mut window = NonceCollectionWindow::new(10, 700);
        assert!(window.try_admit(100).is_some());
        let admission = window.try_admit(100).unwrap();
        window.record(admission, 6);
        assert!(!window.floor_reached());
        assert_eq!(window.weight(), 6);
    }
}
