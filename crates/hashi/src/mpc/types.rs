// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::GroupElement;
use fastcrypto::groups::secp256k1::POINT_SIZE_IN_BYTES;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::ecies_v1::Ciphertext;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::threshold_schnorr::Address as DerivationAddress;
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
use hashi_types::move_types::StampedDealerSubmissionV1;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;

pub type EncryptionGroupElement = fastcrypto::groups::ristretto255::RistrettoPoint;
pub(crate) const EXPECT_SERIALIZATION_SUCCESS: &str = "Serialization should always succeed";
pub type MessagesHash = Digest;
pub type RotationMessages = BTreeMap<ShareIndex, avss::Message>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceMessage {
    pub batch_index: u32,
    pub message: batch_avss::Message,
}

pub type AvidConfirmCertificate = SignedMessage<AvssVoteMessagesHash>;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcConfig {
    pub epoch: u64,
    /// `nodes`, `threshold` and `max_faulty` are returned together by weight reduction.
    pub nodes: Nodes<EncryptionGroupElement>,
    pub threshold: u16,
    pub max_faulty: u16,
    pub nonce_generation_protocol: NonceGenerationProtocol,
    pub nonce_accumulation_window_ms: u64,
}

impl MpcConfig {
    pub fn new(
        epoch: u64,
        nodes: Nodes<EncryptionGroupElement>,
        threshold: u16,
        max_faulty: u16,
        nonce_generation_protocol: NonceGenerationProtocol,
        nonce_accumulation_window_ms: u64,
    ) -> Self {
        Self {
            epoch,
            nodes,
            threshold,
            max_faulty,
            nonce_generation_protocol,
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

    pub fn with_cutoff(required_weight: u32, cutoff_ms: Option<u64>) -> Self {
        let Some(cutoff_ms) = cutoff_ms else {
            return Self::new(required_weight, 0);
        };
        Self {
            required_weight,
            window_ms: 0,
            weight: 0,
            state: NonceCollectionState::Window { cutoff_ms },
        }
    }

    pub fn closed(&self) -> bool {
        matches!(self.state, NonceCollectionState::Closed { .. })
    }

    pub fn floor_reached(&self) -> bool {
        self.weight >= self.required_weight
    }

    pub fn weight(&self) -> u32 {
        self.weight
    }

    pub fn required_weight(&self) -> u32 {
        self.required_weight
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
            // A zero crossing stamp marks the bare (pre-stamped-package) cert path.
            self.state = if self.window_ms == 0 || admission.timestamp_ms == 0 {
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
}

impl SessionId {
    // TODO: `new` accepts any protocol but only DKG and rotation reach it; nonce generation
    // uses `nonce_dealer_session_id`.
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
    pub(crate) fn compute_hash(&self) -> MessagesHash {
        let bytes = bcs::to_bytes(self).expect(EXPECT_SERIALIZATION_SUCCESS);
        MessagesHash::from(Blake2b256::digest(&bytes).digest)
    }

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
        batch_index: u32,
        complaint: complaint::Complaint,
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
        vote_cert: SignedMessage<AvidVoteMessagesHash>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplainRequest {
    pub epoch: u64,
    // TODO: Redundant since the request already pins the protocol.
    // Removing it from the proto is a separate staged rollout since the field is required today
    // and this RPC has no version negotiation.
    pub protocol_type: ProtocolTypeIndicator,
    pub dealer: Address,
    pub batch_index: Option<u32>,        // Only for nonce generation
    pub share_index: Option<ShareIndex>, // Only for key rotation
    pub complaint: ProtocolComplaint,
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
    pub messages_hash: MessagesHash,
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

pub(crate) trait NonceCertPayload: hashi_types::intent::IntentMessage {
    fn dealer_address(&self) -> Address;
    fn messages_hash(&self) -> MessagesHash;
}

impl NonceCertPayload for DealerMessagesHash {
    fn dealer_address(&self) -> Address {
        self.dealer_address
    }
    fn messages_hash(&self) -> MessagesHash {
        self.messages_hash
    }
}

impl NonceCertPayload for AvssVoteMessagesHash {
    fn dealer_address(&self) -> Address {
        self.dealer_address
    }
    fn messages_hash(&self) -> MessagesHash {
        self.messages_hash
    }
}

impl NonceCertPayload for AvidVoteMessagesHash {
    fn dealer_address(&self) -> Address {
        self.dealer_address
    }
    fn messages_hash(&self) -> MessagesHash {
        self.messages_hash
    }
}

pub(crate) struct UnclassifiedNonceCert {
    epoch: u64,
    dealer_address: Address,
    messages_hash: MessagesHash,
    batch_index: u32,
    signature: Vec<u8>,
    signers_bitmap: Vec<u8>,
}

impl UnclassifiedNonceCert {
    pub(crate) fn from_signed<T: NonceCertPayload>(
        cert: &SignedMessage<T>,
        batch_index: u32,
    ) -> Self {
        Self::from_signature_parts(
            cert.message().dealer_address(),
            cert.message().messages_hash(),
            batch_index,
            cert.committee_signature(),
        )
    }

    pub(crate) fn from_dealer_certificate(cert: &DealerCertificate, batch_index: u32) -> Self {
        Self::from_signature_parts(
            cert.message().dealer_address,
            cert.message().messages_hash,
            batch_index,
            cert.committee_signature(),
        )
    }

    pub(crate) fn from_signature_parts(
        dealer_address: Address,
        messages_hash: MessagesHash,
        batch_index: u32,
        signature: &hashi_types::committee::CommitteeSignature,
    ) -> Self {
        Self {
            epoch: signature.epoch(),
            dealer_address,
            messages_hash,
            batch_index,
            signature: signature.signature_bytes().to_vec(),
            signers_bitmap: signature.signers_bitmap_bytes().to_vec(),
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn as_dealer_messages_hash(&self) -> MpcResult<DealerCertificate> {
        self.retype(DealerMessagesHash {
            dealer_address: self.dealer_address,
            messages_hash: self.messages_hash,
        })
    }

    pub(crate) fn as_avss_vote(&self) -> MpcResult<SignedMessage<AvssVoteMessagesHash>> {
        self.retype(AvssVoteMessagesHash {
            dealer_address: self.dealer_address,
            messages_hash: self.messages_hash,
            batch_index: self.batch_index,
        })
    }

    pub(crate) fn as_avid_vote(&self) -> MpcResult<SignedMessage<AvidVoteMessagesHash>> {
        self.retype(AvidVoteMessagesHash {
            dealer_address: self.dealer_address,
            messages_hash: self.messages_hash,
            batch_index: self.batch_index,
        })
    }

    fn retype<T: hashi_types::intent::IntentMessage>(
        &self,
        message: T,
    ) -> MpcResult<SignedMessage<T>> {
        SignedMessage::new(self.epoch, message, &self.signature, &self.signers_bitmap)
            .map_err(|e| MpcError::InvalidCertificate(e.to_string()))
    }
}

/// AVID optimistic-path (`CertKind::AvssVote`) signing domain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssVoteMessagesHash {
    pub dealer_address: Address,
    pub messages_hash: MessagesHash,
    pub batch_index: u32,
}

impl hashi_types::intent::IntentMessage for AvssVoteMessagesHash {
    const INTENT: hashi_types::intent::Intent = hashi_types::intent::Intent::AvssVoteMessagesHash;
}

/// AVID pessimistic-path (`CertKind::AvidVote`) signing domain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidVoteMessagesHash {
    pub dealer_address: Address,
    pub messages_hash: MessagesHash,
    pub batch_index: u32,
}

impl hashi_types::intent::IntentMessage for AvidVoteMessagesHash {
    const INTENT: hashi_types::intent::Intent = hashi_types::intent::Intent::AvidVoteMessagesHash;
}

pub(crate) trait NonceCertToVerify {
    fn to_dealer_certificate(&self, epoch: u64) -> MpcResult<DealerCertificate>;
}

impl NonceCertToVerify for DealerSubmissionV1 {
    fn to_dealer_certificate(&self, epoch: u64) -> MpcResult<DealerCertificate> {
        DealerMessagesHash::from_onchain_cert(self, epoch)
    }
}

impl NonceCertToVerify for CertificateV1 {
    fn to_dealer_certificate(&self, _epoch: u64) -> MpcResult<DealerCertificate> {
        match self {
            CertificateV1::NonceGeneration { cert, .. } => Ok(cert.clone()),
            _ => Err(MpcError::InvalidCertificate(
                "expected a nonce-generation certificate".into(),
            )),
        }
    }
}

impl NonceCertToVerify for StampedDealerSubmissionV1 {
    fn to_dealer_certificate(&self, epoch: u64) -> MpcResult<DealerCertificate> {
        self.submission.to_dealer_certificate(epoch)
    }
}

pub(crate) trait NonceCertTimestamp {
    fn nonce_timestamp_ms(&self) -> u64;

    fn signed_dealer(&self, epoch: u64) -> Option<Address>;
}

impl NonceCertTimestamp for StampedDealerSubmissionV1 {
    fn nonce_timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    fn signed_dealer(&self, epoch: u64) -> Option<Address> {
        self.to_dealer_certificate(epoch)
            .ok()
            .map(|cert| cert.message().dealer_address)
    }
}

impl NonceCertTimestamp for CertificateV1 {
    fn nonce_timestamp_ms(&self) -> u64 {
        match self {
            CertificateV1::NonceGeneration { timestamp_ms, .. } => *timestamp_ms,
            _ => 0,
        }
    }

    fn signed_dealer(&self, _epoch: u64) -> Option<Address> {
        match self {
            CertificateV1::NonceGeneration { cert, .. } => Some(cert.message().dealer_address),
            _ => None,
        }
    }
}

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
    pub(crate) fn protocol_label(&self) -> &'static str {
        match self {
            CertificateV1::Dkg(_) => crate::metrics::MPC_LABEL_DKG,
            CertificateV1::Rotation(_) => crate::metrics::MPC_LABEL_KEY_ROTATION,
            CertificateV1::NonceGeneration { .. } => crate::metrics::MPC_LABEL_NONCE_GENERATION,
        }
    }

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

#[derive(Clone, Debug)]
pub struct VerifiedCertificateV1(CertificateV1);

impl VerifiedCertificateV1 {
    pub(crate) fn new_unchecked(cert: CertificateV1) -> Self {
        Self(cert)
    }

    pub fn inner(&self) -> &CertificateV1 {
        &self.0
    }
}

pub(crate) fn hash_avid_vote(vote: &batch_avss_avid::AvidVote) -> MessagesHash {
    let bytes = bcs::to_bytes(vote).expect("AvidVote is serializable");
    MessagesHash::from(Blake2b256::digest(&bytes).digest)
}

pub trait AvidLeg {
    type Domain: hashi_types::intent::IntentMessage;
}

impl AvidLeg for batch_avss_avid::AvssVote {
    type Domain = AvssVoteMessagesHash;
}

impl AvidLeg for batch_avss_avid::AvidVote {
    type Domain = AvidVoteMessagesHash;
}

#[derive(Clone)]
pub struct AvidCertificate<P: AvidLeg> {
    dealer_cert: SignedMessage<P::Domain>,
    payload: P,
    committee: Arc<Committee>,
    /// The Hashi deployment the dealer cert's preimage is bound to.
    hashi_id: Address,
    signers: BTreeSet<PartyId>,
}

pub(crate) type VerifiedAvidVoteCert =
    VerifiedCertificate<AvidCertificate<batch_avss_avid::AvidVote>>;

impl<P: Clone + AvidLeg> Certificate for AvidCertificate<P> {
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
            .verify_signature_any_weight(self.hashi_id, &self.dealer_cert)
            .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
    }
}

impl AvidCertificate<batch_avss_avid::AvssVote> {
    pub fn confirm(
        hashi_id: Address,
        dealer_cert: SignedMessage<AvssVoteMessagesHash>,
        committee: Arc<Committee>,
    ) -> MpcResult<Self> {
        let payload = batch_avss_avid::AvssVote {
            common_message_hash: to_fastcrypto_digest(&dealer_cert.message().messages_hash),
        };
        let signers = resolve_signers(&dealer_cert, &committee)?;
        Ok(Self {
            dealer_cert,
            payload,
            committee,
            hashi_id,
            signers,
        })
    }
}

impl AvidCertificate<batch_avss_avid::AvidVote> {
    pub fn vote(
        hashi_id: Address,
        dealer_cert: SignedMessage<AvidVoteMessagesHash>,
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
            hashi_id,
            signers,
        })
    }
}

fn to_fastcrypto_digest(h: &MessagesHash) -> fastcrypto::hash::Digest<32> {
    fastcrypto::hash::Digest::new(*<MessagesHash as AsRef<[u8; 32]>>::as_ref(h))
}

fn resolve_signers<T: hashi_types::intent::IntentMessage>(
    dealer_cert: &SignedMessage<T>,
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

    #[error("Stored message for dealer {dealer} does not match its certificate")]
    StoredMessageDiverged { dealer: Address },

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

pub enum ReconfigOutcome {
    Output(MpcOutput),
    Dealt,
    NotNeeded,
    NoShares,
    NoRole,
}

impl std::fmt::Debug for ReconfigOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl ReconfigOutcome {
    pub fn into_output(self) -> Option<MpcOutput> {
        match self {
            Self::Output(output) => Some(output),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Output(_) => "output",
            Self::Dealt => "dealt",
            Self::NotNeeded => "not_needed",
            Self::NoShares => "no_shares",
            Self::NoRole => "no_role",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationRole {
    DealerAndParty,
    DealerOnly,
}

pub struct DealerFlowData {
    pub request: SendMessagesRequest,
    pub recipients: Vec<Address>,
    pub messages_hash: DealerMessagesHash,
    pub my_signature: Option<MemberSignature>,
    pub required_reduced_weight: u32,
    pub committee: Committee,
    /// The Hashi deployment every collected signature must be bound to.
    pub hashi_id: Address,
    pub nodes: Nodes<EncryptionGroupElement>,
}

pub(crate) struct AvidDealerFlowData {
    pub(crate) builder: batch_avss_avid::AvssMessageBuilder,
    pub(crate) confirm_target: AvssVoteMessagesHash,
    pub(crate) my_signature: MemberSignature,
    /// Per-recipient optimistic messages, excluding the dealer's own.
    pub(crate) recipient_messages: Vec<(Address, Messages)>,
    pub(crate) committee: Committee,
    /// The Hashi deployment every collected signature must be bound to.
    pub(crate) hashi_id: Address,
    pub(crate) nodes: Nodes<EncryptionGroupElement>,
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
    Rotation(Address, ShareIndex),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComplaintsToProcessKey {
    Dkg(Address),
    Rotation {
        epoch: u64,
        dealer: Address,
        share_index: ShareIndex,
    },
    NonceGeneration {
        batch_index: u32,
        dealer: Address,
    },
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

pub(crate) fn signing_nonce_bytes(public_presig: &G, beacon: &S) -> [u8; POINT_SIZE_IN_BYTES] {
    (*public_presig + G::generator() * beacon).to_byte_array()
}

pub(crate) fn signing_request_digest(
    message: &[u8],
    derivation_address: Option<&DerivationAddress>,
) -> [u8; 32] {
    let mut h = Blake2b256::default();
    h.update((message.len() as u64).to_le_bytes());
    h.update(message);
    match derivation_address {
        Some(a) => {
            h.update([1u8]);
            h.update(a);
        }
        None => h.update([0u8]),
    }
    h.finalize().digest
}

#[derive(Clone, Debug)]
pub struct PartialSigningOutput {
    public_nonce: G,
    signing_nonce_bytes: [u8; POINT_SIZE_IN_BYTES],
    request_digest: [u8; 32],
    pub partial_sigs: Vec<Eval<S>>,
}

impl PartialSigningOutput {
    pub fn new(
        public_nonce: G,
        beacon: &S,
        message: &[u8],
        derivation_address: Option<&DerivationAddress>,
        partial_sigs: Vec<Eval<S>>,
    ) -> Self {
        Self {
            signing_nonce_bytes: signing_nonce_bytes(&public_nonce, beacon),
            request_digest: signing_request_digest(message, derivation_address),
            public_nonce,
            partial_sigs,
        }
    }

    pub fn public_nonce(&self) -> G {
        self.public_nonce
    }

    pub fn signing_nonce_bytes(&self) -> &[u8; POINT_SIZE_IN_BYTES] {
        &self.signing_nonce_bytes
    }

    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

#[derive(Clone, Debug)]
pub struct GetPartialSignaturesRequest {
    pub signing_ids: Vec<Address>,
}

#[derive(Clone, Debug)]
pub struct GetPartialSignaturesResponse {
    pub partial_sigs: BTreeMap<Address, Vec<Eval<S>>>,
    pub signing_nonces: BTreeMap<Address, Vec<u8>>,
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
        "Not enough usable partial signatures to recover: collected {collected}, threshold {threshold}"
    )]
    TooManyInvalidSignatures { collected: usize, threshold: u16 },

    #[error("Presignature pool exhausted, new batch not yet available")]
    PoolExhausted,

    #[error(
        "Cached partial signatures for {signing_id} were computed under a different message, \
         derivation address or beacon"
    )]
    RequestChanged { signing_id: Address },
}

pub type SigningResult<T> = Result<T, SigningError>;

#[cfg(test)]
mod tests {
    const TEST_HASHI_ID: Address = Address::new([0xAA; 32]);
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

    #[test]
    fn avid_domains_differ_and_batch_index_changes_the_bcs_body() {
        use hashi_types::intent::IntentMessage;

        assert_ne!(
            AvssVoteMessagesHash::INTENT.as_u16(),
            AvidVoteMessagesHash::INTENT.as_u16()
        );
        assert_ne!(
            DealerMessagesHash::INTENT.as_u16(),
            AvssVoteMessagesHash::INTENT.as_u16()
        );

        let dealer_address = Address::new([3u8; 32]);
        let messages_hash = MessagesHash::from([7u8; 32]);
        let batch_0 = AvssVoteMessagesHash {
            dealer_address,
            messages_hash,
            batch_index: 0,
        };
        let batch_1 = AvssVoteMessagesHash {
            dealer_address,
            messages_hash,
            batch_index: 1,
        };
        assert_ne!(
            bcs::to_bytes(&batch_0).unwrap(),
            bcs::to_bytes(&batch_1).unwrap()
        );
    }

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
        let committee = Committee::new(members, epoch, 0u16, 3333u16, 0);
        (committee, signing_keys)
    }

    fn confirm_cert_over(
        committee: &Committee,
        keys: &[Bls12381PrivateKey],
        signer_indices: &[usize],
        epoch: u64,
        messages_hash: MessagesHash,
    ) -> SignedMessage<AvssVoteMessagesHash> {
        cert_over(
            committee,
            keys,
            signer_indices,
            epoch,
            AvssVoteMessagesHash {
                dealer_address: Address::new([0u8; 32]),
                messages_hash,
                batch_index: 0,
            },
        )
    }

    fn vote_cert_over(
        committee: &Committee,
        keys: &[Bls12381PrivateKey],
        signer_indices: &[usize],
        epoch: u64,
        messages_hash: MessagesHash,
    ) -> SignedMessage<AvidVoteMessagesHash> {
        cert_over(
            committee,
            keys,
            signer_indices,
            epoch,
            AvidVoteMessagesHash {
                dealer_address: Address::new([0u8; 32]),
                messages_hash,
                batch_index: 0,
            },
        )
    }

    fn cert_over<T: hashi_types::intent::IntentMessage + Clone>(
        committee: &Committee,
        keys: &[Bls12381PrivateKey],
        signer_indices: &[usize],
        epoch: u64,
        message: T,
    ) -> SignedMessage<T> {
        let mut aggregator = BlsSignatureAggregator::new(TEST_HASHI_ID, committee, message.clone());
        for &i in signer_indices {
            let sig = keys[i].sign(TEST_HASHI_ID, epoch, Address::new([i as u8; 32]), &message);
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
        let signed = confirm_cert_over(&committee, &keys, &[0, 1, 2], epoch, h_v.into());
        let committee = Arc::new(committee);

        let cert = AvidCertificate::confirm(TEST_HASHI_ID, signed.clone(), committee).unwrap();

        assert_eq!(cert.signers(), &BTreeSet::from([0u16, 1, 2]));
        assert_eq!(cert.payload().common_message_hash.digest, h_v);
        assert!(cert.verify().is_ok());
        assert!(cert.to_verified().is_ok());

        let (other, _) = test_committee(3, epoch);
        let bad = AvidCertificate::confirm(TEST_HASHI_ID, signed, Arc::new(other)).unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn avid_vote_certificate_hash_pins_the_payload() {
        let epoch = 7;
        let avid_vote = mint_avid_vote(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let (committee, keys) = test_committee(3, epoch);
        let good = vote_cert_over(
            &committee,
            &keys,
            &[0, 1, 2],
            epoch,
            hash_avid_vote(&avid_vote),
        );
        let wrong = vote_cert_over(&committee, &keys, &[0, 1, 2], epoch, [0u8; 32].into());
        let committee = Arc::new(committee);

        let cert = AvidCertificate::vote(TEST_HASHI_ID, good, avid_vote.clone(), committee.clone())
            .unwrap();
        assert!(cert.verify().is_ok());
        assert!(cert.to_verified().is_ok());
        assert_eq!(
            bcs::to_bytes(cert.payload()).unwrap(),
            bcs::to_bytes(&avid_vote).unwrap(),
        );

        assert!(AvidCertificate::vote(TEST_HASHI_ID, wrong, avid_vote, committee).is_err());
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
        let h_v = MessagesHash::from(own_message.common.hash().digest);
        let confirmers: Vec<usize> = (0..=7).collect();
        let signed = confirm_cert_over(&committee, &keys, &confirmers, epoch, h_v);
        let confirm_cert =
            AvidCertificate::confirm(TEST_HASHI_ID, signed, Arc::new(committee)).unwrap();
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
        let signed = vote_cert_over(
            &committee,
            &keys,
            &[0, 1, 2],
            epoch,
            hash_avid_vote(&vote_89),
        );
        assert!(
            AvidCertificate::vote(TEST_HASHI_ID, signed, vote_79, Arc::new(committee)).is_err()
        );
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
    fn test_session_id_derivation_is_wire_stable() {
        let dealer = Address::new([1; 32]);
        let share = NonZeroU16::new(1).unwrap();
        let dkg = SessionId::new("testnet", 100, &ProtocolType::Dkg);
        let rotation = SessionId::new("testnet", 100, &ProtocolType::KeyRotation);

        let actual: Vec<String> = vec![
            hex::encode(dkg.to_vec()),
            hex::encode(dkg.dealer_session_id(&dealer).to_vec()),
            hex::encode(rotation.to_vec()),
            hex::encode(rotation.rotation_session_id(&dealer, share).to_vec()),
            hex::encode(SessionId::nonce_dealer_session_id("testnet", 100, 7, &dealer).to_vec()),
        ];
        assert_eq!(
            actual,
            vec![
                "44d9e2d76343404d73e639b8136c7998173923cde4743df8fdddc2f5988025bd9355634e11abdf9be378ff86ef1aa200b6f16a8d39e083543cfc78ab8714905b",
                "66191197a9a9d5ed703cfeceed7f540a7a88c0838919ae3ebef7e69c23db0fd227529ab9484ac1538be6c8e62f40fc30ae2fc9a563e9a0ac0dbe6b98d810e86c",
                "e201fd2004f6607e4ca4acf2d411a132977df4c5d4ce7df9dd40038b6a4cf5f77ca3ab08219ddbbc502bb5e2619ed029392d49dc358944ff909fefc8321a3be8",
                "ea2e0d56a9bd2044e2a5af55df94274bae36c8e890d8a50ba6fe32b301a36583a533ce54a766bcc3431f1ab74b5f2d02111a3d4d11680cd092fbe97b67bec448",
                "0558d7ae18d26c18a9fa47e045f35c814aef2e64421f1f2a00b7077dda8ad835cee5bf830a2970472aa33a5f153345db55ef13fef18fbc405a8ad5b740a38890",
            ]
        );
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
        let committee = Committee::new(members, epoch, 0u16, 3333u16, 0);

        // Create a DealerMessagesHash
        let dealer_address = Address::new([0u8; 32]);
        let messages_hash: [u8; 32] = [42u8; 32];
        let dkg_message = DealerMessagesHash {
            dealer_address,
            messages_hash: messages_hash.into(),
        };

        // Sign with committee members to create a valid certificate
        let mut aggregator =
            BlsSignatureAggregator::new(TEST_HASHI_ID, &committee, dkg_message.clone());
        for (i, key) in signing_keys.iter().enumerate() {
            let addr = Address::new([i as u8; 32]);
            let sig = key.sign(TEST_HASHI_ID, epoch, addr, &dkg_message);
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
            <MessagesHash as AsRef<[u8; 32]>>::as_ref(&parsed.message().messages_hash),
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
    fn nonce_collection_window_zero_crossing_stamp_forces_floor_only() {
        let mut window = NonceCollectionWindow::new(10, 700);
        let admission = window.try_admit(0).unwrap();
        window.record(admission, 6);
        assert!(!window.closed());
        let admission = window.try_admit(0).unwrap();
        window.record(admission, 4);
        assert!(window.closed());
        assert_eq!(window.cutoff_ms(), None);
        assert!(window.try_admit(0).is_none());
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

    fn party_loop_cutoff(
        stamps: &[u64],
        weight_each: u32,
        required_weight: u32,
        window_ms: u64,
        skip: &[usize],
    ) -> Option<u64> {
        let decided = {
            let mut gate = NonceCollectionWindow::new(required_weight, window_ms);
            for &ts in stamps {
                let Some(admission) = gate.try_admit(ts) else {
                    break;
                };
                gate.record(admission, weight_each);
            }
            gate.cutoff_ms()
        };
        let mut window = NonceCollectionWindow::with_cutoff(required_weight, decided);
        for (i, &ts) in stamps.iter().enumerate() {
            if window.closed() {
                break;
            }
            let Some(admission) = window.try_admit(ts) else {
                break;
            };
            if skip.contains(&i) {
                continue;
            }
            window.record(admission, weight_each);
        }
        window.cutoff_ms()
    }

    #[test]
    fn cutoff_must_not_depend_on_locally_unconsumable_certs() {
        let stamps = [1_000u64, 1_000, 1_000, 1_000, 1_800];
        let baseline = party_loop_cutoff(&stamps, 1, 4, 700, &[]);
        for skipped in 0..stamps.len() {
            assert_eq!(
                party_loop_cutoff(&stamps, 1, 4, 700, &[skipped]),
                baseline,
                "skipping cert {skipped} moved the cutoff from {baseline:?}; the cutoff \
                 must be a function of the on-chain cert list, not of which certs this \
                 node could process"
            );
        }
    }
}
