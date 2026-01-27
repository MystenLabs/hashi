//! Definitions of the raw Move structs in the hashi package

use fastcrypto::traits::ToFromBytes;
use std::collections::BTreeSet;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::FromBcs;
use sui_sdk_types::bcs::ToBcs;

pub trait MoveType {
    const PACKAGE_VERSION: u64 = 1;
    const MODULE: &'static str;
    const NAME: &'static str;
    const MODULE_NAME: (&'static str, &'static str) = (Self::MODULE, Self::NAME);
}

/// Rust version of the Move hashi::hashi::Hashi type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub treasury: Treasury,
    pub deposit_queue: DepositRequestQueue,
    pub utxo_pool: UtxoPool,
    pub proposals: Bag,
    pub tob: Bag,
}

/// Rust version of the Move hashi::committee_set::CommitteeSet type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct CommitteeSet {
    pub members: Bag,
    /// The current epoch.
    pub epoch: u64,
    pub committees: Bag,
    pub pending_epoch_change: Option<u64>,
}

/// Rust version of the Move sui::bag::Bag type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Bag {
    pub id: Address,
    pub size: u64,
}

/// Rust version of the Move sui::object_bag::ObjectBag type.
pub type ObjectBag = Bag;

#[derive(Debug, serde_derive::Deserialize)]
pub struct Field<N, V> {
    pub id: Address,
    pub name: N,
    pub value: V,
}

/// Rust version of the Move hashi::committee_set::MemberInfo type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct MemberInfo {
    /// Sui Validator Address of this node
    pub validator_address: Address,

    /// Sui Address of an operations account
    pub operator_address: Address,

    /// bls12381 public key to be used in the next epoch.
    ///
    /// The public key for this node which is active in the current epoch can
    /// be found in the `Committee` struct.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    pub next_epoch_public_key: Vec<u8>, //Element<UncompressedG1>,

    /// The HTTPS network address where the instance of the `hashi` service for
    /// this validator can be reached.
    ///
    /// This HTTPS address can be rotated and any such updates will take effect
    /// immediately.
    pub https_address: String,

    /// ed25519 public key used to verify TLS self-signed x509 certs
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    pub tls_public_key: Vec<u8>,

    /// A 32-byte ristretto255 Ristretto encryption public key (ristretto255
    /// RistrettoPoint) for MPC ECIES, to be used in the next epoch.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    pub next_epoch_encryption_public_key: Vec<u8>,
}

impl MoveType for MemberInfo {
    const MODULE: &'static str = "committee_set";
    const NAME: &'static str = "MemberInfo";
}

/// Rust version of the Move hashi::committee::CommitteeMember type.
#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct CommitteeMember {
    pub validator_address: Address,
    pub public_key: Vec<u8>, //Element<UncompressedG1>,
    pub encryption_public_key: Vec<u8>,
    pub weight: u64,
}

/// This represents a BLS signing committee for a given epoch.
///
/// Rust version of the Move hashi::committee::Committee type.
/// Also used in the guardian to serialize Committee.
#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct Committee {
    /// The epoch in which the committee is active.
    pub epoch: u64,
    /// A vector of committee members
    pub members: Vec<CommitteeMember>,
    /// Total voting weight of the committee.
    pub total_weight: u64,
}

/// Rust version of the Move hashi::config::Config type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Config {
    pub config: Vec<(String, ConfigValue)>,
    pub enabled_versions: VecSet<u64>,
    pub upgrade_cap: Option<UpgradeCap>,
}

/// Rust version of the Move sui::package::UpgradeCap type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct UpgradeCap {
    pub id: Address,
    pub package: Address,
    pub version: u64,
    pub policy: u8,
}

/// Rust version of the Move hashi::config_value::Value type.
#[derive(Debug, serde_derive::Deserialize)]
pub enum ConfigValue {
    U64(u64),
    Address(Address),
    String(String),
    Bool(bool),
    Bytes(Vec<u8>),
    // Dynamic(TypeName, vector<u8>)
}

/// Rust version of the Move sui::vec_set::VecSet type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct VecSet<T> {
    pub contents: Vec<T>,
}

/// Rust version of the Move hashi::treasury::Treasury type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Treasury {
    pub objects: ObjectBag,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct TreasuryCap {
    pub id: Address,
    pub supply: u64,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct MetadataCap {
    pub id: Address,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct Coin {
    pub id: Address,
    pub balance: u64,
}

/// Rust version of the Move hashi::deposit_queue::DepositRequestQueue type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequestQueue {
    pub requests: Bag,
}

/// Rust version of the Move hashi::deposit_queue::DepositRequest type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequest {
    pub id: Address,
    pub utxo: Utxo,
    pub timestamp_ms: u64,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct Utxo {
    pub id: UtxoId,
    // In satoshis
    pub amount: u64,
    pub derivation_path: Option<Address>,
}

/// txid:vout
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde_derive::Deserialize)]
pub struct UtxoId {
    // a 32 byte sha256 of the transaction
    pub txid: Address,
    // Out position of the UTXO
    pub vout: u32,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct UtxoPool {
    pub utxos: Bag,
}

/// Rust version of the Move hashi::tob::ProtocolType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum ProtocolType {
    Dkg,
    KeyRotation,
}

/// Rust version of the Move hashi::tob::EpochCertsV1 type.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct EpochCertsV1 {
    pub epoch: u64,
    pub protocol_type: ProtocolType,
    /// Certificates indexed by dealer address (first-cert-wins).
    // LinkedTable<address, CertifiedMessage<DealerMessagesHashV1>>
    pub certs: LinkedTable<Address>,
}

/// Rust version of the Move sui::linked_table::LinkedTable type.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct LinkedTable<K> {
    pub id: Address,
    pub size: u64,
    pub head: Option<K>,
    pub tail: Option<K>,
}

/// Rust version of the Move sui::linked_table::Node type.
/// This is the value stored in each dynamic field entry of a LinkedTable.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct LinkedTableNode<K, V> {
    pub prev: Option<K>,
    pub next: Option<K>,
    pub value: V,
}

/// Rust version of the Move hashi::tob::DealerMessagesHashV1 type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct DealerMessagesHashV1 {
    pub dealer_address: Address,
    pub messages_hash: Vec<u8>,
}

/// Rust version of the Move hashi::committee::CommitteeSignature type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct CommitteeSignature {
    pub epoch: u64,
    pub signature: Vec<u8>,
    pub signers_bitmap: Vec<u8>,
}

/// Rust version of the Move hashi::committee::CertifiedMessage type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct CertifiedMessage<T> {
    pub message: T,
    pub signature: CommitteeSignature,
    pub stake_support: u64,
}

#[derive(Debug)]
pub enum HashiEvent {
    ValidatorRegistered(ValidatorRegistered),
    ValidatorUpdated(ValidatorUpdated),
    VoteCastEvent(VoteCastEvent),
    VoteRemovedEvent(VoteRemovedEvent),
    ProposalDeletedEvent(ProposalDeletedEvent),
    ProposalExecutedEvent(ProposalExecutedEvent),
    QuorumReachedEvent(QuorumReachedEvent),
    PackageUpgradedEvent(PackageUpgradedEvent),
    MintEvent(MintEvent),
    BurnEvent(BurnEvent),
    DepositRequestedEvent(DepositRequestedEvent),
    DepositConfirmedEvent(DepositConfirmedEvent),
    ExpiredDepositDeletedEvent(ExpiredDepositDeletedEvent),
    StartReconfigEvent(StartReconfigEvent),
    EndReconfigEvent(EndReconfigEvent),
    AbortReconfigEvent(AbortReconfigEvent),
}

impl HashiEvent {
    pub fn try_parse(
        package_ids: &BTreeSet<Address>,
        bcs: &Bcs,
    ) -> Result<Option<Self>, anyhow::Error> {
        let event_type = bcs.name().parse::<StructTag>()?;

        // If this isn't from a package we care about we can skip
        if !package_ids.contains(event_type.address()) {
            return Ok(None);
        }

        let event = match (event_type.module().as_str(), event_type.name().as_str()) {
            ValidatorRegistered::MODULE_NAME => ValidatorRegistered::from_bcs(bcs.value())?.into(),
            ValidatorUpdated::MODULE_NAME => ValidatorUpdated::from_bcs(bcs.value())?.into(),
            VoteCastEvent::MODULE_NAME => VoteCastEvent::from_bcs(bcs.value())?.into(),
            VoteRemovedEvent::MODULE_NAME => VoteRemovedEvent::from_bcs(bcs.value())?.into(),
            ProposalDeletedEvent::MODULE_NAME => {
                ProposalDeletedEvent::from_bcs(bcs.value())?.into()
            }
            ProposalExecutedEvent::MODULE_NAME => {
                ProposalExecutedEvent::from_bcs(bcs.value())?.into()
            }
            QuorumReachedEvent::MODULE_NAME => QuorumReachedEvent::from_bcs(bcs.value())?.into(),
            MintEvent::MODULE_NAME => MintEvent::new(&event_type, bcs.value())?.into(),
            BurnEvent::MODULE_NAME => BurnEvent::new(&event_type, bcs.value())?.into(),
            DepositRequestedEvent::MODULE_NAME => {
                DepositRequestedEvent::from_bcs(bcs.value())?.into()
            }
            DepositConfirmedEvent::MODULE_NAME => {
                DepositConfirmedEvent::from_bcs(bcs.value())?.into()
            }
            StartReconfigEvent::MODULE_NAME => StartReconfigEvent::from_bcs(bcs.value())?.into(),
            EndReconfigEvent::MODULE_NAME => EndReconfigEvent::from_bcs(bcs.value())?.into(),
            AbortReconfigEvent::MODULE_NAME => AbortReconfigEvent::from_bcs(bcs.value())?.into(),
            _ => {
                return Ok(None);
            }
        };

        Ok(Some(event))
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ValidatorRegistered {
    pub validator: Address,
}

impl MoveType for ValidatorRegistered {
    const MODULE: &'static str = "validator";
    const NAME: &'static str = "ValidatorRegistered";
}

impl From<ValidatorRegistered> for HashiEvent {
    fn from(value: ValidatorRegistered) -> Self {
        Self::ValidatorRegistered(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ValidatorUpdated {
    pub validator: Address,
}

impl MoveType for ValidatorUpdated {
    const MODULE: &'static str = "validator";
    const NAME: &'static str = "ValidatorUpdated";
}

impl From<ValidatorUpdated> for HashiEvent {
    fn from(value: ValidatorUpdated) -> Self {
        Self::ValidatorUpdated(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct VoteCastEvent {
    pub proposal_id: Address,
    pub voter: Address,
}

impl MoveType for VoteCastEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteCastEvent";
}

impl From<VoteCastEvent> for HashiEvent {
    fn from(value: VoteCastEvent) -> Self {
        Self::VoteCastEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct VoteRemovedEvent {
    pub proposal_id: Address,
    pub voter: Address,
}

impl MoveType for VoteRemovedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteRemovedEvent";
}

impl From<VoteRemovedEvent> for HashiEvent {
    fn from(value: VoteRemovedEvent) -> Self {
        Self::VoteRemovedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ProposalDeletedEvent {
    pub proposal_id: Address,
}

impl MoveType for ProposalDeletedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalDeletedEvent";
}

impl From<ProposalDeletedEvent> for HashiEvent {
    fn from(value: ProposalDeletedEvent) -> Self {
        Self::ProposalDeletedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ProposalExecutedEvent {
    pub proposal_id: Address,
}

impl MoveType for ProposalExecutedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalExecutedEvent";
}

impl From<ProposalExecutedEvent> for HashiEvent {
    fn from(value: ProposalExecutedEvent) -> Self {
        Self::ProposalExecutedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct QuorumReachedEvent {
    pub proposal_id: Address,
}

impl MoveType for QuorumReachedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "QuorumReachedEvent";
}

impl From<QuorumReachedEvent> for HashiEvent {
    fn from(value: QuorumReachedEvent) -> Self {
        Self::QuorumReachedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct PackageUpgradedEvent {
    pub package: Address,
    pub version: u64,
}

impl MoveType for PackageUpgradedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "PackageUpgradedEvent";
}

impl From<PackageUpgradedEvent> for HashiEvent {
    fn from(value: PackageUpgradedEvent) -> Self {
        Self::PackageUpgradedEvent(value)
    }
}

#[derive(Debug)]
pub struct MintEvent {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for MintEvent {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "MintEvent";
}

impl MintEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        if event_type.module() == Self::MODULE
            && event_type.name() == Self::NAME
            && let [coin_type] = event_type.type_params()
        {
            Ok(Self {
                coin_type: coin_type.to_owned(),
                amount: bcs::from_bytes(bcs)?,
            })
        } else {
            Err(anyhow::anyhow!("invalid MintEvent"))
        }
    }
}

impl From<MintEvent> for HashiEvent {
    fn from(value: MintEvent) -> Self {
        Self::MintEvent(value)
    }
}

#[derive(Debug)]
pub struct BurnEvent {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for BurnEvent {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "BurnEvent";
}

impl BurnEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        if event_type.module() == Self::MODULE
            && event_type.name() == Self::NAME
            && let [coin_type] = event_type.type_params()
        {
            Ok(Self {
                coin_type: coin_type.to_owned(),
                amount: bcs::from_bytes(bcs)?,
            })
        } else {
            Err(anyhow::anyhow!("invalid BurnEvent"))
        }
    }
}

impl From<BurnEvent> for HashiEvent {
    fn from(value: BurnEvent) -> Self {
        Self::BurnEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequestedEvent {
    pub request_id: Address,
    pub utxo_id: UtxoId,
    pub amount: u64,
    pub derivation_path: Option<Address>,
    pub timestamp_ms: u64,
}

impl MoveType for DepositRequestedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositRequestedEvent";
}

impl From<DepositRequestedEvent> for HashiEvent {
    fn from(value: DepositRequestedEvent) -> Self {
        Self::DepositRequestedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositConfirmedEvent {
    pub request_id: Address,
    pub utxo_id: UtxoId,
    pub amount: u64,
    pub derivation_path: Option<Address>,
    // signature: XXX
}

impl MoveType for DepositConfirmedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositConfirmedEvent";
}

impl From<DepositConfirmedEvent> for HashiEvent {
    fn from(value: DepositConfirmedEvent) -> Self {
        Self::DepositConfirmedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ExpiredDepositDeletedEvent {
    pub request_id: Address,
}

impl MoveType for ExpiredDepositDeletedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "ExpiredDepositDeletedEvent";
}

impl From<ExpiredDepositDeletedEvent> for HashiEvent {
    fn from(value: ExpiredDepositDeletedEvent) -> Self {
        Self::ExpiredDepositDeletedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct StartReconfigEvent {
    pub epoch: u64,
}

impl MoveType for StartReconfigEvent {
    const MODULE: &'static str = "reconfig";
    const NAME: &'static str = "StartReconfigEvent";
}

impl From<StartReconfigEvent> for HashiEvent {
    fn from(value: StartReconfigEvent) -> Self {
        Self::StartReconfigEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct EndReconfigEvent {
    pub epoch: u64,
}

impl MoveType for EndReconfigEvent {
    const MODULE: &'static str = "reconfig";
    const NAME: &'static str = "EndReconfigEvent";
}

impl From<EndReconfigEvent> for HashiEvent {
    fn from(value: EndReconfigEvent) -> Self {
        Self::EndReconfigEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct AbortReconfigEvent {
    pub epoch: u64,
}

impl MoveType for AbortReconfigEvent {
    const MODULE: &'static str = "reconfig";
    const NAME: &'static str = "AbortReconfigEvent";
}

impl From<AbortReconfigEvent> for HashiEvent {
    fn from(value: AbortReconfigEvent) -> Self {
        Self::AbortReconfigEvent(value)
    }
}

impl From<&crate::committee::CommitteeMember> for CommitteeMember {
    fn from(m: &crate::committee::CommitteeMember) -> Self {
        Self {
            validator_address: m.validator_address(),
            public_key: m.public_key().as_bytes().to_vec(),
            encryption_public_key: m.encryption_public_key().to_bcs().expect("should not fail"),
            weight: m.weight(),
        }
    }
}

impl TryFrom<CommitteeMember> for crate::committee::CommitteeMember {
    type Error = anyhow::Error;

    fn try_from(m: CommitteeMember) -> Result<Self, Self::Error> {
        let public_key = crate::committee::BLS12381PublicKey::from_bytes(&m.public_key)
            .map_err(|e| anyhow::anyhow!("invalid public key {}", e))?;

        let encryption_public_key =
            crate::committee::EncryptionPublicKey::from_bcs(&m.encryption_public_key)
                .map_err(|e| anyhow::anyhow!("invalid encryption public key {}", e))?;

        Ok(crate::committee::CommitteeMember::new(
            m.validator_address,
            public_key,
            encryption_public_key,
            m.weight,
        ))
    }
}

impl From<&crate::committee::Committee> for Committee {
    fn from(c: &crate::committee::Committee) -> Self {
        Self {
            epoch: c.epoch(),
            members: c.members().iter().map(Into::into).collect(),
            total_weight: c.total_weight(),
        }
    }
}
