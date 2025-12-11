#![allow(unused)] // TODO remove this

//! Definitions of the raw Move structs in the hashi package

use sui_sdk_types::Address;

/// Rust version of the Move hashi::hashi::Hashi type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub treasury: Treasury,
    pub deposit_queue: DepositRequestQueue,
    pub utxo_pool: UtxoPool,
    pub proposals: ProposalSet,
}

/// Rust version of the Move hashi::committee_set::CommitteeSet type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct CommitteeSet {
    pub members: Bag,
    /// The current epoch.
    pub epoch: u64,
    pub committees: Bag,
}

/// Rust version of the Move sui::bag::Bag type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Bag {
    pub id: Address,
    pub size: u64,
}

/// Rust version of the Move sui::object_bag::ObjectBag type.
pub type ObjectBag = Bag;

/// Rust version of the Move hashi::proposal_set::ProposalSet type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct ProposalSet {
    pub proposals: Bag,
    pub seq_num: u64,
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
    /// be found in the `BlsCommittee` struct.
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

/// Rust version of the Move hashi::committee::CommitteeMember type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct CommitteeMember {
    pub validator_address: Address,
    pub public_key: Vec<u8>, //Element<UncompressedG1>,
    pub encryption_key: Vec<u8>,
    pub weight: u16,
}

/// This represents a BLS signing committee for a given epoch.
///
/// Rust version of the Move hashi::committee::Committee type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Committee {
    /// The epoch in which the committee is active.
    pub epoch: u64,
    /// A vector of committee members
    pub members: Vec<CommitteeMember>,
    /// Total voting weight of the committee.
    pub total_weight: u16,
    pub total_aggregated_key: Vec<u8>, // Element<G1>,
}

/// Rust version of the Move hashi::config::Config type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Config {
    pub config: Vec<(String, ConfigValue)>,
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
