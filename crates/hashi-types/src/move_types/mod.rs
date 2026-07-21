// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Definitions of the raw Move structs in the hashi package

use fastcrypto::traits::ToFromBytes;
use std::collections::BTreeSet;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::FromBcs;
use sui_sdk_types::bcs::ToBcs;

use crate::bitcoin_txid::BitcoinTxid;

/// A Rust mirror of a Move struct, identified by its module and name.
///
/// `matches` deliberately ignores the package address: a hashi package
/// upgrade changes the address while `hashi::module::Name` remains the
/// same struct. Callers that need package filtering (e.g. event
/// parsing) check the address separately.
pub trait MoveType {
    const MODULE: &'static str;
    const NAME: &'static str;
    /// The number of type parameters the struct tag must carry.
    const TYPE_PARAMS: usize = 0;
    const MODULE_NAME: (&'static str, &'static str) = (Self::MODULE, Self::NAME);

    fn matches(tag: &StructTag) -> bool {
        tag.module() == Self::MODULE
            && tag.name() == Self::NAME
            && tag.type_params().len() == Self::TYPE_PARAMS
    }
}

/// Validates that the event's StructTag matches `T` and extracts the
/// single type parameter.
fn extract_type_param<T: MoveType>(event_type: &StructTag) -> Result<TypeTag, anyhow::Error> {
    if T::matches(event_type)
        && let [type_param] = event_type.type_params()
    {
        Ok(type_param.to_owned())
    } else {
        Err(anyhow::anyhow!("invalid {}", T::NAME))
    }
}

/// True when the struct tag is the Sui framework's
/// `0x2::dynamic_field::Field` (any type parameters).
pub fn is_dynamic_field(tag: &StructTag) -> bool {
    tag.address() == &Address::TWO
        && tag.module() == "dynamic_field"
        && tag.name() == "Field"
        && tag.type_params().len() == 2
}

/// True when the struct tag is a `Field<_, V>` whose value-side `V` is
/// the struct `<module>::<name>` from any package. The package address
/// of `V` is ignored so package upgrades don't invalidate the match.
pub fn is_field_with_value(tag: &StructTag, module: &str, name: &str) -> bool {
    if !is_dynamic_field(tag) {
        return false;
    }
    let Some(TypeTag::Struct(value)) = tag.type_params().get(1) else {
        return false;
    };
    value.module() == module && value.name() == name
}

/// True when the struct tag is a dynamic object field wrapper —
/// `0x2::dynamic_field::Field<0x2::dynamic_object_field::Wrapper<K>, ID>`.
/// The wrapper is the intermediate object that owns a DOF's value
/// object; its contents hold the value's object id.
pub fn is_dof_wrapper(tag: &StructTag) -> bool {
    if !is_dynamic_field(tag) {
        return false;
    }
    let Some(TypeTag::Struct(name_type)) = tag.type_params().first() else {
        return false;
    };
    name_type.address() == &Address::TWO
        && name_type.module() == "dynamic_object_field"
        && name_type.name() == "Wrapper"
}

/// Rust version of the Move hashi::hashi::Hashi type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub versioning: Versioning,
    pub treasury: Treasury,
    pub proposals: Proposals,
    /// TOB certificates by (epoch, batch_index) -> EpochCertsV1
    pub tob: Bag,
    /// Number of presignatures consumed in the current epoch.
    pub num_consumed_presigs: u64,
}

/// Rust version of the Move hashi::bitcoin_state::BitcoinStateKey type.
#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct BitcoinStateKey {
    pub dummy_field: bool,
}

/// Rust version of the Move hashi::bitcoin_state::BitcoinState type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct BitcoinState {
    pub id: Address,
    pub deposit_queue: DepositRequestQueue,
    pub withdrawal_queue: WithdrawalRequestQueue,
    pub utxo_pool: UtxoPool,
    pub user_requests: Table,
}

/// Rust version of the Move hashi::committee_set::CommitteeSet type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct CommitteeSet {
    pub members: Bag,
    /// The current epoch.
    pub epoch: u64,
    pub committees: Bag,
    pub pending_epoch_change: Option<PendingEpochChange>,

    /// The MPC committee's threshold public key.
    pub mpc_public_key: Vec<u8>,
}

/// Rust version of the Move hashi::committee_set::PendingEpochChange type.
#[derive(Debug, Clone, serde_derive::Deserialize)]
pub struct PendingEpochChange {
    pub epoch: u64,
    pub committee_handoff_cert: Option<CommitteeSignature>,
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

    /// The publicly reachable URL where the `hashi` service for this validator
    /// can be reached.
    ///
    /// This URL can be rotated and any such updates will take effect
    /// immediately.
    pub endpoint_url: String,

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

    /// Open-ended per-member extension slot. Empty today.
    pub extra_fields: Config,
}

impl MoveType for MemberInfo {
    const MODULE: &'static str = "committee_set";
    const NAME: &'static str = "MemberInfo";
}

/// Rust version of the Move hashi::committee::CommitteeMember type.
#[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct Committee {
    /// The epoch in which the committee is active.
    pub epoch: u64,
    /// A vector of committee members
    pub members: Vec<CommitteeMember>,
    /// Total voting weight of the committee.
    pub total_weight: u64,
    /// The config pinned from the governed config at reconfig, BCS-mirroring the
    /// Move `Committee.mpc: Config`. Carried verbatim end to end so the
    /// committee's signed BCS bytes match the on-chain committee exactly; never
    /// reconstructed from extracted fields.
    pub config: Config,
}

/// Rust version of the Move hashi::committee_set::CommitteeHandoffKey type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct CommitteeHandoffKey {
    pub epoch: u64,
}

/// Rust version of the Move hashi::committee_set::CommitteeHandoff type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct CommitteeHandoff {
    pub next_epoch: u64,
    pub cert: CommitteeSignature,
}

/// Rust version of the Move hashi::versioning::Versioning type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Versioning {
    pub enabled_versions: VecSet<u64>,
    pub upgrade_cap: Option<UpgradeCap>,
}

/// Rust version of the Move sui::package::UpgradeCap type.
#[derive(Debug, PartialEq, serde_derive::Deserialize)]
pub struct UpgradeCap {
    pub id: Address,
    pub package: Address,
    pub version: u64,
    pub policy: u8,
}

/// Rust version of the Move hashi::config_value::Value type. Variant order MUST
/// match Move (U64 = 0, …) for BCS.
#[derive(Debug, Clone, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum ConfigValue {
    U64(u64),
    U128(u128),
    /// Move `u256`, as its 32 little-endian BCS bytes (no Rust u256 primitive;
    /// a fixed-size array BCS-encodes to exactly the same 32 bytes).
    U256([u8; 32]),
    Address(Address),
    String(String),
    Bool(bool),
    Bytes(Vec<u8>),
}

/// MPC parameter keys, in the canonical order Move's `mpc_config::pin` writes
/// them. Load-bearing for [`Config::from_mpc_params`].
const KEY_MPC_THRESHOLD_IN_BASIS_POINTS: &str = "mpc_threshold_in_basis_points";
const KEY_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA: &str = "mpc_weight_reduction_allowed_delta";
const KEY_MPC_MAX_FAULTY_IN_BASIS_POINTS: &str = "mpc_max_faulty_in_basis_points";
const KEY_MPC_NONCE_GENERATION_PROTOCOL: &str = "mpc_nonce_generation_protocol";

/// Default MPC threshold in basis points. Mirrors `DEFAULT_THRESHOLD_IN_BASIS_POINTS`
/// in `mpc_config.move`.
pub const DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS: u16 = 3334;
/// Mirrors `DEFAULT_WEIGHT_REDUCTION_ALLOWED_DELTA` in `mpc_config.move`.
pub const DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA: u16 = 800;
/// Mirrors `DEFAULT_MAX_FAULTY_IN_BASIS_POINTS` in `mpc_config.move`.
pub const DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS: u16 = 3333;
/// Mirrors `VANILLA_NONCE_GENERATION_PROTOCOL` in `mpc_config.move`.
pub const VANILLA_MPC_NONCE_GENERATION_PROTOCOL: u16 = 0;

/// Rust version of the Move hashi::config::Config type: a general-purpose,
/// order-preserving key-value store (`VecMap<String, Value>`). Embedded both as
/// the package's global config and as the per-epoch snapshot pinned onto a
/// [`Committee`].
///
/// `#[serde(transparent)]` makes this serialize exactly as its inner entry
/// vector, BCS-identical to the Move single-field `Config` struct. A committee's
/// pinned config is carried verbatim end to end (scrape → rich committee → gRPC
/// → re-serialize for signing) so its signed bytes match the on-chain committee
/// without ever being reconstructed from extracted fields. Domain-typed
/// accessors (the MPC parameters) are layered on, mirroring Move's `mpc_config`.
#[derive(Debug, Clone, PartialEq, Default, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(transparent)]
pub struct Config(Vec<(String, ConfigValue)>);

impl Config {
    /// Wrap an entry list read verbatim from chain or the wire. The order is
    /// preserved as given — do not sort or canonicalize here.
    pub fn from_entries(entries: Vec<(String, ConfigValue)>) -> Self {
        Self(entries)
    }

    /// The raw entries, in their on-chain order.
    pub fn entries(&self) -> &[(String, ConfigValue)] {
        &self.0
    }

    /// Consume into the raw entries.
    pub fn into_entries(self) -> Vec<(String, ConfigValue)> {
        self.0
    }

    /// Read a `u64` value by key, falling back to `default` if the key is absent
    /// or not a `U64` (matches the Move accessors' default-on-absent behavior).
    pub fn get_u64(&self, key: &str, default: u64) -> u64 {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                ConfigValue::U64(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(default)
    }

    // ===== MPC parameters (mirror Move's `mpc_config` accessors) =====

    /// Build a config holding the MPC parameters, inserting the full key set in
    /// the same fixed order as Move's `mpc_config::pin`. For synthetic
    /// committees only (tests, fallbacks); the scrape/wire paths carry the
    /// on-chain config verbatim via [`Config::from_entries`].
    pub fn from_mpc_params(
        threshold_in_basis_points: u16,
        weight_reduction_allowed_delta: u16,
        max_faulty_in_basis_points: u16,
        nonce_generation_protocol: u16,
    ) -> Self {
        Self(vec![
            (
                KEY_MPC_THRESHOLD_IN_BASIS_POINTS.to_string(),
                ConfigValue::U64(threshold_in_basis_points as u64),
            ),
            (
                KEY_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA.to_string(),
                ConfigValue::U64(weight_reduction_allowed_delta as u64),
            ),
            (
                KEY_MPC_MAX_FAULTY_IN_BASIS_POINTS.to_string(),
                ConfigValue::U64(max_faulty_in_basis_points as u64),
            ),
            (
                KEY_MPC_NONCE_GENERATION_PROTOCOL.to_string(),
                ConfigValue::U64(nonce_generation_protocol as u64),
            ),
        ])
    }

    pub fn mpc_threshold_in_basis_points(&self) -> u16 {
        self.mpc_param(
            KEY_MPC_THRESHOLD_IN_BASIS_POINTS,
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
        )
    }

    pub fn mpc_weight_reduction_allowed_delta(&self) -> u16 {
        self.mpc_param(
            KEY_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
        )
    }

    pub fn mpc_max_faulty_in_basis_points(&self) -> u16 {
        self.mpc_param(
            KEY_MPC_MAX_FAULTY_IN_BASIS_POINTS,
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
        )
    }

    pub fn mpc_nonce_generation_protocol(&self) -> u16 {
        self.mpc_param(
            KEY_MPC_NONCE_GENERATION_PROTOCOL,
            VANILLA_MPC_NONCE_GENERATION_PROTOCOL,
        )
    }

    fn mpc_param(&self, key: &str, default: u16) -> u16 {
        u16::try_from(self.get_u64(key, default as u64))
            .unwrap_or_else(|_| panic!("MPC param {key} exceeds u16::MAX"))
    }
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

/// Rust version of the Move hashi::proposals::Proposals type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct Proposals {
    /// Proposals that have been created but not yet executed.
    pub active: ObjectBag,
    /// Proposals that have executed successfully (kept indefinitely).
    pub executed: ObjectBag,
}

/// Rust version of the Move hashi::deposit_queue::DepositRequestQueue type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequestQueue {
    /// Active deposits awaiting confirmation
    pub requests: Bag,
    /// Completed deposits (confirmed or expired)
    pub processed: Bag,
}

/// Rust version of the Move sui::table::Table type (header only).
#[derive(Debug, serde_derive::Deserialize)]
pub struct Table {
    pub id: Address,
    pub size: u64,
}

/// Rust version of the Move hashi::withdrawal_queue::WithdrawalRequestQueue type.
#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalRequestQueue {
    /// Active requests awaiting action (Requested, Approved)
    pub requests: Bag,
    /// Processed requests (Processing, Signed, Confirmed)
    pub processed: Bag,
    /// In-flight withdrawal transactions
    pub withdrawal_txns: Bag,
    /// Confirmed withdrawal transactions (historical record)
    pub confirmed_txns: Bag,
}

/// Rust version of the Move hashi::withdrawal_queue::WithdrawalStatus enum.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum WithdrawalStatus {
    Requested,
    Approved,
    Processing,
    Signed,
    Confirmed,
}

impl WithdrawalStatus {
    /// Returns true if the status is `Approved`.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Returns true if the status is `Requested`.
    pub fn is_requested(&self) -> bool {
        matches!(self, Self::Requested)
    }
}

/// Rust version of the Move hashi::withdrawal_queue::WithdrawalRequest type.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct WithdrawalRequest {
    pub id: Address,
    pub sender: Address,
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
    pub created_timestamp_ms: u64,
    pub status: WithdrawalStatus,
    /// Committee certificate recorded at approval time. `None` until
    /// `approve_request` has been called.
    pub approval_cert: Option<CommitteeSignature>,
    /// Clock timestamp at the moment of approval. `None` until
    /// `approve_request` has been called.
    pub approved_timestamp_ms: Option<u64>,
    pub withdrawal_txn_id: Option<Address>,
    pub sui_tx_digest: Digest,
    /// BTC balance in satoshis.
    pub btc: u64,
}

/// Lightweight info extracted from a request at commit time for validation.
#[derive(Debug, serde_derive::Deserialize)]
pub struct CommittedRequestInfo {
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
}

/// Rust version of the Move hashi::mpc_signing::MpcSig enum. Variant order
/// MUST match Move (Pending = 0, Signed = 1) for BCS.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum MpcSig {
    /// Awaiting signature; holds the presignature index (valid in the batch's epoch).
    Pending(u64),
    /// Completed per-input MPC Schnorr signature bytes.
    Signed(Vec<u8>),
}

/// Rust version of the Move hashi::mpc_signing::SigningBatch type. Field order
/// MUST match Move exactly (BCS-decoded, positional).
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct SigningBatch {
    pub signatures: Vec<MpcSig>,
    /// Epoch the `Pending` presig indices belong to.
    pub epoch: u64,
}

impl SigningBatch {
    pub fn num_inputs(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_complete(&self) -> bool {
        self.signatures
            .iter()
            .all(|s| matches!(s, MpcSig::Signed(_)))
    }

    pub fn pending_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|s| matches!(s, MpcSig::Pending(_)))
            .count()
    }

    /// Number of inputs whose MPC signature is complete.
    pub fn signed_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|s| matches!(s, MpcSig::Signed(_)))
            .count()
    }

    /// Indices of inputs still awaiting an MPC signature (the resume set).
    pub fn unsigned_indices(&self) -> Vec<u64> {
        self.signatures
            .iter()
            .enumerate()
            .filter_map(|(i, s)| matches!(s, MpcSig::Pending(_)).then_some(i as u64))
            .collect()
    }

    /// Presig index assigned to input `i`, or `None` if it is already signed
    /// or out of range.
    pub fn pending_index(&self, i: usize) -> Option<u64> {
        match self.signatures.get(i) {
            Some(MpcSig::Pending(idx)) => Some(*idx),
            _ => None,
        }
    }

    /// Dense per-input MPC signatures, or `None` if any input is unsigned.
    pub fn dense_signatures(&self) -> Option<Vec<Vec<u8>>> {
        self.signatures
            .iter()
            .map(|s| match s {
                MpcSig::Signed(b) => Some(b.clone()),
                MpcSig::Pending(_) => None,
            })
            .collect()
    }
}

/// Rust version of the Move hashi::withdrawal_queue::WithdrawalTransaction type.
///
/// Field order MUST match the Move struct exactly — these are BCS-decoded
/// from on-chain bytes and are positional.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct WithdrawalTransaction {
    pub id: Address,
    pub txid: BitcoinTxid,
    pub request_ids: Vec<Address>,
    pub inputs: Vec<Utxo>,
    pub withdrawal_outputs: Vec<OutputUtxo>,
    /// Change outputs back to the bridge, in BTC transaction order. These are
    /// the trailing outputs: change output `j` sits at vout
    /// `withdrawal_outputs.len() + j`. Empty when there is no change.
    pub change_outputs: Vec<OutputUtxo>,
    pub created_timestamp_ms: u64,
    /// Clock timestamp at which the transaction became fully signed
    /// (guardian signatures attached). `None` until `finalize_withdrawal`.
    pub signed_timestamp_ms: Option<u64>,
    /// Clock timestamp at which the Bitcoin transaction was confirmed.
    /// `None` until `confirm_withdrawal`.
    pub confirmed_timestamp_ms: Option<u64>,
    pub randomness: Vec<u8>,
    /// Per-input MPC signatures, accumulated incrementally and out-of-order.
    pub signing: SigningBatch,
    /// Per-input guardian enclave signatures, written once at finalize.
    /// Together with the MPC signatures, forms the 2-of-2 taproot witness.
    pub guardian_signatures: Option<Vec<Vec<u8>>>,
}

impl WithdrawalTransaction {
    pub fn all_outputs(&self) -> Vec<OutputUtxo> {
        let mut outputs = self.withdrawal_outputs.clone();
        outputs.extend(self.change_outputs.iter().cloned());
        outputs
    }

    /// Whether the 2-of-2 witness is fully assembled and the txn is broadcast-ready.
    pub fn is_fully_signed(&self) -> bool {
        self.signing.is_complete() && self.guardian_signatures.is_some()
    }

    /// Dense per-input MPC signatures, available only once fully signed (the
    /// state the broadcast/rebuild path operates on).
    pub fn mpc_signatures(&self) -> Option<Vec<Vec<u8>>> {
        if self.is_fully_signed() {
            self.signing.dense_signatures()
        } else {
            None
        }
    }

    /// The epoch the current (pending) presig indices belong to.
    pub fn signing_epoch(&self) -> u64 {
        self.signing.epoch
    }
}

/// Rust version of the Move hashi::withdrawal_queue::OutputUtxo type.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct OutputUtxo {
    /// In satoshis
    pub amount: u64,
    pub bitcoin_address: Vec<u8>,
}

/// Rust version of the Move hashi::deposit_queue::DepositRequest type.
///
/// `approval_cert` and `approved_timestamp_ms` are populated when the
/// committee approves the deposit via `approve_deposit`. They remain
/// `None` until then. `confirm_deposit` requires both to be set.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize)]
pub struct DepositRequest {
    pub id: Address,
    pub sender: Address,
    pub created_timestamp_ms: u64,
    pub sui_tx_digest: Digest,
    pub utxo: Utxo,
    pub approval_cert: Option<CommitteeSignature>,
    pub approved_timestamp_ms: Option<u64>,
    pub confirmed_timestamp_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Utxo {
    pub id: UtxoId,
    // In satoshis
    pub amount: u64,
    pub derivation_path: Option<Address>,
}

/// Rust version of the Move hashi::utxo_pool::UtxoRecord type.
#[derive(Clone, Debug, serde_derive::Deserialize)]
pub struct UtxoRecord {
    pub utxo: Utxo,
    pub produced_by: Option<Address>,
    pub spent_by: Option<Address>,
    pub spent_epoch: Option<u64>,
}

/// txid:vout
#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde_derive::Deserialize,
    serde_derive::Serialize,
)]
pub struct UtxoId {
    // a 32 byte sha256 of the transaction
    pub txid: BitcoinTxid,
    // Out position of the UTXO
    pub vout: u32,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct UtxoPool {
    pub utxo_records: Bag,
    pub spent_utxos: Bag,
}

/// Rust version of the Move hashi::tob::ProtocolType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum ProtocolType {
    Dkg,
    KeyRotation,
    NonceGeneration,
}

/// Rust version of the Move struct `hashi::reconfig::ReconfigCompletionMessage`.
#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct ReconfigCompletionMessage {
    /// The epoch being transitioned to.
    pub epoch: u64,
    /// The MPC committee's threshold public key.
    pub mpc_public_key: Vec<u8>,
}

impl crate::intent::IntentMessage for ReconfigCompletionMessage {
    const INTENT: crate::intent::Intent = crate::intent::Intent::ReconfigCompletion;
}

/// Rust version of the Move hashi::proposal::Proposal type.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Proposal<T> {
    pub id: Address,
    pub creator: Address,
    pub votes: Vec<Address>,
    pub quorum_threshold_bps: u64,
    pub created_timestamp_ms: u64,
    /// Clock timestamp at execution. `None` until the proposal executes.
    pub executed_timestamp_ms: Option<u64>,
    pub metadata: VecMap<String, String>,
    pub data: T,
}

/// Rust version of the Move hashi::update_config::UpdateConfig type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct UpdateConfig {
    pub entries: VecMap<String, ConfigValue>,
}

/// Rust version of the Move hashi::enable_version::EnableVersion type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct EnableVersion {
    pub version: u64,
}

/// Rust version of the Move hashi::disable_version::DisableVersion type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct DisableVersion {
    pub version: u64,
}

/// Rust version of the Move hashi::upgrade::Upgrade type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Upgrade {
    pub digest: Vec<u8>,
}

/// Rust version of the Move hashi::emergency_pause::EmergencyPause type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct EmergencyPause {
    pub pause: bool,
}

/// Rust version of the Move hashi::abort_reconfig::AbortReconfig type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct AbortReconfig {
    pub epoch: u64,
}

/// Rust version of the Move hashi::update_guardian::UpdateGuardian type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct UpdateGuardian {
    pub url: String,
}

/// Rust version of the Move sui::vec_map::VecMap type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct VecMap<K, V> {
    pub contents: Vec<Entry<K, V>>,
}

/// Rust version of the Move sui::vec_map::Entry type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Entry<K, V> {
    pub key: K,
    pub value: V,
}

/// Rust version of the Move hashi::tob::EpochCertsV1 type.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct EpochCertsV1 {
    pub epoch: u64,
    pub protocol_type: ProtocolType,
    /// Dealer submissions indexed by dealer address (first-submission-wins).
    // LinkedTable<address, DealerSubmissionV1>
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
#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Deserialize, serde_derive::Serialize)]
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

/// Rust version of the Move hashi::tob::DealerSubmissionV1 type.
#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct DealerSubmissionV1 {
    pub message: DealerMessagesHashV1,
    pub signature: CommitteeSignature,
}

#[derive(Debug)]
pub enum HashiEvent {
    ValidatorRegistered(ValidatorRegistered),
    ValidatorUpdated(ValidatorUpdated),
    VoteCast(VoteCast),
    VoteRemoved(VoteRemoved),
    ProposalCreated(ProposalCreated),
    ProposalDeleted(ProposalDeleted),
    ProposalExecuted(ProposalExecuted),
    QuorumReached(QuorumReached),
    PackageUpgraded(PackageUpgraded),
    Minted(Minted),
    Burned(Burned),
    DepositRequested(DepositRequested),
    DepositApproved(DepositApproved),
    DepositConfirmed(DepositConfirmed),
    ExpiredDepositDeleted(ExpiredDepositDeleted),
    WithdrawalRequested(WithdrawalRequested),
    WithdrawalApproved(WithdrawalApproved),
    WithdrawalPickedForProcessing(WithdrawalPickedForProcessing),
    WithdrawalSigned(WithdrawalSigned),
    WithdrawalInputsSigned(WithdrawalInputsSigned),
    WithdrawalPresigsReassigned(WithdrawalPresigsReassigned),
    WithdrawalConfirmed(WithdrawalConfirmed),
    UtxoSpent(UtxoSpent),
    ReconfigStarted(ReconfigStarted),
    ReconfigEnded(ReconfigEnded),
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
            VoteCast::MODULE_NAME => VoteCast::new(&event_type, bcs.value())?.into(),
            VoteRemoved::MODULE_NAME => VoteRemoved::new(&event_type, bcs.value())?.into(),
            ProposalCreated::MODULE_NAME => ProposalCreated::new(&event_type, bcs.value())?.into(),
            ProposalDeleted::MODULE_NAME => ProposalDeleted::new(&event_type, bcs.value())?.into(),
            ProposalExecuted::MODULE_NAME => {
                ProposalExecuted::new(&event_type, bcs.value())?.into()
            }
            QuorumReached::MODULE_NAME => QuorumReached::new(&event_type, bcs.value())?.into(),
            Minted::MODULE_NAME => Minted::new(&event_type, bcs.value())?.into(),
            Burned::MODULE_NAME => Burned::new(&event_type, bcs.value())?.into(),
            DepositRequested::MODULE_NAME => DepositRequested::from_bcs(bcs.value())?.into(),
            DepositApproved::MODULE_NAME => DepositApproved::from_bcs(bcs.value())?.into(),
            DepositConfirmed::MODULE_NAME => DepositConfirmed::from_bcs(bcs.value())?.into(),
            ExpiredDepositDeleted::MODULE_NAME => {
                ExpiredDepositDeleted::from_bcs(bcs.value())?.into()
            }
            WithdrawalRequested::MODULE_NAME => WithdrawalRequested::from_bcs(bcs.value())?.into(),
            WithdrawalApproved::MODULE_NAME => WithdrawalApproved::from_bcs(bcs.value())?.into(),
            WithdrawalPickedForProcessing::MODULE_NAME => {
                WithdrawalPickedForProcessing::from_bcs(bcs.value())?.into()
            }
            WithdrawalSigned::MODULE_NAME => WithdrawalSigned::from_bcs(bcs.value())?.into(),
            WithdrawalInputsSigned::MODULE_NAME => {
                WithdrawalInputsSigned::from_bcs(bcs.value())?.into()
            }
            WithdrawalPresigsReassigned::MODULE_NAME => {
                WithdrawalPresigsReassigned::from_bcs(bcs.value())?.into()
            }
            WithdrawalConfirmed::MODULE_NAME => WithdrawalConfirmed::from_bcs(bcs.value())?.into(),
            UtxoSpent::MODULE_NAME => UtxoSpent::from_bcs(bcs.value())?.into(),
            ReconfigStarted::MODULE_NAME => ReconfigStarted::from_bcs(bcs.value())?.into(),
            ReconfigEnded::MODULE_NAME => ReconfigEnded::from_bcs(bcs.value())?.into(),
            PackageUpgraded::MODULE_NAME => PackageUpgraded::from_bcs(bcs.value())?.into(),
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

#[derive(Debug)]
pub struct ProposalCreated {
    pub proposal_id: Address,
    pub timestamp_ms: u64,
    pub proposal_type: TypeTag,
}

impl ProposalCreated {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let (proposal_id, timestamp_ms): (Address, u64) = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            timestamp_ms,
            proposal_type,
        })
    }
}

impl MoveType for ProposalCreated {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "ProposalCreated";
    const TYPE_PARAMS: usize = 1;
}

impl From<ProposalCreated> for HashiEvent {
    fn from(value: ProposalCreated) -> Self {
        Self::ProposalCreated(value)
    }
}

#[derive(Debug)]
pub struct VoteCast {
    pub proposal_id: Address,
    pub voter: Address,
    pub proposal_type: TypeTag,
}

impl VoteCast {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let (proposal_id, voter): (Address, Address) = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            voter,
            proposal_type,
        })
    }
}

impl MoveType for VoteCast {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "VoteCast";
    const TYPE_PARAMS: usize = 1;
}

impl From<VoteCast> for HashiEvent {
    fn from(value: VoteCast) -> Self {
        Self::VoteCast(value)
    }
}

#[derive(Debug)]
pub struct VoteRemoved {
    pub proposal_id: Address,
    pub voter: Address,
    pub proposal_type: TypeTag,
}

impl VoteRemoved {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let (proposal_id, voter): (Address, Address) = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            voter,
            proposal_type,
        })
    }
}

impl MoveType for VoteRemoved {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "VoteRemoved";
    const TYPE_PARAMS: usize = 1;
}

impl From<VoteRemoved> for HashiEvent {
    fn from(value: VoteRemoved) -> Self {
        Self::VoteRemoved(value)
    }
}

#[derive(Debug)]
pub struct ProposalDeleted {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
}

impl ProposalDeleted {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let proposal_id: Address = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            proposal_type,
        })
    }
}

impl MoveType for ProposalDeleted {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "ProposalDeleted";
    const TYPE_PARAMS: usize = 1;
}

impl From<ProposalDeleted> for HashiEvent {
    fn from(value: ProposalDeleted) -> Self {
        Self::ProposalDeleted(value)
    }
}

#[derive(Debug)]
pub struct ProposalExecuted {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
    /// BCS-encoded bytes of the proposal `data` payload (`T` in the Move
    /// `ProposalExecuted<T>`). Decode using `proposal_type` to get the
    /// typed value.
    pub data_bcs: Vec<u8>,
}

impl ProposalExecuted {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        // Layout is `(proposal_id: Address, data: T)`; Address is a fixed
        // 32-byte BCS encoding with no length prefix, so split there.
        if bcs.len() < 32 {
            anyhow::bail!("ProposalExecuted payload too short: {} bytes", bcs.len());
        }
        let proposal_id: Address = bcs::from_bytes(&bcs[..32])?;
        let data_bcs = bcs[32..].to_vec();
        Ok(Self {
            proposal_id,
            proposal_type,
            data_bcs,
        })
    }
}

impl MoveType for ProposalExecuted {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "ProposalExecuted";
    const TYPE_PARAMS: usize = 1;
}

impl From<ProposalExecuted> for HashiEvent {
    fn from(value: ProposalExecuted) -> Self {
        Self::ProposalExecuted(value)
    }
}

#[derive(Debug)]
pub struct QuorumReached {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
}

impl QuorumReached {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let proposal_id: Address = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            proposal_type,
        })
    }
}

impl MoveType for QuorumReached {
    const MODULE: &'static str = "proposal";
    const NAME: &'static str = "QuorumReached";
    const TYPE_PARAMS: usize = 1;
}

impl From<QuorumReached> for HashiEvent {
    fn from(value: QuorumReached) -> Self {
        Self::QuorumReached(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct PackageUpgraded {
    pub package: Address,
    pub version: u64,
}

impl MoveType for PackageUpgraded {
    const MODULE: &'static str = "upgrade";
    const NAME: &'static str = "PackageUpgraded";
}

impl From<PackageUpgraded> for HashiEvent {
    fn from(value: PackageUpgraded) -> Self {
        Self::PackageUpgraded(value)
    }
}

#[derive(Debug)]
pub struct Minted {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for Minted {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "Minted";
    const TYPE_PARAMS: usize = 1;
}

impl Minted {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let coin_type = extract_type_param::<Self>(event_type)?;
        Ok(Self {
            coin_type,
            amount: bcs::from_bytes(bcs)?,
        })
    }
}

impl From<Minted> for HashiEvent {
    fn from(value: Minted) -> Self {
        Self::Minted(value)
    }
}

#[derive(Debug)]
pub struct Burned {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for Burned {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "Burned";
    const TYPE_PARAMS: usize = 1;
}

impl Burned {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let coin_type = extract_type_param::<Self>(event_type)?;
        Ok(Self {
            coin_type,
            amount: bcs::from_bytes(bcs)?,
        })
    }
}

impl From<Burned> for HashiEvent {
    fn from(value: Burned) -> Self {
        Self::Burned(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequested {
    pub request_id: Address,
    pub utxo_id: UtxoId,
    pub amount: u64,
    pub derivation_path: Option<Address>,
    pub timestamp_ms: u64,
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
}

impl MoveType for DepositRequested {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositRequested";
}

impl From<DepositRequested> for HashiEvent {
    fn from(value: DepositRequested) -> Self {
        Self::DepositRequested(value)
    }
}

/// Emitted by `approve_deposit` when the committee certifies a pending
/// deposit. The corresponding `hBTC` is not yet minted — the deposit
/// must still wait through the time-delay window and then be confirmed.
/// `approved_timestamp_ms` is the on-chain clock timestamp recorded on
/// the request, against which `confirm_deposit` enforces the delay.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositApproved {
    pub request_id: Address,
    pub utxo: Utxo,
    pub cert: CommitteeSignature,
    pub approved_timestamp_ms: u64,
}

impl MoveType for DepositApproved {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositApproved";
}

impl From<DepositApproved> for HashiEvent {
    fn from(value: DepositApproved) -> Self {
        Self::DepositApproved(value)
    }
}

/// Emitted by `confirm_deposit` once an approved deposit clears the
/// time-delay window and the corresponding `hBTC` is minted.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositConfirmed {
    pub request_id: Address,
    pub utxo: Utxo,
}

impl MoveType for DepositConfirmed {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositConfirmed";
}

impl From<DepositConfirmed> for HashiEvent {
    fn from(value: DepositConfirmed) -> Self {
        Self::DepositConfirmed(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ExpiredDepositDeleted {
    pub request_id: Address,
}

impl MoveType for ExpiredDepositDeleted {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "ExpiredDepositDeleted";
}

impl From<ExpiredDepositDeleted> for HashiEvent {
    fn from(value: ExpiredDepositDeleted) -> Self {
        Self::ExpiredDepositDeleted(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalRequested {
    pub request_id: Address,
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
    pub timestamp_ms: u64,
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
}

impl MoveType for WithdrawalRequested {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalRequested";
}

impl From<WithdrawalRequested> for HashiEvent {
    fn from(value: WithdrawalRequested) -> Self {
        Self::WithdrawalRequested(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalApproved {
    pub request_id: Address,
}

impl MoveType for WithdrawalApproved {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalApproved";
}

impl From<WithdrawalApproved> for HashiEvent {
    fn from(value: WithdrawalApproved) -> Self {
        Self::WithdrawalApproved(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalPickedForProcessing {
    pub withdrawal_txn_id: Address,
    pub txid: BitcoinTxid,
    pub request_ids: Vec<Address>,
    pub inputs: Vec<Utxo>,
    pub withdrawal_outputs: Vec<OutputUtxo>,
    /// Change outputs back to the bridge, in BTC transaction order (trailing
    /// outputs). Empty when there is no change.
    pub change_outputs: Vec<OutputUtxo>,
    pub timestamp_ms: u64,
    pub randomness: Vec<u8>,
}

impl MoveType for WithdrawalPickedForProcessing {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalPickedForProcessing";
}

impl From<WithdrawalPickedForProcessing> for HashiEvent {
    fn from(value: WithdrawalPickedForProcessing) -> Self {
        Self::WithdrawalPickedForProcessing(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalSigned {
    pub withdrawal_txn_id: Address,
    pub request_ids: Vec<Address>,
    /// Per-input MPC committee Schnorr signatures.
    pub signatures: Vec<Vec<u8>>,
    /// Per-input guardian enclave Schnorr signatures (same length as
    /// `signatures`). Together they form the 2-of-2 taproot witness.
    pub guardian_signatures: Vec<Vec<u8>>,
}

impl MoveType for WithdrawalSigned {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalSigned";
}

impl From<WithdrawalSigned> for HashiEvent {
    fn from(value: WithdrawalSigned) -> Self {
        Self::WithdrawalSigned(value)
    }
}

/// Emitted on each incremental chunk write so the watcher can track signing
/// progress (signed_count / num_inputs); the per-input state lives on the object.
#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalInputsSigned {
    pub withdrawal_txn_id: Address,
    pub signed_count: u64,
    pub num_inputs: u64,
}

impl MoveType for WithdrawalInputsSigned {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalInputsSigned";
}

impl From<WithdrawalInputsSigned> for HashiEvent {
    fn from(value: WithdrawalInputsSigned) -> Self {
        Self::WithdrawalInputsSigned(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalPresigsReassigned {
    pub withdrawal_txn_id: Address,
    pub epoch: u64,
    pub presig_start_index: u64,
}

impl MoveType for WithdrawalPresigsReassigned {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalPresigsReassigned";
}

impl From<WithdrawalPresigsReassigned> for HashiEvent {
    fn from(value: WithdrawalPresigsReassigned) -> Self {
        Self::WithdrawalPresigsReassigned(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalConfirmed {
    pub withdrawal_txn_id: Address,
    pub txid: BitcoinTxid,
    /// Change UTXO IDs promoted to confirmed, in vout order. Empty when there
    /// is no change.
    pub change_utxo_ids: Vec<UtxoId>,
    pub request_ids: Vec<Address>,
    /// Per-change-output amounts, parallel to `change_utxo_ids`.
    pub change_utxo_amounts: Vec<u64>,
}

impl MoveType for WithdrawalConfirmed {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalConfirmed";
}

impl From<WithdrawalConfirmed> for HashiEvent {
    fn from(value: WithdrawalConfirmed) -> Self {
        Self::WithdrawalConfirmed(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct UtxoSpent {
    pub utxo_id: UtxoId,
    pub spent_epoch: u64,
}

impl MoveType for UtxoSpent {
    const MODULE: &'static str = "utxo_pool";
    const NAME: &'static str = "UtxoSpent";
}

impl From<UtxoSpent> for HashiEvent {
    fn from(value: UtxoSpent) -> Self {
        Self::UtxoSpent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ReconfigStarted {
    pub epoch: u64,
}

impl MoveType for ReconfigStarted {
    const MODULE: &'static str = "reconfig";
    const NAME: &'static str = "ReconfigStarted";
}

impl From<ReconfigStarted> for HashiEvent {
    fn from(value: ReconfigStarted) -> Self {
        Self::ReconfigStarted(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ReconfigEnded {
    pub from_epoch: u64,
    pub epoch: u64,
    pub mpc_public_key: Vec<u8>,
}

impl MoveType for ReconfigEnded {
    const MODULE: &'static str = "reconfig";
    const NAME: &'static str = "ReconfigEnded";
}

impl From<ReconfigEnded> for HashiEvent {
    fn from(value: ReconfigEnded) -> Self {
        Self::ReconfigEnded(value)
    }
}

impl From<&crate::committee::CommitteeMember> for CommitteeMember {
    fn from(m: &crate::committee::CommitteeMember) -> Self {
        Self {
            validator_address: m.validator_address(),
            public_key: bls_public_key_to_uncompressed_g1_bytes(m.public_key()),
            encryption_public_key: m.encryption_public_key().to_bcs().expect("should not fail"),
            weight: m.weight(),
        }
    }
}

impl TryFrom<CommitteeMember> for crate::committee::CommitteeMember {
    type Error = anyhow::Error;

    fn try_from(m: CommitteeMember) -> Result<Self, Self::Error> {
        let public_key = bls_public_key_from_uncompressed_g1_bytes(&m.public_key)?;

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

fn bls_public_key_to_uncompressed_g1_bytes(
    public_key: &crate::committee::BLS12381PublicKey,
) -> Vec<u8> {
    blst::min_pk::PublicKey::from_bytes(public_key.as_bytes())
        .expect("valid BLS public key")
        .serialize()
        .to_vec()
}

fn bls_public_key_from_uncompressed_g1_bytes(
    public_key: &[u8],
) -> Result<crate::committee::BLS12381PublicKey, anyhow::Error> {
    let public_key = blst::min_pk::PublicKey::deserialize(public_key)
        .map_err(|e| anyhow::anyhow!("invalid public key {e:?}"))?;
    crate::committee::BLS12381PublicKey::from_bytes(public_key.to_bytes().as_slice())
        .map_err(|e| anyhow::anyhow!("invalid public key {e}"))
}

impl From<&crate::committee::Committee> for Committee {
    fn from(c: &crate::committee::Committee) -> Self {
        Self {
            epoch: c.epoch(),
            members: c.members().iter().map(Into::into).collect(),
            total_weight: c.total_weight(),
            // Carry the pinned config verbatim — no reconstruction, so the
            // serialized bytes match the on-chain committee exactly.
            config: c.config().clone(),
        }
    }
}

impl TryFrom<Committee> for crate::committee::Committee {
    type Error = anyhow::Error;

    fn try_from(c: Committee) -> Result<Self, Self::Error> {
        let members = c
            .members
            .into_iter()
            .map(crate::committee::CommitteeMember::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::committee::Committee::with_config(
            members, c.epoch, c.config,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sui_sdk_types::Identifier;

    fn tag(address: Address, module: &str, name: &str, type_params: Vec<TypeTag>) -> StructTag {
        StructTag::new(
            address,
            Identifier::new(module).unwrap(),
            Identifier::new(name).unwrap(),
            type_params,
        )
    }

    fn hashi_package() -> Address {
        Address::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap()
    }

    fn field_tag(name_type: TypeTag, value_type: TypeTag) -> StructTag {
        tag(
            Address::TWO,
            "dynamic_field",
            "Field",
            vec![name_type, value_type],
        )
    }

    fn member_info_value() -> TypeTag {
        TypeTag::Struct(Box::new(tag(
            hashi_package(),
            "committee_set",
            "MemberInfo",
            vec![],
        )))
    }

    #[test]
    fn move_type_matches_ignores_package_address() {
        for address in [hashi_package(), Address::TWO] {
            let t = tag(address, "committee_set", "MemberInfo", vec![]);
            assert!(MemberInfo::matches(&t));
        }
    }

    #[test]
    fn move_type_matches_rejects_wrong_module_name_or_arity() {
        let wrong_module = tag(hashi_package(), "committee", "MemberInfo", vec![]);
        assert!(!MemberInfo::matches(&wrong_module));

        let wrong_name = tag(hashi_package(), "committee_set", "Committee", vec![]);
        assert!(!MemberInfo::matches(&wrong_name));

        let wrong_arity = tag(
            hashi_package(),
            "committee_set",
            "MemberInfo",
            vec![TypeTag::U64],
        );
        assert!(!MemberInfo::matches(&wrong_arity));
    }

    #[test]
    fn typed_event_matches_requires_one_type_param() {
        let bare = tag(hashi_package(), "proposal", "ProposalCreated", vec![]);
        assert!(!ProposalCreated::matches(&bare));

        let typed = tag(
            hashi_package(),
            "proposal",
            "ProposalCreated",
            vec![TypeTag::U64],
        );
        assert!(ProposalCreated::matches(&typed));
    }

    #[test]
    fn is_dynamic_field_requires_framework_field_shape() {
        assert!(is_dynamic_field(&field_tag(
            TypeTag::Address,
            member_info_value()
        )));

        // Same shape but not in the Sui framework package.
        let impostor = tag(
            hashi_package(),
            "dynamic_field",
            "Field",
            vec![TypeTag::Address, member_info_value()],
        );
        assert!(!is_dynamic_field(&impostor));

        // The framework Field always has exactly two type parameters.
        let wrong_arity = tag(Address::TWO, "dynamic_field", "Field", vec![TypeTag::U64]);
        assert!(!is_dynamic_field(&wrong_arity));

        let not_a_field = tag(hashi_package(), "committee_set", "MemberInfo", vec![]);
        assert!(!is_dynamic_field(&not_a_field));
    }

    #[test]
    fn is_field_with_value_matches_the_value_side_only() {
        let member_field = field_tag(TypeTag::Address, member_info_value());
        assert!(is_field_with_value(
            &member_field,
            "committee_set",
            "MemberInfo"
        ));
        assert!(!is_field_with_value(
            &member_field,
            "committee",
            "Committee"
        ));

        // A primitive value side never matches a struct query.
        let primitive_value = field_tag(TypeTag::Address, TypeTag::U64);
        assert!(!is_field_with_value(
            &primitive_value,
            "committee_set",
            "MemberInfo"
        ));
    }

    #[test]
    fn is_dof_wrapper_detects_the_wrapper_name_type() {
        let wrapper_name = TypeTag::Struct(Box::new(tag(
            Address::TWO,
            "dynamic_object_field",
            "Wrapper",
            vec![TypeTag::Address],
        )));
        let wrapper = field_tag(wrapper_name, TypeTag::Address);
        assert!(is_dof_wrapper(&wrapper));
        // A DOF wrapper is still a plain dynamic field structurally.
        assert!(is_dynamic_field(&wrapper));

        // A plain dynamic field is not a DOF wrapper.
        let plain = field_tag(TypeTag::Address, member_info_value());
        assert!(!is_dof_wrapper(&plain));

        // A Wrapper name type from outside the framework doesn't count.
        let impostor_name = TypeTag::Struct(Box::new(tag(
            hashi_package(),
            "dynamic_object_field",
            "Wrapper",
            vec![TypeTag::Address],
        )));
        assert!(!is_dof_wrapper(&field_tag(impostor_name, TypeTag::Address)));
    }

    #[test]
    fn committee_mpc_config_carried_verbatim_through_bcs() {
        let committee = crate::committee::Committee::new(vec![], 5, 3334, 800, 3333, 1);
        let move_committee = Committee::from(&committee);

        // Round-trip the serialized committee and confirm the verbatim config
        // survives byte-for-byte.
        let bytes = bcs::to_bytes(&move_committee).expect("serialize");
        let decoded: Committee = bcs::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded.config, move_committee.config);
        assert_eq!(decoded.config.mpc_threshold_in_basis_points(), 3334);
        assert_eq!(decoded.config.mpc_weight_reduction_allowed_delta(), 800);
        assert_eq!(decoded.config.mpc_max_faulty_in_basis_points(), 3333);
        assert_eq!(decoded.config.mpc_nonce_generation_protocol(), 1);

        let back = crate::committee::Committee::try_from(decoded).expect("convert back");
        assert_eq!(back.config(), &move_committee.config);
    }

    /// Pins the exact BCS bytes of a committee's pinned config so a change to the
    /// canonical key order, the `ConfigValue` encoding, or the entry set is
    /// caught here rather than silently breaking handoff-cert verification.
    /// The expected vector must equal what Move's `mpc_config::pin` produces.
    #[test]
    fn committee_mpc_config_bcs_is_pinned() {
        let mpc = Config::from_mpc_params(3334, 800, 3333, 1);
        let bytes = bcs::to_bytes(&mpc).expect("serialize");

        // VecMap<String,Value> = ULEB128 len (4) then, per entry, ULEB128 key
        // length, key bytes, 1-byte Value variant tag (U64 = 0), 8-byte LE u64.
        let expected: Vec<u8> = {
            let mut v = vec![4u8];
            for (key, val) in [
                ("mpc_threshold_in_basis_points", 3334u64),
                ("mpc_weight_reduction_allowed_delta", 800),
                ("mpc_max_faulty_in_basis_points", 3333),
                ("mpc_nonce_generation_protocol", 1),
            ] {
                v.push(key.len() as u8);
                v.extend_from_slice(key.as_bytes());
                v.push(0); // ConfigValue::U64 tag
                v.extend_from_slice(&val.to_le_bytes());
            }
            v
        };
        assert_eq!(bytes, expected);

        // And the bytes decode back to the same entries.
        let decoded: Config = bcs::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, mpc);
        assert!(matches!(decoded.entries()[0].1, ConfigValue::U64(3334)));
    }

    /// Pins the BCS encoding of the wide-integer `ConfigValue` variants against
    /// what Move produces: 1-byte variant tag (U128 = 1, U256 = 2) followed by
    /// the little-endian integer bytes (16 for u128, 32 for u256).
    #[test]
    fn config_value_wide_integer_bcs_round_trip() {
        let u128_value = ConfigValue::U128(1u128 << 100);
        let bytes = bcs::to_bytes(&u128_value).expect("serialize");
        let mut expected = vec![1u8];
        expected.extend_from_slice(&(1u128 << 100).to_le_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(
            bcs::from_bytes::<ConfigValue>(&bytes).expect("deserialize"),
            u128_value
        );

        let mut le = [0u8; 32];
        le[16] = 1; // 2^128, unrepresentable in u128
        let u256_value = ConfigValue::U256(le);
        let bytes = bcs::to_bytes(&u256_value).expect("serialize");
        let mut expected = vec![2u8];
        expected.extend_from_slice(&le);
        assert_eq!(bytes, expected);
        assert_eq!(
            bcs::from_bytes::<ConfigValue>(&bytes).expect("deserialize"),
            u256_value
        );
    }
}
