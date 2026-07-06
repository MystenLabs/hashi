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

pub trait MoveType {
    const PACKAGE_VERSION: u64 = 1;
    const MODULE: &'static str;
    const NAME: &'static str;
    const MODULE_NAME: (&'static str, &'static str) = (Self::MODULE, Self::NAME);
}

/// Validates that the event's StructTag matches the expected module/name for `T`
/// and extracts the single type parameter.
fn extract_type_param<T: MoveType>(event_type: &StructTag) -> Result<TypeTag, anyhow::Error> {
    if event_type.module() == T::MODULE
        && event_type.name() == T::NAME
        && let [type_param] = event_type.type_params()
    {
        Ok(type_param.to_owned())
    } else {
        Err(anyhow::anyhow!("invalid {}", T::NAME))
    }
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
#[derive(Debug, serde_derive::Deserialize)]
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
    pub timestamp_ms: u64,
    pub status: WithdrawalStatus,
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
    pub timestamp_ms: u64,
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
/// `approval_cert` and `approval_timestamp_ms` are populated when the
/// committee approves the deposit via `approve_deposit`. They remain
/// `None` until then. `confirm_deposit` requires both to be set.
#[derive(Clone, Debug, PartialEq, serde_derive::Deserialize)]
pub struct DepositRequest {
    pub id: Address,
    pub sender: Address,
    pub creation_timestamp_ms: u64,
    pub sui_tx_digest: Digest,
    pub utxo: Utxo,
    pub approval_cert: Option<CommitteeSignature>,
    pub approval_timestamp_ms: Option<u64>,
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
    pub locked_by: Option<Address>,
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

/// Rust version of the Move hashi::proposal::Proposal type.
#[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Proposal<T> {
    pub id: Address,
    pub creator: Address,
    pub votes: Vec<Address>,
    pub quorum_threshold_bps: u64,
    pub timestamp_ms: u64,
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
    VoteCastEvent(VoteCastEvent),
    VoteRemovedEvent(VoteRemovedEvent),
    ProposalCreatedEvent(ProposalCreatedEvent),
    ProposalDeletedEvent(ProposalDeletedEvent),
    ProposalExecutedEvent(ProposalExecutedEvent),
    QuorumReachedEvent(QuorumReachedEvent),
    PackageUpgradedEvent(PackageUpgradedEvent),
    MintEvent(MintEvent),
    BurnEvent(BurnEvent),
    DepositRequestedEvent(DepositRequestedEvent),
    DepositApprovedEvent(DepositApprovedEvent),
    DepositConfirmedEvent(DepositConfirmedEvent),
    ExpiredDepositDeletedEvent(ExpiredDepositDeletedEvent),
    WithdrawalRequestedEvent(WithdrawalRequestedEvent),
    WithdrawalApprovedEvent(WithdrawalApprovedEvent),
    WithdrawalPickedForProcessingEvent(WithdrawalPickedForProcessingEvent),
    WithdrawalSignedEvent(WithdrawalSignedEvent),
    WithdrawalInputsSignedEvent(WithdrawalInputsSignedEvent),
    WithdrawalPresigsReassignedEvent(WithdrawalPresigsReassignedEvent),
    WithdrawalConfirmedEvent(WithdrawalConfirmedEvent),
    UtxoSpentEvent(UtxoSpentEvent),
    StartReconfigEvent(StartReconfigEvent),
    EndReconfigEvent(EndReconfigEvent),
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
            VoteCastEvent::MODULE_NAME => VoteCastEvent::new(&event_type, bcs.value())?.into(),
            VoteRemovedEvent::MODULE_NAME => {
                VoteRemovedEvent::new(&event_type, bcs.value())?.into()
            }
            ProposalCreatedEvent::MODULE_NAME => {
                ProposalCreatedEvent::new(&event_type, bcs.value())?.into()
            }
            ProposalDeletedEvent::MODULE_NAME => {
                ProposalDeletedEvent::new(&event_type, bcs.value())?.into()
            }
            ProposalExecutedEvent::MODULE_NAME => {
                ProposalExecutedEvent::new(&event_type, bcs.value())?.into()
            }
            QuorumReachedEvent::MODULE_NAME => {
                QuorumReachedEvent::new(&event_type, bcs.value())?.into()
            }
            MintEvent::MODULE_NAME => MintEvent::new(&event_type, bcs.value())?.into(),
            BurnEvent::MODULE_NAME => BurnEvent::new(&event_type, bcs.value())?.into(),
            DepositRequestedEvent::MODULE_NAME => {
                DepositRequestedEvent::from_bcs(bcs.value())?.into()
            }
            DepositApprovedEvent::MODULE_NAME => {
                DepositApprovedEvent::from_bcs(bcs.value())?.into()
            }
            DepositConfirmedEvent::MODULE_NAME => {
                DepositConfirmedEvent::from_bcs(bcs.value())?.into()
            }
            ExpiredDepositDeletedEvent::MODULE_NAME => {
                ExpiredDepositDeletedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalRequestedEvent::MODULE_NAME => {
                WithdrawalRequestedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalApprovedEvent::MODULE_NAME => {
                WithdrawalApprovedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalPickedForProcessingEvent::MODULE_NAME => {
                WithdrawalPickedForProcessingEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalSignedEvent::MODULE_NAME => {
                WithdrawalSignedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalInputsSignedEvent::MODULE_NAME => {
                WithdrawalInputsSignedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalPresigsReassignedEvent::MODULE_NAME => {
                WithdrawalPresigsReassignedEvent::from_bcs(bcs.value())?.into()
            }
            WithdrawalConfirmedEvent::MODULE_NAME => {
                WithdrawalConfirmedEvent::from_bcs(bcs.value())?.into()
            }
            UtxoSpentEvent::MODULE_NAME => UtxoSpentEvent::from_bcs(bcs.value())?.into(),
            StartReconfigEvent::MODULE_NAME => StartReconfigEvent::from_bcs(bcs.value())?.into(),
            EndReconfigEvent::MODULE_NAME => EndReconfigEvent::from_bcs(bcs.value())?.into(),
            PackageUpgradedEvent::MODULE_NAME => {
                PackageUpgradedEvent::from_bcs(bcs.value())?.into()
            }
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
pub struct ProposalCreatedEvent {
    pub proposal_id: Address,
    pub timestamp_ms: u64,
    pub proposal_type: TypeTag,
}

impl ProposalCreatedEvent {
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

impl MoveType for ProposalCreatedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalCreatedEvent";
}

impl From<ProposalCreatedEvent> for HashiEvent {
    fn from(value: ProposalCreatedEvent) -> Self {
        Self::ProposalCreatedEvent(value)
    }
}

#[derive(Debug)]
pub struct VoteCastEvent {
    pub proposal_id: Address,
    pub voter: Address,
    pub proposal_type: TypeTag,
}

impl VoteCastEvent {
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

impl MoveType for VoteCastEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteCastEvent";
}

impl From<VoteCastEvent> for HashiEvent {
    fn from(value: VoteCastEvent) -> Self {
        Self::VoteCastEvent(value)
    }
}

#[derive(Debug)]
pub struct VoteRemovedEvent {
    pub proposal_id: Address,
    pub voter: Address,
    pub proposal_type: TypeTag,
}

impl VoteRemovedEvent {
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

impl MoveType for VoteRemovedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteRemovedEvent";
}

impl From<VoteRemovedEvent> for HashiEvent {
    fn from(value: VoteRemovedEvent) -> Self {
        Self::VoteRemovedEvent(value)
    }
}

#[derive(Debug)]
pub struct ProposalDeletedEvent {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
}

impl ProposalDeletedEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let proposal_id: Address = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            proposal_type,
        })
    }
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

#[derive(Debug)]
pub struct ProposalExecutedEvent {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
    /// BCS-encoded bytes of the proposal `data` payload (`T` in the Move
    /// `ProposalExecutedEvent<T>`). Decode using `proposal_type` to get the
    /// typed value.
    pub data_bcs: Vec<u8>,
}

impl ProposalExecutedEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        // Layout is `(proposal_id: Address, data: T)`; Address is a fixed
        // 32-byte BCS encoding with no length prefix, so split there.
        if bcs.len() < 32 {
            anyhow::bail!(
                "ProposalExecutedEvent payload too short: {} bytes",
                bcs.len()
            );
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

impl MoveType for ProposalExecutedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalExecutedEvent";
}

impl From<ProposalExecutedEvent> for HashiEvent {
    fn from(value: ProposalExecutedEvent) -> Self {
        Self::ProposalExecutedEvent(value)
    }
}

#[derive(Debug)]
pub struct QuorumReachedEvent {
    pub proposal_id: Address,
    pub proposal_type: TypeTag,
}

impl QuorumReachedEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        let proposal_type = extract_type_param::<Self>(event_type)?;
        let proposal_id: Address = bcs::from_bytes(bcs)?;
        Ok(Self {
            proposal_id,
            proposal_type,
        })
    }
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
        let coin_type = extract_type_param::<Self>(event_type)?;
        Ok(Self {
            coin_type,
            amount: bcs::from_bytes(bcs)?,
        })
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
        let coin_type = extract_type_param::<Self>(event_type)?;
        Ok(Self {
            coin_type,
            amount: bcs::from_bytes(bcs)?,
        })
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
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
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

/// Emitted by `approve_deposit` when the committee certifies a pending
/// deposit. The corresponding `hBTC` is not yet minted — the deposit
/// must still wait through the time-delay window and then be confirmed.
/// `approval_timestamp_ms` is the on-chain clock timestamp recorded on
/// the request, against which `confirm_deposit` enforces the delay.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositApprovedEvent {
    pub request_id: Address,
    pub utxo: Utxo,
    pub cert: CommitteeSignature,
    pub approval_timestamp_ms: u64,
}

impl MoveType for DepositApprovedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositApprovedEvent";
}

impl From<DepositApprovedEvent> for HashiEvent {
    fn from(value: DepositApprovedEvent) -> Self {
        Self::DepositApprovedEvent(value)
    }
}

/// Emitted by `confirm_deposit` once an approved deposit clears the
/// time-delay window and the corresponding `hBTC` is minted.
#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositConfirmedEvent {
    pub request_id: Address,
    pub utxo: Utxo,
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
pub struct WithdrawalRequestedEvent {
    pub request_id: Address,
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
    pub timestamp_ms: u64,
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
}

impl MoveType for WithdrawalRequestedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalRequestedEvent";
}

impl From<WithdrawalRequestedEvent> for HashiEvent {
    fn from(value: WithdrawalRequestedEvent) -> Self {
        Self::WithdrawalRequestedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalApprovedEvent {
    pub request_id: Address,
}

impl MoveType for WithdrawalApprovedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalApprovedEvent";
}

impl From<WithdrawalApprovedEvent> for HashiEvent {
    fn from(value: WithdrawalApprovedEvent) -> Self {
        Self::WithdrawalApprovedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalPickedForProcessingEvent {
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

impl MoveType for WithdrawalPickedForProcessingEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalPickedForProcessingEvent";
}

impl From<WithdrawalPickedForProcessingEvent> for HashiEvent {
    fn from(value: WithdrawalPickedForProcessingEvent) -> Self {
        Self::WithdrawalPickedForProcessingEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalSignedEvent {
    pub withdrawal_txn_id: Address,
    pub request_ids: Vec<Address>,
    /// Per-input MPC committee Schnorr signatures.
    pub signatures: Vec<Vec<u8>>,
    /// Per-input guardian enclave Schnorr signatures (same length as
    /// `signatures`). Together they form the 2-of-2 taproot witness.
    pub guardian_signatures: Vec<Vec<u8>>,
}

impl MoveType for WithdrawalSignedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalSignedEvent";
}

impl From<WithdrawalSignedEvent> for HashiEvent {
    fn from(value: WithdrawalSignedEvent) -> Self {
        Self::WithdrawalSignedEvent(value)
    }
}

/// Emitted on each incremental chunk write so the watcher can track signing
/// progress (signed_count / num_inputs); the per-input state lives on the object.
#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalInputsSignedEvent {
    pub withdrawal_txn_id: Address,
    pub signed_count: u64,
    pub num_inputs: u64,
}

impl MoveType for WithdrawalInputsSignedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalInputsSignedEvent";
}

impl From<WithdrawalInputsSignedEvent> for HashiEvent {
    fn from(value: WithdrawalInputsSignedEvent) -> Self {
        Self::WithdrawalInputsSignedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalPresigsReassignedEvent {
    pub withdrawal_txn_id: Address,
    pub epoch: u64,
    pub presig_start_index: u64,
}

impl MoveType for WithdrawalPresigsReassignedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalPresigsReassignedEvent";
}

impl From<WithdrawalPresigsReassignedEvent> for HashiEvent {
    fn from(value: WithdrawalPresigsReassignedEvent) -> Self {
        Self::WithdrawalPresigsReassignedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct WithdrawalConfirmedEvent {
    pub withdrawal_txn_id: Address,
    pub txid: BitcoinTxid,
    /// Change UTXO IDs promoted to confirmed, in vout order. Empty when there
    /// is no change.
    pub change_utxo_ids: Vec<UtxoId>,
    pub request_ids: Vec<Address>,
    /// Per-change-output amounts, parallel to `change_utxo_ids`.
    pub change_utxo_amounts: Vec<u64>,
}

impl MoveType for WithdrawalConfirmedEvent {
    const MODULE: &'static str = "withdrawal_queue";
    const NAME: &'static str = "WithdrawalConfirmedEvent";
}

impl From<WithdrawalConfirmedEvent> for HashiEvent {
    fn from(value: WithdrawalConfirmedEvent) -> Self {
        Self::WithdrawalConfirmedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct UtxoSpentEvent {
    pub utxo_id: UtxoId,
    pub spent_epoch: u64,
}

impl MoveType for UtxoSpentEvent {
    const MODULE: &'static str = "utxo_pool";
    const NAME: &'static str = "UtxoSpentEvent";
}

impl From<UtxoSpentEvent> for HashiEvent {
    fn from(value: UtxoSpentEvent) -> Self {
        Self::UtxoSpentEvent(value)
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
    pub from_epoch: u64,
    pub epoch: u64,
    pub mpc_public_key: Vec<u8>,
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
}
