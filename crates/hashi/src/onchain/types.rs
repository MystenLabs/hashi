#![allow(unused)] // TODO remove this

//! Usable definitions of the onchain state of hashi

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use axum::http;
use base64ct::Encoding;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;
use sui_sdk_types::TypeTag;

use crate::grpc::Client;
use hashi_types::committee::Committee;
use hashi_types::committee::EncryptionPublicKey;
use hashi_types::utils::Base64;

#[derive(Debug)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub treasury: Treasury,
    pub deposit_queue: DepositRequestQueue,
    pub withdrawal_queue: WithdrawalRequestQueue,
    pub utxo_pool: UtxoPool,
    pub proposals: Proposals,
    pub tob_id: Address,
}

pub struct CommitteeSet {
    /// Id of the `Bag` containing the validator info structs
    members_id: Address,
    members: BTreeMap<Address, MemberInfo>,
    tls_public_key_to_address: BTreeMap<[u8; 32], Address>,
    /// The current epoch.
    epoch: u64,
    pending_epoch_change: Option<u64>,

    /// The MPC committee's threshold public key.
    mpc_public_key: Vec<u8>,

    /// Id of the `Bag` containing the committee's per epoch
    committees_id: Address,
    committees: BTreeMap<u64, Committee>,

    tls_private_key: Option<ed25519_dalek::SigningKey>,
    grpc_max_decoding_message_size: Option<usize>,
    clients: BTreeMap<Address, Client>,
}

impl fmt::Debug for CommitteeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render tls_public_key_to_address with base64 keys
        let tls_key_map: BTreeMap<String, &Address> = self
            .tls_public_key_to_address
            .iter()
            .map(|(k, v)| (base64ct::Base64::encode_string(k), v))
            .collect();

        // Render tls_private_key as redacted with public key
        let tls_private_key_display = self.tls_private_key.as_ref().map(|key| {
            format!(
                "<redacted, public_key: {}>",
                base64ct::Base64::encode_string(key.verifying_key().as_bytes())
            )
        });

        f.debug_struct("CommitteeSet")
            .field("members_id", &self.members_id)
            .field("members", &self.members)
            .field("tls_public_key_to_address", &tls_key_map)
            .field("epoch", &self.epoch)
            .field("pending_epoch_change", &self.pending_epoch_change)
            .field(
                "mpc_public_key",
                &Base64("MpcPublicKey", &self.mpc_public_key),
            )
            .field("committees_id", &self.committees_id)
            .field("committees", &self.committees)
            .field("tls_private_key", &tls_private_key_display)
            .field(
                "grpc_max_decoding_message_size",
                &self.grpc_max_decoding_message_size,
            )
            .field("clients", &format_args!("<{} clients>", self.clients.len()))
            .finish()
    }
}

impl CommitteeSet {
    pub fn new(members_id: Address, committees_id: Address) -> Self {
        Self {
            members_id,
            members: BTreeMap::new(),
            tls_public_key_to_address: BTreeMap::new(),
            epoch: 0,
            pending_epoch_change: None,
            mpc_public_key: Vec::new(),
            committees_id,
            committees: BTreeMap::new(),
            tls_private_key: None,
            grpc_max_decoding_message_size: None,
            clients: BTreeMap::new(),
        }
    }

    pub fn members_id(&self) -> Address {
        self.members_id
    }

    pub fn members(&self) -> &BTreeMap<Address, MemberInfo> {
        &self.members
    }

    pub fn committees_id(&self) -> Address {
        self.committees_id
    }

    pub fn committees(&self) -> &BTreeMap<u64, Committee> {
        &self.committees
    }

    pub fn committees_mut(&mut self) -> &mut BTreeMap<u64, Committee> {
        &mut self.committees
    }

    pub fn current_committee(&self) -> Option<&Committee> {
        self.committees().get(&self.epoch())
    }

    pub fn previous_committee(&self) -> Option<&Committee> {
        self.epoch
            .checked_sub(1)
            .and_then(|e| self.committees().get(&e))
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn mpc_public_key(&self) -> &[u8] {
        &self.mpc_public_key
    }

    pub fn pending_epoch_change(&self) -> Option<u64> {
        self.pending_epoch_change
    }

    pub fn client(&self, validator: &Address) -> Option<Client> {
        self.clients.get(validator).cloned()
    }

    // Set the tls private key to use when constructing tls configs for clients to other validators
    pub fn set_tls_private_key(&mut self, tls_private_key: ed25519_dalek::SigningKey) -> &mut Self {
        self.tls_private_key = Some(tls_private_key);
        self.update_all_clients();
        self
    }

    pub fn set_grpc_max_decoding_message_size(&mut self, limit: usize) -> &mut Self {
        self.grpc_max_decoding_message_size = Some(limit);
        self.update_all_clients();
        self
    }

    pub fn set_members(&mut self, members: BTreeMap<Address, MemberInfo>) -> &mut Self {
        self.tls_public_key_to_address = members
            .values()
            .filter_map(|info| {
                info.tls_public_key
                    .as_ref()
                    .map(|pubkey| (*pubkey.as_bytes(), info.validator_address))
            })
            .collect();
        self.members = members;
        self.update_all_clients();
        self
    }

    fn update_all_clients(&mut self) {
        self.clients = self
            .members
            .values()
            .filter_map(|info| {
                if let (Some(addr), Some(public_key)) = (info.endpoint_url(), info.tls_public_key())
                {
                    Some((info.validator_address, addr, public_key))
                } else {
                    None
                }
            })
            .filter_map(|(validator, endpoint_url, tls_public_key)| {
                let tls_config = if let Some(tls_private_key) = &self.tls_private_key {
                    crate::tls::make_client_config_with_client_auth(tls_private_key, tls_public_key)
                } else {
                    crate::tls::make_client_config(tls_public_key)
                };
                let mut client = Client::new(endpoint_url, tls_config)
                    .inspect_err(|e| tracing::debug!("unable to build client for {validator}: {e}"))
                    .ok()?;
                if let Some(limit) = self.grpc_max_decoding_message_size {
                    client = client.max_decoding_message_size(limit);
                }
                Some((validator, client))
            })
            .collect();
    }

    pub fn update_validator(&mut self, info: MemberInfo) {
        let validator = info.validator_address;
        let info_entry = self.members.entry(validator);

        // remove old tls public key mapping
        if let std::collections::btree_map::Entry::Occupied(entry) = &info_entry
            && let Some(tls_public_key) = &entry.get().tls_public_key
        {
            self.tls_public_key_to_address
                .remove(tls_public_key.as_bytes());
        }

        // insert new tls public key mapping
        if let Some(tls_public_key) = &info.tls_public_key {
            self.tls_public_key_to_address
                .insert(*tls_public_key.as_bytes(), validator);
        }

        // update client
        self.clients.remove(&validator);
        if let Some(endpoint_url) = &info.endpoint_url
            && let Some(tls_public_key) = &info.tls_public_key
        {
            let tls_config = if let Some(tls_private_key) = &self.tls_private_key {
                crate::tls::make_client_config_with_client_auth(tls_private_key, tls_public_key)
            } else {
                crate::tls::make_client_config(tls_public_key)
            };
            if let Ok(mut client) = Client::new(endpoint_url, tls_config)
                .inspect_err(|e| tracing::debug!("unable to build client for {validator}: {e}"))
            {
                if let Some(limit) = self.grpc_max_decoding_message_size {
                    client = client.max_decoding_message_size(limit);
                }
                self.clients.insert(validator, client);
            }
        }

        // replace info
        match info_entry {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(info);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(info);
            }
        }
    }

    pub fn set_epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    pub fn set_pending_epoch_change(&mut self, pending_epoch_change: Option<u64>) -> &mut Self {
        self.pending_epoch_change = pending_epoch_change;
        self
    }

    pub fn set_mpc_public_key(&mut self, mpc_public_key: Vec<u8>) -> &mut Self {
        assert!(self.mpc_public_key.is_empty() || self.mpc_public_key == mpc_public_key);
        self.mpc_public_key = mpc_public_key;
        self
    }

    pub fn set_committees(&mut self, committees: BTreeMap<u64, Committee>) -> &mut Self {
        self.committees = committees;
        self
    }

    pub fn lookup_address_by_tls_public_key(
        &self,
        tls_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Option<Address> {
        self.tls_public_key_to_address
            .get(tls_public_key.as_bytes())
            .copied()
    }
}

#[derive(Clone)]
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
    pub next_epoch_public_key: BLS12381PublicKey,

    /// The publicly reachable URL where the `hashi` service for this validator
    /// can be reached.
    ///
    /// This URL can be rotated and any such updates will take effect
    /// immediately.
    pub endpoint_url: Option<http::Uri>,

    /// ed25519 public key used to verify TLS self-signed x509 certs
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    pub tls_public_key: Option<ed25519_dalek::VerifyingKey>,

    /// A 32-byte ristretto255 Ristretto encryption public key (ristretto255
    /// RistrettoPoint) for MPC ECIES, to be used in the next epoch.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    pub next_epoch_encryption_public_key: Option<EncryptionPublicKey>,
}

impl fmt::Debug for MemberInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encryption_key_bytes = self
            .next_epoch_encryption_public_key
            .as_ref()
            .map(|k| k.as_element().to_byte_array());

        f.debug_struct("MemberInfo")
            .field("validator_address", &self.validator_address)
            .field("operator_address", &self.operator_address)
            .field(
                "next_epoch_public_key",
                &Base64("BLS12381PublicKey", self.next_epoch_public_key.as_bytes()),
            )
            .field("endpoint_url", &self.endpoint_url)
            .field(
                "tls_public_key",
                &self
                    .tls_public_key
                    .as_ref()
                    .map(|k| Base64("Ed25519PublicKey", k.as_bytes())),
            )
            .field(
                "next_epoch_encryption_public_key",
                &encryption_key_bytes
                    .as_ref()
                    .map(|b| Base64("EncryptionPublicKey", b.as_slice())),
            )
            .finish()
    }
}

impl MemberInfo {
    pub fn validator_address(&self) -> &Address {
        &self.validator_address
    }

    pub fn operator_address(&self) -> &Address {
        &self.operator_address
    }

    pub fn next_epoch_public_key(&self) -> &BLS12381PublicKey {
        &self.next_epoch_public_key
    }

    pub fn tls_public_key(&self) -> Option<&ed25519_dalek::VerifyingKey> {
        self.tls_public_key.as_ref()
    }

    pub fn endpoint_url(&self) -> Option<&http::Uri> {
        self.endpoint_url.as_ref()
    }

    pub fn next_epoch_encryption_public_key(&self) -> Option<&EncryptionPublicKey> {
        self.next_epoch_encryption_public_key.as_ref()
    }
}

/// Proposals bag - stores governance proposals by ID
#[derive(Debug)]
pub struct Proposals {
    pub id: Address,
    pub size: u64,
    pub(crate) proposals: BTreeMap<Address, Proposal>,
}

impl Proposals {
    pub fn proposals(&self) -> &BTreeMap<Address, Proposal> {
        &self.proposals
    }
}

/// A proposal stored in the proposals bag
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: Address,
    pub timestamp_ms: u64,
    pub proposal_type: ProposalType,
}

/// The type of proposal data stored in a `Proposal<T>`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalType {
    UpdateConfig,
    EnableVersion,
    DisableVersion,
    Upgrade,
    Unknown(String),
}

impl ProposalType {
    pub fn as_str(&self) -> &str {
        match self {
            ProposalType::UpdateConfig => "update_config",
            ProposalType::EnableVersion => "enable_version",
            ProposalType::DisableVersion => "disable_version",
            ProposalType::Upgrade => "upgrade",
            ProposalType::Unknown(_) => "unknown",
        }
    }

    pub fn all_labels() -> &'static [&'static str] {
        &[
            "update_config",
            "enable_version",
            "disable_version",
            "upgrade",
            "unknown",
        ]
    }
}

#[derive(Debug)]
pub struct Config {
    pub config: BTreeMap<String, ConfigValue>,
    pub enabled_versions: BTreeSet<u64>,
    pub upgrade_cap: Option<UpgradeCap>,
}

// These constants mirror the values in config.move and must be kept in sync.
const DUST_RELAY_MIN_VALUE: u64 = 546;
const MIN_RELAY_FEE_RATE: u64 = 1;
const INPUT_VB: u64 = 100;
const OUTPUT_VB: u64 = 43;
const NUM_OUTPUTS: u64 = 2;
const TX_FIXED_VB: u64 = 11;

impl Config {
    pub fn withdrawal_fee_btc(&self) -> u64 {
        match self.config.get("withdrawal_fee_btc") {
            Some(ConfigValue::U64(v)) => (*v).max(DUST_RELAY_MIN_VALUE),
            _ => DUST_RELAY_MIN_VALUE,
        }
    }

    pub fn max_fee_rate(&self) -> u64 {
        match self.config.get("max_fee_rate") {
            Some(ConfigValue::U64(v)) => (*v).max(MIN_RELAY_FEE_RATE),
            _ => MIN_RELAY_FEE_RATE,
        }
    }

    pub fn max_inputs(&self) -> u64 {
        match self.config.get("max_inputs") {
            Some(ConfigValue::U64(v)) => (*v).max(1),
            _ => 1,
        }
    }

    /// Worst-case network (miner) fee for a withdrawal transaction,
    /// mirroring the formula in config.move.
    pub fn worst_case_network_fee(&self) -> u64 {
        let tx_vbytes = TX_FIXED_VB + (self.max_inputs() * INPUT_VB) + (NUM_OUTPUTS * OUTPUT_VB);
        self.max_fee_rate() * tx_vbytes
    }

    /// Computed withdrawal minimum, mirroring the formula in config.move.
    pub fn withdrawal_minimum(&self) -> u64 {
        self.withdrawal_fee_btc() + self.worst_case_network_fee() + DUST_RELAY_MIN_VALUE
    }

    pub fn paused(&self) -> bool {
        matches!(self.config.get("paused"), Some(ConfigValue::Bool(true)))
    }

    pub fn bitcoin_chain_id(&self) -> Option<Address> {
        match self.config.get("bitcoin_chain_id") {
            Some(ConfigValue::Address(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn bitcoin_confirmation_threshold(&self) -> u32 {
        match self.config.get("bitcoin_confirmation_threshold") {
            Some(ConfigValue::U64(v)) => u32::try_from(*v).unwrap_or(u32::MAX),
            _ => 6,
        }
    }
}

#[derive(Debug)]
pub struct UpgradeCap {
    pub id: Address,
    pub package: Address,
    pub version: u64,
    pub policy: u8,
}

#[derive(Debug)]
pub enum ConfigValue {
    U64(u64),
    Address(Address),
    String(String),
    Bool(bool),
    Bytes(Vec<u8>),
}

#[derive(Debug)]
pub struct Treasury {
    pub id: Address,
    pub treasury_caps: BTreeMap<TypeTag, TreasuryCap>,
    pub metadata_caps: BTreeMap<TypeTag, MetadataCap>,
}

#[derive(Debug)]
pub struct DepositRequestQueue {
    pub(super) id: Address,
    pub(super) requests: BTreeMap<Address, DepositRequest>,
}

impl DepositRequestQueue {
    pub fn id(&self) -> &Address {
        &self.id
    }

    pub fn requests(&self) -> &BTreeMap<Address, DepositRequest> {
        &self.requests
    }
}

#[derive(Debug)]
pub struct WithdrawalRequestQueue {
    pub(super) requests_id: Address,
    pub(super) requests: BTreeMap<Address, WithdrawalRequest>,
    pub(super) pending_withdrawals_id: Address,
    pub(super) pending_withdrawals: BTreeMap<Address, PendingWithdrawal>,
    pub(super) num_consumed_presigs: u64,
}

impl WithdrawalRequestQueue {
    pub fn requests_id(&self) -> &Address {
        &self.requests_id
    }

    pub fn requests(&self) -> &BTreeMap<Address, WithdrawalRequest> {
        &self.requests
    }

    pub fn pending_withdrawals_id(&self) -> &Address {
        &self.pending_withdrawals_id
    }

    pub fn pending_withdrawals(&self) -> &BTreeMap<Address, PendingWithdrawal> {
        &self.pending_withdrawals
    }

    pub fn num_consumed_presigs(&self) -> u64 {
        self.num_consumed_presigs
    }
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct WithdrawalRequest {
    pub id: Address,
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
    pub timestamp_ms: u64,
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
    pub approved: bool,
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct WithdrawalRequestInfo {
    pub id: Address,
    pub btc_amount: u64,
    pub bitcoin_address: Vec<u8>,
    pub timestamp_ms: u64,
    pub requester_address: Address,
    pub sui_tx_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct PendingWithdrawal {
    pub id: Address,
    pub txid: Address,
    pub requests: Vec<WithdrawalRequestInfo>,
    pub inputs: Vec<Utxo>,
    pub withdrawal_outputs: Vec<OutputUtxo>,
    pub change_output: Option<OutputUtxo>,
    pub timestamp_ms: u64,
    pub randomness: Vec<u8>,
    pub signatures: Option<Vec<Vec<u8>>>,
}

impl PendingWithdrawal {
    pub fn request_ids(&self) -> Vec<Address> {
        self.requests.iter().map(|r| r.id).collect()
    }

    pub fn all_outputs(&self) -> Vec<OutputUtxo> {
        let mut outputs = self.withdrawal_outputs.clone();
        if let Some(ref change) = self.change_output {
            outputs.push(change.clone());
        }
        outputs
    }
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct OutputUtxo {
    /// In satoshis
    pub amount: u64,
    pub bitcoin_address: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct DepositRequest {
    pub id: Address,
    pub utxo: Utxo,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, serde_derive::Serialize)]
pub struct Utxo {
    pub id: UtxoId,
    // In satoshis
    pub amount: u64,
    pub derivation_path: Option<Address>,
}

/// txid:vout
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde_derive::Serialize)]
pub struct UtxoId {
    // a 32 byte sha256 of the transaction
    pub txid: Address,
    // Out position of the UTXO
    pub vout: u32,
}

impl From<hashi_types::move_types::UtxoId> for UtxoId {
    fn from(id: hashi_types::move_types::UtxoId) -> Self {
        Self {
            txid: id.txid,
            vout: id.vout,
        }
    }
}

#[derive(Debug)]
pub struct UtxoPool {
    pub(super) active_utxos_id: Address,
    pub(super) active_utxos: BTreeMap<UtxoId, Utxo>,
    pub(super) spent_utxos_id: Address,
    pub(super) spent_utxos: BTreeMap<UtxoId, u64>,
}

impl UtxoPool {
    pub fn active_utxos_id(&self) -> &Address {
        &self.active_utxos_id
    }

    pub fn active_utxos(&self) -> &BTreeMap<UtxoId, Utxo> {
        &self.active_utxos
    }

    pub fn spent_utxos_id(&self) -> &Address {
        &self.spent_utxos_id
    }

    pub fn spent_utxos(&self) -> &BTreeMap<UtxoId, u64> {
        &self.spent_utxos
    }
}

#[derive(Debug)]
pub struct TreasuryCap {
    pub coin_type: TypeTag,
    pub id: Address,
    pub supply: u64,
}

impl TreasuryCap {
    pub fn try_from_contents(type_tag: &TypeTag, contents: &[u8]) -> Option<Self> {
        let TypeTag::Struct(struct_tag) = type_tag else {
            return None;
        };

        if struct_tag.address() == &Address::TWO
            && struct_tag.module() == "coin"
            && struct_tag.name() == "TreasuryCap"
            && let [coin_type] = struct_tag.type_params()
            && contents.len() == Address::LENGTH + std::mem::size_of::<u64>()
        {
            let id = Address::new((&contents[..Address::LENGTH]).try_into().unwrap());
            let supply = u64::from_le_bytes((&contents[Address::LENGTH..]).try_into().unwrap());
            Some(Self {
                coin_type: coin_type.to_owned(),
                id,
                supply,
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct MetadataCap {
    pub coin_type: TypeTag,
    pub id: Address,
}

impl MetadataCap {
    pub fn try_from_contents(type_tag: &TypeTag, contents: &[u8]) -> Option<Self> {
        let TypeTag::Struct(struct_tag) = type_tag else {
            return None;
        };

        if struct_tag.address() == &Address::TWO
            && struct_tag.module() == "coin_registry"
            && struct_tag.name() == "MetadataCap"
            && let [coin_type] = struct_tag.type_params()
            && contents.len() == Address::LENGTH
        {
            let id = Address::from_bytes(contents).unwrap();

            Some(Self {
                coin_type: coin_type.to_owned(),
                id,
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Coin {
    pub coin_type: TypeTag,
    pub id: Address,
    pub balance: u64,
}

impl Coin {
    pub fn try_from_contents(type_tag: &TypeTag, contents: &[u8]) -> Option<Self> {
        let TypeTag::Struct(struct_tag) = type_tag else {
            return None;
        };

        if struct_tag.address() == &Address::TWO
            && struct_tag.module() == "coin"
            && struct_tag.name() == "Coin"
            && let [coin_type] = struct_tag.type_params()
            && contents.len() == Address::LENGTH + std::mem::size_of::<u64>()
        {
            let id = Address::new((&contents[..Address::LENGTH]).try_into().unwrap());
            let balance = u64::from_le_bytes((&contents[Address::LENGTH..]).try_into().unwrap());
            Some(Self {
                coin_type: coin_type.to_owned(),
                id,
                balance,
            })
        } else {
            None
        }
    }
}
