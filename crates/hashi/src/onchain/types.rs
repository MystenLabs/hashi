#![allow(unused)] // TODO remove this

//! Usable definitions of the onchain state of hashi

use std::collections::BTreeMap;

use axum::http;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use sui_sdk_types::{Address, TypeTag};

use crate::{bls::BlsCommittee, grpc::Client};

#[derive(Debug)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub treasury: Treasury,
    pub deposit_queue: DepositRequestQueue,
    pub utxo_pool: UtxoPool,
    pub proposals: ProposalSet,
}

#[derive(Debug)]
pub struct CommitteeSet {
    /// Id of the `Bag` containing the validator info structs
    members_id: Address,
    members: BTreeMap<Address, MemberInfo>,
    tls_public_key_to_address: BTreeMap<[u8; 32], Address>,
    /// The current epoch.
    epoch: u64,
    /// Id of the `Bag` containing the committee's per epoch
    committees_id: Address,
    committees: BTreeMap<u64, BlsCommittee>,

    tls_private_key: Option<ed25519_dalek::SigningKey>,
    clients: BTreeMap<Address, Client>,
}

impl CommitteeSet {
    pub fn new(members_id: Address, committees_id: Address) -> Self {
        Self {
            members_id,
            members: BTreeMap::new(),
            tls_public_key_to_address: BTreeMap::new(),
            epoch: 0,
            committees_id,
            committees: BTreeMap::new(),
            tls_private_key: None,
            clients: BTreeMap::new(),
        }
    }

    pub fn members(&self) -> &BTreeMap<Address, MemberInfo> {
        &self.members
    }

    pub fn committees(&self) -> &BTreeMap<u64, BlsCommittee> {
        &self.committees
    }

    pub fn current_committee(&self) -> Option<&BlsCommittee> {
        self.committees().get(&self.epoch())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
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
                if let (Some(addr), Some(public_key)) =
                    (info.https_address(), info.tls_public_key())
                {
                    Some((info.validator_address, addr, public_key))
                } else {
                    None
                }
            })
            .filter_map(|(validator, https_address, tls_public_key)| {
                let tls_config = if let Some(tls_private_key) = &self.tls_private_key {
                    crate::tls::make_client_config_with_client_auth(tls_private_key, tls_public_key)
                } else {
                    crate::tls::make_client_config(tls_public_key)
                };
                let client = Client::new(https_address, tls_config)
                    .inspect_err(|e| tracing::debug!("unable to build client for {validator}: {e}"))
                    .ok()?;
                Some((validator, client))
            })
            .collect();
    }

    pub fn set_epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    pub fn set_committees(&mut self, committees: BTreeMap<u64, BlsCommittee>) -> &mut Self {
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

#[derive(Debug)]
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
    pub next_epoch_public_key: BLS12381PublicKey,

    /// The HTTPS network address where the instance of the `hashi` service for
    /// this validator can be reached.
    ///
    /// This HTTPS address can be rotated and any such updates will take effect
    /// immediately.
    pub https_address: Option<http::Uri>,

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
    pub next_epoch_encryption_public_key:
        Option<fastcrypto_tbls::ecies_v1::PublicKey<crate::dkg::EncryptionGroupElement>>,
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

    pub fn https_address(&self) -> Option<&http::Uri> {
        self.https_address.as_ref()
    }

    pub fn next_epoch_encryption_public_key(
        &self,
    ) -> Option<&fastcrypto_tbls::ecies_v1::PublicKey<crate::dkg::EncryptionGroupElement>> {
        self.next_epoch_encryption_public_key.as_ref()
    }
}

#[derive(Debug)]
pub struct ProposalSet {
    pub id: Address,
    pub size: u64,
    pub seq_num: u64,
}

#[derive(Debug)]
pub struct Config {
    pub config: BTreeMap<String, ConfigValue>,
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
    pub coins: BTreeMap<TypeTag, Coin>,
}

#[derive(Debug)]
pub struct DepositRequestQueue {
    pub(super) id: Address,
    pub(super) requests: BTreeMap<UtxoId, DepositRequest>,
}

impl DepositRequestQueue {
    pub fn id(&self) -> &Address {
        &self.id
    }

    pub fn requests(&self) -> &BTreeMap<UtxoId, DepositRequest> {
        &self.requests
    }
}

#[derive(Debug)]
pub struct DepositRequest {
    pub utxo: Utxo,
    pub timestamp_ms: u64,
}

#[derive(Debug)]
pub struct Utxo {
    pub id: UtxoId,
    // In satoshis
    pub amount: u64,
    pub derivation_path: Option<Address>,
}

/// txid:vout
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtxoId {
    // a 32 byte sha256 of the transaction
    pub txid: Address,
    // Out position of the UTXO
    pub vout: u32,
}

#[derive(Debug)]
pub struct UtxoPool {
    pub(super) id: Address,
    pub(super) utxos: BTreeMap<UtxoId, Utxo>,
}

impl UtxoPool {
    pub fn id(&self) -> &Address {
        &self.id
    }

    pub fn utxos(&self) -> &BTreeMap<UtxoId, Utxo> {
        &self.utxos
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
