#![allow(unused)] // TODO remove this

//! Usable definitions of the onchain state of hashi

use std::collections::BTreeMap;

use axum::http;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use sui_sdk_types::{Address, Ed25519PublicKey, TypeTag};

use crate::bls::BlsCommittee;

#[derive(Debug)]
pub struct Hashi {
    pub id: Address,
    pub committees: CommitteeSet,
    pub config: Config,
    pub treasury: Treasury,
    pub deposit_queue: DepositRequestQueue,
    pub utxo_pool: UtxoPool,
}

#[derive(Debug)]
pub struct CommitteeSet {
    /// Id of the `Bag` containing the validator info structs
    pub members_id: Address,
    pub members: BTreeMap<Address, MemberInfo>,
    /// The current epoch.
    pub epoch: u64,
    /// Id of the `Bag` containing the committee's per epoch
    pub committees_id: Address,
    pub committees: BTreeMap<u64, BlsCommittee>,
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
