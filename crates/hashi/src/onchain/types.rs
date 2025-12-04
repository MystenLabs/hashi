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
    pub members_id: Address,
    pub members: BTreeMap<Address, MemberInfo>,
    /// The current epoch.
    pub epoch: u64,
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
}

#[derive(Debug)]
pub struct Config {
    pub config: BTreeMap<String, CoinfigValue>,
}

#[derive(Debug)]
pub enum CoinfigValue {
    U64(u64),
    Address(Address),
    String(String),
    Bool(bool),
    Bytes(Vec<u8>),
}

#[derive(Debug)]
pub struct Treasury {
    pub id: Address,
    //TODO have maps to treasury and metadata
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

#[derive(Debug)]
pub struct MetadataCap {
    pub coin_type: TypeTag,
    pub id: Address,
}

#[derive(Debug)]
pub struct Coin {
    pub coin_type: TypeTag,
    pub id: Address,
    pub balance: u64,
}
