#![allow(unused)] // TODO remove this

//! Usable definitions of the onchain state of hashi

use std::collections::BTreeMap;

use crate::dkg::types::{AddressToPartyId, DkgConfig, DkgError};
use axum::http;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use fastcrypto_tbls::nodes::{Node, Nodes};
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

impl CommitteeSet {
    pub fn build_dkg_config(&self) -> Result<DkgConfig, DkgError> {
        use itertools::Itertools;

        let committee = self
            .committees
            .get(&self.epoch)
            .ok_or_else(|| DkgError::CryptoError("no committee for current epoch".into()))?;
        let members_with_weight: Vec<_> = committee
            .members()
            .iter()
            .map(|member| {
                let addr = member.validator_address();
                let member_info = self.members.get(&addr).ok_or_else(|| {
                    DkgError::CryptoError(format!("no member info for validator {}", addr))
                })?;
                Ok((addr, member.weight(), member_info))
            })
            .collect::<Result<Vec<_>, DkgError>>()?
            .into_iter()
            .sorted_by_key(|(addr, _, _)| *addr)
            .collect();
        let mut nodes_vec = Vec::with_capacity(members_with_weight.len());
        let mut address_to_party_id = AddressToPartyId::new();
        for (id, (validator_address, weight, member_info)) in members_with_weight.iter().enumerate()
        {
            let encryption_pk = member_info.encryption_public_key.as_ref().ok_or_else(|| {
                DkgError::CryptoError(format!(
                    "validator {} has no encryption public key",
                    validator_address
                ))
            })?;
            nodes_vec.push(Node {
                id: id as u16,
                pk: encryption_pk.clone(),
                weight: *weight as u16,
            });
            address_to_party_id.insert(*validator_address, id as u16);
        }
        let nodes = Nodes::new(nodes_vec).map_err(|e| DkgError::CryptoError(e.to_string()))?;
        let total_weight = nodes.total_weight();
        let max_faulty = (total_weight - 1) / 3;
        let threshold = max_faulty + 1;
        DkgConfig::new(
            self.epoch,
            nodes,
            address_to_party_id,
            threshold,
            max_faulty,
        )
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
    /// RistrettoPoint) for MPC ECIES.
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    pub encryption_public_key:
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

    pub fn encryption_public_key(
        &self,
    ) -> Option<&fastcrypto_tbls::ecies_v1::PublicKey<crate::dkg::EncryptionGroupElement>> {
        self.encryption_public_key.as_ref()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{BlsCommittee, BlsCommitteeMember};
    use crate::dkg::EncryptionGroupElement;
    use fastcrypto::bls12381::min_pk::BLS12381KeyPair;
    use fastcrypto::traits::KeyPair;
    use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};

    fn create_test_member_info(id: u8) -> MemberInfo {
        let encryption_private_key =
            PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());
        let encryption_public_key = PublicKey::from_private_key(&encryption_private_key);
        let bls_keypair = BLS12381KeyPair::generate(&mut rand::thread_rng());

        MemberInfo {
            validator_address: Address::new([id; 32]),
            operator_address: Address::new([id; 32]),
            next_epoch_public_key: bls_keypair.public().clone(),
            https_address: None,
            tls_public_key: None,
            encryption_public_key: Some(encryption_public_key),
        }
    }

    fn create_test_committee_member(id: u8, weight: u64) -> BlsCommitteeMember {
        let bls_keypair = BLS12381KeyPair::generate(&mut rand::thread_rng());
        BlsCommitteeMember::new(Address::new([id; 32]), bls_keypair.public().clone(), weight)
    }

    fn create_test_committee_set(member_weights: &[(u8, u64)], epoch: u64) -> CommitteeSet {
        let members: BTreeMap<Address, MemberInfo> = member_weights
            .iter()
            .map(|(id, _)| {
                let addr = Address::new([*id; 32]);
                (addr, create_test_member_info(*id))
            })
            .collect();

        let committee_members: Vec<BlsCommitteeMember> = member_weights
            .iter()
            .map(|(id, weight)| create_test_committee_member(*id, *weight))
            .collect();

        let committee = BlsCommittee::new(committee_members, epoch);
        let mut committees = BTreeMap::new();
        committees.insert(epoch, committee);

        CommitteeSet {
            members_id: Address::new([0; 32]),
            members,
            epoch,
            committees_id: Address::new([1; 32]),
            committees,
        }
    }

    #[test]
    fn test_build_dkg_config_basic() {
        let committee_set = create_test_committee_set(
            &[(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1)],
            42,
        );
        let config = committee_set.build_dkg_config().unwrap();

        assert_eq!(config.epoch, 42);
        assert_eq!(config.total_weight(), 7);
        // max_faulty = (7-1)/3 = 2, threshold = 2+1 = 3
        assert_eq!(config.max_faulty, 2);
        assert_eq!(config.threshold, 3);
    }

    #[test]
    fn test_build_dkg_config_deterministic_party_ids() {
        // Create members in reverse order
        let committee_set = create_test_committee_set(&[(3, 1), (2, 1), (1, 1), (0, 1)], 1);
        let config = committee_set.build_dkg_config().unwrap();

        // Party IDs should be assigned by sorted address order
        assert_eq!(
            config.address_to_party_id.get(&Address::new([0; 32])),
            Some(&0)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([1; 32])),
            Some(&1)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([2; 32])),
            Some(&2)
        );
        assert_eq!(
            config.address_to_party_id.get(&Address::new([3; 32])),
            Some(&3)
        );
    }

    #[test]
    fn test_build_dkg_config_weighted() {
        let committee_set = create_test_committee_set(&[(0, 3), (1, 2), (2, 2), (3, 1), (4, 1)], 1);
        let config = committee_set.build_dkg_config().unwrap();

        assert_eq!(config.total_weight(), 9);
        // max_faulty = (9-1)/3 = 2, threshold = 2+1 = 3
        assert_eq!(config.max_faulty, 2);
        assert_eq!(config.threshold, 3);
    }

    #[test]
    fn test_build_dkg_config_missing_encryption_key() {
        let mut committee_set = create_test_committee_set(&[(0, 1), (1, 1), (2, 1), (3, 1)], 1);
        // Remove encryption key from one member
        committee_set
            .members
            .get_mut(&Address::new([0; 32]))
            .unwrap()
            .encryption_public_key = None;

        let result = committee_set.build_dkg_config();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no encryption public key"));
    }

    #[test]
    fn test_build_dkg_config_no_committee_for_epoch() {
        let mut committee_set = create_test_committee_set(&[(0, 1), (1, 1), (2, 1), (3, 1)], 1);
        // Change epoch to one without a committee
        committee_set.epoch = 999;

        let result = committee_set.build_dkg_config();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no committee for current epoch"));
    }
}
