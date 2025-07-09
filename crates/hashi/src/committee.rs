use sui_sdk_types::Address;
use sui_sdk_types::Ed25519PublicKey;

use crate::bls::BlsCommittee;

#[allow(unused)]
pub struct Committee {
    members: Vec<CommitteeMemberInfo>,
    active_committee: BlsCommittee,
}

pub struct CommitteeMemberInfo {
    validator_address: Address,
    operator_address: Address,

    next_epoch_public_key: Ed25519PublicKey,
    https_address: String,
    tls_public_key: Ed25519PublicKey,
}

impl CommitteeMemberInfo {
    pub fn validator_address(&self) -> &Address {
        &self.validator_address
    }

    pub fn operator_address(&self) -> &Address {
        &self.operator_address
    }

    pub fn next_epoch_public_key(&self) -> &Ed25519PublicKey {
        &self.next_epoch_public_key
    }

    pub fn tls_public_key(&self) -> &Ed25519PublicKey {
        &self.tls_public_key
    }

    pub fn https_address(&self) -> &str {
        &self.https_address
    }
}
