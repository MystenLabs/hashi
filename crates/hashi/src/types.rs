//! Shared types used across multiple modules

use serde::{Deserialize, Serialize};
use std::fmt;
use sui_sdk_types::Address;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ValidatorAddress(pub [u8; 32]);

impl fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl From<ValidatorAddress> for Address {
    fn from(value: ValidatorAddress) -> Self {
        Address::new(value.0)
    }
}

impl From<&ValidatorAddress> for Address {
    fn from(value: &ValidatorAddress) -> Self {
        Address::new(value.0)
    }
}

impl From<Address> for ValidatorAddress {
    fn from(value: Address) -> Self {
        ValidatorAddress(value.into_inner())
    }
}
