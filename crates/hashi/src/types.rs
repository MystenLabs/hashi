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

impl Into<Address> for &ValidatorAddress {
    fn into(self) -> Address {
        Address::new(self.0)
    }
}
