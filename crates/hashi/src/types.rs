//! Shared types used across multiple modules

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ValidatorAddress(pub [u8; 32]);

impl fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}
