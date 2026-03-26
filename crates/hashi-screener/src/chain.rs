// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::HashiScreenerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainName {
    Bitcoin,
    Sui,
}

impl ChainName {
    /// Parse from a CAIP-2 chain ID string (e.g. "bip122:000…" or "sui:35834a8a").
    /// Returns the chain name and the suffix.
    pub fn from_caip2(caip2_chain_id: &str) -> Result<(Self, &str), HashiScreenerError> {
        if let Some(suffix) = caip2_chain_id.strip_prefix("bip122:") {
            Ok((Self::Bitcoin, suffix))
        } else if let Some(suffix) = caip2_chain_id.strip_prefix("sui:") {
            Ok((Self::Sui, suffix))
        } else {
            Err(HashiScreenerError::ValidationError(format!(
                "unsupported CAIP-2 chain ID: '{}'",
                caip2_chain_id
            )))
        }
    }

    /// MerkleScience blockchain identifier for this chain.
    /// See: <https://docs.merklescience.com/reference/currencies>
    pub fn merkle_blockchain_id(self) -> &'static str {
        match self {
            Self::Bitcoin => "0",
            Self::Sui => "84",
        }
    }
}

/// Network environment, derived from the CAIP-2 suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Mainnet,
    Testnet,
    Regtest,
}

impl Environment {
    pub fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }
}

/// Map a CAIP-2 suffix to an [`Environment`] for a given chain.
pub fn lookup_environment(chain: ChainName, suffix: &str) -> Option<Environment> {
    match (chain, suffix) {
        // Bitcoin mainnet — first 16 bytes of genesis block hash
        (ChainName::Bitcoin, "000000000019d6689c085ae165831e93") => Some(Environment::Mainnet),
        // Bitcoin testnet3
        (ChainName::Bitcoin, "000000000933ea01ad0ee984209779ba") => Some(Environment::Testnet),
        // Bitcoin signet
        (ChainName::Bitcoin, "00000008819873e925422c1ff0f99f7c") => Some(Environment::Testnet),
        // Bitcoin regtest
        (ChainName::Bitcoin, "0f9188f13cb7b2c71f2a335e3a4fc328") => Some(Environment::Regtest),
        // Sui mainnet — first 4 bytes of genesis checkpoint digest
        (ChainName::Sui, "35834a8a") => Some(Environment::Mainnet),
        // Sui testnet
        (ChainName::Sui, "4c78adac") => Some(Environment::Testnet),
        _ => None,
    }
}

/// known CAIP-2 chain IDs for use in tests and configuration.
pub mod caip2 {
    pub const BTC_MAINNET: &str = "bip122:000000000019d6689c085ae165831e93";
    pub const BTC_TESTNET3: &str = "bip122:000000000933ea01ad0ee984209779ba";
    pub const BTC_SIGNET: &str = "bip122:00000008819873e925422c1ff0f99f7c";
    pub const BTC_REGTEST: &str = "bip122:0f9188f13cb7b2c71f2a335e3a4fc328";

    pub const SUI_MAINNET: &str = "sui:35834a8a";
    pub const SUI_TESTNET: &str = "sui:4c78adac";
}
