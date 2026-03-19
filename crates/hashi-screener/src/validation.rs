// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use bitcoin::Address as BitcoinAddress;
use bitcoin::Txid;
use bitcoin::address::NetworkUnchecked;
use sui_sdk_types::Address as SuiAddress;
use sui_sdk_types::Digest;

use crate::error::HashiScreenerError;

pub fn validate_btc_tx_hash(hash: &str) -> Result<Txid, HashiScreenerError> {
    Txid::from_str(hash).map_err(|_| {
        HashiScreenerError::ValidationError(format!("invalid Bitcoin transaction hash: '{}'", hash))
    })
}

pub fn validate_btc_address(
    address: &str,
) -> Result<BitcoinAddress<NetworkUnchecked>, HashiScreenerError> {
    BitcoinAddress::from_str(address).map_err(|_| {
        HashiScreenerError::ValidationError(format!("invalid Bitcoin address: '{}'", address))
    })
}

pub fn validate_sui_address(address: &str) -> Result<SuiAddress, HashiScreenerError> {
    SuiAddress::from_str(address).map_err(|_| {
        HashiScreenerError::ValidationError(format!("invalid Sui address: '{}'", address))
    })
}

pub fn validate_sui_tx_hash(hash: &str) -> Result<Digest, HashiScreenerError> {
    Digest::from_str(hash).map_err(|_| {
        HashiScreenerError::ValidationError(format!("invalid Sui transaction hash: '{}'", hash))
    })
}
