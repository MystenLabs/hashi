// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A newtype for Bitcoin transaction IDs that is BCS-compatible with
//! `sui_sdk_types::Address` but uses Bitcoin's reversed-hex display
//! convention.
//!
//! On the Move side, bitcoin txids are stored as `address` (a
//! fixed-width 32-byte value). `sui_sdk_types::Address` serializes
//! identically under BCS (32 raw bytes, no length prefix), so this
//! wrapper can be deserialized from the same on-chain bytes. The
//! difference is purely in the human-readable representation:
//! `Address` displays as `0x<hex>` while `BitcoinTxid` displays in
//! the standard Bitcoin reversed-hex format.

use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use sui_sdk_types::Address;

/// A Bitcoin transaction ID.
///
/// Internally stores the same 32 bytes as [`Address`] (the raw
/// double-SHA256 hash in internal byte order). Serializes identically
/// to `Address` under BCS, but displays and parses using Bitcoin's
/// standard reversed-hex convention.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTxid([u8; 32]);

impl BitcoinTxid {
    /// The all-zeros txid.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a new `BitcoinTxid` from raw bytes (internal byte
    /// order, same as `Address`).
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes in internal byte order.
    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }

    /// Returns a reference to the underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constructs a `BitcoinTxid` by parsing raw bytes as a
    /// `bitcoin::Txid`. This accepts the bytes in the same order as
    /// `bitcoin::Txid::from_slice`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, bitcoin::hashes::FromSliceError> {
        bitcoin::Txid::from_slice(bytes).map(Self::from)
    }
}

// -- Conversions to/from sui_sdk_types::Address --

impl From<Address> for BitcoinTxid {
    fn from(addr: Address) -> Self {
        Self(addr.into_inner())
    }
}

impl From<BitcoinTxid> for Address {
    fn from(txid: BitcoinTxid) -> Self {
        Address::new(txid.0)
    }
}

impl From<BitcoinTxid> for [u8; 32] {
    fn from(txid: BitcoinTxid) -> Self {
        txid.0
    }
}

// -- Conversions to/from bitcoin::Txid --

impl From<bitcoin::Txid> for BitcoinTxid {
    fn from(txid: bitcoin::Txid) -> Self {
        Self(txid.to_byte_array())
    }
}

impl From<BitcoinTxid> for bitcoin::Txid {
    fn from(txid: BitcoinTxid) -> Self {
        bitcoin::Txid::from_byte_array(txid.0)
    }
}

// -- Display / FromStr using Bitcoin's reversed-hex convention --

impl fmt::Display for BitcoinTxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let txid = bitcoin::Txid::from_byte_array(self.0);
        fmt::Display::fmt(&txid, f)
    }
}

impl fmt::Debug for BitcoinTxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitcoinTxid({})", self)
    }
}

impl FromStr for BitcoinTxid {
    type Err = bitcoin::hashes::hex::HexToArrayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bitcoin::Txid::from_str(s).map(Self::from)
    }
}

// -- Serde: delegate to [u8; 32] so BCS layout matches Address --

impl serde::Serialize for BitcoinTxid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for BitcoinTxid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genesis block coinbase txid, a well-known reference value.
    const GENESIS_TXID_HEX: &str =
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2fc77ab847d46d3298b06f";

    /// The internal byte representation of the genesis coinbase txid.
    /// This is the reversed form of the display hex.
    fn genesis_internal_bytes() -> [u8; 32] {
        let txid: bitcoin::Txid = GENESIS_TXID_HEX.parse().unwrap();
        txid.to_byte_array()
    }

    #[test]
    fn display_matches_bitcoin_convention() {
        let txid = BitcoinTxid::new(genesis_internal_bytes());
        assert_eq!(txid.to_string(), GENESIS_TXID_HEX);
    }

    #[test]
    fn from_str_roundtrip() {
        let txid: BitcoinTxid = GENESIS_TXID_HEX.parse().unwrap();
        assert_eq!(txid.to_string(), GENESIS_TXID_HEX);
        assert_eq!(txid.as_bytes(), &genesis_internal_bytes());
    }

    #[test]
    fn from_str_invalid() {
        assert!("not_a_txid".parse::<BitcoinTxid>().is_err());
        // Too short.
        assert!("abcd".parse::<BitcoinTxid>().is_err());
    }

    #[test]
    fn address_roundtrip() {
        let original = BitcoinTxid::new(genesis_internal_bytes());
        let addr: Address = original.into();
        let recovered = BitcoinTxid::from(addr);
        assert_eq!(original, recovered);
    }

    #[test]
    fn bitcoin_txid_roundtrip() {
        let btc_txid: bitcoin::Txid = GENESIS_TXID_HEX.parse().unwrap();
        let ours = BitcoinTxid::from(btc_txid);
        let back: bitcoin::Txid = ours.into();
        assert_eq!(btc_txid, back);
    }

    #[test]
    fn bcs_matches_address_layout() {
        let bytes = genesis_internal_bytes();
        let txid = BitcoinTxid::new(bytes);
        let addr = Address::new(bytes);

        let txid_bcs = bcs::to_bytes(&txid).unwrap();
        let addr_bcs = bcs::to_bytes(&addr).unwrap();
        assert_eq!(txid_bcs, addr_bcs, "BCS encoding must match Address");

        // Deserialize back from the same bytes.
        let recovered: BitcoinTxid = bcs::from_bytes(&addr_bcs).unwrap();
        assert_eq!(recovered, txid);
    }

    #[test]
    fn from_slice_valid() {
        let bytes = genesis_internal_bytes();
        let txid = BitcoinTxid::from_slice(&bytes).unwrap();
        assert_eq!(txid.to_string(), GENESIS_TXID_HEX);
    }

    #[test]
    fn from_slice_invalid_length() {
        assert!(BitcoinTxid::from_slice(&[0u8; 16]).is_err());
    }

    #[test]
    fn zero() {
        let z = BitcoinTxid::ZERO;
        assert_eq!(z.as_bytes(), &[0u8; 32]);
        assert_eq!(
            z.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn debug_format() {
        let txid = BitcoinTxid::ZERO;
        let debug = format!("{:?}", txid);
        assert!(debug.starts_with("BitcoinTxid("));
        assert!(debug.ends_with(')'));
    }

    #[test]
    fn ord_matches_byte_order() {
        let a = BitcoinTxid::new([0; 32]);
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 1;
        let b = BitcoinTxid::new(b_bytes);
        assert!(a < b);
    }
}
