// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin utilities shared between Hashi and Guardian. `utxo` holds the UTXO /
//! transaction types and signing; `taproot` holds the 2-of-2 descriptor, address,
//! and child-key derivation. The shared secp context and derivation-path alias
//! live here.

pub mod taproot;
pub mod utxo;

pub use taproot::*;
pub use utxo::*;

use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use std::sync::LazyLock;

pub static BTC_LIB: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// A Hashi key-derivation path: the 32-byte Sui address of the deposit
/// recipient. Converted to fastcrypto's raw `[u8; 32]` form only at the
/// `derive_verifying_key` boundary (see `taproot::derive_hashi_child_pubkey`).
pub type DerivationPath = sui_sdk_types::Address;
