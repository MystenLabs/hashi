// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin primitives shared by Hashi and Guardian. `utxo` holds the UTXO /
//! transaction types and signing; `taproot` holds the 2-of-2 descriptor, address,
//! and child-key derivation. Shared address/weight helpers, secp context, and
//! derivation-path alias live here.

pub mod taproot;
pub mod utxo;

pub use bitcoin::Address as BitcoinAddress;
pub use bitcoin::secp256k1::Keypair as BitcoinKeypair;
pub use bitcoin::secp256k1::XOnlyPublicKey as BitcoinPubkey;
pub use bitcoin::taproot::Signature as BitcoinSignature;
pub use fastcrypto_tbls::threshold_schnorr::G as HashiMasterG;
pub use taproot::taproot_address;
pub use taproot::taproot_script_spend_sighashes;
pub use taproot::taproot_witness_artifacts;
pub use utxo::ExternalOutputUTXOWire;
pub use utxo::InputUTXO;
pub use utxo::InternalOutputUTXO;
pub use utxo::OutputUTXOWire;
pub use utxo::TxUTXOs;
pub use utxo::TxUTXOsWire;
pub use utxo::construct_tx;
pub use utxo::sign_btc_tx;

use anyhow::anyhow;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use std::sync::LazyLock;

pub static BTC_LIB: LazyLock<Secp256k1<bitcoin::secp256k1::All>> = LazyLock::new(Secp256k1::new);

/// A Hashi key-derivation path: the 32-byte Sui address of the deposit
/// recipient. Converted to fastcrypto's raw `[u8; 32]` form only at the
/// `derive_verifying_key` boundary in `taproot`.
pub type DerivationPath = sui_sdk_types::Address;

pub fn witness_program_from_address(address: &BitcoinAddress) -> anyhow::Result<Vec<u8>> {
    let script = address.script_pubkey();
    let bytes = script.as_bytes();
    match bytes {
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => Ok(rest.to_vec()),
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => Ok(rest.to_vec()),
        _ => anyhow::bail!("Unsupported script pubkey for withdrawal output: {script}"),
    }
}

/// Convert raw witness program bytes to a `ScriptBuf`.
/// 32-byte addresses are P2TR (witness v1), 20-byte addresses are P2WPKH (witness v0).
pub fn script_pubkey_from_witness_program(address_bytes: &[u8]) -> anyhow::Result<ScriptBuf> {
    let version = match address_bytes.len() {
        32 => WitnessVersion::V1,
        20 => WitnessVersion::V0,
        len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
    };
    let program = WitnessProgram::new(version, address_bytes)
        .map_err(|e| anyhow!("Invalid witness program: {e}"))?;
    Ok(ScriptBuf::new_witness_program(&program))
}

/// Convert raw witness program bytes to a human-readable Bitcoin address string.
pub fn address_string_from_witness_program(
    address_bytes: &[u8],
    network: Network,
) -> anyhow::Result<String> {
    let script = script_pubkey_from_witness_program(address_bytes)?;
    let address = BitcoinAddress::from_script(&script, network)
        .map_err(|e| anyhow!("Failed to convert script to address: {e}"))?;
    Ok(address.to_string())
}

/// Full input weight (WU) for a 2-of-2 taproot script-path spend.
/// TXIN_BASE_WEIGHT (164 WU) + satisfaction (234 WU) = 398 WU (100 vB).
pub const SCRIPT_PATH_2OF2_TXIN_WEIGHT: u64 = 164 + 234;

/// Non-witness fixed overhead for a segwit transaction:
/// nVersion(4x4) + nLockTime(4x4) = 32 WU, plus the segwit marker/flag (2 WU).
pub const TX_FIXED_WEIGHT_WU: u64 = 34;

/// P2TR output weight: TXOUT_BASE(36) + OP_1 OP_PUSHBYTES_32 <32 bytes>(136) = 172 WU.
pub const P2TR_OUTPUT_WEIGHT_WU: u64 = 172;

/// P2WPKH output weight: TXOUT_BASE(36) + OP_0 OP_PUSHBYTES_20 <20 bytes>(88) = 124 WU.
pub const P2WPKH_OUTPUT_WEIGHT_WU: u64 = 124;

pub fn output_weight_for_witness_program(bitcoin_address: &[u8]) -> anyhow::Result<u64> {
    match bitcoin_address.len() {
        32 => Ok(P2TR_OUTPUT_WEIGHT_WU),
        20 => Ok(P2WPKH_OUTPUT_WEIGHT_WU),
        len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
    }
}

/// Deterministic Bitcoin keypair helper for tests.
pub fn create_btc_keypair_for_test(sk: &[u8; 32]) -> BitcoinKeypair {
    let secret_key = SecretKey::from_slice(sk).expect("valid secret key");
    BitcoinKeypair::from_secret_key(&BTC_LIB, &secret_key)
}

/// Convert a bitcoin-lib x-only key into the even-y `G` point for tests.
///
/// The bitcoin-lib `Keypair` always signs against the even-y projection of its
/// master pubkey, so tests that derive from a keypair need the matching `G`.
pub fn hashi_master_g_from_btc_xonly_for_test(pubkey: &BitcoinPubkey) -> HashiMasterG {
    HashiMasterG::with_even_y_from_x_be_bytes(&pubkey.serialize()).expect("valid x coordinate")
}
