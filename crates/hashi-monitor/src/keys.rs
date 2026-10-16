// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The bridge keys and the addresses they derive.
//!
//! Why it exists: every bridge address is a taproot address derived from
//! two fixed keys and a derivation path. The monitor reads the keys once
//! from the guardian's records and derives addresses to check what Sui
//! and the guardian claim.

use bitcoin::Network;
use bitcoin::ScriptBuf;
use hashi_types::bitcoin::BitcoinAddress;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::DerivationPath;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::bitcoin::taproot_address;

/// The two fixed keys that every bridge address derives from.
#[derive(Clone)]
pub struct HashiBTCKeys {
    guardian_btc_pubkey: BitcoinPubkey,
    mpc_master_g: HashiMasterG,
    network: Network,
}

impl HashiBTCKeys {
    pub fn new(
        guardian_btc_pubkey: BitcoinPubkey,
        mpc_master_g: HashiMasterG,
        network: Network,
    ) -> Self {
        Self {
            guardian_btc_pubkey,
            mpc_master_g,
            network,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The bridge address for `derivation_path`. A missing path is the zero
    /// path, as in Move.
    pub fn address(&self, derivation_path: Option<&DerivationPath>) -> BitcoinAddress {
        taproot_address(
            &self.guardian_btc_pubkey,
            &self.mpc_master_g,
            derivation_path.unwrap_or(&DerivationPath::ZERO),
            self.network,
        )
    }

    /// The script of the bridge address for `derivation_path`.
    pub fn script_pubkey(&self, derivation_path: Option<&DerivationPath>) -> ScriptBuf {
        self.address(derivation_path).script_pubkey()
    }
}
