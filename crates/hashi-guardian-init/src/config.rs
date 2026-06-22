// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::LimiterConfig;
use hashi_types::move_types::Committee as CommitteeRepr;
use serde::Deserialize;
use std::path::Path;
use std::path::PathBuf;

use crate::kp_roster::KpRosterConfig;

#[derive(Deserialize)]
pub struct ProvisionConfig {
    #[serde(flatten)]
    pub common: KpRosterConfig,
    /// Path to this KP's armored OpenPGP public cert (the one they exported
    /// from their yubikey and gave to the operator at ceremony time). Used to
    /// find this KP's share in `shares/` by fingerprint, and to confirm the
    /// ciphertext is genuinely encrypted to this cert before decrypting.
    pub kp_pgp_cert_path: PathBuf,
    /// Optional gpg homedir for the yubikey-backed agent. Defaults to gpg's
    /// default (`~/.gnupg`) when unset.
    pub gpg_homedir: Option<PathBuf>,
    /// Relay endpoint the KP's encrypted share is submitted to. The relay
    /// collects T-of-N shares before forwarding them to the guardian in one
    /// `ProvisionerInit` call.
    pub relay_endpoint: String,

    /// Genesis committee — required only at genesis, when `committee-update/` is
    /// still empty; omit it once any update has been logged (it's scraped from
    /// there after). Stands in for the authoritative on-chain `CommitteeSet`
    /// until the tool reads chain directly. Validated via the `state_hash` match.
    pub hashi_committee_genesis: Option<CommitteeRepr>,
    // Limiter config
    pub limiter_config: LimiterConfig,
    /// MPC committee `G` (on-chain `CommitteeSet.mpc_public_key`) as hex of `bcs(G)`;
    /// the derivation master (NOT the guardian's own key). Must match operator init.
    pub hashi_btc_master_pubkey_hex: String,
}

impl ProvisionConfig {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path).with_context(|| {
            format!(
                "failed to read provisioner-init config at {}",
                path.display()
            )
        })?;
        serde_yaml::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse provisioner-init yaml at {}",
                path.display()
            )
        })
    }

    /// The MPC committee verifying key `G`, decoded from `hashi_btc_master_pubkey_hex`.
    pub fn mpc_master_g(&self) -> anyhow::Result<HashiMasterG> {
        decode_master_g_hex(&self.hashi_btc_master_pubkey_hex)
    }
}

/// Decode the MPC committee verifying key `G` from hex of its `bcs(G)` encoding
/// (the same `bcs(G)` `Hashi::onchain_verifying_key_g` reads from chain).
fn decode_master_g_hex(hex_str: &str) -> anyhow::Result<HashiMasterG> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("hashi_btc_master_pubkey_hex is not valid hex")?;
    bcs::from_bytes(&bytes).context("decode MPC verifying key G from bcs(G)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_master_g_hex_accepts_bcs_g_and_rejects_garbage() {
        // hex of a real on-chain CommitteeSet.mpc_public_key (bcs(G), devnet).
        let g_hex = "a6adc1f72da0e65df2dfb17820fe6dc26d42a84f5738a8b7cb1fa745626f818c00";
        decode_master_g_hex(g_hex).expect("valid bcs(G) decodes");
        assert!(decode_master_g_hex("nothex").is_err());
        assert!(decode_master_g_hex("0011").is_err());
    }
}
