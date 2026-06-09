// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareID;
use hashi_types::move_types::Committee as CommitteeRepr;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use serde::Deserialize;
use std::num::NonZeroU16;
use std::path::Path;

#[derive(Deserialize)]
pub struct ProvisionerConfig {
    /// The Key Provisioner's secret share.
    pub share: ShareInput,
    /// Relay endpoint the KP's encrypted share is forwarded to. The relay
    /// collects T-of-N shares before submitting them to the guardian.
    pub relay_endpoint: Option<String>,

    /// Config
    pub s3: S3Config,

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

    /// Expected enclave-image measurement: PCR0 as hex, pinned against every
    /// session's attestation. Required (a value is needed even in non-Nitro dev,
    /// where verification is a no-op).
    pub expected_pcr0: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShareInput {
    pub id: u16,
    pub value_hex: String,
}

impl ProvisionerConfig {
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

    /// The expected enclave measurement, decoded from `expected_pcr0`.
    pub fn build_pcrs(&self) -> anyhow::Result<BuildPcrs> {
        let pcr0 = hex::decode(self.expected_pcr0.trim_start_matches("0x"))
            .context("expected_pcr0 is not valid hex")?;
        Ok(BuildPcrs::new(pcr0))
    }
}

/// Decode the MPC committee verifying key `G` from hex of its `bcs(G)` encoding
/// (the same `bcs(G)` `Hashi::onchain_verifying_key_g` reads from chain).
fn decode_master_g_hex(hex_str: &str) -> anyhow::Result<HashiMasterG> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("hashi_btc_master_pubkey_hex is not valid hex")?;
    bcs::from_bytes(&bytes).context("decode MPC verifying key G from bcs(G)")
}

impl ShareInput {
    pub fn to_domain(&self) -> anyhow::Result<Share> {
        let id =
            NonZeroU16::new(self.id).ok_or_else(|| anyhow::anyhow!("share id must be non-zero"))?;
        let bytes = hex::decode(&self.value_hex)
            .with_context(|| format!("invalid share value hex for id={}", self.id))?;
        let scalar_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("share value must be 32 bytes"))?;
        let scalar = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(scalar_bytes)))
            .ok_or_else(|| anyhow::anyhow!("invalid scalar in share value"))?;
        Ok(Share {
            id: ShareID::from(id),
            value: scalar,
        })
    }
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
