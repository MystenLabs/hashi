// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareCommitments;
use hashi_types::guardian::ShareID;
use hashi_types::guardian::proto_conversions::pb_share_commitments_to_domain;
use hashi_types::move_types::Committee as CommitteeRepr;
use hashi_types::proto as pb;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use serde::Deserialize;
use std::num::NonZeroU16;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct GuardianConfig {
    pub bucket_info: S3BucketInfo,
    pub share_commitments: ShareCommitments,
}

impl GuardianConfig {
    fn from_guardian_info(info: &GuardianInfo) -> anyhow::Result<Self> {
        let bucket_info = info.bucket_info.clone().ok_or_else(|| {
            anyhow::anyhow!("guardian info missing bucket_info; operator_init may be incomplete")
        })?;
        // TODO: also verify num_shares and threshold against KP-side expected values.
        let share_commitments = info
            .secret_sharing_instance
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "guardian info missing secret_sharing_instance; operator_init may be incomplete"
                )
            })?
            .commitments()
            .clone();
        Ok(Self {
            bucket_info,
            share_commitments,
        })
    }

    pub fn ensure_matches_info(&self, info: &GuardianInfo) -> anyhow::Result<()> {
        let actual = Self::from_guardian_info(info)?;
        anyhow::ensure!(
            actual == *self,
            "guardian config mismatch: expected {:?}, got {:?}",
            self,
            actual
        );
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct ProvisionerConfig {
    /// The Key Provisioner's secret share.
    pub share: ShareInput,
    /// Relay endpoint the KP's encrypted share is forwarded to. The relay
    /// collects T-of-N shares before submitting them to the guardian.
    pub relay_endpoint: Option<String>,

    /// Config
    pub s3: S3Config,
    pub share_commitments: Vec<ShareCommitmentInput>,

    /// Expected WithdrawModeState (operator-supplied; the KP recomputes its digest)
    // Current Hashi committee
    pub hashi_committee: CommitteeRepr,
    // Limiter config
    pub limiter_config: LimiterConfig,
    /// MPC committee `G` (on-chain `CommitteeSet.mpc_public_key`) as hex of `bcs(G)`;
    /// the derivation master (NOT the guardian's own key). Must match operator init.
    pub hashi_btc_master_pubkey_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShareCommitmentInput {
    pub id: u16,
    pub digest_hex: String,
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

    pub fn expected_guardian_config(&self) -> anyhow::Result<GuardianConfig> {
        let pb_commitments = self
            .share_commitments
            .iter()
            .map(ShareCommitmentInput::to_pb)
            .collect::<Vec<_>>();

        // Domain validation checks
        let share_commitments =
            pb_share_commitments_to_domain(&pb_commitments).map_err(|e| anyhow::anyhow!(e))?;

        Ok(GuardianConfig {
            bucket_info: self.s3.bucket_info.clone(),
            share_commitments,
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

impl ShareCommitmentInput {
    fn to_pb(&self) -> pb::GuardianShareCommitment {
        pb::GuardianShareCommitment {
            id: Some(pb::GuardianShareId {
                id: Some(self.id.into()),
            }),
            digest_hex: Some(self.digest_hex.clone()),
        }
    }
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
