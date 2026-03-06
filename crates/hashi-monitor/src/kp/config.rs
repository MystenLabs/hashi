use anyhow::Context;
use hashi_types::guardian::BitcoinPubkey;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareCommitments;
use hashi_types::guardian::ShareID;
use hashi_types::guardian::WithdrawalConfig;
use hashi_types::guardian::enclave_state::CommitteeStoreRepr;
use hashi_types::guardian::proto_conversions::pb_share_commitments_to_domain;
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
        let share_commitments = info.share_commitments.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "guardian info missing share_commitments; operator_init may be incomplete"
            )
        })?;
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
    /// If endpoint is present, the tool will try to submit the request.
    pub guardian_endpoint: Option<String>,

    /// Config
    pub s3: S3Config,
    pub share_commitments: Vec<ShareCommitmentInput>,

    /// ProvisionerInitState
    // Hashi BLS keys used to sign cert's
    pub hashi_committees: CommitteeStoreRepr,
    // Withdrawal config
    pub withdrawal_config: WithdrawalConfig,
    // Hashi BTC pubkey
    pub hashi_btc_master_pubkey: BitcoinPubkey,
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
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read kp-init config at {}", path.display()))?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse kp-init yaml at {}", path.display()))
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
