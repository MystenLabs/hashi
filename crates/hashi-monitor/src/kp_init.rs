use crate::rpc::guardian::heartbeat::kp_heartbeat_audits;
use anyhow::Context;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::ShareCommitment;
use hashi_types::guardian::ShareID;
use hashi_types::guardian::verify_enclave_attestation;
use serde::Deserialize;
use std::num::NonZeroU16;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct KpInitConfig {
    pub s3: S3Config,
    pub share_commitments: Vec<ShareCommitmentInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShareCommitmentInput {
    pub id: u16,
    pub digest_hex: String,
}

impl KpInitConfig {
    pub fn load_yaml(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read kp-init config at {}", path.display()))?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse kp-init yaml at {}", path.display()))
    }

    fn expected_share_commitments(&self) -> anyhow::Result<Vec<ShareCommitment>> {
        self.share_commitments
            .iter()
            .map(ShareCommitmentInput::to_domain)
            .collect()
    }
}

impl ShareCommitmentInput {
    fn to_domain(&self) -> anyhow::Result<ShareCommitment> {
        let id = NonZeroU16::new(self.id)
            .ok_or_else(|| anyhow::anyhow!("share commitment id must be non-zero"))?;
        let digest = hex::decode(&self.digest_hex)
            .with_context(|| format!("invalid hex digest for share id {}", self.id))?;
        Ok(ShareCommitment {
            id: ShareID::from(id),
            digest,
        })
    }
}

pub async fn run(cfg: KpInitConfig) -> anyhow::Result<()> {
    let session_id = kp_heartbeat_audits(&cfg.s3).await?;

    let expected_share_commitments = cfg.expected_share_commitments()?;
    let guardian_info = check_init_logs(&cfg.s3, &session_id, &expected_share_commitments).await?;

    tracing::info!(session_id, "kp-init checks passed for selected session");
    tracing::info!(
        encryption_pubkey_len = guardian_info.encryption_pubkey.len(),
        "guardian init info validated"
    );
    Ok(())
}

async fn check_init_logs(
    s3: &S3Config,
    session_id: &str,
    expected_share_commitments: &[ShareCommitment],
) -> anyhow::Result<GuardianInfo> {
    let s3_client = S3Logger::new(s3).await;
    s3_client
        .test_s3_connectivity()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let (attestation, signing_pubkey) = s3_client
        .get_attestation(session_id)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    verify_enclave_attestation(attestation).map_err(|e| anyhow::anyhow!(e))?;

    let info = s3_client
        .get_guardian_info(session_id, &signing_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let actual_bucket = info
        .bucket_info
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OIGuardianInfo missing bucket_info"))?;
    if actual_bucket != &s3.bucket_info {
        anyhow::bail!(
            "bucket_info mismatch: expected {:?}, got {:?}",
            &s3.bucket_info,
            actual_bucket
        );
    }

    let mut expected = expected_share_commitments.to_vec();
    expected.sort_by_key(|x| x.id.get());
    let mut actual = info
        .share_commitments
        .clone()
        .ok_or_else(|| anyhow::anyhow!("OIGuardianInfo missing share_commitments"))?;
    actual.sort_by_key(|x| x.id.get());
    if actual != expected {
        anyhow::bail!("share_commitments mismatch");
    }

    Ok(info)
}
