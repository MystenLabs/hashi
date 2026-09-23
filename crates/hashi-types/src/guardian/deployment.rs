// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Non-secret deployment policy installed once during operator initialization.
/// KPs authorize the full policy in both ceremony and withdraw mode.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeploymentConfig {
    pub bucket_info: S3BucketInfo,
    pub retention_environment: S3RetentionEnvironment,
    pub bitcoin_network: bitcoin::Network,
    pub pcr_allowlist: PcrAllowlist,
}

/// Public view of the installed policy. Verifiers retain their own full allowlist;
/// the revision is a label and never replaces an independently approved PCR pin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeploymentConfigSummary {
    pub bucket_info: S3BucketInfo,
    pub retention_environment: S3RetentionEnvironment,
    pub bitcoin_network: bitcoin::Network,
    pub git_revision: GitRevision,
}

impl DeploymentConfig {
    pub fn summary(&self) -> DeploymentConfigSummary {
        DeploymentConfigSummary {
            bucket_info: self.bucket_info.clone(),
            retention_environment: self.retention_environment,
            bitcoin_network: self.bitcoin_network,
            git_revision: self.pcr_allowlist.current_build().git_revision().to_owned(),
        }
    }

    pub fn resolved_s3_config(&self, credentials: S3Credentials) -> ResolvedS3Config {
        ResolvedS3Config {
            credentials,
            bucket_info: self.bucket_info.clone(),
            retention_environment: self.retention_environment,
        }
    }

    /// Canonical commitment to all deployment settings, including previous builds.
    pub fn digest(&self) -> [u8; 32] {
        Blake2b::<U32>::digest(bcs::to_bytes(self).expect("serializable deployment config")).into()
    }
}

impl GuardianInfo {
    pub fn deployment(&self) -> GuardianResult<&DeploymentConfigSummary> {
        self.deployment
            .as_ref()
            .ok_or_else(|| InvalidInputs("Deployment is uninitialized".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_deployment_setting_is_bound_into_both_approvals() {
        let original = DeploymentConfig::mock_for_testing();
        let state = CeremonyState::from(SetupNewKeyResponse::mock_for_testing());
        let init = InitConfig::mock_for_testing(None);
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.bucket_info.bucket.push_str("-other");
        changes.push(changed);
        let mut changed = original.clone();
        changed.bucket_info.region = "us-west-2".into();
        changes.push(changed);
        let mut changed = original.clone();
        changed.retention_environment = S3RetentionEnvironment::Devnet;
        changes.push(changed);
        let mut changed = original.clone();
        changed.bitcoin_network = bitcoin::Network::Bitcoin;
        changes.push(changed);
        let mut changed = original.clone();
        changed.pcr_allowlist = PcrAllowlist::new(BuildPcrs::new("other", vec![0]), []).unwrap();
        changes.push(changed);
        let mut changed = original.clone();
        changed.pcr_allowlist = PcrAllowlist::new(BuildPcrs::new("unknown", vec![1]), []).unwrap();
        changes.push(changed);
        let mut changed = original.clone();
        changed.pcr_allowlist = PcrAllowlist::new(
            original.pcr_allowlist.current_build().clone(),
            [BuildPcrs::new("previous", vec![2])],
        )
        .unwrap();
        changes.push(changed);
        for changed in changes {
            assert_ne!(changed.digest(), original.digest());
            assert_ne!(
                state.confirmation_digest(&changed),
                state.confirmation_digest(&original)
            );
            let changed_init = InitConfig::new(
                *init.limiter_config(),
                init.hashi_btc_master_pubkey(),
                changed,
                init.hashi_object_id(),
            )
            .unwrap();
            assert_ne!(changed_init.digest(), init.digest());
        }
    }

    #[test]
    fn summary_omits_allowlist_but_commitment_includes_it() {
        let config = DeploymentConfig::mock_for_testing();
        let mut updated = config.clone();
        updated.pcr_allowlist = PcrAllowlist::new(
            config.pcr_allowlist.current_build().clone(),
            [BuildPcrs::new("previous", vec![2])],
        )
        .unwrap();
        assert_eq!(config.summary(), updated.summary());
        assert_ne!(config.digest(), updated.digest());
        let json = serde_json::to_value(config.summary()).unwrap();
        assert!(json.get("pcr_allowlist").is_none());
        assert_eq!(
            serde_json::from_value::<DeploymentConfigSummary>(json).unwrap(),
            config.summary()
        );
        let mut info = GuardianInfo::mock_for_testing();
        info.deployment = None;
        assert_eq!(
            serde_json::from_str::<GuardianInfo>(&serde_json::to_string(&info).unwrap()).unwrap(),
            info
        );
    }
}
