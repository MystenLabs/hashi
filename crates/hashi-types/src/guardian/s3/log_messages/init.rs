// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_INIT;
use crate::bitcoin::BitcoinPubkey;
use crate::bitcoin::HashiMasterG;
use crate::guardian::CeremonyStage;
use crate::guardian::DeploymentConfig;
use crate::guardian::EncPubKeyBytes;
use crate::guardian::EnclaveMode;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianInfo;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::LimiterConfig;
use crate::guardian::LimiterState;
use crate::guardian::NitroAttestation;
use crate::guardian::SecretSharingInstance;
use crate::guardian::ShareID;
use crate::guardian::WithdrawStage;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Durable facts established by completed operator initialization. This schema
/// is independent of the live GuardianInfo response and its lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInitInfo {
    /// Full installed policy, including current and historical PCR pins.
    pub deployment: DeploymentConfig,
    /// KPs use this key to encrypt shares for the initialized session.
    #[serde(with = "hex::serde")]
    pub encryption_pubkey: EncPubKeyBytes,
    pub mode: OperatorInitMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OperatorInitMode {
    Ceremony,
    Withdraw(Box<WithdrawOperatorInitInfo>),
}

/// Withdraw-mode arming data, installed before the OI record is written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawOperatorInitInfo {
    pub secret_sharing_instance: SecretSharingInstance,
    #[serde(with = "hex::serde")]
    pub config_hash: [u8; 32],
    pub limiter_config: LimiterConfig,
    /// Immutable binding loaded from genesis or pinned for bootstrap authorization.
    pub hashi_object_id: sui_sdk_types::Address,
    /// MPC derivation master from the same genesis source.
    pub mpc_master_g: HashiMasterG,
    /// Present when OI supplies bootstrap genesis for KP authorization; absent
    /// when immutable bindings are loaded from an established genesis record.
    #[serde(with = "crate::guardian::serde::option_hex_32")]
    pub genesis_state_hash: Option<[u8; 32]>,
}

impl OperatorInitInfo {
    pub fn mode(&self) -> EnclaveMode {
        match &self.mode {
            OperatorInitMode::Ceremony => EnclaveMode::Ceremony,
            OperatorInitMode::Withdraw(_) => EnclaveMode::Withdraw,
        }
    }

    /// Compare completed OI facts with the live response immediately after OI.
    /// Later-stage fields are checked on the live response, not stored in the log.
    pub fn match_post_oi_guardian_info(&self, live_info: &GuardianInfo) -> anyhow::Result<()> {
        let expected_lifecycle = match &self.mode {
            OperatorInitMode::Ceremony => CeremonyStage::OperatorInitialized.into(),
            OperatorInitMode::Withdraw(_) => WithdrawStage::OperatorInitialized.into(),
        };
        anyhow::ensure!(
            live_info.lifecycle == expected_lifecycle,
            "S3 OI mode {:?} does not match live post-OperatorInit lifecycle {:?}",
            self.mode(),
            live_info.lifecycle
        );
        anyhow::ensure!(
            live_info.deployment_info.as_ref() == Some(&self.deployment.summary()),
            "S3 OI deployment differs from live post-OperatorInit GuardianInfo"
        );
        anyhow::ensure!(
            live_info.encryption_pubkey == self.encryption_pubkey,
            "S3 OI encryption pubkey differs from live post-OperatorInit GuardianInfo"
        );
        anyhow::ensure!(
            live_info.enclave_btc_pubkey.is_none()
                && live_info.limiter_state.is_none()
                && live_info.current_committee_epoch.is_none(),
            "live post-OperatorInit GuardianInfo contains later-stage state"
        );
        match &self.mode {
            OperatorInitMode::Ceremony => anyhow::ensure!(
                live_info.secret_sharing_instance.is_none()
                    && live_info.config_hash.is_none()
                    && live_info.limiter_config.is_none()
                    && live_info.hashi_object_id.is_none()
                    && live_info.mpc_master_g.is_none()
                    && live_info.genesis_state_hash.is_none(),
                "live ceremony GuardianInfo contains withdraw initialization state"
            ),
            OperatorInitMode::Withdraw(withdraw) => {
                anyhow::ensure!(
                    live_info.secret_sharing_instance.as_ref()
                        == Some(&withdraw.secret_sharing_instance),
                    "S3 OI secret-sharing instance differs from live post-OperatorInit GuardianInfo"
                );
                anyhow::ensure!(
                    live_info.config_hash == Some(withdraw.config_hash),
                    "S3 OI config_hash differs from live post-OperatorInit GuardianInfo"
                );
                anyhow::ensure!(
                    live_info.limiter_config == Some(withdraw.limiter_config),
                    "S3 OI limiter config differs from live post-OperatorInit GuardianInfo"
                );
                anyhow::ensure!(
                    live_info.hashi_object_id == Some(withdraw.hashi_object_id),
                    "S3 OI Hashi object ID differs from live post-OperatorInit GuardianInfo"
                );
                anyhow::ensure!(
                    live_info.mpc_master_g == Some(withdraw.mpc_master_g),
                    "S3 OI MPC master G differs from live post-OperatorInit GuardianInfo"
                );
                anyhow::ensure!(
                    live_info.genesis_state_hash == withdraw.genesis_state_hash,
                    "S3 OI genesis_state_hash differs from live post-OperatorInit GuardianInfo"
                );
            }
        }
        Ok(())
    }
}

/// OI: operator_init
/// PI: provisioner_init
/// Init messages are expected to be logged in the following order:
/// OIAttestationUnsigned -> OIGuardianInfo -> PIEnclaveFullyInitialized -> OAActivated.
#[derive(Debug, Serialize, Deserialize)]
pub enum InitLogMessage {
    /// Attestation and signing public key posted in /operator_init
    OIAttestationUnsigned {
        attestation: NitroAttestation,
        #[serde(with = "crate::guardian::serde::guardian_pubkey")]
        signing_public_key: GuardianPubKey,
    },
    /// Signed completion record for /operator_init. The signing key is bound
    /// by the preceding attestation record; later PI/OA state is logged separately.
    OIGuardianInfo(Box<OperatorInitInfo>),
    /// Threshold reached — enclave BTC key reconstructed (happens once).
    PIEnclaveFullyInitialized {
        sharing_seq: u64,
        share_ids: Vec<ShareID>,
        enclave_btc_pubkey: BitcoinPubkey,
    },
    /// Operator activation succeeded and installed live serving state.
    OAActivated {
        #[serde(with = "hex::serde")]
        state_hash: [u8; 32],
        #[serde(with = "hex::serde")]
        config_hash: [u8; 32],
        sharing_seq: u64,
        committee_epoch: u64,
        limiter_state: LimiterState,
    },
}

impl InitLogMessage {
    pub const OI_ATTEST_UNSIGNED: &'static str = "01-oi-attestation-unsigned";
    pub const OI_GUARDIAN_INFO: &'static str = "02-oi-guardian-info";
    pub const PI_FULLY_INITIALIZED: &'static str = "03-pi-enclave-fully-initialized";
    pub const OA_ACTIVATED: &'static str = "04-oa-activated";

    pub fn object_key(&self, session_id: &str) -> String {
        let suffix = match self {
            InitLogMessage::OIAttestationUnsigned { .. } => Self::OI_ATTEST_UNSIGNED,
            InitLogMessage::OIGuardianInfo(_) => Self::OI_GUARDIAN_INFO,
            InitLogMessage::PIEnclaveFullyInitialized { .. } => Self::PI_FULLY_INITIALIZED,
            InitLogMessage::OAActivated { .. } => Self::OA_ACTIVATED,
        };

        Self::object_key_for_suffix(session_id, suffix)
    }

    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id))
    }

    pub fn attestation_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::OI_ATTEST_UNSIGNED)
    }

    pub fn guardian_info_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::OI_GUARDIAN_INFO)
    }

    pub fn pi_fully_initialized_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::PI_FULLY_INITIALIZED)
    }

    pub fn oa_activated_object_key(session_id: &str) -> String {
        Self::object_key_for_suffix(session_id, Self::OA_ACTIVATED)
    }

    /// Verify facts repeated between 02 OIGuardianInfo and 03
    /// PIEnclaveFullyInitialized.
    pub fn verify_oi_pi_consistency(
        oi_info: &OperatorInitInfo,
        pi_message: &Self,
    ) -> GuardianResult<()> {
        let Self::PIEnclaveFullyInitialized {
            sharing_seq: pi_sharing_seq,
            share_ids,
            ..
        } = pi_message
        else {
            return Err(InvalidS3Log(
                "expected PIEnclaveFullyInitialized init log".into(),
            ));
        };
        let OperatorInitMode::Withdraw(withdraw) = &oi_info.mode else {
            return Err(InvalidS3Log(
                "PI requires withdraw-mode operator initialization".into(),
            ));
        };
        let oi_instance = &withdraw.secret_sharing_instance;
        let oi_sharing_seq = oi_instance.sharing_seq();

        if *pi_sharing_seq != oi_sharing_seq {
            return Err(InvalidS3Log(format!(
                "PIEnclaveFullyInitialized sharing_seq {pi_sharing_seq} differs from OIGuardianInfo sharing_seq {oi_sharing_seq}"
            )));
        }

        let unique_share_ids = share_ids.iter().copied().collect::<BTreeSet<_>>();
        if unique_share_ids.len() != share_ids.len() {
            return Err(InvalidS3Log(
                "PIEnclaveFullyInitialized contains duplicate share_ids".into(),
            ));
        }
        if share_ids.len() < oi_instance.threshold() || share_ids.len() > oi_instance.num_shares() {
            return Err(InvalidS3Log(format!(
                "PIEnclaveFullyInitialized has {} share_ids; expected between {} and {}",
                share_ids.len(),
                oi_instance.threshold(),
                oi_instance.num_shares(),
            )));
        }

        let commitment_ids = oi_instance
            .commitments()
            .iter()
            .map(|commitment| commitment.id)
            .collect::<BTreeSet<_>>();
        if !unique_share_ids.is_subset(&commitment_ids) {
            return Err(InvalidS3Log(
                "PIEnclaveFullyInitialized contains share_ids absent from OIGuardianInfo commitments"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Verify facts repeated between 02 OIGuardianInfo and 04 OAActivated.
    pub fn verify_oi_oa_consistency(
        oi_info: &OperatorInitInfo,
        oa_message: &Self,
    ) -> GuardianResult<()> {
        let Self::OAActivated {
            config_hash: oa_config_hash,
            sharing_seq: oa_sharing_seq,
            ..
        } = oa_message
        else {
            return Err(InvalidS3Log("expected OAActivated init log".into()));
        };
        let OperatorInitMode::Withdraw(withdraw) = &oi_info.mode else {
            return Err(InvalidS3Log(
                "OA requires withdraw-mode operator initialization".into(),
            ));
        };
        let oi_sharing_seq = withdraw.secret_sharing_instance.sharing_seq();
        let oi_config_hash = withdraw.config_hash;

        if *oa_sharing_seq != oi_sharing_seq {
            return Err(InvalidS3Log(format!(
                "OAActivated sharing_seq {oa_sharing_seq} differs from OIGuardianInfo sharing_seq {oi_sharing_seq}"
            )));
        }
        if *oa_config_hash != oi_config_hash {
            return Err(InvalidS3Log(
                "OAActivated config_hash differs from OIGuardianInfo config_hash".into(),
            ));
        }
        Ok(())
    }

    /// Verify facts repeated between 03 PIEnclaveFullyInitialized and 04
    /// OAActivated.
    pub fn verify_pi_oa_consistency(pi_message: &Self, oa_message: &Self) -> GuardianResult<()> {
        let Self::PIEnclaveFullyInitialized {
            sharing_seq: pi_sharing_seq,
            ..
        } = pi_message
        else {
            return Err(InvalidS3Log(
                "expected PIEnclaveFullyInitialized init log".into(),
            ));
        };
        let Self::OAActivated {
            sharing_seq: oa_sharing_seq,
            ..
        } = oa_message
        else {
            return Err(InvalidS3Log("expected OAActivated init log".into()));
        };

        if oa_sharing_seq != pi_sharing_seq {
            return Err(InvalidS3Log(format!(
                "OAActivated sharing_seq {oa_sharing_seq} differs from PIEnclaveFullyInitialized sharing_seq {pi_sharing_seq}"
            )));
        }
        Ok(())
    }

    fn object_key_for_suffix(session_id: &str, suffix: &str) -> String {
        format!("{S3_DIR_INIT}/{session_id}/{suffix}.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::create_btc_keypair_for_test;
    use crate::guardian::ShareID;

    fn pi_message_with_ids(sharing_seq: u64, share_ids: Vec<ShareID>) -> InitLogMessage {
        InitLogMessage::PIEnclaveFullyInitialized {
            sharing_seq,
            share_ids,
            enclave_btc_pubkey: create_btc_keypair_for_test(&[1; 32]).x_only_public_key().0,
        }
    }

    fn share_ids(ids: &[u16]) -> Vec<ShareID> {
        ids.iter().map(|id| ShareID::new(*id).unwrap()).collect()
    }

    fn pi_message(sharing_seq: u64) -> InitLogMessage {
        pi_message_with_ids(sharing_seq, share_ids(&[1, 2, 3]))
    }

    fn oa_message(config_hash: [u8; 32], sharing_seq: u64) -> InitLogMessage {
        InitLogMessage::OAActivated {
            state_hash: [1; 32],
            config_hash,
            sharing_seq,
            committee_epoch: 0,
            limiter_state: LimiterState {
                num_tokens_available: 0,
                last_updated_at: 0,
                next_seq: 0,
            },
        }
    }

    #[test]
    fn verifies_pairwise_init_log_consistency() {
        let oi_info = OperatorInitInfo::mock_for_testing();
        let pi = pi_message(0);
        let oa = oa_message([2; 32], 0);

        InitLogMessage::verify_oi_pi_consistency(&oi_info, &pi).unwrap();
        InitLogMessage::verify_oi_oa_consistency(&oi_info, &oa).unwrap();
        InitLogMessage::verify_pi_oa_consistency(&pi, &oa).unwrap();

        assert!(InitLogMessage::verify_oi_pi_consistency(&oi_info, &pi_message(1)).is_err());
        assert!(
            InitLogMessage::verify_oi_pi_consistency(
                &oi_info,
                &pi_message_with_ids(0, share_ids(&[1, 1, 2])),
            )
            .is_err()
        );
        assert!(
            InitLogMessage::verify_oi_pi_consistency(
                &oi_info,
                &pi_message_with_ids(0, share_ids(&[1, 2])),
            )
            .is_err()
        );
        assert!(
            InitLogMessage::verify_oi_pi_consistency(
                &oi_info,
                &pi_message_with_ids(0, share_ids(&[1, 2, 6])),
            )
            .is_err()
        );
        assert!(
            InitLogMessage::verify_oi_pi_consistency(
                &oi_info,
                &pi_message_with_ids(0, share_ids(&[1, 2, 3, 4, 5, 6])),
            )
            .is_err()
        );
        assert!(
            InitLogMessage::verify_oi_oa_consistency(&oi_info, &oa_message([3; 32], 0)).is_err()
        );
        assert!(
            InitLogMessage::verify_oi_oa_consistency(&oi_info, &oa_message([2; 32], 1)).is_err()
        );
        assert!(InitLogMessage::verify_pi_oa_consistency(&pi, &oa_message([2; 32], 1)).is_err());
    }

    #[test]
    fn ceremony_initialization_cannot_authorize_pi_or_oa() {
        let mut oi_info = OperatorInitInfo::mock_for_testing();
        assert_eq!(oi_info.mode(), EnclaveMode::Withdraw);
        oi_info.mode = OperatorInitMode::Ceremony;
        assert_eq!(oi_info.mode(), EnclaveMode::Ceremony);
        assert!(InitLogMessage::verify_oi_pi_consistency(&oi_info, &pi_message(0)).is_err());
        assert!(
            InitLogMessage::verify_oi_oa_consistency(&oi_info, &oa_message([2; 32], 0)).is_err()
        );
    }

    #[test]
    fn operator_init_schema_requires_common_and_withdraw_fields() {
        let json = serde_json::to_value(OperatorInitInfo::mock_for_testing()).unwrap();
        for field in ["deployment", "encryption_pubkey", "mode"] {
            let mut incomplete = json.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<OperatorInitInfo>(incomplete).is_err(),
                "{field}"
            );
        }
        for field in [
            "secret_sharing_instance",
            "config_hash",
            "limiter_config",
            "hashi_object_id",
            "mpc_master_g",
        ] {
            let mut incomplete = json.clone();
            incomplete["mode"]["Withdraw"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<OperatorInitInfo>(incomplete).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn post_init_comparison_preserves_withdraw_bindings_and_stage_checks() {
        let mut oi = OperatorInitInfo::mock_for_testing();
        for genesis_state_hash in [None, Some([3; 32])] {
            let OperatorInitMode::Withdraw(withdraw) = &mut oi.mode else {
                unreachable!();
            };
            withdraw.genesis_state_hash = genesis_state_hash;
            let live = GuardianInfo {
                lifecycle: WithdrawStage::OperatorInitialized.into(),
                deployment_info: Some(oi.deployment.summary()),
                encryption_pubkey: oi.encryption_pubkey.clone(),
                secret_sharing_instance: Some(withdraw.secret_sharing_instance.clone()),
                config_hash: Some(withdraw.config_hash),
                limiter_config: Some(withdraw.limiter_config),
                hashi_object_id: Some(withdraw.hashi_object_id),
                mpc_master_g: Some(withdraw.mpc_master_g),
                genesis_state_hash,
                enclave_btc_pubkey: None,
                limiter_state: None,
                current_committee_epoch: None,
            };
            oi.match_post_oi_guardian_info(&live).unwrap();
            let mutations: &[fn(&mut GuardianInfo)] = &[
                |info| info.lifecycle = WithdrawStage::ProvisionerInitialized.into(),
                |info| info.lifecycle = CeremonyStage::OperatorInitialized.into(),
                |info| {
                    info.deployment_info
                        .as_mut()
                        .unwrap()
                        .git_revision
                        .push_str("-other")
                },
                |info| info.encryption_pubkey[0] ^= 1,
                |info| info.secret_sharing_instance = None,
                |info| info.config_hash = Some([9; 32]),
                |info| info.limiter_config = None,
                |info| info.hashi_object_id = None,
                |info| info.mpc_master_g = None,
                |info| info.genesis_state_hash = Some([9; 32]),
                |info| {
                    info.enclave_btc_pubkey = Some(
                        crate::bitcoin::create_btc_keypair_for_test(&[1; 32])
                            .x_only_public_key()
                            .0,
                    )
                },
                |info| {
                    info.limiter_state = Some(crate::guardian::LimiterState {
                        num_tokens_available: 0,
                        last_updated_at: 0,
                        next_seq: 0,
                    })
                },
                |info| info.current_committee_epoch = Some(0),
            ];
            for (index, mutate) in mutations.iter().enumerate() {
                let mut changed = live.clone();
                mutate(&mut changed);
                assert!(
                    oi.match_post_oi_guardian_info(&changed).is_err(),
                    "mutation {index}"
                );
            }
        }
    }

    #[test]
    fn post_init_comparison_accepts_ceremony_without_withdraw_state() {
        let mut oi = OperatorInitInfo::mock_for_testing();
        oi.mode = OperatorInitMode::Ceremony;
        let mut live = GuardianInfo::mock_for_testing();
        live.lifecycle = CeremonyStage::OperatorInitialized.into();
        live.deployment_info = Some(oi.deployment.summary());
        live.encryption_pubkey = oi.encryption_pubkey.clone();
        oi.match_post_oi_guardian_info(&live).unwrap();
        live.lifecycle = None;
        assert!(oi.match_post_oi_guardian_info(&live).is_err());
        live.lifecycle = CeremonyStage::OperatorInitialized.into();
        live.config_hash = Some([2; 32]);
        assert!(oi.match_post_oi_guardian_info(&live).is_err());
    }
}
