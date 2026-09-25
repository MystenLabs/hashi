// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_INIT;
use crate::bitcoin::BitcoinPubkey;
use crate::bitcoin::HashiMasterG;
use crate::guardian::DeploymentConfigSummary;
use crate::guardian::EncPubKeyBytes;
use crate::guardian::EnclaveMode;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::LimiterConfig;
use crate::guardian::LimiterState;
use crate::guardian::NitroAttestation;
use crate::guardian::SecretSharingInstance;
use crate::guardian::ShareID;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Durable facts established by completed operator initialization. This schema
/// is independent of the live GuardianInfo response and its lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInitInfo {
    pub deployment_info: DeploymentConfigSummary,
    /// KPs use this key to encrypt shares for the initialized session.
    #[serde(with = "hex::serde")]
    pub encryption_pubkey: EncPubKeyBytes,
    pub initialization: OperatorInitMode,
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
        match &self.initialization {
            OperatorInitMode::Ceremony => EnclaveMode::Ceremony,
            OperatorInitMode::Withdraw(_) => EnclaveMode::Withdraw,
        }
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
        let OperatorInitMode::Withdraw(withdraw) = &oi_info.initialization else {
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
        let OperatorInitMode::Withdraw(withdraw) = &oi_info.initialization else {
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
        oi_info.initialization = OperatorInitMode::Ceremony;
        assert_eq!(oi_info.mode(), EnclaveMode::Ceremony);
        assert!(InitLogMessage::verify_oi_pi_consistency(&oi_info, &pi_message(0)).is_err());
        assert!(
            InitLogMessage::verify_oi_oa_consistency(&oi_info, &oa_message([2; 32], 0)).is_err()
        );
    }

    #[test]
    fn operator_init_schema_requires_common_and_withdraw_fields() {
        let json = serde_json::to_value(OperatorInitInfo::mock_for_testing()).unwrap();
        for field in ["deployment_info", "encryption_pubkey", "initialization"] {
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
            incomplete["initialization"]["Withdraw"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<OperatorInitInfo>(incomplete).is_err(),
                "{field}"
            );
        }
    }
}
