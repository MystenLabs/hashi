// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_INIT;
use crate::bitcoin::BitcoinPubkey;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianInfo;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianResult;
use crate::guardian::LimiterState;
use crate::guardian::NitroAttestation;
use crate::guardian::ShareID;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

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
    /// Signed GuardianInfo logged in /operator_init (secret-sharing instance,
    /// config_hash, encryption/BTC pubkeys). Boxed: much larger than the other
    /// variants (`clippy::large_enum_variant`).
    OIGuardianInfo(Box<GuardianInfo>),
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
        oi_info: &GuardianInfo,
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
        let oi_instance = oi_info
            .secret_sharing_instance
            .as_ref()
            .ok_or_else(|| InvalidS3Log("OIGuardianInfo missing secret-sharing instance".into()))?;
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
        oi_info: &GuardianInfo,
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
        let oi_sharing_seq = oi_info
            .secret_sharing_instance
            .as_ref()
            .ok_or_else(|| InvalidS3Log("OIGuardianInfo missing secret-sharing instance".into()))?
            .sharing_seq();
        let oi_config_hash = oi_info
            .config_hash
            .ok_or_else(|| InvalidS3Log("OIGuardianInfo missing config_hash".into()))?;

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
    use crate::guardian::SetupNewKeyResponse;
    use crate::guardian::ShareID;

    fn oi_info() -> GuardianInfo {
        let mut info = GuardianInfo::mock_for_testing();
        info.secret_sharing_instance =
            Some(SetupNewKeyResponse::mock_for_testing().secret_sharing_instance);
        info.config_hash = Some([2; 32]);
        info
    }

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
        let oi_info = oi_info();
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
}
