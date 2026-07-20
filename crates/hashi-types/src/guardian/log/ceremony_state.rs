// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Combined ceremony and KP share state derived from guardian log messages.

use super::message::CeremonyLogMessage;
use super::message::KpShareStateLogMessage;
use crate::bitcoin::BitcoinPubkey;
use crate::guardian::GuardianError;
use crate::guardian::GuardianResult;
use crate::guardian::KPEncryptedShares;
use crate::guardian::SecretSharingInstance;
use crate::guardian::SetupNewKeyResponse;
use serde::Serialize;

/// The current ceremony result together with its latest encrypted KP share state.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CeremonyState {
    pub secret_sharing_instance: SecretSharingInstance,
    pub btc_master_pubkey: BitcoinPubkey,
    pub cert_seq: u64,
    pub encrypted_shares: KPEncryptedShares,
}

impl CeremonyState {
    /// Combine a ceremony log message with the KP share-state message for its
    /// resulting secret-sharing instance.
    pub fn new(
        ceremony: CeremonyLogMessage,
        kp_share_state: KpShareStateLogMessage,
    ) -> GuardianResult<Self> {
        let (secret_sharing_instance, btc_master_pubkey) = ceremony.into_instance_and_pubkey();
        if kp_share_state.sharing_seq != secret_sharing_instance.sharing_seq() {
            return Err(GuardianError::InternalError(format!(
                "kp-shares sharing_seq ({}) differs from ceremony sharing_seq ({})",
                kp_share_state.sharing_seq,
                secret_sharing_instance.sharing_seq()
            )));
        }
        Self::from_parts(
            secret_sharing_instance,
            btc_master_pubkey,
            kp_share_state.cert_seq,
            kp_share_state.encrypted_shares,
        )
    }

    fn from_parts(
        secret_sharing_instance: SecretSharingInstance,
        btc_master_pubkey: BitcoinPubkey,
        cert_seq: u64,
        encrypted_shares: KPEncryptedShares,
    ) -> GuardianResult<Self> {
        if encrypted_shares.len() != secret_sharing_instance.num_shares() {
            return Err(GuardianError::InternalError(format!(
                "encrypted share count ({}) differs from ceremony num_shares ({})",
                encrypted_shares.len(),
                secret_sharing_instance.num_shares()
            )));
        }
        Ok(Self {
            secret_sharing_instance,
            btc_master_pubkey,
            cert_seq,
            encrypted_shares,
        })
    }

    /// Confirm the ceremony uses the expected secret-sharing parameters.
    pub fn validate_sharing_params(
        &self,
        expected_n: usize,
        expected_t: usize,
    ) -> GuardianResult<()> {
        if self.secret_sharing_instance.num_shares() != expected_n {
            return Err(GuardianError::InvalidInputs(format!(
                "ceremony num_shares ({}) differs from expected ({expected_n})",
                self.secret_sharing_instance.num_shares()
            )));
        }
        if self.secret_sharing_instance.threshold() != expected_t {
            return Err(GuardianError::InvalidInputs(format!(
                "ceremony threshold ({}) differs from expected ({expected_t})",
                self.secret_sharing_instance.threshold()
            )));
        }
        Ok(())
    }
}

impl From<SetupNewKeyResponse> for CeremonyState {
    fn from(response: SetupNewKeyResponse) -> Self {
        let SetupNewKeyResponse {
            encrypted_shares,
            secret_sharing_instance,
            btc_master_pubkey,
        } = response;
        Self::from_parts(
            secret_sharing_instance,
            btc_master_pubkey,
            0,
            encrypted_shares,
        )
        .expect("SetupNewKeyResponse must contain one encrypted share per participant")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::GuardianSigned;

    #[test]
    fn serialization_includes_all_encrypted_shares() {
        let response = GuardianSigned::<SetupNewKeyResponse>::mock_for_testing().data;
        let expected_share_count = response.encrypted_shares.len();
        let state = CeremonyState::from(response);

        let json = serde_json::to_value(&state).unwrap();

        assert_eq!(
            json["encrypted_shares"].as_array().unwrap().len(),
            expected_share_count
        );
    }

    #[test]
    fn new_rejects_mismatched_sharing_seq() {
        let response = GuardianSigned::<SetupNewKeyResponse>::mock_for_testing().data;
        let sharing_seq = response.secret_sharing_instance.sharing_seq();
        let err = CeremonyState::new(
            CeremonyLogMessage::NewKey {
                instance: response.secret_sharing_instance,
                btc_master_pubkey: response.btc_master_pubkey,
            },
            KpShareStateLogMessage::new(sharing_seq + 1, 0, response.encrypted_shares),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("kp-shares sharing_seq"), "{err}");
    }

    #[test]
    fn new_rejects_mismatched_share_count() {
        let response = GuardianSigned::<SetupNewKeyResponse>::mock_for_testing().data;
        let sharing_seq = response.secret_sharing_instance.sharing_seq();
        let err = CeremonyState::new(
            CeremonyLogMessage::NewKey {
                instance: response.secret_sharing_instance,
                btc_master_pubkey: response.btc_master_pubkey,
            },
            KpShareStateLogMessage::new(sharing_seq, 0, KPEncryptedShares::new(vec![]).unwrap()),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("encrypted share count"), "{err}");
    }
}
