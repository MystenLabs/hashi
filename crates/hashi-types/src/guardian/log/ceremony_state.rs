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

/// The current ceremony result together with its latest encrypted KP share state.
#[derive(Clone, Debug, PartialEq)]
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
        Ok(Self {
            secret_sharing_instance,
            btc_master_pubkey,
            cert_seq: kp_share_state.cert_seq,
            encrypted_shares: kp_share_state.encrypted_shares,
        })
    }
}

impl From<SetupNewKeyResponse> for CeremonyState {
    fn from(response: SetupNewKeyResponse) -> Self {
        let SetupNewKeyResponse {
            encrypted_shares,
            secret_sharing_instance,
            btc_master_pubkey,
        } = response;
        Self {
            secret_sharing_instance,
            btc_master_pubkey,
            cert_seq: 0,
            encrypted_shares,
        }
    }
}
