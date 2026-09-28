// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3_DIR_CEREMONY;
use super::super::log_layout::S3_DIR_KP_SHARES;
use crate::bitcoin::BitcoinPubkey;
use crate::guardian::KpEncryptedShareRoster;
use crate::guardian::SecretSharingInstance;
use serde::Deserialize;
use serde::Serialize;

/// The authoritative secret-sharing instance, written to `ceremony/` after each
/// ceremony. Carries the commitments + n/t/seq; encrypted KP shares live in
/// `kp-shares/`. A rotation records the `old_instance` it consumed so the chain
/// is auditable from the log alone.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CeremonyLogMessage {
    /// Initial key setup (`setup_new_key`), possibly after abandoned attempts.
    NewKey {
        instance: SecretSharingInstance,
        /// The x-only BTC master pubkey this ceremony produced; lets KPs and
        /// monitors cross-check it against the on-chain `guardian_btc_public_key`.
        btc_master_pubkey: BitcoinPubkey,
    },
    /// Key rotation (`rotate_kp_set`) from `old_instance` to `new_instance`.
    Rotate {
        old_instance: SecretSharingInstance,
        new_instance: SecretSharingInstance,
        /// See [`Self::NewKey`]; invariant across rotations (the same key is re-shared).
        btc_master_pubkey: BitcoinPubkey,
    },
}

impl CeremonyLogMessage {
    /// The slash-terminated prefix containing ceremony records.
    pub fn object_key_dir() -> String {
        format!("{S3_DIR_CEREMONY}/")
    }

    /// Consume the ceremony result. `NewKey` yields its initial instance;
    /// `Rotate` yields the new instance after verifying that it advances
    /// to a greater `sharing_seq` than the consumed instance.
    pub fn into_instance_and_pubkey(self) -> (SecretSharingInstance, BitcoinPubkey) {
        match self {
            Self::NewKey {
                instance,
                btc_master_pubkey,
            } => (instance, btc_master_pubkey),
            Self::Rotate {
                old_instance,
                new_instance,
                btc_master_pubkey,
            } => {
                assert!(
                    new_instance.sharing_seq() > old_instance.sharing_seq(),
                    "Rotate must advance sharing_seq"
                );
                (new_instance, btc_master_pubkey)
            }
        }
    }

    /// The resulting instance's `sharing_seq` — used as the `ceremony/` object key.
    pub fn sharing_seq(&self) -> u64 {
        match self {
            CeremonyLogMessage::NewKey { instance, .. } => instance.sharing_seq(),
            CeremonyLogMessage::Rotate { new_instance, .. } => new_instance.sharing_seq(),
        }
    }

    pub fn object_key(&self) -> String {
        format!("{}{:020}.json", Self::object_key_dir(), self.sharing_seq())
    }
}

/// A ceremony attempt awaiting confirmation from every key provisioner.
///
/// The proposal carries the ceremony metadata and encrypted shares that will
/// become authoritative only after every key provisioner confirms.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CeremonyProposalLogMessage {
    pub ceremony: CeremonyLogMessage,
    pub encrypted_shares: KpEncryptedShareRoster,
}

impl CeremonyProposalLogMessage {
    pub fn new(ceremony: CeremonyLogMessage, encrypted_shares: KpEncryptedShareRoster) -> Self {
        Self {
            ceremony,
            encrypted_shares,
        }
    }

    /// `kp-shares/proposed/{session_id}.json` — one proposal per ceremony
    /// enclave session.
    pub fn object_key(session_id: &str) -> String {
        format!("{S3_DIR_KP_SHARES}/proposed/{session_id}.json")
    }
}
