// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::ObjectKeyPattern;
use super::super::S3_DIR_CEREMONY;
use crate::bitcoin::BitcoinPubkey;
use crate::guardian::SecretSharingInstance;
use serde::Deserialize;
use serde::Serialize;

/// The authoritative secret-sharing instance, written to `ceremony/` after each
/// ceremony. Carries the commitments + n/t/seq; encrypted KP shares live in
/// `kp-shares/`. A rotation records the `old_instance` it consumed so the chain
/// is auditable from the log alone.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CeremonyLogMessage {
    /// Initial key setup (`setup_new_key`); `instance` has `sharing_seq` 0.
    NewKey {
        instance: SecretSharingInstance,
        /// The x-only BTC master pubkey this ceremony produced; lets KPs and
        /// monitors cross-check it against the on-chain `guardian_btc_public_key`.
        btc_master_pubkey: BitcoinPubkey,
    },
    /// Key rotation (`rotate_kps`) from `old_instance` to `new_instance`.
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
    /// `Rotate` yields the new instance after verifying that it advances exactly
    /// one `sharing_seq` from the consumed instance.
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
                let expected = old_instance
                    .sharing_seq()
                    .checked_add(1)
                    .expect("Rotate old sharing_seq must not be u64::MAX");
                assert_eq!(
                    new_instance.sharing_seq(),
                    expected,
                    "Rotate must advance sharing_seq by exactly one"
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

    pub fn object_key(&self, session_id: &str) -> String {
        format!(
            "{}{:020}-{session_id}.json",
            Self::object_key_dir(),
            self.sharing_seq(),
        )
    }

    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id))
    }
}
