// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_KP_SHARES;
use crate::guardian::KpEncryptedShareRoster;
use serde::Deserialize;
use serde::Serialize;

/// Current encrypted KP share state for a secret-sharing instance. The initial
/// ceremony writes `cert_seq = 0`; later individual KP cert rotations can write
/// higher `cert_seq` entries for the same `sharing_seq` without changing the
/// `ceremony/` instance. Both S3 schema versions use this scalar-recipient
/// payload so deployed V1 signing preimages remain unchanged.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KpShareStateLogMessage {
    pub sharing_seq: u64,
    pub cert_seq: u64,
    pub encrypted_shares: KpEncryptedShareRoster,
}

impl KpShareStateLogMessage {
    pub fn new(sharing_seq: u64, cert_seq: u64, encrypted_shares: KpEncryptedShareRoster) -> Self {
        Self {
            sharing_seq,
            cert_seq,
            encrypted_shares,
        }
    }

    /// `kp-shares/{sharing_seq:020}/` — the slash-terminated S3 key prefix
    /// containing every cert-state version for one `SecretSharingInstance`.
    pub fn object_key_dir(sharing_seq: u64) -> String {
        format!("{S3_DIR_KP_SHARES}/{sharing_seq:020}/")
    }

    /// `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session_id}.json` — the
    /// object key for one written KP share state.
    pub fn object_key(session_id: &str, sharing_seq: u64, cert_seq: u64) -> String {
        format!(
            "{}{:020}-{session_id}.json",
            Self::object_key_dir(sharing_seq),
            cert_seq
        )
    }

    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(Self::object_key(
            session_id,
            self.sharing_seq,
            self.cert_seq,
        ))
    }
}
