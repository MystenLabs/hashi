// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::S3NumericDirectory;
use super::super::log_layout::S3_DIR_KP_SHARES;
use crate::guardian::KpEncryptedShareRoster;
use serde::Deserialize;
use serde::Serialize;

/// Current encrypted KP share state for a secret-sharing instance. The initial
/// ceremony writes `cert_seq = 0`; later individual KP cert rotations can write
/// higher `cert_seq` entries for the same `sharing_seq` without changing the
/// `ceremony/` instance. Each encrypted share has one recipient fingerprint and
/// one ciphertext.
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

    /// The slash-terminated prefix containing all KP-share records.
    pub fn root_dir() -> String {
        format!("{S3_DIR_KP_SHARES}/")
    }

    /// `kp-shares/{sharing_seq:020}/` — the slash-terminated S3 key prefix
    /// containing every cert-state version for one `SecretSharingInstance`.
    pub fn object_key_dir(sharing_seq: u64) -> String {
        format!("{}{sharing_seq:020}/", Self::root_dir())
    }

    /// Parse the sharing sequence from a canonical KP-share directory.
    pub fn sharing_seq_from_dir(path: &str) -> anyhow::Result<u64> {
        let dir = S3NumericDirectory::from_path(path)?;
        let [seq] = dir.components() else {
            anyhow::bail!("expected one sharing sequence component in {path}");
        };

        // Comparing with the formatter enforces the prefix, zero-padding, and
        // trailing slash without duplicating the key format's rules here.
        anyhow::ensure!(
            path == Self::object_key_dir(*seq),
            "noncanonical KP-share directory {path}"
        );

        Ok(*seq)
    }

    /// `kp-shares/{sharing_seq:020}/{cert_seq:020}.json` — the
    /// object key for one written KP share state.
    pub fn object_key(sharing_seq: u64, cert_seq: u64) -> String {
        format!("{}{:020}.json", Self::object_key_dir(sharing_seq), cert_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::KpShareStateLogMessage;

    #[test]
    fn sharing_sequence_directory_format() {
        for (seq, path) in [
            (0, "kp-shares/00000000000000000000/"),
            (3, "kp-shares/00000000000000000003/"),
            (u64::MAX, "kp-shares/18446744073709551615/"),
        ] {
            assert_eq!(KpShareStateLogMessage::object_key_dir(seq), path);
            assert_eq!(
                KpShareStateLogMessage::sharing_seq_from_dir(path).unwrap(),
                seq
            );
        }
    }

    #[test]
    fn rejects_noncanonical_sharing_sequence_directories() {
        for path in [
            "kp-shares/",
            "kp-shares/proposed/",
            "ceremony/00000000000000000003/",
            "kp-shares/3/",
            "kp-shares/0000000000000000003/",
            "kp-shares/000000000000000000003/",
            "kp-shares/+0000000000000000003/",
            "kp-shares/-0000000000000000003/",
            "kp-shares/00000000000000000003",
            "kp-shares/00000000000000000003//",
            "kp-shares/00000000000000000003/0/",
            "kp-shares/00000000000000000003.json",
            "kp-shares/18446744073709551616/",
        ] {
            assert!(
                KpShareStateLogMessage::sharing_seq_from_dir(path).is_err(),
                "{path}"
            );
        }
    }
}
