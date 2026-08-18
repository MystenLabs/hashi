// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_KP_SHARES;
use crate::guardian::GuardianError;
use crate::guardian::KPEncryptedShares;
use crate::guardian::KPEncryptedSharesRoster;
use crate::guardian::KPFingerprint;
use crate::guardian::ShareID;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Current encrypted KP share state for a secret-sharing instance. The initial
/// ceremony writes `cert_seq = 0`; later individual KP cert rotations can write
/// higher `cert_seq` entries for the same `sharing_seq` without changing the
/// `ceremony/` instance.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KpShareStateLogMessageV2 {
    pub sharing_seq: u64,
    pub cert_seq: u64,
    pub encrypted_shares: KPEncryptedSharesRoster,
}

/// The KP-share state emitted by writers and returned by ceremony readers.
pub type KpShareStateLogMessage = KpShareStateLogMessageV2;

/// V1 encrypted share state: exactly one certificate and ciphertext per KP.
/// Kept solely for reading and authenticating existing V1 logs.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KpShareStateLogMessageV1 {
    pub sharing_seq: u64,
    pub cert_seq: u64,
    pub encrypted_shares: KPEncryptedSharesV1,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KPEncryptedShareV1 {
    pub id: ShareID,
    pub recipient_fingerprint: KPFingerprint,
    pub armored_ciphertext: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct KPEncryptedSharesV1(Vec<KPEncryptedShareV1>);

impl KPEncryptedSharesV1 {
    fn new(mut shares: Vec<KPEncryptedShareV1>) -> Result<Self, GuardianError> {
        if shares.len() > crate::guardian::crypto::MAX_NUM_SHARES {
            return Err(GuardianError::InvalidInputs(format!(
                "{} encrypted shares must be at most u16::MAX",
                shares.len()
            )));
        }

        shares.sort_by_key(|share| share.id);
        let ids = shares
            .iter()
            .map(|share| share.id.get())
            .collect::<Vec<_>>();
        let expected = (1..=shares.len() as u16).collect::<Vec<_>>();
        if ids != expected {
            return Err(GuardianError::InvalidInputs(format!(
                "encrypted share ids are not exactly 1..={}: got {ids:?}",
                shares.len()
            )));
        }

        Ok(Self(shares))
    }
}

impl<'de> Deserialize<'de> for KPEncryptedSharesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shares = Vec::<KPEncryptedShareV1>::deserialize(deserializer)?;
        Self::new(shares).map_err(serde::de::Error::custom)
    }
}

impl KpShareStateLogMessageV1 {
    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(KpShareStateLogMessageV2::object_key(
            session_id,
            self.sharing_seq,
            self.cert_seq,
        ))
    }
}

impl TryFrom<KpShareStateLogMessageV1> for KpShareStateLogMessageV2 {
    type Error = GuardianError;

    fn try_from(message: KpShareStateLogMessageV1) -> Result<Self, Self::Error> {
        let shares = message
            .encrypted_shares
            .0
            .into_iter()
            .map(|share| KPEncryptedShares {
                id: share.id,
                ciphertexts_by_fingerprint: BTreeMap::from([(
                    share.recipient_fingerprint,
                    share.armored_ciphertext,
                )]),
            })
            .collect();
        Ok(Self::new(
            message.sharing_seq,
            message.cert_seq,
            KPEncryptedSharesRoster::new(shares)?,
        ))
    }
}

impl KpShareStateLogMessageV2 {
    pub fn new(sharing_seq: u64, cert_seq: u64, encrypted_shares: KPEncryptedSharesRoster) -> Self {
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
