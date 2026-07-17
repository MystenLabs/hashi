// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared KP-roster config + ceremony-state verification, used by both the
//! `key-provisioner ceremony` and `key-provisioner provision` commands.
//!
//! Both commands need to:
//! - load a roster of KP OpenPGP certs
//! - discover the latest attested ceremony from S3
//! - validate the ceremony's `secret_sharing_instance` against expected params
//! - confirm every encrypted share in `kp-shares/` is addressed only to its
//!   labeled cert (without decrypting)
//!
//! `provision` additionally decrypts one share via the yubikey and re-encrypts
//! it to a new guardian. The decryption helper lives here so both commands
//! share the same gpg-streaming pattern.

use std::ops::Deref;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::KPEncryptedShare;
use hashi_types::guardian::KPFingerprint;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::Share;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::cert_owns_key_handle;
use hashi_types::pgp::decrypt_armored_via_gpg;
use hashi_types::pgp::pgp_message_recipients;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use serde::Deserialize;
use tracing::info;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Common KP-roster config: the sharing params, the full KP cert roster, and the
/// PCR allowlist. Shared by every command that needs to discover and verify a
/// ceremony against an expected KP set.
#[derive(Deserialize)]
pub struct KpRosterConfig {
    /// Total number of shares. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// Paths to each KP's armored OpenPGP public cert. Order matters for
    /// `operator ceremony` (the cert at index `i` is assigned share id `i + 1`); for
    /// the read-only commands (`key-provisioner ceremony`, `key-provisioner provision`), shares are
    /// matched by fingerprint so order is irrelevant.
    pub kp_pgp_cert_paths: Vec<PathBuf>,
    #[serde(flatten)]
    pub pcr_allowlist: PcrAllowlist,
}

impl KpRosterConfig {
    pub fn validate(&self) -> Result<()> {
        SecretSharingParams::new(self.num_shares, self.threshold)
            .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;

        let cert_count = self.kp_pgp_cert_paths.len();
        anyhow::ensure!(
            self.num_shares == cert_count,
            "num_shares ({}) must equal the number of KP certs ({cert_count})",
            self.num_shares
        );

        Ok(())
    }

    /// The PCR allowlist decoded from `current_build` + `prev_builds`.
    pub fn pcr_allowlist(&self) -> PcrAllowlist {
        self.pcr_allowlist.clone()
    }
}

/// For each encrypted share, confirm (a) its `recipient_fingerprint` label
/// names exactly one of the operator-supplied certs, and (b) the ciphertext is
/// actually encrypted only to that cert (parsed via PKESK without decrypting).
///
/// Identity is by fingerprint, not positional index — a share is matched to its
/// cert by `recipient_fingerprint`, independent of ordering.
pub fn verify_encrypted_share_recipients(
    state: &CeremonyState,
    certs: &[PgpPublicCert],
) -> Result<()> {
    let by_fingerprint: std::collections::HashMap<KPFingerprint, &PgpPublicCert> = certs
        .iter()
        .map(|c| (c.fingerprint().to_hex(), c))
        .collect();
    anyhow::ensure!(
        by_fingerprint.len() == certs.len(),
        "duplicate fingerprints among the supplied KP certs"
    );

    let mut expected_fingerprints: Vec<KPFingerprint> = by_fingerprint.keys().cloned().collect();
    expected_fingerprints.sort_unstable();
    let mut labeled_fingerprints: Vec<KPFingerprint> = state
        .encrypted_shares
        .iter()
        .map(|s| s.recipient_fingerprint.clone())
        .collect();
    labeled_fingerprints.sort_unstable();
    anyhow::ensure!(
        labeled_fingerprints == expected_fingerprints,
        "encrypted share recipient roster differs from expected KP certs: expected \
             {expected_fingerprints:?}, got {labeled_fingerprints:?}"
    );

    for share in state.encrypted_shares.iter() {
        let expected_cert = by_fingerprint
            .get(&share.recipient_fingerprint)
            .with_context(|| {
                format!(
                    "share id {} is labeled for fingerprint {}, which is not among the \
                             operator-supplied KP certs",
                    share.id.get(),
                    share.recipient_fingerprint
                )
            })?;
        let recipients = pgp_message_recipients(&share.armored_ciphertext)
            .with_context(|| format!("parse PGP recipients for share id {}", share.id.get()))?;
        anyhow::ensure!(
            !recipients.is_empty(),
            "share id {} has no PGP recipients",
            share.id.get()
        );
        for handle in &recipients {
            anyhow::ensure!(
                cert_owns_key_handle(expected_cert, handle),
                "share id {} (labeled {}) is encrypted to key {handle}, which is not in \
                     that cert",
                share.id.get(),
                share.recipient_fingerprint
            );
        }
        info!(
            share_id = share.id.get(),
            fingerprint = %share.recipient_fingerprint,
            recipient_count = recipients.len(),
            "verified share is encrypted only to its labeled cert"
        );
    }
    info!(
        "all {} KP share-state entries encrypted to their labeled certs",
        state.encrypted_shares.len()
    );
    Ok(())
}

/// Confirm this KP's own cert is one of the operator-supplied roster certs.
/// Catches a typo'd `kp_pgp_cert_path` before any S3 or yubikey work.
pub fn ensure_cert_in_roster(kp_cert: &PgpPublicCert, certs: &[PgpPublicCert]) -> Result<()> {
    let want_fp = kp_cert.fingerprint();
    anyhow::ensure!(
        certs.iter().any(|c| c.fingerprint() == want_fp),
        "this KP's cert (fingerprint {want_fp}) is not among the configured kp_pgp_cert_paths"
    );
    Ok(())
}

/// Decrypt a KP's encrypted share via the yubikey-backed gpg agent, returning
/// the share wrapped in a [`DecryptedShare`] that wipes its scalar on drop.
/// Nothing touches disk: gpg reads the ciphertext from a piped stdin and
/// streams the plaintext over its stdout pipe into memory.
///
/// **Zeroization scope:** the gpg plaintext bytes, the intermediate scalar
/// byte array, and the returned wrapper's inner [`Scalar`] are zeroed on drop.
/// `k256::Scalar` is `Copy`, so the compiler may produce transient stack
/// copies (e.g. inside `verify_share` / `build_from_share`) that this can't
/// reach — those are wiped only when the process exits. The named locations
/// this code owns are wiped deterministically.
pub fn decrypt_share(share: &KPEncryptedShare) -> Result<DecryptedShare> {
    let plaintext = Zeroizing::new(decrypt_armored_via_gpg(&share.armored_ciphertext, None)?);
    let scalar = scalar_from_decrypted_plaintext(&plaintext)?;
    Ok(DecryptedShare(Share {
        id: share.id,
        value: scalar,
    }))
}

/// Owning wrapper around a decrypted [`Share`] that wipes the scalar value on
/// drop. Use `&*share` to access the inner [`Share`] for commitment
/// verification / re-encryption. See [`decrypt_share`] for the zeroization
/// scope.
pub struct DecryptedShare(Share);

impl Deref for DecryptedShare {
    type Target = Share;

    fn deref(&self) -> &Share {
        &self.0
    }
}

impl Drop for DecryptedShare {
    fn drop(&mut self) {
        self.0.value.zeroize();
    }
}

/// Parse the decrypted plaintext bytes into a secp256k1 scalar. Extracted from
/// [`decrypt_share`] so the byte-length and canonical-scalar checks are
/// unit-testable without invoking gpg.
fn scalar_from_decrypted_plaintext(plaintext: &[u8]) -> Result<Scalar> {
    let src: &[u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow!("decrypted share is {} bytes, expected 32", plaintext.len()))?;
    let mut scalar_bytes = Zeroizing::new([0u8; 32]);
    scalar_bytes.copy_from_slice(src);
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(*scalar_bytes)))
        .ok_or_else(|| anyhow!("decrypted share is not a valid secp256k1 scalar"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::KPEncryptedShares;
    use hashi_types::guardian::SecretSharingInstance;
    use hashi_types::guardian::SetupNewKeyResponse;
    use hashi_types::guardian::ShareCommitment;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::pgp::encrypt_armored;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::num::NonZeroU16;

    fn commitments(ids: &[u16]) -> ShareCommitments {
        let vec: Vec<ShareCommitment> = ids
            .iter()
            .map(|&i| ShareCommitment {
                id: NonZeroU16::new(i).unwrap(),
                digest: vec![i as u8],
            })
            .collect();
        ShareCommitments::new(vec).unwrap()
    }

    fn dummy_btc_pubkey() -> hashi_types::bitcoin::BitcoinPubkey {
        hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey(
            &k256::SecretKey::from_slice(&[9u8; 32]).unwrap(),
        )
    }

    fn mock_cert() -> PgpPublicCert {
        let (public, _secret) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
    }

    fn encrypted_share(id: u16, cert: &PgpPublicCert) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint: cert.fingerprint().to_hex(),
            armored_ciphertext: encrypt_armored(&[id as u8; 32], cert).unwrap(),
        }
    }

    fn encrypted_response(certs_by_share: &[&PgpPublicCert]) -> SetupNewKeyResponse {
        let n = certs_by_share.len();
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedShares::new(
                certs_by_share
                    .iter()
                    .enumerate()
                    .map(|(i, cert)| encrypted_share((i + 1) as u16, cert))
                    .collect(),
            )
            .unwrap(),
            secret_sharing_instance: SecretSharingInstance::new(
                commitments(&(1..=n as u16).collect::<Vec<_>>()),
                n,
                2,
                0,
            )
            .unwrap(),
            btc_master_pubkey: dummy_btc_pubkey(),
        }
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_reordered_expected_certs() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);
        let state = CeremonyState::from(resp);

        verify_encrypted_share_recipients(&state, &[cert3, cert1, cert2])
            .expect("recipient validation should be by fingerprint, not config order");
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_duplicate_share_labels() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert1, &cert3]);
        let state = CeremonyState::from(resp);

        let err = verify_encrypted_share_recipients(&state, &[cert1, cert2, cert3]).unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
            "{err}"
        );
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_omitted_expected_cert() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let unexpected = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &unexpected]);
        let state = CeremonyState::from(resp);

        let err = verify_encrypted_share_recipients(&state, &[cert1, cert2, cert3]).unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
            "{err}"
        );
    }

    #[test]
    fn ensure_cert_in_roster_accepts_member() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let roster = [cert1, cert2, cert3.clone()];
        ensure_cert_in_roster(&cert3, &roster).expect("cert is in the roster");
    }

    #[test]
    fn ensure_cert_in_roster_rejects_non_member() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let outsider = mock_cert();
        let roster = [cert1, cert2];
        let err = ensure_cert_in_roster(&outsider, &roster).unwrap_err();
        assert!(
            format!("{err}").contains("not among the configured"),
            "{err}"
        );
    }

    #[test]
    fn scalar_from_decrypted_plaintext_accepts_32_bytes() {
        // Any non-zero, sub-curve-order byte pattern is a valid scalar.
        let bytes = [1u8; 32];
        scalar_from_decrypted_plaintext(&bytes).expect("32 bytes should parse to a scalar");
    }

    #[test]
    fn scalar_from_decrypted_plaintext_rejects_wrong_length() {
        assert!(scalar_from_decrypted_plaintext(&[1u8; 31]).is_err());
        assert!(scalar_from_decrypted_plaintext(&[1u8; 33]).is_err());
        assert!(scalar_from_decrypted_plaintext(&[]).is_err());
    }

    #[test]
    fn scalar_from_decrypted_plaintext_rejects_non_canonical() {
        // secp256k1 order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.
        // A 32-byte value >= n is non-canonical and must be rejected.
        let mut over_order = [0xFFu8; 32];
        over_order[31] = 0x42; // > 0x41 (low byte of n)
        assert!(scalar_from_decrypted_plaintext(&over_order).is_err());
    }
}
