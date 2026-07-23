// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared KP-roster config and ceremony-state verification for key-provisioner
//! commands.
//!
//! These commands need to:
//! - load a roster of KP OpenPGP certs
//! - discover the latest attested ceremony from S3
//! - validate the ceremony's `secret_sharing_instance` against expected params
//! - confirm every PGP-encrypted share in `kp-shares/` matches the
//!   expected certificates for that KP/share id (without decrypting)
//!
//! `ceremony` decrypts every copy in this KP's roster entry. `provision` and
//! `rotate-cert` decrypt only the copy selected by `kp_pgp_cert_path`. The
//! decryption helper lives here so all commands share the same gpg-streaming
//! pattern.

use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::KpCerts;
use hashi_types::guardian::KpCertsRoster;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareID;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::decrypt_armored_via_gpg;
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
    /// Total number of shares/KPs. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// Paths to each KP's armored OpenPGP public certificates. Order matters for
    /// `operator ceremony` (the entry at index `i` is assigned share id
    /// `i + 1`); for read-only commands, shares are matched by fingerprint.
    pub kp_pgp_cert_paths: Vec<KpPgpCertPaths>,
    #[serde(flatten)]
    pub pcr_allowlist: PcrAllowlist,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum KpPgpCertPaths {
    Single(PathBuf),
    Multiple(Vec<PathBuf>),
}

impl KpPgpCertPaths {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Multiple(paths) if paths.is_empty())
    }

    fn paths(&self) -> Vec<&PathBuf> {
        match self {
            Self::Single(path) => vec![path],
            Self::Multiple(paths) => paths.iter().collect(),
        }
    }
}

impl KpRosterConfig {
    pub fn validate(&self) -> Result<()> {
        SecretSharingParams::new(self.num_shares, self.threshold)
            .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;

        let roster_entry_count = self.kp_pgp_cert_paths.len();
        anyhow::ensure!(
            self.num_shares == roster_entry_count,
            "num_shares ({}) must equal the number of KP cert roster entries ({roster_entry_count})",
            self.num_shares
        );
        for (idx, cert_paths) in self.kp_pgp_cert_paths.iter().enumerate() {
            anyhow::ensure!(
                !cert_paths.is_empty(),
                "kp_pgp_cert_paths entry {} must contain at least one cert path",
                idx + 1
            );
        }

        Ok(())
    }

    pub fn cert_count(&self) -> usize {
        self.kp_pgp_cert_paths
            .iter()
            .map(|cert_paths| cert_paths.paths().len())
            .sum()
    }

    pub fn load_certs_roster(&self) -> Result<KpCertsRoster> {
        let roster_entries = self
            .kp_pgp_cert_paths
            .iter()
            .enumerate()
            .map(|(idx, cert_paths)| {
                let certs = cert_paths
                    .paths()
                    .into_iter()
                    .map(load_cert)
                    .collect::<Result<Vec<_>>>()?;
                KpCerts::new(certs)
                    .with_context(|| format!("invalid KP cert roster entry {}", idx + 1))
            })
            .collect::<Result<Vec<_>>>()?;
        KpCertsRoster::new(roster_entries).context("invalid KP certificate roster")
    }

    /// The PCR allowlist decoded from `current_build` + `prev_builds`.
    pub fn pcr_allowlist(&self) -> PcrAllowlist {
        self.pcr_allowlist.clone()
    }
}

fn load_cert(path: &PathBuf) -> Result<PgpPublicCert> {
    let armored = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read PGP cert at {}", path.display()))?;
    let cert = PgpPublicCert::new(armored)
        .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
    info!(fingerprint = %cert, path = %path.display(), "loaded PGP cert");
    Ok(cert)
}

/// Decrypt and commitment-check the ciphertext for every supplied KP cert, in
/// order. All ciphertexts must contain the same share.
pub fn decrypt_kp_share_copies(
    state: &CeremonyState,
    kp_certs: &[PgpPublicCert],
) -> Result<DecryptedShare> {
    anyhow::ensure!(!kp_certs.is_empty(), "at least one KP cert is required");

    let mut selected = Vec::with_capacity(kp_certs.len());
    for cert in kp_certs {
        let fingerprint = cert.fingerprint().to_hex();
        let (share, ciphertext) = state
            .encrypted_shares
            .find_by_fingerprint(&fingerprint)
            .ok_or_else(|| {
                anyhow!(
                    "no share in the kp-shares log has a ciphertext for this KP's \
                     fingerprint {fingerprint} (recipient roster by share: {:?})",
                    state.encrypted_shares.recipient_roster()
                )
            })?;
        selected.push((fingerprint, share.id, ciphertext));
    }

    let share_id = selected[0].1;
    for (fingerprint, actual_share_id, _) in &selected {
        anyhow::ensure!(
            *actual_share_id == share_id,
            "configured KP cert fingerprint {fingerprint} resolves to share id {}, \
             expected share id {}",
            actual_share_id.get(),
            share_id.get()
        );
    }

    let mut verified_share: Option<DecryptedShare> = None;
    for (index, (fingerprint, _, ciphertext)) in selected.into_iter().enumerate() {
        info!(
            phase = "share decrypt",
            certificate_index = index + 1,
            certificate_count = kp_certs.len(),
            share_id = share_id.get(),
            fingerprint = %fingerprint,
            "decrypting encrypted share copy via yubikey"
        );
        let candidate = decrypt_pgp_ciphertext(share_id, ciphertext).with_context(|| {
            format!(
                "decrypt share id {} for fingerprint {fingerprint}",
                share_id.get()
            )
        })?;
        state
            .secret_sharing_instance
            .commitments()
            .verify_share(&candidate)
            .with_context(|| {
                format!(
                    "decrypted share id {} for fingerprint {fingerprint} does not match its commitment",
                    share_id.get()
                )
            })?;

        match &verified_share {
            Some(expected) => anyhow::ensure!(
                candidate.id == expected.id && candidate.value == expected.value,
                "decrypted share copy for fingerprint {fingerprint} differs from the first \
                 verified copy"
            ),
            None => verified_share = Some(candidate),
        }

        info!(
            phase = "share decrypt",
            certificate_index = index + 1,
            certificate_count = kp_certs.len(),
            share_id = share_id.get(),
            fingerprint = %fingerprint,
            "decrypted and verified encrypted share copy"
        );
    }

    verified_share.ok_or_else(|| anyhow!("at least one KP cert is required"))
}

/// Load the cert selected by this KP for the current command.
pub fn load_kp_cert(path: &Path) -> Result<PgpPublicCert> {
    let cert = PgpPublicCert::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("read KP cert at {}", path.display()))?,
    )
    .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
    info!(
        fingerprint = %cert.fingerprint(),
        path = %path.display(),
        "loaded this KP's cert"
    );
    Ok(cert)
}

/// Decrypt a KP's selected PGP-encrypted share via the yubikey-backed gpg
/// agent, returning the share wrapped in a [`DecryptedShare`] that wipes its
/// scalar on drop. Nothing touches disk: gpg reads the ciphertext from a piped
/// stdin and streams the plaintext over its stdout pipe into memory.
///
/// **Zeroization scope:** the gpg plaintext bytes, the intermediate scalar
/// byte array, and the returned wrapper's inner [`Scalar`] are zeroed on drop.
/// `k256::Scalar` is `Copy`, so the compiler may produce transient stack
/// copies (e.g. inside `verify_share` / `build_from_share`) that this can't
/// reach — those are wiped only when the process exits. The named locations
/// this code owns are wiped deterministically.
pub fn decrypt_pgp_ciphertext(share_id: ShareID, ciphertext: &str) -> Result<DecryptedShare> {
    let plaintext = Zeroizing::new(decrypt_armored_via_gpg(ciphertext, None)?);
    let scalar = scalar_from_decrypted_plaintext(&plaintext)?;
    Ok(DecryptedShare(Share {
        id: share_id,
        value: scalar,
    }))
}

/// Owning wrapper around a decrypted [`Share`] that wipes the scalar value on
/// drop. Use `&*share` to access the inner [`Share`] for commitment
/// verification / re-encryption. See [`decrypt_pgp_ciphertext`] for the
/// zeroization scope.
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
/// [`decrypt_pgp_ciphertext`] so the byte-length and canonical-scalar checks are
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
    use hashi_types::guardian::KPEncryptedSharesRoster;
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

    fn encrypted_share(id: u16, cert: &PgpPublicCert) -> KPEncryptedShares {
        KPEncryptedShares {
            id: NonZeroU16::new(id).unwrap(),
            ciphertexts_by_fingerprint: [(
                cert.fingerprint().to_hex(),
                encrypt_armored(&[id as u8; 32], cert).unwrap(),
            )]
            .into_iter()
            .collect(),
        }
    }

    fn encrypted_response(certs_by_share: &[&PgpPublicCert]) -> SetupNewKeyResponse {
        let n = certs_by_share.len();
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedSharesRoster::new(
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

    fn encrypted_response_from_sets(
        cert_sets_by_share: &[Vec<&PgpPublicCert>],
    ) -> SetupNewKeyResponse {
        let n = cert_sets_by_share.len();
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedSharesRoster::new(
                cert_sets_by_share
                    .iter()
                    .enumerate()
                    .map(|(i, certs)| {
                        let id = (i + 1) as u16;
                        KPEncryptedShares {
                            id: NonZeroU16::new(id).unwrap(),
                            ciphertexts_by_fingerprint: certs
                                .iter()
                                .map(|cert| {
                                    (
                                        cert.fingerprint().to_hex(),
                                        encrypt_armored(&[id as u8; 32], cert).unwrap(),
                                    )
                                })
                                .collect(),
                        }
                    })
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

    fn cert_set(certs: &[&PgpPublicCert]) -> KpCerts {
        KpCerts::new(certs.iter().map(|cert| (*cert).clone()).collect()).unwrap()
    }

    fn certs_roster(cert_sets: Vec<KpCerts>) -> KpCertsRoster {
        KpCertsRoster::new(cert_sets).unwrap()
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_single_cert_sets() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);
        let state = CeremonyState::from(resp);

        state
            .encrypted_shares
            .verify_recipients(&certs_roster(vec![
                cert_set(&[&cert1]),
                cert_set(&[&cert2]),
                cert_set(&[&cert3]),
            ]))
            .expect("recipient validation should accept the matching cert roster");
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_multiple_certs_per_share() {
        let cert1 = mock_cert();
        let cert2a = mock_cert();
        let cert2b = mock_cert();
        let cert3 = mock_cert();
        let resp =
            encrypted_response_from_sets(&[vec![&cert1], vec![&cert2a, &cert2b], vec![&cert3]]);
        let state = CeremonyState::from(resp);

        assert_eq!(state.encrypted_shares.share_count(), 3);
        assert_eq!(state.encrypted_shares.ciphertext_count(), 4);
        state
            .encrypted_shares
            .verify_recipients(&certs_roster(vec![
                cert_set(&[&cert1]),
                cert_set(&[&cert2a, &cert2b]),
                cert_set(&[&cert3]),
            ]))
            .expect("recipient validation should accept multi-cert KP sets");
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_wrong_cert_grouping() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);
        let state = CeremonyState::from(resp);

        let err = state
            .encrypted_shares
            .verify_recipients(&certs_roster(vec![
                cert_set(&[&cert2]),
                cert_set(&[&cert1]),
                cert_set(&[&cert3]),
            ]))
            .unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
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
