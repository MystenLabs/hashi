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
//!   expected certificate for that KP/share id (without decrypting)
//!
//! The decryption helper lives here so all commands share the same
//! gpg-streaming pattern.

use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::KpCertRoster;
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
    /// Ordered paths to each KP's armored OpenPGP public certificate. The path
    /// at index `i` is assigned share id `i + 1`; read-only commands match
    /// shares by fingerprint.
    pub kp_pgp_cert_paths: Vec<PathBuf>,
    #[serde(flatten)]
    pub pcr_allowlist: PcrAllowlist,
}

impl KpRosterConfig {
    pub fn validate(&self) -> Result<()> {
        validate_kp_set(self.num_shares, self.threshold, &self.kp_pgp_cert_paths)
    }

    pub fn load_certs_roster(&self) -> Result<KpCertRoster> {
        load_kp_certs_roster(&self.kp_pgp_cert_paths)
    }

    /// The PCR allowlist decoded from `current_build` + `prev_builds`.
    pub fn pcr_allowlist(&self) -> PcrAllowlist {
        self.pcr_allowlist.clone()
    }
}

/// The KP set a `rotate-kp-set` proposes: sharing params and one cert per
/// KP, in share order. The proposal carries `kp_roster`'s PCR allowlist.
#[derive(Deserialize)]
pub struct KpSetConfig {
    pub num_shares: usize,
    pub threshold: usize,
    pub kp_pgp_cert_paths: Vec<PathBuf>,
}

impl KpSetConfig {
    pub fn validate(&self) -> Result<()> {
        validate_kp_set(self.num_shares, self.threshold, &self.kp_pgp_cert_paths)
    }

    pub fn params(&self) -> Result<SecretSharingParams> {
        SecretSharingParams::new(self.num_shares, self.threshold)
            .map_err(|e| anyhow!("invalid sharing params: {e:?}"))
    }

    pub fn load_certs_roster(&self) -> Result<KpCertRoster> {
        load_kp_certs_roster(&self.kp_pgp_cert_paths)
    }
}

fn validate_kp_set(num_shares: usize, threshold: usize, cert_paths: &[PathBuf]) -> Result<()> {
    SecretSharingParams::new(num_shares, threshold)
        .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;

    let cert_path_count = cert_paths.len();
    anyhow::ensure!(
        num_shares == cert_path_count,
        "num_shares ({num_shares}) must equal the number of KP cert paths ({cert_path_count})"
    );
    Ok(())
}

fn load_kp_certs_roster(cert_paths: &[PathBuf]) -> Result<KpCertRoster> {
    let certs = cert_paths
        .iter()
        .enumerate()
        .map(|(idx, cert_path)| {
            load_cert(cert_path)
                .with_context(|| format!("invalid KP cert at roster position {}", idx + 1))
        })
        .collect::<Result<Vec<_>>>()?;
    KpCertRoster::new(certs).context("invalid KP certificate roster")
}

fn load_cert(path: &PathBuf) -> Result<PgpPublicCert> {
    let armored = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read PGP cert at {}", path.display()))?;
    let cert = PgpPublicCert::new(armored)
        .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
    info!(fingerprint = %cert, path = %path.display(), "loaded PGP cert");
    Ok(cert)
}

/// Find, decrypt, and commitment-check the share addressed to `kp_cert`.
pub fn decrypt_kp_share(state: &CeremonyState, kp_cert: &PgpPublicCert) -> Result<DecryptedShare> {
    decrypt_kp_share_with(state, kp_cert, decrypt_pgp_ciphertext)
}

fn decrypt_kp_share_with(
    state: &CeremonyState,
    kp_cert: &PgpPublicCert,
    decrypt: impl FnOnce(ShareID, &str) -> Result<DecryptedShare>,
) -> Result<DecryptedShare> {
    let fingerprint = kp_cert.fingerprint().to_hex();
    let encrypted_share = state
        .encrypted_shares
        .find_by_fingerprint(&fingerprint)
        .ok_or_else(|| {
            anyhow!(
                "no share in the kp-shares log is addressed to this KP's \
                 fingerprint {fingerprint} (recipients by share: {:?})",
                state.encrypted_shares.recipient_fingerprints()
            )
        })?;
    let share_id = encrypted_share.id;

    info!(
        phase = "share decrypt",
        share_id = share_id.get(),
        fingerprint = %fingerprint,
        "decrypting encrypted share via yubikey"
    );
    let decrypted = decrypt(share_id, &encrypted_share.armored_ciphertext).with_context(|| {
        format!(
            "decrypt share id {} for fingerprint {fingerprint}",
            share_id.get()
        )
    })?;
    state
        .secret_sharing_instance
        .commitments()
        .verify_share(&decrypted)
        .with_context(|| {
            format!(
                "decrypted share id {} for fingerprint {fingerprint} does not match its commitment",
                share_id.get()
            )
        })?;
    info!(
        phase = "share decrypt",
        share_id = share_id.get(),
        fingerprint = %fingerprint,
        "decrypted and verified encrypted share"
    );

    Ok(decrypted)
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
    use hashi_types::guardian::KpEncryptedShare;
    use hashi_types::guardian::KpEncryptedShareRoster;
    use hashi_types::guardian::SecretSharingInstance;
    use hashi_types::guardian::SetupNewKeyResponse;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::num::NonZeroU16;

    fn dummy_btc_pubkey() -> hashi_types::bitcoin::BitcoinPubkey {
        hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey(
            &k256::SecretKey::from_slice(&[9u8; 32]).unwrap(),
        )
    }

    fn mock_cert() -> PgpPublicCert {
        let (public, _secret) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
    }

    fn decryptable_state(certs_by_share: &[&PgpPublicCert]) -> (CeremonyState, Vec<Share>) {
        let shares = certs_by_share
            .iter()
            .enumerate()
            .map(|(i, _)| Share {
                id: NonZeroU16::new((i + 1) as u16).unwrap(),
                value: Scalar::from((i + 11) as u64),
            })
            .collect::<Vec<_>>();
        let encrypted_shares = certs_by_share
            .iter()
            .zip(&shares)
            .map(|(cert, share)| KpEncryptedShare {
                id: share.id,
                recipient_fingerprint: cert.fingerprint().to_hex(),
                armored_ciphertext: format!("ciphertext-for-share-{}", share.id.get()),
            })
            .collect();
        let response = SetupNewKeyResponse {
            encrypted_shares: KpEncryptedShareRoster::new(encrypted_shares).unwrap(),
            secret_sharing_instance: SecretSharingInstance::new(
                ShareCommitments::from_shares(&shares).unwrap(),
                shares.len(),
                2,
                0,
            )
            .unwrap(),
            btc_master_pubkey: dummy_btc_pubkey(),
        };
        (CeremonyState::from(response), shares)
    }

    fn roster_yaml(paths: &str) -> String {
        format!(
            "num_shares: 2\n\
             threshold: 2\n\
             kp_pgp_cert_paths:\n\
             {paths}\
             current_build:\n\
             \x20 git_revision: \"0000000000000000000000000000000000000000\"\n\
             \x20 pcr0: \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\
             prev_builds: []\n"
        )
    }

    #[test]
    fn flat_kp_cert_paths_deserialize_in_order() {
        let cfg: KpRosterConfig =
            serde_yaml::from_str(&roster_yaml("  - /path/kp1.asc\n  - /path/kp2.asc\n")).unwrap();

        assert_eq!(
            cfg.kp_pgp_cert_paths,
            vec![
                PathBuf::from("/path/kp1.asc"),
                PathBuf::from("/path/kp2.asc")
            ]
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn nested_kp_cert_paths_are_rejected() {
        let parsed = serde_yaml::from_str::<KpRosterConfig>(&roster_yaml(
            "  - [/path/kp1-a.asc, /path/kp1-b.asc]\n  - /path/kp2.asc\n",
        ));

        assert!(parsed.is_err(), "nested certificate paths must be rejected");
    }

    #[test]
    fn decrypt_kp_share_selects_singular_recipient_and_verifies_commitment() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let (state, shares) = decryptable_state(&[&cert1, &cert2]);

        let decrypted = decrypt_kp_share_with(&state, &cert2, |id, ciphertext| {
            assert_eq!(id, shares[1].id);
            assert_eq!(ciphertext, "ciphertext-for-share-2");
            Ok(DecryptedShare(shares[1]))
        })
        .expect("the selected scalar share should decrypt and match its commitment");

        assert_eq!(decrypted.id, shares[1].id);
        assert_eq!(decrypted.value, shares[1].value);
    }

    #[test]
    fn decrypt_kp_share_rejects_unaddressed_certificate_without_decrypting() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let unaddressed_cert = mock_cert();
        let (state, _) = decryptable_state(&[&cert1, &cert2]);

        let err = decrypt_kp_share_with(&state, &unaddressed_cert, |_, _| {
            panic!("decrypt must not run when no scalar share matches the certificate")
        })
        .err()
        .expect("an unaddressed certificate must be rejected");

        assert!(
            format!("{err:#}").contains("no share in the kp-shares log is addressed"),
            "{err:#}"
        );
    }

    #[test]
    fn decrypt_kp_share_rejects_decrypted_value_with_wrong_commitment() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let (state, shares) = decryptable_state(&[&cert1, &cert2]);
        let wrong_share = Share {
            id: shares[0].id,
            value: shares[0].value + Scalar::from(1u64),
        };

        let err = decrypt_kp_share_with(&state, &cert1, |_, _| Ok(DecryptedShare(wrong_share)))
            .err()
            .expect("a decrypted value with the wrong commitment must be rejected");

        let message = format!("{err:#}");
        assert!(
            message.contains("does not match its commitment"),
            "{message}"
        );
        assert!(message.contains("No matching share found"), "{message}");
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
