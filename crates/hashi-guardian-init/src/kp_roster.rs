// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared KP-roster config + ceremony-state verification, used by both the
//! `key-provisioner ceremony` and `key-provisioner provision` commands.
//!
//! Both commands need to:
//! - load a roster of KP OpenPGP certs
//! - discover the latest attested ceremony from S3
//! - validate the ceremony's `secret_sharing_instance` against expected params
//! - confirm every encrypted share in `shares/` is addressed only to its
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
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::KPEncryptedShare;
use hashi_types::guardian::KPEncryptedShares;
use hashi_types::guardian::KPFingerprint;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::SetupNewKeyResponse;
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

/// Common KP-roster config: the sharing params, the guardian's S3 log bucket,
/// the full KP cert roster, and the PCR allowlist. Shared (via
/// `#[serde(flatten)]`) by `operator ceremony`, `key-provisioner ceremony`, and
/// `key-provisioner provision` —
/// every command that needs to discover and verify a ceremony against an
/// expected KP set.
#[derive(Deserialize)]
pub struct KpRosterConfig {
    /// Total number of shares. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// S3 config for the guardian's log bucket (object-lock enabled).
    pub guardian_s3: S3Config,
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

/// Validated ceremony state. May come from the live `SetupNewKeyResponse`
/// (`operator ceremony`) or be reconstructed from the guardian's `ceremony/` +
/// `shares/` logs (`key-provisioner ceremony`, `key-provisioner provision`).
#[derive(Debug, PartialEq)]
pub struct VerifiedCeremonyState {
    pub session_id: String,
    pub encrypted_shares: KPEncryptedShares,
    pub secret_sharing_instance: SecretSharingInstance,
}

impl VerifiedCeremonyState {
    pub fn from_response(
        response: SetupNewKeyResponse,
        session_id: String,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        let state = Self {
            session_id,
            encrypted_shares: response.encrypted_shares,
            secret_sharing_instance: response.secret_sharing_instance,
        };
        state.validate(expected_sharing_seq, expected_n, expected_t)?;
        Ok(state)
    }

    pub async fn latest_from_s3(
        reader: &mut GuardianReader,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        // TODO: KP-begins discovery for rotations needs to read the latest
        // historical ceremony with `BuildPolicy::AnyAllowlisted` to learn N.
        // Keep this helper current-build-only for target verification, and add
        // a separate discovery path there.
        let (session_id, instance, roster) = reader
            .read_latest_ceremony(BuildPolicy::Current)
            .await?
            .ok_or_else(|| anyhow!("no ceremony logs found in guardian S3 bucket"))?;
        let encrypted_shares = reader
            .read_shares(&session_id, instance.sharing_seq(), BuildPolicy::Current)
            .await?;
        Self::from_scraped(
            session_id,
            instance,
            encrypted_shares,
            &roster,
            expected_sharing_seq,
            expected_n,
            expected_t,
        )
    }

    /// Assemble + validate from parts already scraped from S3 (the ceremony
    /// log and the shares log). Use instead of [`Self::latest_from_s3`] when the
    /// caller has already read those objects and wants to avoid a second walk.
    pub fn from_scraped(
        session_id: String,
        secret_sharing_instance: SecretSharingInstance,
        encrypted_shares: KPEncryptedShares,
        roster: &[KPFingerprint],
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        let state = Self {
            session_id,
            encrypted_shares,
            secret_sharing_instance,
        };
        state.validate(expected_sharing_seq, expected_n, expected_t)?;
        state.ensure_roster_matches(roster)?;
        Ok(state)
    }

    /// Confirm the state uses the expected ceremony instance and carries
    /// exactly `expected_n` encrypted shares.
    pub fn validate(
        &self,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<()> {
        anyhow::ensure!(
            self.secret_sharing_instance.sharing_seq() == expected_sharing_seq,
            "ceremony sharing_seq ({}) differs from expected ({expected_sharing_seq})",
            self.secret_sharing_instance.sharing_seq()
        );
        anyhow::ensure!(
            self.secret_sharing_instance.num_shares() == expected_n,
            "ceremony num_shares ({}) differs from expected ({expected_n})",
            self.secret_sharing_instance.num_shares()
        );
        anyhow::ensure!(
            self.secret_sharing_instance.threshold() == expected_t,
            "ceremony threshold ({}) differs from expected ({expected_t})",
            self.secret_sharing_instance.threshold()
        );
        anyhow::ensure!(
            self.encrypted_shares.len() == expected_n,
            "expected {expected_n} encrypted shares, got {}",
            self.encrypted_shares.len()
        );
        Ok(())
    }

    /// Confirm the agreed `ceremony/` roster matches the recipient fingerprints
    /// on the `shares/` ciphertexts. The roster is ordered by share id, so this
    /// check preserves the ceremony log's share-id-to-KP binding.
    pub fn ensure_roster_matches(&self, roster: &[KPFingerprint]) -> Result<()> {
        let got = self.encrypted_shares.recipient_roster();
        anyhow::ensure!(
            roster == got.as_slice(),
            "ceremony/ roster differs from shares/ recipient fingerprints: expected \
             {roster:?}, got {got:?}"
        );
        Ok(())
    }

    /// For each encrypted share, confirm (a) its `recipient_fingerprint` label
    /// names exactly one of the operator-supplied certs, and (b) the ciphertext
    /// is actually encrypted only to that cert (parsed via PKESK without
    /// decrypting).
    ///
    /// Identity is by fingerprint, not positional index — a share is matched to
    /// its cert by `recipient_fingerprint`, independent of ordering.
    pub fn verify_encrypted_share_recipients(&self, certs: &[PgpPublicCert]) -> Result<()> {
        let by_fingerprint: std::collections::HashMap<KPFingerprint, &PgpPublicCert> =
            certs.iter().map(|c| (c.fingerprint(), c)).collect();
        anyhow::ensure!(
            by_fingerprint.len() == certs.len(),
            "duplicate fingerprints among the supplied KP certs"
        );

        let mut expected_fingerprints: Vec<KPFingerprint> =
            by_fingerprint.keys().cloned().collect();
        expected_fingerprints.sort_unstable();
        let mut labeled_fingerprints: Vec<KPFingerprint> = self
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

        for share in self.encrypted_shares.iter() {
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
            "all {} shares encrypted to their labeled certs",
            self.encrypted_shares.len()
        );
        Ok(())
    }
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
    use hashi_types::guardian::ShareCommitment;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::pgp::encrypt_armored;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::num::NonZeroU16;

    fn share(id: u16) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint: format!("DUMMY FINGERPRINT {id}"),
            armored_ciphertext: "dummy".into(),
        }
    }

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

    fn response(shares: &[u16], commitment_ids: &[u16]) -> SetupNewKeyResponse {
        response_with_instance(
            shares,
            SecretSharingInstance::new(commitments(commitment_ids), commitment_ids.len(), 2, 0)
                .unwrap(),
        )
    }

    fn response_with_instance(
        shares: &[u16],
        secret_sharing_instance: SecretSharingInstance,
    ) -> SetupNewKeyResponse {
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedShares::new(shares.iter().map(|&i| share(i)).collect())
                .unwrap(),
            secret_sharing_instance,
        }
    }

    fn mock_cert() -> PgpPublicCert {
        let (public, _secret) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
    }

    fn encrypted_share(id: u16, cert: &PgpPublicCert) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint: cert.fingerprint(),
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
        }
    }

    #[test]
    fn verified_ceremony_state_accepts_well_formed() {
        let resp = response(&[1, 2, 3], &[1, 2, 3]);
        VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("well-formed response should pass");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_share_count() {
        let resp = response(&[1, 2], &[1, 2, 3]);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("encrypted shares"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_num_shares() {
        let resp = response(&[1, 2], &[1, 2]);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("num_shares"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_threshold() {
        let instance = SecretSharingInstance::new(commitments(&[1, 2, 3]), 3, 3, 0).unwrap();
        let resp = response_with_instance(&[1, 2, 3], instance);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("threshold"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_sharing_seq() {
        let instance = SecretSharingInstance::new(commitments(&[1, 2, 3]), 3, 2, 1).unwrap();
        let resp = response_with_instance(&[1, 2, 3], instance);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("sharing_seq"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_matches_roster() {
        // Shares arrive in arbitrary id order (`[3, 1, 2]`), but
        // KPEncryptedShares normalizes them by share id. The ceremony roster is
        // ordered by share id too, so a permutation must fail.
        let resp = response(&[3, 1, 2], &[1, 2, 3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");
        let canonical = vec![
            "DUMMY FINGERPRINT 1".to_string(),
            "DUMMY FINGERPRINT 2".to_string(),
            "DUMMY FINGERPRINT 3".to_string(),
        ];
        let reordered = vec![
            "DUMMY FINGERPRINT 3".to_string(),
            "DUMMY FINGERPRINT 1".to_string(),
            "DUMMY FINGERPRINT 2".to_string(),
        ];

        state
            .ensure_roster_matches(&canonical)
            .expect("canonical roster matches");
        let err = state.ensure_roster_matches(&reordered).unwrap_err();
        assert!(format!("{err}").contains("roster differs"), "{err}");

        // A genuinely different fingerprint set must still fail.
        let different = vec![
            "DUMMY FINGERPRINT 1".to_string(),
            "DUMMY FINGERPRINT 2".to_string(),
            "DUMMY FINGERPRINT 9".to_string(),
        ];
        let err = state.ensure_roster_matches(&different).unwrap_err();
        assert!(format!("{err}").contains("roster differs"), "{err}");
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_reordered_expected_certs() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        state
            .verify_encrypted_share_recipients(&[cert3, cert1, cert2])
            .expect("recipient validation should be by fingerprint, not config order");
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_duplicate_share_labels() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert1, &cert3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        let err = state
            .verify_encrypted_share_recipients(&[cert1, cert2, cert3])
            .unwrap_err();
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
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        let err = state
            .verify_encrypted_share_recipients(&[cert1, cert2, cert3])
            .unwrap_err();
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
