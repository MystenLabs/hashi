// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::primitives::*;
use crate::guardian::errors::GuardianError::InvalidInputs;
use crate::guardian::errors::GuardianResult;
use crate::pgp::Fingerprint;
use crate::pgp::PgpPublicCert;
use crate::pgp::cert_owns_key_handle;
use crate::pgp::encrypt_armored;
use crate::pgp::pgp_message_recipients;
use k256::Scalar;
use k256::Secp256k1;
use k256::elliptic_curve::ScalarPrimitive;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use tracing::info;

/// A key-provisioner's PGP fingerprint as bare uppercase hex — the string
/// form persisted in ceremony artifacts (ciphertext map keys, log rosters). For
/// comparing fingerprints, prefer the canonical [`crate::pgp::Fingerprint`].
pub type KPFingerprint = String;

/// One key provisioner's accepted OpenPGP certs. A KP may have multiple
/// certs for the same share id, e.g. independent yubikeys.
/// Certificates must have unique fingerprints.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KpCerts(Vec<PgpPublicCert>);

/// The ordered KP certificate roster for a sharing instance.
///
/// The cert collection at position `i` is assigned share id `i + 1`. This type
/// preserves that caller-supplied order and requires every certificate
/// fingerprint to occur in exactly one roster entry. Each [`KpCerts`]
/// separately canonicalizes its certificate order.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KpCertsRoster(Vec<KpCerts>);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianEncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

/// The encrypted copies of one secret share assigned to one KP, with one
/// ciphertext per accepted certificate.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KPEncryptedShares {
    pub id: ShareID,
    /// Recipient PGP fingerprint to armored ciphertext.
    pub ciphertexts_by_fingerprint: BTreeMap<KPFingerprint, String>,
}

/// The complete encrypted-share roster for a ceremony, canonicalized by share
/// id. Each entry contains one KP's ciphertexts.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KPEncryptedSharesRoster(Vec<KPEncryptedShares>);

impl KpCerts {
    pub fn new(mut pgp_certs: Vec<PgpPublicCert>) -> GuardianResult<Self> {
        if pgp_certs.is_empty() {
            return Err(InvalidInputs(
                "KP certs must contain at least one OpenPGP certificate".into(),
            ));
        }

        pgp_certs.sort_by_key(|cert| cert.fingerprint().to_hex());
        let mut seen = HashSet::with_capacity(pgp_certs.len());
        for cert in &pgp_certs {
            let fingerprint = cert.fingerprint();
            if !seen.insert(fingerprint.clone()) {
                return Err(InvalidInputs(format!(
                    "duplicate OpenPGP certificate fingerprint {fingerprint}"
                )));
            }
        }

        Ok(Self(pgp_certs))
    }

    pub fn pgp_certs(&self) -> &[PgpPublicCert] {
        &self.0
    }

    pub fn into_pgp_certs(self) -> Vec<PgpPublicCert> {
        self.0
    }

    pub fn fingerprints(&self) -> Vec<KPFingerprint> {
        self.0
            .iter()
            .map(|cert| cert.fingerprint().to_hex())
            .collect()
    }

    /// Replace one certificate identified by its current primary-key
    /// fingerprint, then revalidate and canonicalize this KP's certificate set.
    pub fn replace_cert(
        self,
        current_fingerprint: &Fingerprint,
        new_cert: PgpPublicCert,
    ) -> GuardianResult<Self> {
        let mut pgp_certs = self.0;
        let cert = pgp_certs
            .iter_mut()
            .find(|cert| cert.fingerprint() == *current_fingerprint)
            .ok_or_else(|| {
                InvalidInputs(format!(
                    "OpenPGP certificate fingerprint {current_fingerprint} is not in this KP \
                    certificate set"
                ))
            })?;
        let new_fingerprint = new_cert.fingerprint();
        if new_fingerprint == *current_fingerprint {
            return Err(InvalidInputs(format!(
                "replacement OpenPGP certificate fingerprint {new_fingerprint} must differ from \
                 the current fingerprint"
            )));
        }
        *cert = new_cert;
        Self::new(pgp_certs)
    }
}

impl KpCertsRoster {
    pub fn new(kp_certs: Vec<KpCerts>) -> GuardianResult<Self> {
        let cert_count = kp_certs.iter().map(|certs| certs.pgp_certs().len()).sum();
        let mut seen = HashSet::with_capacity(cert_count);
        for cert in kp_certs.iter().flat_map(KpCerts::pgp_certs) {
            let fingerprint = cert.fingerprint();
            if !seen.insert(fingerprint.clone()) {
                return Err(InvalidInputs(format!(
                    "duplicate OpenPGP certificate fingerprint {fingerprint}"
                )));
            }
        }

        Ok(Self(kp_certs))
    }

    pub fn num_kps(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &KpCerts> {
        self.0.iter()
    }

    pub fn certs_for_share(&self, share_id: ShareID) -> Option<&KpCerts> {
        self.0.get(usize::from(share_id.get()) - 1)
    }

    /// Return the complete KP cert set containing `fingerprint`.
    pub fn certs_for_fingerprint(&self, fingerprint: &Fingerprint) -> Option<&KpCerts> {
        self.0.iter().find(|certs| {
            certs
                .pgp_certs()
                .iter()
                .any(|cert| cert.fingerprint() == *fingerprint)
        })
    }

    pub fn fingerprints(&self) -> Vec<Vec<KPFingerprint>> {
        self.0.iter().map(KpCerts::fingerprints).collect()
    }

    pub fn into_vec(self) -> Vec<KpCerts> {
        self.0
    }

    /// Replace one certificate in the roster while preserving the KP/share
    /// ordering and global fingerprint-uniqueness invariant.
    pub fn replace_cert(
        self,
        current_fingerprint: &Fingerprint,
        new_cert: PgpPublicCert,
    ) -> GuardianResult<Self> {
        let mut kp_certs = self.0;
        let certs = kp_certs
            .iter_mut()
            .find(|certs| {
                certs
                    .pgp_certs()
                    .iter()
                    .any(|cert| cert.fingerprint() == *current_fingerprint)
            })
            .ok_or_else(|| {
                InvalidInputs(format!(
                    "OpenPGP certificate fingerprint {current_fingerprint} is not in the KP \
                     certificate roster"
                ))
            })?;
        *certs = certs.clone().replace_cert(current_fingerprint, new_cert)?;
        Self::new(kp_certs)
    }
}

impl KPEncryptedShares {
    /// Verify that this share has exactly one ciphertext per expected cert and
    /// that every ciphertext targets only keys owned by its keyed cert.
    pub fn verify_recipients(&self, certs: &KpCerts) -> GuardianResult<()> {
        let expected_fingerprints = certs.fingerprints();
        let actual_fingerprints = self
            .ciphertexts_by_fingerprint
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        if actual_fingerprints != expected_fingerprints {
            return Err(InvalidInputs(format!(
                "encrypted share recipient roster differs for share id {}: expected {:?}, got \
                 {:?}",
                self.id.get(),
                expected_fingerprints,
                actual_fingerprints
            )));
        }

        for cert in certs.pgp_certs() {
            let fingerprint = cert.fingerprint().to_hex();
            let ciphertext = self
                .ciphertexts_by_fingerprint
                .get(&fingerprint)
                .expect("fingerprint rosters were checked for equality");
            verify_pgp_ciphertext_recipient(self.id, &fingerprint, ciphertext, cert)?;
        }
        Ok(())
    }
}

impl KPEncryptedSharesRoster {
    pub fn new(mut shares: Vec<KPEncryptedShares>) -> GuardianResult<Self> {
        shares.sort_by_key(|s| s.id);

        if shares.len() > MAX_NUM_SHARES {
            return Err(InvalidInputs(format!(
                "{} shares must be at most u16::MAX",
                shares.len()
            )));
        }
        let ids: Vec<u16> = shares.iter().map(|s| s.id.get()).collect();
        let expected: Vec<u16> = (1..=shares.len() as u16).collect();
        if ids != expected {
            return Err(InvalidInputs(format!(
                "encrypted share ids are not exactly 1..={}: got {ids:?}",
                shares.len()
            )));
        }

        let mut seen_fingerprints = HashSet::new();
        for share in &shares {
            if share.ciphertexts_by_fingerprint.is_empty() {
                return Err(InvalidInputs(format!(
                    "encrypted share id {} must have at least one PGP ciphertext",
                    share.id.get()
                )));
            }
            for fingerprint in share.ciphertexts_by_fingerprint.keys() {
                if !seen_fingerprints.insert(fingerprint.clone()) {
                    return Err(InvalidInputs(format!(
                        "duplicate encrypted share recipient fingerprint {}",
                        fingerprint
                    )));
                }
            }
        }

        Ok(Self(shares))
    }

    /// Number of secret shares, not the number of cert-wrapped
    /// ciphertexts. A KP may have multiple ciphertexts for the same share id.
    pub fn share_count(&self) -> usize {
        self.0.len()
    }

    pub fn ciphertext_count(&self) -> usize {
        self.0
            .iter()
            .map(|share| share.ciphertexts_by_fingerprint.len())
            .sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = &KPEncryptedShares> {
        self.0.iter()
    }

    pub fn into_vec(self) -> Vec<KPEncryptedShares> {
        self.0
    }

    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<(&KPEncryptedShares, &str)> {
        self.iter().find_map(|share| {
            share
                .ciphertexts_by_fingerprint
                .get(fingerprint)
                .map(|ciphertext| (share, ciphertext.as_str()))
        })
    }

    /// Require `fingerprint` to be assigned to `submitted_share_id` in this
    /// encrypted-share roster.
    pub fn validate_share_assignment(
        &self,
        fingerprint: &str,
        submitted_share_id: ShareID,
    ) -> GuardianResult<()> {
        let (assigned_share, _) = self.find_by_fingerprint(fingerprint).ok_or_else(|| {
            InvalidInputs(format!(
                "KP fingerprint {fingerprint} is not present in the encrypted-share roster"
            ))
        })?;
        if assigned_share.id != submitted_share_id {
            return Err(InvalidInputs(format!(
                "KP fingerprint {fingerprint} is assigned share id {}, not submitted share id {}",
                assigned_share.id.get(),
                submitted_share_id.get()
            )));
        }
        Ok(())
    }

    /// Replace one certificate-specific ciphertext while preserving every
    /// other KP/share entry and revalidating global fingerprint uniqueness.
    pub fn replace_recipient(
        self,
        current_fingerprint: &str,
        new_fingerprint: KPFingerprint,
        new_ciphertext: String,
    ) -> GuardianResult<(Self, KPEncryptedShares)> {
        if new_fingerprint == current_fingerprint {
            return Err(InvalidInputs(format!(
                "replacement KP fingerprint {new_fingerprint} must differ from the current \
                 fingerprint"
            )));
        }
        if self.find_by_fingerprint(&new_fingerprint).is_some() {
            return Err(InvalidInputs(format!(
                "new KP fingerprint {new_fingerprint} is already present in the encrypted share \
                 roster"
            )));
        }

        let mut shares = self.0;
        let share = shares
            .iter_mut()
            .find(|share| {
                share
                    .ciphertexts_by_fingerprint
                    .contains_key(current_fingerprint)
            })
            .ok_or_else(|| {
                InvalidInputs(format!(
                    "current KP fingerprint {current_fingerprint} is not present in the \
                     encrypted share roster"
                ))
            })?;
        share
            .ciphertexts_by_fingerprint
            .remove(current_fingerprint)
            .expect("the current fingerprint was located in this entry");
        share
            .ciphertexts_by_fingerprint
            .insert(new_fingerprint, new_ciphertext);
        let changed_share = share.clone();
        Ok((Self::new(shares)?, changed_share))
    }

    /// Recipient PGP fingerprints grouped by share id.
    pub fn recipient_roster(&self) -> Vec<Vec<KPFingerprint>> {
        let mut grouped: Vec<Vec<KPFingerprint>> = Vec::with_capacity(self.share_count());
        for share in &self.0 {
            grouped.push(share.ciphertexts_by_fingerprint.keys().cloned().collect());
        }
        grouped
    }

    /// Verify every encrypted share against the certs assigned to its share id.
    pub fn verify_recipients(&self, certs_roster: &KpCertsRoster) -> GuardianResult<()> {
        if self.share_count() != certs_roster.num_kps() {
            return Err(InvalidInputs(format!(
                "expected {} KP cert roster entries, got {} encrypted shares",
                certs_roster.num_kps(),
                self.share_count()
            )));
        }

        for share in self.iter() {
            let certs = certs_roster
                .certs_for_share(share.id)
                .expect("encrypted share ids are exactly 1..=roster length");
            share.verify_recipients(certs)?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for KPEncryptedSharesRoster {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shares = Vec::<KPEncryptedShares>::deserialize(deserializer)?;
        Self::new(shares).map_err(serde::de::Error::custom)
    }
}

fn verify_pgp_ciphertext_recipient(
    share_id: ShareID,
    recipient_fingerprint: &str,
    ciphertext: &str,
    expected_cert: &PgpPublicCert,
) -> GuardianResult<()> {
    let recipients = pgp_message_recipients(ciphertext).map_err(|e| {
        InvalidInputs(format!(
            "failed to parse PGP recipients for share id {}: {e}",
            share_id.get()
        ))
    })?;
    if recipients.is_empty() {
        return Err(InvalidInputs(format!(
            "share id {} has no PGP recipients",
            share_id.get()
        )));
    }
    for handle in &recipients {
        if !cert_owns_key_handle(expected_cert, handle) {
            return Err(InvalidInputs(format!(
                "share id {} (keyed by {}) is encrypted to key {handle}, which is not in that \
                 cert",
                share_id.get(),
                recipient_fingerprint
            )));
        }
    }
    info!(
        share_id = share_id.get(),
        fingerprint = %recipient_fingerprint,
        recipient_count = recipients.len(),
        "verified encrypted share targets only its keyed recipient cert"
    );
    Ok(())
}

/// Encrypt a share with optional AAD
pub fn encrypt_share<R: CryptoRng + RngCore>(
    share: &Share,
    pk: &EncPubKey,
    aad: Option<&[u8; 32]>,
    rng: &mut R,
) -> GuardianEncryptedShare {
    GuardianEncryptedShare {
        id: share.id,
        ciphertext: encrypt(&share.value.to_bytes(), pk, aad, rng)
            .expect("neither plaintext nor aad are long"),
    }
}

/// Split `sk` into `params.num_shares()` shares with reconstruction threshold
/// `params.threshold()`, encrypt each share to every cert in the matching KP
/// cert collection, and compute one commitment per share. The roster assigns
/// its entry at position `i` to share ID `i + 1`.
///
/// # Panics
///
/// Panics if `kp_certs_roster.num_kps() != params.num_shares()`.
pub fn split_and_encrypt_for_kps<R: CryptoRng + RngCore>(
    sk: &k256::SecretKey,
    kp_certs_roster: &KpCertsRoster,
    params: &SecretSharingParams,
    rng: &mut R,
) -> (KPEncryptedSharesRoster, ShareCommitments) {
    assert_eq!(
        kp_certs_roster.num_kps(),
        params.num_shares(),
        "request validation ensures one KP cert collection per share",
    );
    let shares = split_secret(sk, params, rng);
    let n = params.num_shares();
    let mut encrypted_shares = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    for (share, cert_set) in shares.iter().zip(kp_certs_roster.iter()) {
        let ciphertexts_by_fingerprint = cert_set
            .pgp_certs()
            .iter()
            .map(|cert| {
                (
                    cert.fingerprint().to_hex(),
                    encrypt_share_for_provisioner(share, cert),
                )
            })
            .collect();
        encrypted_shares.push(KPEncryptedShares {
            id: share.id,
            ciphertexts_by_fingerprint,
        });
        commitments.push(commit_share(share));
    }
    let encrypted_shares = KPEncryptedSharesRoster::new(encrypted_shares)
        .expect("split_secret produces share ids exactly 1..=n");
    let commitments =
        ShareCommitments::new(commitments).expect("share IDs 1..=n are unique by construction");
    (encrypted_shares, commitments)
}

/// Encrypt a share for delivery to a key provisioner using OpenPGP ASCII armor.
pub fn encrypt_share_for_provisioner(share: &Share, cert: &PgpPublicCert) -> String {
    encrypt_armored(&share.value.to_bytes(), cert)
        .expect("PgpPublicCert validation ensures OpenPGP encryption works")
}

/// Decrypt an encrypted share with optional AAD
pub fn decrypt_share(
    encrypted_share: &GuardianEncryptedShare,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Share> {
    let serialized_share = decrypt(&encrypted_share.ciphertext, sk, aad)?;
    let value = ScalarPrimitive::<Secp256k1>::from_slice(&serialized_share)
        .map(Scalar::from)
        .map_err(|_| InvalidInputs("Failed to deserialize share".into()))?;
    Ok(Share {
        id: encrypted_share.id,
        value,
    })
}

/// Decrypt each signed submission, verify it against the sharing instance, and
/// reject duplicate share ids. The KP signature authenticates each ciphertext,
/// so no additional HPKE AAD is needed.
pub fn decrypt_verify_shares(
    encrypted: &[GuardianEncryptedShare],
    sk: &EncSecKey,
    instance: &SecretSharingInstance,
) -> GuardianResult<Vec<Share>> {
    let share_count = encrypted.len();
    let threshold = instance.threshold();
    let num_shares = instance.num_shares();
    if share_count < threshold {
        return Err(InvalidInputs(format!(
            "need at least {threshold} signed share submissions, got {share_count}"
        )));
    }
    if share_count > num_shares {
        return Err(InvalidInputs(format!(
            "at most {num_shares} signed share submissions are allowed, got {share_count}"
        )));
    }

    let mut shares: Vec<Share> = Vec::with_capacity(encrypted.len());
    for enc in encrypted {
        let share = decrypt_share(enc, sk, None)?;
        instance.commitments().verify_share(&share)?;
        if shares.iter().any(|s| s.id == share.id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
        shares.push(share);
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgp::test_utils::mock_pgp_keypair;
    use std::num::NonZeroU16;

    fn cert() -> PgpPublicCert {
        let (public, _) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
    }

    #[test]
    fn decrypt_share_rejects_wrong_plaintext_length() {
        let keypair = GuardianEncKeyPair::random(&mut rand::thread_rng());
        for len in [31, 33] {
            let encrypted_share = GuardianEncryptedShare {
                id: ShareID::new(1).unwrap(),
                ciphertext: encrypt(
                    &vec![0; len],
                    keypair.public_key(),
                    None,
                    &mut rand::thread_rng(),
                )
                .unwrap(),
            };

            let Err(err) = decrypt_share(&encrypted_share, keypair.secret_key(), None) else {
                panic!("{len}-byte plaintext must be rejected");
            };
            assert!(matches!(err, InvalidInputs(_)), "{err:?}");
        }
    }

    fn test_kp_encrypted_shares(id: u16) -> KPEncryptedShares {
        test_kp_encrypted_shares_for_fingerprint(id, format!("fingerprint-{id}"))
    }

    fn test_kp_encrypted_shares_for_fingerprint(
        id: u16,
        recipient_fingerprint: String,
    ) -> KPEncryptedShares {
        test_kp_encrypted_shares_for_fingerprints(id, vec![recipient_fingerprint])
    }

    fn test_kp_encrypted_shares_for_fingerprints(
        id: u16,
        recipient_fingerprints: Vec<String>,
    ) -> KPEncryptedShares {
        KPEncryptedShares {
            id: NonZeroU16::new(id).unwrap(),
            ciphertexts_by_fingerprint: recipient_fingerprints
                .into_iter()
                .map(|recipient_fingerprint| {
                    (
                        recipient_fingerprint,
                        "-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----".into(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn kp_encrypted_shares_roster_canonicalizes_by_share_id_then_fingerprint() {
        let shares = KPEncryptedSharesRoster::new(vec![
            test_kp_encrypted_shares(3),
            test_kp_encrypted_shares_for_fingerprints(
                2,
                vec!["fingerprint-2".into(), "fingerprint-2b".into()],
            ),
            test_kp_encrypted_shares(1),
        ])
        .unwrap();

        let entries = shares
            .iter()
            .map(|s| {
                (
                    s.id.get(),
                    s.ciphertexts_by_fingerprint
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec![
                (1, vec!["fingerprint-1"]),
                (2, vec!["fingerprint-2", "fingerprint-2b"]),
                (3, vec!["fingerprint-3"]),
            ]
        );
        assert_eq!(shares.share_count(), 3);
        assert_eq!(shares.ciphertext_count(), 4);
        assert_eq!(
            shares.recipient_roster(),
            vec![
                vec!["fingerprint-1".to_string()],
                vec!["fingerprint-2".to_string(), "fingerprint-2b".to_string()],
                vec!["fingerprint-3".to_string()],
            ]
        );
    }

    #[test]
    fn kp_encrypted_shares_roster_rejects_wrong_share_ids() {
        let err = KPEncryptedSharesRoster::new(vec![
            test_kp_encrypted_shares(1),
            test_kp_encrypted_shares(2),
            test_kp_encrypted_shares(4),
        ])
        .expect_err("ids [1, 2, 4] are not exactly 1..=n");
        assert!(format!("{err}").contains("share ids"), "{err}");
    }

    #[test]
    fn kp_encrypted_shares_roster_replaces_one_recipient_and_preserves_the_rest() {
        let shares = KPEncryptedSharesRoster::new(vec![
            test_kp_encrypted_shares_for_fingerprints(1, vec!["a".into(), "b".into()]),
            test_kp_encrypted_shares_for_fingerprints(2, vec!["c".into()]),
        ])
        .unwrap();

        let (rotated, changed) = shares
            .clone()
            .replace_recipient("a", "d".into(), "new ciphertext".into())
            .unwrap();
        assert_eq!(changed.id.get(), 1);
        assert_eq!(
            changed
                .ciphertexts_by_fingerprint
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["b", "d"]
        );
        assert_eq!(rotated.ciphertext_count(), 3);
        assert!(rotated.find_by_fingerprint("a").is_none());
        assert!(rotated.find_by_fingerprint("b").is_some());
        assert!(rotated.find_by_fingerprint("c").is_some());
        assert!(rotated.find_by_fingerprint("d").is_some());

        let err = shares
            .clone()
            .replace_recipient("a", "c".into(), "collision".into())
            .unwrap_err();
        assert!(format!("{err}").contains("already present"), "{err}");

        let err = shares
            .replace_recipient("a", "a".into(), "same fingerprint".into())
            .unwrap_err();
        assert!(format!("{err}").contains("must differ"), "{err}");
    }

    #[test]
    fn kp_encrypted_shares_roster_deserialize_through_validation() {
        let json = serde_json::to_string(&vec![
            test_kp_encrypted_shares(2),
            test_kp_encrypted_shares(1),
        ])
        .unwrap();
        let shares: KPEncryptedSharesRoster = serde_json::from_str(&json).unwrap();
        let ids = shares.iter().map(|s| s.id.get()).collect::<Vec<_>>();
        assert_eq!(ids, vec![1, 2]);

        let bad_json = serde_json::to_string(&vec![
            test_kp_encrypted_shares(1),
            test_kp_encrypted_shares(1),
        ])
        .unwrap();
        let err = serde_json::from_str::<KPEncryptedSharesRoster>(&bad_json).unwrap_err();
        assert!(err.to_string().contains("encrypted share ids"), "{err}");
    }

    #[test]
    fn replace_cert_preserves_kp_grouping_and_rejects_fingerprint_collisions() {
        let old = cert();
        let sibling = cert();
        let other_kp = cert();
        let replacement = cert();
        let roster = KpCertsRoster::new(vec![
            KpCerts::new(vec![old.clone(), sibling.clone()]).unwrap(),
            KpCerts::new(vec![other_kp.clone()]).unwrap(),
        ])
        .unwrap();

        let rotated = roster
            .clone()
            .replace_cert(&old.fingerprint(), replacement.clone())
            .unwrap();
        assert_eq!(rotated.num_kps(), 2);
        assert_eq!(
            rotated.fingerprints(),
            vec![
                KpCerts::new(vec![sibling.clone(), replacement])
                    .unwrap()
                    .fingerprints(),
                vec![other_kp.fingerprint().to_hex()],
            ]
        );

        let err = roster
            .clone()
            .replace_cert(&old.fingerprint(), sibling)
            .unwrap_err();
        assert!(format!("{err}").contains("duplicate"), "{err}");

        let err = roster.replace_cert(&old.fingerprint(), old).unwrap_err();
        assert!(format!("{err}").contains("must differ"), "{err}");
    }

    #[test]
    fn finds_complete_cert_set_by_member_fingerprint() {
        let first = cert();
        let sibling = cert();
        let other_kp = cert();
        let expected = KpCerts::new(vec![first, sibling.clone()]).unwrap();
        let roster = KpCertsRoster::new(vec![
            expected.clone(),
            KpCerts::new(vec![other_kp]).unwrap(),
        ])
        .unwrap();

        assert_eq!(
            roster.certs_for_fingerprint(&sibling.fingerprint()),
            Some(&expected)
        );
        assert!(
            roster
                .certs_for_fingerprint(&cert().fingerprint())
                .is_none()
        );
    }
}
