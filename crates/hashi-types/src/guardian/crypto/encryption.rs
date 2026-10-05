// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::primitives::*;
use crate::guardian::errors::GuardianError::InvalidInputs;
use crate::guardian::errors::GuardianResult;
use crate::pgp::AttestedPgpKeys;
use crate::pgp::Fingerprint;
use crate::pgp::PgpPublicCert;
use crate::pgp::encrypt_armored_for_key;
use crate::pgp::pgp_message_recipients;
use k256::Scalar;
use k256::Secp256k1;
use k256::elliptic_curve::ScalarPrimitive;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use tracing::info;

#[cfg(any(test, feature = "test-utils"))]
#[path = "encryption/attested_test_utils.rs"]
pub(crate) mod attested_test_utils;

/// A key-provisioner's PGP fingerprint as bare uppercase hex — the string
/// form persisted in ceremony artifacts. For comparing fingerprints, prefer
/// the canonical [`crate::pgp::Fingerprint`].
pub type KPFingerprint = String;

/// A key-provisioner's PGP certificate and its verified YubiKey attestations.
///
/// Construction checks the certificate and all three PEM artifacts with
/// [`crate::pgp::verify_yubikey_attestations`]. The sole usable signing key must
/// be the primary key attested by SIG; DEC attests the sole usable encryption
/// key separately. This records a successful check
/// at construction, not ongoing freshness or a time-validity policy: the
/// verifier does not enforce X.509 dates, revocation, touch, or freshness, or
/// establish current possession of either private key.
///
/// Fields are immutable; deserialization repeats the pinned attestation checks.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AttestedKpCert {
    cert: PgpPublicCert,
    device_pem: Vec<u8>,
    sig_pem: Vec<u8>,
    dec_pem: Vec<u8>,
    #[serde(skip)]
    keys: AttestedPgpKeys,
}

impl AttestedKpCert {
    /// Validate the attestation bundle using the pinned production trust policy.
    pub fn new(
        cert: PgpPublicCert,
        device_pem: Vec<u8>,
        sig_pem: Vec<u8>,
        dec_pem: Vec<u8>,
    ) -> GuardianResult<Self> {
        let keys = crate::pgp::verify_yubikey_attestations_and_keys(
            &cert,
            &device_pem,
            &sig_pem,
            &dec_pem,
        )
        .map_err(|err| InvalidInputs(format!("invalid KP certificate attestations: {err:#}")))?;
        Ok(Self {
            cert,
            device_pem,
            sig_pem,
            dec_pem,
            keys,
        })
    }

    pub fn cert(&self) -> &PgpPublicCert {
        &self.cert
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.cert.fingerprint()
    }

    pub(crate) fn signing_fingerprint(&self) -> &Fingerprint {
        &self.keys.signing
    }

    pub(crate) fn encryption_fingerprint(&self) -> &Fingerprint {
        &self.keys.encryption
    }

    pub fn device_pem(&self) -> &[u8] {
        &self.device_pem
    }

    pub fn sig_pem(&self) -> &[u8] {
        &self.sig_pem
    }

    pub fn dec_pem(&self) -> &[u8] {
        &self.dec_pem
    }

    pub fn into_parts(self) -> (PgpPublicCert, Vec<u8>, Vec<u8>, Vec<u8>) {
        (self.cert, self.device_pem, self.sig_pem, self.dec_pem)
    }
}

impl<'de> Deserialize<'de> for AttestedKpCert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Bundle {
            cert: PgpPublicCert,
            device_pem: Vec<u8>,
            sig_pem: Vec<u8>,
            dec_pem: Vec<u8>,
        }
        let bundle = Bundle::deserialize(deserializer)?;
        Self::new(
            bundle.cert,
            bundle.device_pem,
            bundle.sig_pem,
            bundle.dec_pem,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// A canonical set of KP certificates, sorted by primary fingerprint in hex order.
///
/// Certificate positions do not identify ownership of existing shares. Use
/// [`KpEncryptedShareRoster`] for share assignments. Canonical order makes
/// equality, serialization, and fresh dealing independent of input order.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KpCertRoster(Vec<AttestedKpCert>);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianEncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

/// One encrypted secret share assigned to one key provisioner.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KpEncryptedShare {
    pub id: ShareID,
    pub recipient_fingerprint: KPFingerprint,
    pub armored_ciphertext: String,
}

/// The complete encrypted-share roster for a ceremony, canonicalized by share
/// id.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KpEncryptedShareRoster(Vec<KpEncryptedShare>);

impl KpCertRoster {
    pub fn new(mut kp_certs: Vec<AttestedKpCert>) -> GuardianResult<Self> {
        kp_certs.sort_by_cached_key(|cert| cert.fingerprint().to_hex());
        for pair in kp_certs.windows(2) {
            let fingerprint = pair[0].fingerprint();
            if fingerprint == pair[1].fingerprint() {
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

    pub fn iter(&self) -> impl Iterator<Item = &AttestedKpCert> {
        self.0.iter()
    }

    pub fn cert_for_fingerprint(&self, fingerprint: &Fingerprint) -> Option<&AttestedKpCert> {
        self.0
            .iter()
            .find(|cert| cert.fingerprint() == *fingerprint)
    }

    pub fn fingerprints(&self) -> Vec<KPFingerprint> {
        self.0
            .iter()
            .map(|cert| cert.fingerprint().to_hex())
            .collect()
    }

    pub fn into_vec(self) -> Vec<AttestedKpCert> {
        self.0
    }

    /// Replace the certificate identified by fingerprint while preserving
    /// fingerprint uniqueness and canonical order. This does not change any
    /// share assignments.
    pub fn replace_cert(
        &self,
        current_fingerprint: &Fingerprint,
        new_cert: AttestedKpCert,
    ) -> GuardianResult<Self> {
        let new_fingerprint = new_cert.fingerprint();
        if new_fingerprint == *current_fingerprint {
            return Err(InvalidInputs(format!(
                "replacement OpenPGP certificate fingerprint {new_fingerprint} must differ from \
                 the current fingerprint"
            )));
        }

        let mut kp_certs = self.0.clone();
        let cert = kp_certs
            .iter_mut()
            .find(|cert| cert.fingerprint() == *current_fingerprint)
            .ok_or_else(|| {
                InvalidInputs(format!(
                    "OpenPGP certificate fingerprint {current_fingerprint} is not in the KP \
                     certificate roster"
                ))
            })?;
        *cert = new_cert;
        Self::new(kp_certs)
    }
}

impl KpEncryptedShare {
    /// Verify the recorded certificate identity and require exactly one OpenPGP
    /// recipient identifying its attested encryption key, including no duplicates.
    pub fn verify_recipient(&self, cert: &AttestedKpCert) -> GuardianResult<()> {
        let expected_fingerprint = cert.fingerprint().to_hex();
        if self.recipient_fingerprint != expected_fingerprint {
            return Err(InvalidInputs(format!(
                "encrypted share recipient differs for share id {}: expected {}, got {}",
                self.id.get(),
                expected_fingerprint,
                self.recipient_fingerprint
            )));
        }
        let recipients = pgp_message_recipients(&self.armored_ciphertext).map_err(|e| {
            InvalidInputs(format!(
                "failed to parse PGP recipients for share id {}: {e}",
                self.id.get()
            ))
        })?;
        let [handle] = recipients.as_slice() else {
            return Err(InvalidInputs(format!(
                "share id {} must have exactly one PGP recipient, got {}",
                self.id.get(),
                recipients.len()
            )));
        };
        let expected_key = sequoia_openpgp::KeyHandle::from(cert.encryption_fingerprint().clone());
        if !expected_key.aliases(handle) {
            return Err(InvalidInputs(format!(
                "share id {} (keyed by {}) is encrypted to key {handle}, which is not the \
                 attested encryption key",
                self.id.get(),
                self.recipient_fingerprint
            )));
        }
        info!(
            share_id = self.id.get(),
            fingerprint = %self.recipient_fingerprint,
            recipient_count = recipients.len(),
            "verified encrypted share targets only its keyed recipient cert"
        );
        Ok(())
    }
}

impl KpEncryptedShareRoster {
    pub fn new(mut shares: Vec<KpEncryptedShare>) -> GuardianResult<Self> {
        shares.sort_by_key(|s| s.id);

        if shares.len() > MAX_NUM_SHARES {
            return Err(InvalidInputs(format!(
                "{} shares must be at most u16::MAX",
                shares.len()
            )));
        }
        if shares
            .iter()
            .enumerate()
            .any(|(index, share)| usize::from(share.id.get()) != index + 1)
        {
            let ids = shares
                .iter()
                .map(|share| share.id.get())
                .collect::<Vec<_>>();
            return Err(InvalidInputs(format!(
                "encrypted share ids are not exactly 1..={}: got {ids:?}",
                shares.len()
            )));
        }

        let mut seen_fingerprints: HashSet<&str> = HashSet::with_capacity(shares.len());
        for share in &shares {
            if !seen_fingerprints.insert(share.recipient_fingerprint.as_str()) {
                return Err(InvalidInputs(format!(
                    "duplicate encrypted share recipient fingerprint {}",
                    share.recipient_fingerprint
                )));
            }
        }

        Ok(Self(shares))
    }

    pub fn share_count(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &KpEncryptedShare> {
        self.0.iter()
    }

    pub fn into_vec(self) -> Vec<KpEncryptedShare> {
        self.0
    }

    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<&KpEncryptedShare> {
        self.iter()
            .find(|share| share.recipient_fingerprint == fingerprint)
    }

    /// Require `fingerprint` to be assigned to `submitted_share_id` in this
    /// encrypted-share roster.
    pub fn validate_share_assignment(
        &self,
        fingerprint: &str,
        submitted_share_id: ShareID,
    ) -> GuardianResult<()> {
        let assigned_share = self.find_by_fingerprint(fingerprint).ok_or_else(|| {
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

    /// Replace one recipient and ciphertext while preserving every other
    /// KP/share entry and global fingerprint uniqueness.
    pub fn replace_recipient(
        self,
        current_fingerprint: &str,
        new_fingerprint: KPFingerprint,
        new_ciphertext: String,
    ) -> GuardianResult<(Self, KpEncryptedShare)> {
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
            .find(|share| share.recipient_fingerprint == current_fingerprint)
            .ok_or_else(|| {
                InvalidInputs(format!(
                    "current KP fingerprint {current_fingerprint} is not present in the \
                     encrypted share roster"
                ))
            })?;
        share.recipient_fingerprint = new_fingerprint;
        share.armored_ciphertext = new_ciphertext;
        let changed_share = share.clone();
        Ok((Self(shares), changed_share))
    }

    pub fn recipient_fingerprints(&self) -> Vec<KPFingerprint> {
        self.0
            .iter()
            .map(|share| share.recipient_fingerprint.clone())
            .collect()
    }

    /// Verify the exact configured certificate set and ciphertext recipients,
    /// leaving share assignments to the signed encrypted-share roster.
    pub fn verify_recipients(&self, certs_roster: &KpCertRoster) -> GuardianResult<()> {
        if self.share_count() != certs_roster.num_kps() {
            return Err(InvalidInputs(format!(
                "expected {} KP cert roster entries, got {} encrypted shares",
                certs_roster.num_kps(),
                self.share_count()
            )));
        }

        // Both rosters enforce uniqueness, so equal counts and membership of
        // every configured fingerprint prove exact set equality.
        for cert in certs_roster.iter() {
            let fingerprint = cert.fingerprint().to_hex();
            let share = self.find_by_fingerprint(&fingerprint).ok_or_else(|| {
                InvalidInputs(format!(
                    "KP fingerprint {fingerprint} is not present in the encrypted-share roster"
                ))
            })?;
            share.verify_recipient(cert)?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for KpEncryptedShareRoster {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shares = Vec::<KpEncryptedShare>::deserialize(deserializer)?;
        Self::new(shares).map_err(serde::de::Error::custom)
    }
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
/// `params.threshold()`, encrypt each share to its matching KP certificate, and
/// compute one commitment per share. Fresh dealing assigns the `i`th certificate
/// in canonical fingerprint order to share ID `i + 1` and records ownership in
/// the returned encrypted-share roster.
///
/// # Panics
///
/// Panics if `kp_certs_roster.num_kps() != params.num_shares()`.
pub fn split_and_encrypt_for_kps<R: CryptoRng + RngCore>(
    sk: &k256::SecretKey,
    kp_certs_roster: &KpCertRoster,
    params: &SecretSharingParams,
    rng: &mut R,
) -> (KpEncryptedShareRoster, ShareCommitments) {
    assert_eq!(
        kp_certs_roster.num_kps(),
        params.num_shares(),
        "request validation ensures one KP certificate per share",
    );
    let shares = split_secret(sk, params, rng);
    let n = params.num_shares();
    let mut encrypted_shares = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    for (share, cert) in shares.iter().zip(kp_certs_roster.iter()) {
        encrypted_shares.push(KpEncryptedShare {
            id: share.id,
            recipient_fingerprint: cert.fingerprint().to_hex(),
            armored_ciphertext: encrypt_share_for_provisioner(share, cert),
        });
        commitments.push(commit_share(share));
    }
    let encrypted_shares = KpEncryptedShareRoster::new(encrypted_shares)
        .expect("split_secret produces share ids exactly 1..=n");
    let commitments =
        ShareCommitments::new(commitments).expect("share IDs 1..=n are unique by construction");
    (encrypted_shares, commitments)
}

/// Encrypt a share for delivery to a key provisioner using OpenPGP ASCII armor.
pub fn encrypt_share_for_provisioner(share: &Share, cert: &AttestedKpCert) -> String {
    encrypt_armored_for_key(
        &share.value.to_bytes(),
        cert.cert(),
        cert.encryption_fingerprint(),
    )
    .expect("AttestedKpCert validation ensures the attested encryption key is usable")
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
    use crate::guardian::test_utils::mock_attested_kp_keypair;
    use crate::pgp::decrypt_with_secret_key;
    use k256::SecretKey;
    use std::io::Cursor;
    use std::io::Read;
    use std::num::NonZeroU16;

    fn cert() -> AttestedKpCert {
        mock_attested_kp_keypair().0
    }

    fn cert_and_secret() -> (AttestedKpCert, String) {
        mock_attested_kp_keypair()
    }

    #[test]
    fn attested_kp_cert_rejects_malformed_proof() {
        let proof = b"not a PEM certificate".to_vec();
        let (public, _) = crate::pgp::test_utils::mock_pgp_keypair();
        let result = AttestedKpCert::new(
            PgpPublicCert::new(public).unwrap(),
            proof.clone(),
            proof.clone(),
            proof,
        );
        assert!(matches!(result, Err(InvalidInputs(_))));
    }

    #[test]
    fn attested_kp_cert_deserialization_rejects_test_issuer() {
        let cert = cert();
        assert!(
            AttestedKpCert::new(
                cert.cert().clone(),
                cert.device_pem().to_vec(),
                cert.sig_pem().to_vec(),
                cert.dec_pem().to_vec(),
            )
            .is_err()
        );
        let json = serde_json::to_vec(&cert).unwrap();
        assert!(serde_json::from_slice::<AttestedKpCert>(&json).is_err());
        let bcs = bcs::to_bytes(&cert).unwrap();
        assert!(bcs::from_bytes::<AttestedKpCert>(&bcs).is_err());
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

    fn test_kp_encrypted_share(id: u16) -> KpEncryptedShare {
        test_kp_encrypted_share_for_fingerprint(id, format!("fingerprint-{id}"))
    }

    fn test_kp_encrypted_share_for_fingerprint(
        id: u16,
        recipient_fingerprint: String,
    ) -> KpEncryptedShare {
        KpEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint,
            armored_ciphertext: "-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----".into(),
        }
    }

    #[test]
    fn encrypted_share_roster_canonicalizes_by_share_id() {
        let shares = KpEncryptedShareRoster::new(vec![
            test_kp_encrypted_share(3),
            test_kp_encrypted_share(2),
            test_kp_encrypted_share(1),
        ])
        .unwrap();

        assert_eq!(
            shares
                .iter()
                .map(|share| (share.id.get(), share.recipient_fingerprint.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, "fingerprint-1"),
                (2, "fingerprint-2"),
                (3, "fingerprint-3"),
            ]
        );
    }

    #[test]
    fn encrypted_share_roster_rejects_wrong_ids_and_duplicate_recipients() {
        let err = KpEncryptedShareRoster::new(vec![
            test_kp_encrypted_share(1),
            test_kp_encrypted_share(2),
            test_kp_encrypted_share(4),
        ])
        .expect_err("ids [1, 2, 4] are not exactly 1..=n");
        assert!(format!("{err}").contains("share ids"), "{err}");

        let err = KpEncryptedShareRoster::new(vec![
            test_kp_encrypted_share_for_fingerprint(1, "duplicate".into()),
            test_kp_encrypted_share_for_fingerprint(2, "duplicate".into()),
        ])
        .expect_err("recipient fingerprints must be globally unique");
        assert!(format!("{err}").contains("duplicate"), "{err}");
    }

    #[test]
    fn encrypted_share_roster_validates_signer_to_share_assignment() {
        let shares = KpEncryptedShareRoster::new(vec![
            test_kp_encrypted_share_for_fingerprint(1, "signer-a".into()),
            test_kp_encrypted_share_for_fingerprint(2, "signer-b".into()),
        ])
        .unwrap();

        shares
            .validate_share_assignment("signer-b", ShareID::new(2).unwrap())
            .expect("the signer assigned to share 2 must be accepted");

        let err = shares
            .validate_share_assignment("signer-b", ShareID::new(1).unwrap())
            .expect_err("a signer must not submit another provisioner's share");
        assert!(format!("{err}").contains("assigned share id 2"), "{err}");

        let err = shares
            .validate_share_assignment("unknown-signer", ShareID::new(1).unwrap())
            .expect_err("an unrostered signer must be rejected");
        assert!(format!("{err}").contains("not present"), "{err}");
    }

    #[test]
    fn encrypted_share_roster_replaces_one_recipient_and_preserves_the_rest() {
        let shares = KpEncryptedShareRoster::new(vec![
            test_kp_encrypted_share_for_fingerprint(1, "a".into()),
            test_kp_encrypted_share_for_fingerprint(2, "c".into()),
        ])
        .unwrap();

        let (rotated, changed) = shares
            .clone()
            .replace_recipient("a", "d".into(), "new ciphertext".into())
            .unwrap();
        assert_eq!(changed.id.get(), 1);
        assert_eq!(changed.recipient_fingerprint, "d");
        assert_eq!(changed.armored_ciphertext, "new ciphertext");
        assert!(rotated.find_by_fingerprint("a").is_none());
        assert!(rotated.find_by_fingerprint("d").is_some());
        assert_eq!(
            rotated.iter().nth(1),
            shares.iter().nth(1),
            "replacing share 1 must preserve every field of share 2"
        );

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
    fn recipient_set_preserves_assignments_across_config_permutation_and_rotation() {
        let mut certs = [cert(), cert(), cert()];
        certs.sort_by_cached_key(|cert| cert.fingerprint().to_hex());
        let [replacement, second, first] = certs;
        let shares = KpEncryptedShareRoster::new(
            [&first, &second]
                .into_iter()
                .enumerate()
                .map(|(index, cert)| {
                    let share = Share {
                        id: ShareID::new(index as u16 + 1).unwrap(),
                        value: Scalar::ONE,
                    };
                    KpEncryptedShare {
                        id: share.id,
                        recipient_fingerprint: cert.fingerprint().to_hex(),
                        armored_ciphertext: encrypt_share_for_provisioner(&share, cert),
                    }
                })
                .collect(),
        )
        .unwrap();
        let config = KpCertRoster::new(vec![second.clone(), first.clone()]).unwrap();
        // Existing signed share 1 belongs to the higher fingerprint, independent
        // of the canonical certificate order.
        assert_eq!(
            config.fingerprints(),
            vec![second.fingerprint().to_hex(), first.fingerprint().to_hex()]
        );
        shares.verify_recipients(&config).unwrap();
        shares
            .verify_recipients(&KpCertRoster::new(vec![first.clone(), second.clone()]).unwrap())
            .unwrap();
        assert!(
            shares
                .verify_recipients(&KpCertRoster::new(vec![first.clone()]).unwrap())
                .is_err()
        );
        assert!(
            shares
                .verify_recipients(
                    &KpCertRoster::new(vec![first.clone(), replacement.clone()]).unwrap()
                )
                .is_err()
        );

        // Replacement moves the cert from last to first in canonical order,
        // while its recorded share ID remains unchanged.
        let rotated_config = config
            .replace_cert(&first.fingerprint(), replacement.clone())
            .unwrap();
        let (rotated, changed) = shares
            .clone()
            .replace_recipient(
                &first.fingerprint().to_hex(),
                replacement.fingerprint().to_hex(),
                encrypt_share_for_provisioner(
                    &Share {
                        id: ShareID::new(1).unwrap(),
                        value: Scalar::ONE,
                    },
                    &replacement,
                ),
            )
            .unwrap();
        changed.verify_recipient(&replacement).unwrap();
        assert_eq!(
            rotated.find_by_fingerprint(&replacement.fingerprint().to_hex()),
            Some(&changed)
        );
        assert_eq!(
            rotated_config.fingerprints(),
            vec![
                replacement.fingerprint().to_hex(),
                second.fingerprint().to_hex()
            ]
        );
        rotated.verify_recipients(&rotated_config).unwrap();
        assert_eq!(changed.id.get(), 1);
        assert_eq!(rotated.iter().nth(1), shares.iter().nth(1));
    }

    #[test]
    fn encrypted_share_roster_deserializes_through_validation() {
        let json = serde_json::to_string(&vec![
            test_kp_encrypted_share(2),
            test_kp_encrypted_share(1),
        ])
        .unwrap();
        let shares: KpEncryptedShareRoster = serde_json::from_str(&json).unwrap();
        assert_eq!(
            shares
                .iter()
                .map(|share| share.id.get())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        let duplicate_id_json = serde_json::to_string(&vec![
            test_kp_encrypted_share(1),
            test_kp_encrypted_share(1),
        ])
        .unwrap();
        let err = serde_json::from_str::<KpEncryptedShareRoster>(&duplicate_id_json).unwrap_err();
        assert!(err.to_string().contains("encrypted share ids"), "{err}");

        let duplicate_recipient_json = serde_json::to_string(&vec![
            test_kp_encrypted_share_for_fingerprint(1, "duplicate".into()),
            test_kp_encrypted_share_for_fingerprint(2, "duplicate".into()),
        ])
        .unwrap();
        let err =
            serde_json::from_str::<KpEncryptedShareRoster>(&duplicate_recipient_json).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate encrypted share recipient fingerprint"),
            "{err}"
        );
    }

    #[test]
    fn encrypted_share_verifies_recorded_cert_and_ciphertext_recipient() {
        let recipient = cert();
        let other = cert();
        let plaintext_share = Share {
            id: ShareID::new(1).unwrap(),
            value: Scalar::ONE,
        };
        let ciphertext = encrypt_share_for_provisioner(&plaintext_share, &recipient);
        let encrypted_share = KpEncryptedShare {
            id: plaintext_share.id,
            recipient_fingerprint: recipient.fingerprint().to_hex(),
            armored_ciphertext: ciphertext,
        };

        encrypted_share
            .verify_recipient(&recipient)
            .expect("a real ciphertext encrypted to the recorded cert must verify");
        KpEncryptedShareRoster::new(vec![encrypted_share.clone()])
            .unwrap()
            .verify_recipients(&KpCertRoster::new(vec![recipient.clone()]).unwrap())
            .expect("the matching scalar share and cert rosters must verify");

        let mut wrong_recorded_fingerprint = encrypted_share.clone();
        wrong_recorded_fingerprint.recipient_fingerprint = other.fingerprint().to_hex();
        let err = wrong_recorded_fingerprint
            .verify_recipient(&recipient)
            .expect_err("the recorded recipient fingerprint must identify the supplied cert");
        assert!(format!("{err}").contains("recipient differs"), "{err}");
        wrong_recorded_fingerprint.recipient_fingerprint = "not a fingerprint".into();
        assert!(
            KpEncryptedShareRoster::new(vec![wrong_recorded_fingerprint])
                .unwrap()
                .verify_recipients(&KpCertRoster::new(vec![recipient]).unwrap())
                .is_err()
        );

        let wrong_ciphertext_recipient = KpEncryptedShare {
            recipient_fingerprint: other.fingerprint().to_hex(),
            ..encrypted_share
        };
        let err = wrong_ciphertext_recipient
            .verify_recipient(&other)
            .expect_err("ciphertext encrypted to another cert must be rejected");
        assert!(matches!(err, InvalidInputs(_)));
        assert!(
            KpEncryptedShareRoster::new(vec![wrong_ciphertext_recipient])
                .unwrap()
                .verify_recipients(&KpCertRoster::new(vec![other]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn encrypted_share_rejects_duplicate_correct_key_recipients() {
        use sequoia_openpgp::Packet;
        use sequoia_openpgp::PacketPile;
        use sequoia_openpgp::armor;
        use sequoia_openpgp::parse::Parse;
        use sequoia_openpgp::serialize::Serialize;

        let (recipient, secret) = cert_and_secret();
        let share = Share {
            id: ShareID::new(1).unwrap(),
            value: Scalar::ONE,
        };
        let mut encrypted_share = KpEncryptedShare {
            id: share.id,
            recipient_fingerprint: recipient.fingerprint().to_hex(),
            armored_ciphertext: encrypt_share_for_provisioner(&share, &recipient),
        };
        encrypted_share.verify_recipient(&recipient).unwrap();
        let packets =
            PacketPile::from_bytes(encrypted_share.armored_ciphertext.as_bytes()).unwrap();
        let mut packets: Vec<_> = packets.into_children().collect();
        let pkesk = packets
            .iter()
            .find(|packet| matches!(packet, Packet::PKESK(_)))
            .expect("real encryption must contain a public-key session packet")
            .clone();
        packets.insert(0, pkesk);
        let mut armored = armor::Writer::new(Vec::new(), armor::Kind::Message).unwrap();
        PacketPile::from(packets).serialize(&mut armored).unwrap();
        encrypted_share.armored_ciphertext =
            String::from_utf8(armored.finalize().unwrap()).unwrap();

        let recipients = pgp_message_recipients(&encrypted_share.armored_ciphertext).unwrap();
        assert_eq!(recipients.len(), 2);
        let expected_key =
            sequoia_openpgp::KeyHandle::from(recipient.encryption_fingerprint().clone());
        assert!(recipients.iter().all(|key| expected_key.aliases(key)));
        let mut decryptor = decrypt_with_secret_key(
            Cursor::new(encrypted_share.armored_ciphertext.clone().into_bytes()),
            secret.as_bytes(),
        )
        .unwrap();
        let mut plaintext = Vec::new();
        decryptor.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, share.value.to_bytes().as_slice());
        assert!(matches!(
            encrypted_share.verify_recipient(&recipient),
            Err(InvalidInputs(_))
        ));
        assert!(
            KpEncryptedShareRoster::new(vec![encrypted_share])
                .unwrap()
                .verify_recipients(&KpCertRoster::new(vec![recipient]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn encrypted_share_rejects_malformed_openpgp_ciphertext() {
        let recipient = cert();
        let encrypted_share = KpEncryptedShare {
            id: ShareID::new(1).unwrap(),
            recipient_fingerprint: recipient.fingerprint().to_hex(),
            armored_ciphertext: "not an OpenPGP message".into(),
        };

        let err = encrypted_share
            .verify_recipient(&recipient)
            .expect_err("malformed OpenPGP ciphertext must fail closed");
        assert!(
            format!("{err}").contains("failed to parse PGP recipients"),
            "{err}"
        );
        assert!(
            KpEncryptedShareRoster::new(vec![encrypted_share])
                .unwrap()
                .verify_recipients(&KpCertRoster::new(vec![recipient]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn cert_roster_canonicalizes_and_rejects_fingerprint_collisions() {
        let mut certs = [cert(), cert(), cert()];
        certs.sort_by_cached_key(|cert| cert.fingerprint().to_hex());
        let [old, other, replacement] = certs;
        let duplicate_err = KpCertRoster::new(vec![old.clone(), other.clone(), old.clone()])
            .expect_err("a fingerprint may occur only once in the complete roster");
        assert!(
            format!("{duplicate_err}").contains("duplicate"),
            "{duplicate_err}"
        );
        let roster = KpCertRoster::new(vec![other.clone(), old.clone()]).unwrap();
        let reordered = KpCertRoster::new(vec![old.clone(), other.clone()]).unwrap();
        assert_eq!(roster, reordered);
        assert_eq!(
            bcs::to_bytes(&roster).unwrap(),
            bcs::to_bytes(&reordered).unwrap()
        );

        assert_eq!(
            roster.fingerprints(),
            vec![old.fingerprint().to_hex(), other.fingerprint().to_hex()]
        );
        assert_eq!(roster.cert_for_fingerprint(&old.fingerprint()), Some(&old));

        let rotated = roster
            .replace_cert(&old.fingerprint(), replacement.clone())
            .unwrap();
        assert_eq!(
            rotated.fingerprints(),
            vec![
                other.fingerprint().to_hex(),
                replacement.fingerprint().to_hex()
            ]
        );
        assert_eq!(rotated.num_kps(), 2);
        assert_eq!(
            rotated.cert_for_fingerprint(&other.fingerprint()),
            Some(&other),
            "replacing one certificate must leave the other unchanged"
        );

        assert!(rotated.cert_for_fingerprint(&old.fingerprint()).is_none());
        assert_eq!(
            rotated.cert_for_fingerprint(&replacement.fingerprint()),
            Some(&replacement)
        );
        let err = roster
            .replace_cert(&replacement.fingerprint(), old.clone())
            .unwrap_err();
        assert!(format!("{err}").contains("is not in"), "{err}");

        let err = roster.replace_cert(&old.fingerprint(), other).unwrap_err();
        assert!(format!("{err}").contains("duplicate"), "{err}");

        let err = roster.replace_cert(&old.fingerprint(), old).unwrap_err();
        assert!(format!("{err}").contains("must differ"), "{err}");
    }

    #[test]
    fn split_and_encrypt_n5_t3_assigns_one_decryptable_ciphertext_per_cert() {
        let mut keypairs = (0..5).map(|_| cert_and_secret()).collect::<Vec<_>>();
        keypairs.sort_by_cached_key(|(cert, _)| std::cmp::Reverse(cert.fingerprint().to_hex()));
        let roster =
            KpCertRoster::new(keypairs.iter().map(|(cert, _)| cert.clone()).collect()).unwrap();
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let params = SecretSharingParams::new(5, 3).unwrap();

        let (encrypted_shares, commitments) =
            split_and_encrypt_for_kps(&secret_key, &roster, &params, &mut rand::thread_rng());
        assert_eq!(commitments.len(), 5);

        assert_eq!(
            encrypted_shares.recipient_fingerprints(),
            keypairs
                .iter()
                .rev()
                .map(|(cert, _)| cert.fingerprint().to_hex())
                .collect::<Vec<_>>(),
            "fresh dealing must assign IDs in ascending fingerprint order"
        );

        let mut decrypted_shares = Vec::with_capacity(5);
        for (index, encrypted_share) in encrypted_shares.iter().enumerate() {
            assert_eq!(encrypted_share.id.get() as usize, index + 1);

            let mut decryptor = decrypt_with_secret_key(
                Cursor::new(encrypted_share.armored_ciphertext.clone().into_bytes()),
                keypairs
                    .iter()
                    .find(|(cert, _)| {
                        cert.fingerprint().to_hex() == encrypted_share.recipient_fingerprint
                    })
                    .unwrap()
                    .1
                    .as_bytes(),
            )
            .expect("the matching secret key must open its one ciphertext");
            let mut plaintext = Vec::new();
            decryptor.read_to_end(&mut plaintext).unwrap();
            let share = Share {
                id: encrypted_share.id,
                value: ScalarPrimitive::<Secp256k1>::from_slice(&plaintext)
                    .map(Scalar::from)
                    .expect("decrypted share must be one valid scalar"),
            };
            commitments.verify_share(&share).unwrap();
            decrypted_shares.push(share);

            let wrong_secret = &keypairs
                .iter()
                .find(|(cert, _)| {
                    cert.fingerprint().to_hex() != encrypted_share.recipient_fingerprint
                })
                .unwrap()
                .1;
            let wrong_decryption = decrypt_with_secret_key(
                Cursor::new(encrypted_share.armored_ciphertext.clone().into_bytes()),
                wrong_secret.as_bytes(),
            )
            .and_then(|mut decryptor| {
                let mut plaintext = Vec::new();
                decryptor.read_to_end(&mut plaintext)?;
                Ok(plaintext)
            });
            assert!(
                wrong_decryption.is_err(),
                "share {} ciphertext must reject a nonmatching secret key",
                encrypted_share.id
            );
        }

        let reconstructed = combine_shares(&decrypted_shares[..3], params.threshold()).unwrap();
        assert_eq!(reconstructed.to_bytes(), secret_key.to_bytes());
    }
}
