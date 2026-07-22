// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::crypto::ShareID;
use super::errors::GuardianError::InvalidInputs;
use super::errors::GuardianResult;
use crate::pgp::Fingerprint;
use crate::pgp::PgpPublicCert;
use serde::Serialize;
use std::collections::HashSet;

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

// ---------------------------------
//          Helper impl's
// ---------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgp::test_utils::mock_pgp_keypair;

    fn cert() -> PgpPublicCert {
        let (public, _) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
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
