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
