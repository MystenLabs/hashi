// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::Fingerprint;
use super::POLICY;
use super::PgpPublicCert;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use openpgp::cert::prelude::*;
use openpgp::crypto::Signer;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::SignatureType;
use sequoia_openpgp as openpgp;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::SystemTime;

pub struct EncryptionRecipient<'a> {
    pub cert: &'a openpgp::Cert,
    pub subkey: Option<&'a Fingerprint>,
}

pub struct RecipientAttestation<'a> {
    pub device_pem: &'a [u8],
    pub dec_pem: &'a [u8],
}

pub fn assemble_public_cert(
    primary: &openpgp::Cert,
    recipients: &[EncryptionRecipient<'_>],
    attestations: &BTreeMap<Fingerprint, RecipientAttestation<'_>>,
    require_attestation: bool,
    certifier: &mut dyn Signer,
) -> Result<PgpPublicCert> {
    ensure!(
        !recipients.is_empty(),
        "at least one encryption recipient is required"
    );
    ensure!(
        !primary.is_tsk(),
        "primary certificate must not contain secret key material"
    );
    let now = SystemTime::now();
    let primary_key = primary
        .keys()
        .with_policy(&*POLICY, now)
        .supported()
        .alive()
        .revoked(false)
        .find(|key| key.primary())
        .context("primary certificate has no usable primary key")?;
    ensure!(
        primary_key.for_certification() && primary_key.for_signing(),
        "primary key must permit certification and signing"
    );
    ensure!(
        !primary_key.for_transport_encryption() && !primary_key.for_storage_encryption(),
        "encryption-capable primary keys cannot be used as the assembled identity"
    );
    ensure!(
        certifier.public().fingerprint() == primary.fingerprint(),
        "certifier does not match the primary certificate"
    );

    let mut selected = BTreeSet::new();
    let mut bindings = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        ensure!(
            !recipient.cert.is_tsk(),
            "recipient certificate must not contain secret key material"
        );
        let source_primary = recipient
            .cert
            .keys()
            .with_policy(&*POLICY, now)
            .supported()
            .alive()
            .revoked(false)
            .find(|key| key.primary())
            .context("recipient certificate has no usable primary key")?;
        let mut candidates = recipient
            .cert
            .keys()
            .subkeys()
            .with_policy(&*POLICY, now)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .filter(|key| {
                recipient
                    .subkey
                    .is_none_or(|fp| key.key().fingerprint() == *fp)
            });
        let key = candidates
            .next()
            .context("recipient has no matching usable encryption subkey")?;
        ensure!(
            candidates.next().is_none(),
            "recipient has ambiguous encryption subkeys; select a fingerprint"
        );
        let fingerprint = key.key().fingerprint();
        let attestation = attestations.get(&fingerprint);
        ensure!(
            selected.insert(fingerprint),
            "duplicate encryption recipient"
        );
        match attestation {
            Some(attestation) => super::yubikey_attestation::verify_yubikey_encryption_key(
                key.key(),
                attestation.device_pem,
                attestation.dec_pem,
            )
            .context("recipient DEC attestation is invalid")?,
            None => ensure!(
                !require_attestation,
                "recipient DEC attestation is required"
            ),
        }
        let expiration = [
            key.key_expiration_time(),
            key.binding_signature().signature_expiration_time(),
            key.direct_key_signature()
                .ok()
                .and_then(|sig| sig.signature_expiration_time()),
            source_primary.key_expiration_time(),
            source_primary
                .binding_signature()
                .signature_expiration_time(),
            source_primary
                .direct_key_signature()
                .ok()
                .and_then(|sig| sig.signature_expiration_time()),
        ]
        .into_iter()
        .flatten()
        .min();
        ensure!(
            expiration.is_none_or(|expiration| expiration > now),
            "recipient has expired"
        );
        let binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(now)?
            .set_key_flags(KeyFlags::empty().set_transport_encryption())?
            .set_key_expiration_time(key.key(), expiration)?;
        bindings.push((key.key(), binding));
    }
    ensure!(
        attestations
            .keys()
            .all(|fingerprint| selected.contains(fingerprint)),
        "attestation supplied for an unselected encryption key"
    );

    let mut packets = Vec::with_capacity(bindings.len() * 2);
    for (key, binding) in bindings {
        let signature = binding
            .sign_subkey_binding(certifier, primary.primary_key().key(), key)
            .context("failed to certify encryption subkey")?;
        packets.push(openpgp::Packet::PublicSubkey(key.clone()));
        packets.push(openpgp::Packet::Signature(signature));
    }

    let (assembled, _) = primary
        .clone()
        .retain_subkeys(|_| false)
        .insert_packets(packets)?;
    let mut armored = Vec::new();
    assembled.armored().serialize(&mut armored)?;
    let result = PgpPublicCert::new(String::from_utf8(armored)?)?;
    let actual = super::usable_keys(&result.cert)
        .for_transport_encryption()
        .map(|key| key.key().fingerprint())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == selected,
        "assembled certificate does not contain exactly the selected usable recipients"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn identity() -> openpgp::Cert {
        CertBuilder::new()
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_userid("Backup identity")
            .generate()
            .unwrap()
            .0
    }

    fn signer(cert: &openpgp::Cert) -> openpgp::crypto::KeyPair {
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap()
    }

    struct CountingSigner {
        inner: openpgp::crypto::KeyPair,
        calls: usize,
    }

    impl Signer for CountingSigner {
        fn public(
            &self,
        ) -> &openpgp::packet::Key<
            openpgp::packet::key::PublicParts,
            openpgp::packet::key::UnspecifiedRole,
        > {
            self.inner.public()
        }

        fn sign(
            &mut self,
            hash_algo: openpgp::types::HashAlgorithm,
            digest: &[u8],
        ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
            self.calls += 1;
            self.inner.sign(hash_algo, digest)
        }
    }

    #[test]
    fn assembly_preserves_identity_and_exact_public_subkeys() {
        let primary = identity();
        let mut signer = signer(&primary);
        let primary = primary.strip_secret_key_material();
        let recipients: Vec<_> = (0..3)
            .map(|_| {
                CertBuilder::new()
                    .add_transport_encryption_subkey()
                    .add_transport_encryption_subkey()
                    .generate()
                    .unwrap()
                    .0
                    .strip_secret_key_material()
            })
            .collect();
        let keys: Vec<_> = recipients
            .iter()
            .enumerate()
            .map(|(i, cert)| cert.keys().subkeys().nth(i % 2).unwrap().key())
            .collect();
        let fingerprints: Vec<_> = keys.iter().map(|key| key.fingerprint()).collect();
        let selections: Vec<_> = recipients
            .iter()
            .zip(&fingerprints)
            .map(|(cert, fingerprint)| EncryptionRecipient {
                cert,
                subkey: Some(fingerprint),
            })
            .collect();
        let result =
            assemble_public_cert(&primary, &selections, &BTreeMap::new(), false, &mut signer)
                .unwrap();
        assert_eq!(result.fingerprint(), primary.fingerprint());
        assert_eq!(
            result.cert.clone().retain_subkeys(|_| false),
            primary,
            "all original identity packets must be preserved"
        );
        assert!(!result.cert.is_tsk());
        assert_eq!(result.cert.keys().subkeys().count(), fingerprints.len());
        let bound: Vec<_> = super::super::usable_keys(&result.cert)
            .for_transport_encryption()
            .collect();
        assert_eq!(
            bound
                .iter()
                .map(|key| key.key().fingerprint())
                .collect::<BTreeSet<_>>(),
            fingerprints.iter().cloned().collect::<BTreeSet<_>>()
        );
        for key in keys {
            let assembled = bound
                .iter()
                .find(|bound| bound.key().fingerprint() == key.fingerprint())
                .unwrap();
            assert_eq!(assembled.key().role_as_subordinate(), key);
        }
    }

    #[test]
    fn assembly_rejects_expired_or_revoked_recipient_keys_before_signing() {
        let primary = identity();
        let mut signer = CountingSigner {
            inner: signer(&primary),
            calls: 0,
        };
        let primary = primary.strip_secret_key_material();
        let creation = SystemTime::now() - Duration::from_secs(7200);
        let valid = CertBuilder::new()
            .set_creation_time(creation)
            .set_validity_period(Duration::from_secs(86400))
            .add_subkey(
                KeyFlags::empty().set_transport_encryption(),
                Duration::from_secs(86400),
                None,
            )
            .generate()
            .unwrap()
            .0;
        let valid_public = valid.clone().strip_secret_key_material();
        for (case, primary_invalid, revoked) in [
            ("expired subkey", false, false),
            ("revoked subkey", false, true),
            ("expired source primary", true, false),
            ("revoked source primary", true, true),
        ] {
            let invalid = if revoked {
                let mut source_signer = self::signer(&valid);
                let revocation = if primary_invalid {
                    CertRevocationBuilder::new()
                        .build(&mut source_signer, &valid, None)
                        .unwrap()
                } else {
                    SubkeyRevocationBuilder::new()
                        .build(
                            &mut source_signer,
                            &valid,
                            valid.keys().subkeys().next().unwrap().key(),
                            None,
                        )
                        .unwrap()
                };
                valid.clone().insert_packets(revocation).unwrap().0
            } else {
                CertBuilder::new()
                    .set_creation_time(creation)
                    .set_validity_period(Duration::from_secs(if primary_invalid {
                        3600
                    } else {
                        86400
                    }))
                    .add_subkey(
                        KeyFlags::empty().set_transport_encryption(),
                        Duration::from_secs(if primary_invalid { 86400 } else { 3600 }),
                        None,
                    )
                    .generate()
                    .unwrap()
                    .0
            }
            .strip_secret_key_material();
            let fingerprint = invalid.keys().subkeys().next().unwrap().key().fingerprint();
            let error = assemble_public_cert(
                &primary,
                &[
                    EncryptionRecipient {
                        cert: &valid_public,
                        subkey: None,
                    },
                    EncryptionRecipient {
                        cert: &invalid,
                        subkey: Some(&fingerprint),
                    },
                ],
                &BTreeMap::new(),
                false,
                &mut signer,
            )
            .unwrap_err();
            let reason = if primary_invalid {
                "no usable primary key"
            } else {
                "no matching usable encryption subkey"
            };
            assert!(error.to_string().contains(reason), "{case}: {error:#}");
            assert_eq!(signer.calls, 0, "{case} must be rejected before signing");
        }
        let assembled = assemble_public_cert(
            &primary,
            &[EncryptionRecipient {
                cert: &valid_public,
                subkey: None,
            }],
            &BTreeMap::new(),
            false,
            &mut signer,
        )
        .unwrap();
        assert_eq!(signer.calls, 1);
        assert_eq!(
            super::super::usable_keys(&assembled.cert)
                .for_transport_encryption()
                .next()
                .unwrap()
                .key()
                .fingerprint(),
            valid_public
                .keys()
                .subkeys()
                .next()
                .unwrap()
                .key()
                .fingerprint()
        );
    }

    #[test]
    fn assembly_rejects_inappropriate_certifier_flags() {
        let recipient = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0
            .strip_secret_key_material();
        for (flags, reason) in [
            (KeyFlags::empty().set_signing(), "certification and signing"),
            (
                KeyFlags::empty().set_certification(),
                "certification and signing",
            ),
            (
                KeyFlags::empty()
                    .set_certification()
                    .set_signing()
                    .set_transport_encryption(),
                "encryption-capable primary",
            ),
            (
                KeyFlags::empty()
                    .set_certification()
                    .set_signing()
                    .set_storage_encryption(),
                "encryption-capable primary",
            ),
        ] {
            let primary = CertBuilder::new()
                .set_primary_key_flags(flags.clone())
                .generate()
                .unwrap()
                .0;
            let mut signer = signer(&primary);
            let error = assemble_public_cert(
                &primary.strip_secret_key_material(),
                &[EncryptionRecipient {
                    cert: &recipient,
                    subkey: None,
                }],
                &BTreeMap::new(),
                false,
                &mut signer,
            )
            .unwrap_err();
            assert!(error.to_string().contains(reason), "{flags:?}: {error:#}");
        }
    }

    #[test]
    fn assembly_validates_later_evidence_and_surplus_evidence_before_signing() {
        let primary = identity();
        let mut signer = CountingSigner {
            inner: signer(&primary),
            calls: 0,
        };
        let primary = primary.strip_secret_key_material();
        let recipients: Vec<_> = (0..2)
            .map(|_| {
                CertBuilder::new()
                    .add_transport_encryption_subkey()
                    .generate()
                    .unwrap()
                    .0
                    .strip_secret_key_material()
            })
            .collect();
        let selections: Vec<_> = recipients
            .iter()
            .map(|cert| EncryptionRecipient { cert, subkey: None })
            .collect();
        for (fingerprint, reason) in [
            (
                recipients[1]
                    .keys()
                    .subkeys()
                    .next()
                    .unwrap()
                    .key()
                    .fingerprint(),
                "attestation is invalid",
            ),
            (primary.fingerprint(), "unselected encryption key"),
        ] {
            let evidence = BTreeMap::from([(
                fingerprint,
                RecipientAttestation {
                    device_pem: b"invalid",
                    dec_pem: b"invalid",
                },
            )]);
            let error = assemble_public_cert(&primary, &selections, &evidence, false, &mut signer)
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
            assert_eq!(
                signer.calls, 0,
                "all evidence must be checked before signing"
            );
        }
        let assembled =
            assemble_public_cert(&primary, &selections, &BTreeMap::new(), false, &mut signer)
                .unwrap();
        assert_eq!(signer.calls, selections.len());
        assert_eq!(
            super::super::usable_keys(&assembled.cert)
                .for_transport_encryption()
                .map(|key| key.key().fingerprint())
                .collect::<BTreeSet<_>>(),
            recipients
                .iter()
                .map(|cert| cert.keys().subkeys().next().unwrap().key().fingerprint())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn assembly_caps_each_source_expiration_and_strips_original_subkeys() {
        let primary = CertBuilder::new()
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0;
        let mut signer = primary
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let primary = primary.strip_secret_key_material();
        let creation = SystemTime::UNIX_EPOCH
            + Duration::from_secs(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 60,
            );
        let short = Duration::from_secs(3600);
        let long = Duration::from_secs(7200);
        for limiting_factor in 0..3 {
            let recipient = CertBuilder::new()
                .set_creation_time(creation)
                .set_validity_period(if limiting_factor == 0 { short } else { long })
                .add_subkey_with(
                    KeyFlags::empty().set_transport_encryption(),
                    if limiting_factor == 1 { short } else { long },
                    None,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_validity_period(if limiting_factor == 2 {
                            short
                        } else {
                            long
                        })
                        .unwrap(),
                )
                .unwrap()
                .generate()
                .unwrap()
                .0
                .strip_secret_key_material();
            let result = assemble_public_cert(
                &primary,
                &[EncryptionRecipient {
                    cert: &recipient,
                    subkey: None,
                }],
                &BTreeMap::new(),
                false,
                &mut signer,
            )
            .unwrap();
            assert_eq!(result.cert.keys().subkeys().count(), 1);
            let bound = super::super::usable_keys(&result.cert)
                .for_transport_encryption()
                .next()
                .unwrap();
            assert_eq!(
                bound.key().fingerprint(),
                recipient
                    .keys()
                    .subkeys()
                    .next()
                    .unwrap()
                    .key()
                    .fingerprint()
            );
            assert_eq!(bound.key_expiration_time(), Some(creation + short));
        }
    }

    #[test]
    fn assembly_rejects_ambiguous_duplicate_secret_and_mismatched_inputs() {
        let primary = identity();
        let mut signer = primary
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let public = primary.clone().strip_secret_key_material();
        let recipient = CertBuilder::new()
            .add_transport_encryption_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0;
        let recipient_public = recipient.clone().strip_secret_key_material();
        let fingerprint = recipient
            .keys()
            .subkeys()
            .next()
            .unwrap()
            .key()
            .fingerprint();
        assert!(assemble_public_cert(&public, &[], &BTreeMap::new(), false, &mut signer).is_err());
        let recipients = [EncryptionRecipient {
            cert: &recipient_public,
            subkey: Some(&fingerprint),
        }];
        assert!(
            assemble_public_cert(&public, &recipients, &BTreeMap::new(), true, &mut signer)
                .unwrap_err()
                .to_string()
                .contains("attestation is required")
        );
        let invalid = BTreeMap::from([(
            fingerprint.clone(),
            RecipientAttestation {
                device_pem: b"invalid",
                dec_pem: b"invalid",
            },
        )]);
        assert!(
            assemble_public_cert(&public, &recipients, &invalid, false, &mut signer)
                .unwrap_err()
                .to_string()
                .contains("attestation is invalid")
        );
        let surplus = BTreeMap::from([(
            public.fingerprint(),
            RecipientAttestation {
                device_pem: b"invalid",
                dec_pem: b"invalid",
            },
        )]);
        assert!(
            assemble_public_cert(&public, &recipients, &surplus, false, &mut signer)
                .unwrap_err()
                .to_string()
                .contains("unselected encryption key")
        );
        assert!(
            assemble_public_cert(
                &public,
                &[EncryptionRecipient {
                    cert: &recipient_public,
                    subkey: None,
                }],
                &BTreeMap::new(),
                false,
                &mut signer
            )
            .is_err()
        );
        assert!(
            assemble_public_cert(
                &public,
                &[
                    EncryptionRecipient {
                        cert: &recipient_public,
                        subkey: Some(&fingerprint)
                    },
                    EncryptionRecipient {
                        cert: &recipient_public,
                        subkey: Some(&fingerprint)
                    },
                ],
                &BTreeMap::new(),
                false,
                &mut signer
            )
            .is_err()
        );
        assert!(
            assemble_public_cert(
                &public,
                &[EncryptionRecipient {
                    cert: &recipient,
                    subkey: Some(&fingerprint),
                }],
                &BTreeMap::new(),
                false,
                &mut signer
            )
            .is_err()
        );
        assert!(
            assemble_public_cert(
                &primary,
                &[EncryptionRecipient {
                    cert: &recipient_public,
                    subkey: Some(&fingerprint),
                }],
                &BTreeMap::new(),
                false,
                &mut signer
            )
            .is_err()
        );
        let other = identity().strip_secret_key_material();
        assert!(
            assemble_public_cert(
                &other,
                &[EncryptionRecipient {
                    cert: &recipient_public,
                    subkey: Some(&fingerprint),
                }],
                &BTreeMap::new(),
                false,
                &mut signer
            )
            .is_err()
        );
    }
}
