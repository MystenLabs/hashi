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
use openpgp::types::Features;
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
    let primary_features = primary_key
        .valid_cert()
        .features()
        .unwrap_or_else(Features::empty);

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
        let recipient_features = key.valid_cert().features().unwrap_or_else(Features::empty);
        ensure!(
            recipient_features.normalized_eq(&primary_features),
            "recipient encryption subkey {fingerprint} has effective features \
             {recipient_features:?} differing from certifier {} features {primary_features:?}",
            primary.fingerprint()
        );
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
            .set_key_flags(KeyFlags::empty().set_transport_encryption())?;
        let binding = match expiration {
            Some(expiration) => binding.set_key_expiration_time(key.key(), expiration)?,
            // An absent subpacket inherits the primary's validity period,
            // measured from this subkey's creation time. Encode no expiry.
            None => binding.set_key_validity_period(std::time::Duration::ZERO)?,
        };
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
    fn assembly_preserves_nonexpiring_old_subkey_under_finite_primary() {
        let now = SystemTime::now();
        let lifetime = Duration::from_secs(365 * 24 * 60 * 60);
        let primary = CertBuilder::new()
            .set_creation_time(now - Duration::from_secs(60))
            .set_validity_period(lifetime)
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_userid("Finite backup identity")
            .generate()
            .unwrap()
            .0;
        let mut signer = signer(&primary);
        let primary = primary.strip_secret_key_material();
        let recipient = CertBuilder::new()
            .set_creation_time(now - lifetime * 2)
            .set_validity_period(None)
            .add_subkey(KeyFlags::empty().set_transport_encryption(), None, None)
            .generate()
            .unwrap()
            .0
            .strip_secret_key_material();
        let assembled = assemble_public_cert(
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
        let subkey = super::super::usable_keys(&assembled.cert)
            .for_transport_encryption()
            .next()
            .unwrap();
        assert_eq!(subkey.key_expiration_time(), None);
        assert_eq!(
            subkey.key().fingerprint(),
            recipient
                .keys()
                .subkeys()
                .next()
                .unwrap()
                .key()
                .fingerprint()
        );
        let expiration = primary
            .primary_key()
            .with_policy(&*POLICY, now)
            .unwrap()
            .key_expiration_time()
            .unwrap();
        assert_eq!(
            assembled
                .cert
                .primary_key()
                .with_policy(&*POLICY, now)
                .unwrap()
                .key_expiration_time(),
            Some(expiration)
        );
        assert!(
            assembled
                .cert
                .with_policy(&*POLICY, expiration - Duration::from_secs(1))
                .unwrap()
                .alive()
                .is_ok()
        );
        assert!(
            assembled
                .cert
                .with_policy(&*POLICY, expiration + Duration::from_secs(1))
                .unwrap()
                .alive()
                .is_err()
        );
    }

    fn feature_cert(features: Features, with_userid: bool, recipient: bool) -> openpgp::Cert {
        let mut builder = CertBuilder::new()
            .set_profile(openpgp::Profile::RFC4880)
            .unwrap()
            .set_features(if with_userid {
                Features::empty()
            } else {
                features.clone()
            })
            .unwrap()
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing());
        if recipient {
            builder = builder.add_transport_encryption_subkey();
        }
        let mut cert = builder.generate().unwrap().0;
        if with_userid {
            // Deliberately disagree with the direct-key signature: the
            // primary User ID's preferences must take precedence.
            let userid = openpgp::packet::UserID::from("Backup identity");
            let signature = SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_features(features.clone())
                .unwrap()
                .sign_userid_binding(&mut signer(&cert), cert.primary_key().key(), &userid)
                .unwrap();
            cert = cert
                .insert_packets([
                    openpgp::Packet::UserID(userid),
                    openpgp::Packet::Signature(signature),
                ])
                .unwrap()
                .0;
        }
        assert!(
            cert.with_policy(&*POLICY, None)
                .unwrap()
                .features()
                .unwrap()
                .normalized_eq(&features)
        );
        cert
    }

    #[test]
    fn assembly_rejects_mismatched_effective_features_before_signing() {
        let modern = Features::empty().set_seipdv1().set_seipdv2();
        let legacy = Features::empty().set_seipdv1();
        for primary_userid in [false, true] {
            for recipient_userid in [false, true] {
                for primary_features in [legacy.clone(), modern.clone()] {
                    let other_features = if primary_features.supports_seipdv2() {
                        legacy.clone()
                    } else {
                        modern.clone()
                    };
                    let primary = feature_cert(primary_features.clone(), primary_userid, false);
                    let mut certifier = CountingSigner {
                        inner: signer(&primary),
                        calls: 0,
                    };
                    let primary = primary.strip_secret_key_material();
                    let matching = feature_cert(primary_features, recipient_userid, true)
                        .strip_secret_key_material();
                    let mismatched = feature_cert(other_features, recipient_userid, true)
                        .strip_secret_key_material();
                    let offending = mismatched
                        .keys()
                        .subkeys()
                        .next()
                        .unwrap()
                        .key()
                        .fingerprint();
                    // Both a single mismatched recipient and a mixed group
                    // must fail without certifying even the matching subkey.
                    for sources in [vec![&mismatched], vec![&matching, &mismatched]] {
                        let selections: Vec<_> = sources
                            .into_iter()
                            .map(|cert| EncryptionRecipient { cert, subkey: None })
                            .collect();
                        let error = assemble_public_cert(
                            &primary,
                            &selections,
                            &BTreeMap::new(),
                            false,
                            &mut certifier,
                        )
                        .unwrap_err()
                        .to_string();
                        assert!(error.contains("effective features"), "{error}");
                        assert!(error.contains(&offending.to_string()), "{error}");
                        assert!(
                            error.contains(&primary.fingerprint().to_string()),
                            "{error}"
                        );
                        assert_eq!(certifier.calls, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn assembly_preserves_homogeneous_v1_and_v2_features_and_decryptability() {
        use openpgp::parse::PacketParser;
        use openpgp::parse::PacketParserResult;
        use openpgp::parse::Parse;
        use std::io::Cursor;
        use std::io::Read;

        for (features, pkesk_version, seip_version) in [
            (Features::empty().set_seipdv1(), 3, 1),
            (Features::empty().set_seipdv1().set_seipdv2(), 6, 2),
        ] {
            for with_userid in [false, true] {
                let primary = feature_cert(features.clone(), with_userid, false);
                let mut certifier = CountingSigner {
                    inner: signer(&primary),
                    calls: 0,
                };
                let primary = primary.strip_secret_key_material();
                // Padding is not a capability difference.
                let padded_features = Features::new([
                    if features.supports_seipdv2() {
                        0x09
                    } else {
                        0x01
                    },
                    0,
                ]);
                assert_ne!(features, padded_features);
                assert!(features.normalized_eq(&padded_features));
                let recipients = [
                    feature_cert(features.clone(), false, true),
                    feature_cert(padded_features, true, true),
                ];
                let public_recipients: Vec<_> = recipients
                    .iter()
                    .cloned()
                    .map(openpgp::Cert::strip_secret_key_material)
                    .collect();
                let selections: Vec<_> = public_recipients
                    .iter()
                    .map(|cert| EncryptionRecipient { cert, subkey: None })
                    .collect();
                let assembled = assemble_public_cert(
                    &primary,
                    &selections,
                    &BTreeMap::new(),
                    false,
                    &mut certifier,
                )
                .unwrap();
                assert_eq!(certifier.calls, recipients.len());
                assert_eq!(assembled.cert.fingerprint(), primary.fingerprint());
                assert_eq!(
                    assembled
                        .cert
                        .userids()
                        .map(|uid| uid.userid())
                        .collect::<Vec<_>>(),
                    primary
                        .userids()
                        .map(|uid| uid.userid())
                        .collect::<Vec<_>>()
                );
                assert_eq!(assembled.cert.clone().retain_subkeys(|_| false), primary);
                let plaintext = b"backup decryptable by each original recipient";
                let ciphertext = super::super::encrypt_armored(plaintext, &assembled).unwrap();
                let mut parser = PacketParser::from_bytes(ciphertext.as_bytes()).unwrap();
                let mut pkesks = 0;
                let mut seips = 0;
                while let PacketParserResult::Some(packet) = parser {
                    let (packet, next) = packet.recurse().unwrap();
                    match packet {
                        openpgp::Packet::PKESK(pkesk) => {
                            assert_eq!(pkesk.version(), pkesk_version);
                            pkesks += 1;
                        }
                        openpgp::Packet::SEIP(seip) => {
                            assert_eq!(seip.version(), seip_version);
                            seips += 1;
                        }
                        _ => {}
                    }
                    parser = next;
                }
                assert_eq!(pkesks, recipients.len());
                assert_eq!(seips, 1);
                for recipient in &recipients {
                    let mut secret = Vec::new();
                    recipient.as_tsk().serialize(&mut secret).unwrap();
                    let mut decrypted = Vec::new();
                    super::super::decrypt_with_secret_key(
                        Cursor::new(ciphertext.clone().into_bytes()),
                        &secret,
                    )
                    .unwrap()
                    .read_to_end(&mut decrypted)
                    .unwrap();
                    assert_eq!(decrypted, plaintext);
                }
            }
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
