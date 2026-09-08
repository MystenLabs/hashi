// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::POLICY;
use super::super::PgpPublicCert;
use super::parse_single_certificate_pem;
use super::verify_yubikey_attestations;
use super::verify_yubikey_attestations_with_issuers;
use base64ct::Base64;
use base64ct::Encoding;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use rcgen::BasicConstraints;
use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::CustomExtension;
use rcgen::DistinguishedName;
use rcgen::DnType;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::PKCS_ECDSA_P256_SHA256;
use rcgen::PKCS_ED25519;
use rcgen::PublicKeyData;
use rcgen::SignatureAlgorithm;
use sequoia_openpgp::Profile;
use sequoia_openpgp::cert::prelude::CertBuilder;
use sequoia_openpgp::cert::prelude::CipherSuite;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::Curve;
use sequoia_openpgp::types::KeyFlags;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use x509_parser::parse_x509_certificate;

const SOURCE_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 5, 2];
const FINGERPRINT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 5, 4];
const GENERATED: &[u8] = &[2, 1, 1];

fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Base64::encode_string(der),
    )
}

#[derive(Clone, Copy)]
enum Slot {
    Sig,
    Dec,
}

impl Slot {
    fn common_name(self) -> &'static str {
        match self {
            Self::Sig => "YubiKey OPGP Attestation SIG",
            Self::Dec => "YubiKey OPGP Attestation DEC",
        }
    }

    fn algorithm(self) -> u8 {
        match self {
            Self::Sig => 112, // id-Ed25519
            Self::Dec => 110, // id-X25519
        }
    }
}

struct RawPublicKey(Vec<u8>);

impl PublicKeyData for RawPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &PKCS_ED25519
    }
}

fn params(name: &str) -> CertificateParams {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name);
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params
}

fn pgp_cert(extra_signing: bool, extra_encryption: bool) -> PgpPublicCert {
    let mut builder = CertBuilder::new()
        .set_profile(Profile::RFC4880)
        .unwrap()
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_creation_time(UNIX_EPOCH + Duration::from_secs(1_704_067_200))
        .set_validity_period(None)
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_userid("") // Match provisioning's `oct generate --userid ''`.
        .add_signing_subkey()
        .add_transport_encryption_subkey();
    if extra_signing {
        builder = builder.add_signing_subkey();
    }
    if extra_encryption {
        builder = builder.add_transport_encryption_subkey();
    }
    let (cert, _) = builder.generate().unwrap();
    let mut public = Vec::new();
    cert.armored().export(&mut public).unwrap();
    PgpPublicCert::new(String::from_utf8(public).unwrap()).unwrap()
}

fn key_material(cert: &PgpPublicCert, slot: Slot) -> (Vec<u8>, Vec<u8>) {
    let keys = cert
        .cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false);
    let key = match slot {
        Slot::Sig => keys.for_signing().next().unwrap(),
        Slot::Dec => keys.for_transport_encryption().next().unwrap(),
    };
    let bytes = match key.key().mpis() {
        mpi::PublicKey::EdDSA { curve, q } | mpi::PublicKey::ECDH { curve, q, .. } => {
            assert!(matches!(curve, Curve::Ed25519 | Curve::Cv25519));
            q.decode_point(curve).unwrap().0.to_vec()
        }
        other => panic!("unexpected fixture key: {other:?}"),
    };
    (bytes, key.key().fingerprint().as_bytes().to_vec())
}

struct Fixture {
    cert: PgpPublicCert,
    issuer: Certificate,
    device: Certificate,
    device_key: KeyPair,
    signing_key: SigningKey,
    statements: [Vec<u8>; 2],
}

impl Fixture {
    fn new(cert: PgpPublicCert) -> Self {
        // Exercise an ECDSA issuer, rather than making every chain Ed25519-only.
        let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut issuer_params = params("test pinned issuer");
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = issuer_params.self_signed(&issuer_key).unwrap();
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let mut pkcs8 = vec![
            0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
        ];
        pkcs8.extend_from_slice(&signing_key.to_bytes());
        let device_key = KeyPair::try_from(pkcs8).unwrap();
        let device = params("test attestation device")
            .signed_by(&device_key, &issuer, &issuer_key)
            .unwrap();
        let mut fixture = Self {
            cert,
            issuer,
            device,
            device_key,
            signing_key,
            statements: [Vec::new(), Vec::new()],
        };
        fixture.statements = [Slot::Sig, Slot::Dec].map(|slot| {
            let (key, _) = key_material(&fixture.cert, slot);
            fixture.statement(
                slot,
                slot.common_name(),
                key,
                &[GENERATED],
                slot.algorithm(),
            )
        });
        fixture
    }

    fn statement(
        &self,
        slot: Slot,
        name: &str,
        key: Vec<u8>,
        sources: &[&[u8]],
        algorithm: u8,
    ) -> Vec<u8> {
        let mut params = params(name);
        for source in sources {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    SOURCE_OID,
                    source.to_vec(),
                ));
        }
        // This writable metadata always claims the expected PGP fingerprint,
        // including when a negative case substitutes the actual SPKI key.
        let (_, fingerprint) = key_material(&self.cert, slot);
        let mut metadata = vec![4, fingerprint.len() as u8];
        metadata.extend(fingerprint);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(FINGERPRINT_OID, metadata));
        let mut der = params
            .signed_by(&RawPublicKey(key), &self.device, &self.device_key)
            .unwrap()
            .der()
            .to_vec();
        // rcgen exposes Ed25519 but not X25519 SPKI. Replace only its SPKI OID
        // and re-sign the TBS so algorithm tests cannot fail on a bad signature.
        let (_, parsed) = parse_x509_certificate(&der).unwrap();
        let spki_offset = parsed.public_key().raw.as_ptr() as usize - der.as_ptr() as usize;
        der[spki_offset + 8] = algorithm;
        let (_, parsed) = parse_x509_certificate(&der).unwrap();
        let signature = self.signing_key.sign(parsed.tbs_certificate.as_ref());
        let signature_offset = der.len() - 64;
        der[signature_offset..].copy_from_slice(&signature.to_bytes());
        der
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.verify_inputs(self.device.der(), &self.statements[0], &self.statements[1])
    }

    fn verify_inputs(&self, device: &[u8], sig: &[u8], dec: &[u8]) -> anyhow::Result<()> {
        verify_yubikey_attestations_with_issuers(
            &self.cert,
            device,
            sig,
            dec,
            &[self.issuer.der().as_ref()],
        )
        .map(|_| ())
    }
}

#[test]
fn valid_binding_accepts_ecdsa_issuer_and_both_slot_keys() {
    let fixture = Fixture::new(pgp_cert(false, false));
    fixture.verify().unwrap();
    // A custom trusted test issuer must not become a production trust anchor.
    assert!(
        verify_yubikey_attestations(
            &fixture.cert,
            pem(fixture.device.der()).as_bytes(),
            pem(&fixture.statements[0]).as_bytes(),
            pem(&fixture.statements[1]).as_bytes(),
        )
        .is_err()
    );
}

#[test]
fn attested_kp_cert_rejects_valid_chain_from_untrusted_issuer() {
    let fixture = Fixture::new(pgp_cert(false, false));
    fixture.verify().unwrap();

    let error = crate::guardian::AttestedKpCert::new(
        fixture.cert,
        pem(fixture.device.der()).into_bytes(),
        pem(&fixture.statements[0]).into_bytes(),
        pem(&fixture.statements[1]).into_bytes(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        crate::guardian::GuardianError::InvalidInputs(_)
    ));
}

#[test]
fn issuer_name_alone_does_not_establish_trust() {
    let fixture = Fixture::new(pgp_cert(false, false));
    let impostor_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let impostor = params("test pinned issuer")
        .self_signed(&impostor_key)
        .unwrap();
    assert!(
        verify_yubikey_attestations_with_issuers(
            &fixture.cert,
            fixture.device.der(),
            &fixture.statements[0],
            &fixture.statements[1],
            &[impostor.der().as_ref()],
        )
        .is_err()
    );
}

#[test]
fn every_chain_signature_is_verified() {
    let fixture = Fixture::new(pgp_cert(false, false));
    for index in 0..3 {
        let mut inputs = [
            fixture.device.der().to_vec(),
            fixture.statements[0].clone(),
            fixture.statements[1].clone(),
        ];
        *inputs[index].last_mut().unwrap() ^= 1;
        assert!(
            fixture
                .verify_inputs(&inputs[0], &inputs[1], &inputs[2])
                .is_err()
        );
    }
}

#[test]
fn statement_issuer_name_must_match_even_with_valid_signature() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    let original_device = fixture.device.der().to_vec();
    fixture.device = params("different device name")
        .self_signed(&fixture.device_key)
        .unwrap();
    let (key, _) = key_material(&fixture.cert, Slot::Sig);
    let wrong_issuer =
        fixture.statement(Slot::Sig, Slot::Sig.common_name(), key, &[GENERATED], 112);
    // The original device remains signed by the pinned issuer; only the
    // statement was issued under a different name with the very same key.
    assert!(
        fixture
            .verify_inputs(&original_device, &wrong_issuer, &fixture.statements[1])
            .is_err()
    );
}

#[test]
fn slot_names_are_bound_independently_of_key_bytes() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    for slot in [Slot::Sig, Slot::Dec] {
        let index = match slot {
            Slot::Sig => 0,
            Slot::Dec => 1,
        };
        let (key, _) = key_material(&fixture.cert, slot);
        let wrong = fixture.statement(
            slot,
            "YubiKey OPGP Attestation AUT",
            key,
            &[GENERATED],
            slot.algorithm(),
        );
        let original = std::mem::replace(&mut fixture.statements[index], wrong);
        assert!(fixture.verify().is_err());
        fixture.statements[index] = original;
    }
}

#[test]
fn source_must_be_one_canonical_generated_integer() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    let malformed_sources: &[&[&[u8]]] = &[
        &[],
        &[&[2, 1, 0]],
        &[GENERATED, GENERATED],
        &[&[1, 1, 0xff]], // BOOLEAN true is not INTEGER one.
        &[&[2, 2, 0, 1]], // Non-minimal INTEGER encoding.
    ];
    for sources in malformed_sources {
        let (key, _) = key_material(&fixture.cert, Slot::Dec);
        fixture.statements[1] =
            fixture.statement(Slot::Dec, Slot::Dec.common_name(), key, sources, 110);
        assert!(fixture.verify().is_err());
    }
}

#[test]
fn fingerprint_metadata_cannot_substitute_for_either_public_key() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    let other = pgp_cert(false, false);
    for slot in [Slot::Sig, Slot::Dec] {
        let index = match slot {
            Slot::Sig => 0,
            Slot::Dec => 1,
        };
        let (other_key, _) = key_material(&other, slot);
        let wrong = fixture.statement(
            slot,
            slot.common_name(),
            other_key,
            &[GENERATED],
            slot.algorithm(),
        );
        let original = std::mem::replace(&mut fixture.statements[index], wrong);
        assert!(fixture.verify().is_err());
        fixture.statements[index] = original;
    }
}

#[test]
fn ambiguous_usable_pgp_keys_are_rejected_even_when_first_key_matches() {
    for (extra_signing, extra_encryption) in [(true, false), (false, true)] {
        let fixture = Fixture::new(pgp_cert(extra_signing, extra_encryption));
        assert!(fixture.verify().is_err());
    }
}

#[test]
fn matching_bytes_under_unsupported_spki_algorithm_are_rejected() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    let (key, _) = key_material(&fixture.cert, Slot::Sig);
    // id-Ed448 with 32 bytes: a valid device signature must not make these
    // matching bytes an Ed25519 public key.
    fixture.statements[0] =
        fixture.statement(Slot::Sig, Slot::Sig.common_name(), key, &[GENERATED], 113);
    assert!(fixture.verify().is_err());
}

#[test]
fn malformed_public_key_encoding_is_rejected_after_signature_verification() {
    let mut fixture = Fixture::new(pgp_cert(false, false));
    let (mut key, _) = key_material(&fixture.cert, Slot::Sig);
    key.insert(0, 0x41);
    fixture.statements[0] =
        fixture.statement(Slot::Sig, Slot::Sig.common_name(), key, &[GENERATED], 112);
    assert!(fixture.verify().is_err());
}

#[test]
fn each_der_input_must_contain_exactly_one_certificate() {
    let fixture = Fixture::new(pgp_cert(false, false));
    for index in 0..3 {
        let mut inputs = [
            fixture.device.der().to_vec(),
            fixture.statements[0].clone(),
            fixture.statements[1].clone(),
        ];
        inputs[index].extend_from_slice(fixture.issuer.der());
        assert!(
            fixture
                .verify_inputs(&inputs[0], &inputs[1], &inputs[2])
                .is_err()
        );
    }
}

#[test]
fn pem_parser_accepts_one_certificate_but_not_ambiguous_boundaries() {
    let fixture = Fixture::new(pgp_cert(false, false));
    let valid = pem(fixture.device.der());
    let decoded = parse_single_certificate_pem(valid.as_bytes()).unwrap();
    fixture
        .verify_inputs(&decoded, &fixture.statements[0], &fixture.statements[1])
        .unwrap();
    for invalid in [
        format!("{valid}{valid}"),
        format!("{valid}trailing garbage"),
        format!("leading garbage{valid}"),
        valid.replace("END CERTIFICATE", "END PUBLIC KEY"),
        valid.replace("BEGIN CERTIFICATE", "BEGIN CERTIFICATEX"),
    ] {
        assert!(parse_single_certificate_pem(invalid.as_bytes()).is_err());
    }
}
