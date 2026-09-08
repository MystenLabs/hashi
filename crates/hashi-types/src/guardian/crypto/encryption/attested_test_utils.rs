// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::AttestedKpCert;
use crate::pgp::PgpPublicCert;
use base64ct::Base64;
use base64ct::Encoding;
use ed25519_consensus::SigningKey;
use rcgen::BasicConstraints;
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
use sequoia_openpgp::Cert;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use x509_parser::parse_x509_certificate;

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

fn pem(der: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Base64::encode_string(der),
    )
    .into_bytes()
}

/// Generate an immutable KP bundle verified against a synthetic test authority,
/// together with its armored signing/decryption secret. The public constructor,
/// serde decoder, and protobuf decoder do not trust this authority.
///
/// This helper only generates its own inputs: it cannot bless caller-supplied
/// certificates, attestations, keys, or trust roots.
pub fn mock_attested_kp_keypair() -> (AttestedKpCert, String) {
    let (public, secret) = crate::pgp::test_utils::mock_pgp_keypair();
    let pgp_cert = Cert::from_bytes(public.as_bytes()).unwrap();
    let cert = PgpPublicCert::new(public).unwrap();

    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut issuer_params = params("test pinned issuer");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = issuer_params.self_signed(&issuer_key).unwrap();
    let signing_key = SigningKey::new(rand::thread_rng());
    let mut pkcs8 = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    pkcs8.extend_from_slice(&signing_key.to_bytes());
    let device_key = KeyPair::try_from(pkcs8).unwrap();
    let device = params("test attestation device")
        .signed_by(&device_key, &issuer, &issuer_key)
        .unwrap();

    let policy = StandardPolicy::new();
    let statements = [true, false].map(|signing| {
        let candidates = pgp_cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false);
        let key = if signing {
            candidates.for_signing().next().unwrap()
        } else {
            candidates.for_transport_encryption().next().unwrap()
        };
        let bytes = match key.key().mpis() {
            mpi::PublicKey::EdDSA { curve, q } | mpi::PublicKey::ECDH { curve, q, .. } => {
                q.decode_point(curve).unwrap().0.to_vec()
            }
            other => panic!("unexpected fixture key: {other:?}"),
        };
        let mut statement_params = params(if signing {
            "YubiKey OPGP Attestation SIG"
        } else {
            "YubiKey OPGP Attestation DEC"
        });
        statement_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 5, 2],
                vec![2, 1, 1], // Canonical ASN.1 INTEGER: generated on device.
            ));
        let mut der = statement_params
            .signed_by(&RawPublicKey(bytes), &device, &device_key)
            .unwrap()
            .der()
            .to_vec();
        if !signing {
            // rcgen lacks X25519 SPKI. Change only the Ed25519 SPKI OID,
            // then sign the resulting TBS with the actual device key.
            let (_, parsed) = parse_x509_certificate(&der).unwrap();
            let spki_offset = parsed.public_key().raw.as_ptr() as usize - der.as_ptr() as usize;
            der[spki_offset + 8] = 110; // id-X25519
            let (_, parsed) = parse_x509_certificate(&der).unwrap();
            let signature = signing_key.sign(parsed.tbs_certificate.as_ref());
            let signature_offset = der.len() - 64;
            der[signature_offset..].copy_from_slice(&signature.to_bytes());
        }
        der
    });
    let keys = crate::pgp::verify_yubikey_attestations_with_issuers(
        &cert,
        device.der(),
        &statements[0],
        &statements[1],
        &[issuer.der().as_ref()],
    )
    .expect("generated KP fixture must pass all attestation checks");
    (
        AttestedKpCert {
            cert,
            device_pem: pem(device.der()),
            sig_pem: pem(&statements[0]),
            dec_pem: pem(&statements[1]),
            keys,
        },
        secret,
    )
}

/// Generate distinct KP bundles checked under a test-only authority.
pub fn mock_attested_kp_certs(count: usize) -> Vec<AttestedKpCert> {
    (0..count).map(|_| mock_attested_kp_keypair().0).collect()
}
