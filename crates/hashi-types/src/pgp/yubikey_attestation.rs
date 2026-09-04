// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::POLICY;
use super::PgpPublicCert;
use anyhow::Context;
use anyhow::Result;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::types::Curve;
use std::sync::LazyLock;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::Oid;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

const SIG_COMMON_NAME: &str = "YubiKey OPGP Attestation SIG";
const DEC_COMMON_NAME: &str = "YubiKey OPGP Attestation DEC";
const YUBICO_KEY_SOURCE_OID: Oid<'static> = oid!(1.3.6.1.4.1.41482.5.2);
static YUBICO_OPENPGP_ISSUER_DER: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    let mut input = include_bytes!("yubico-openpgp-issuers.pem").as_slice();
    let mut issuers = Vec::new();
    while let Some(start) = input.iter().position(|byte| !byte.is_ascii_whitespace()) {
        input = &input[start..];
        assert!(
            has_exact_pem_header(input),
            "embedded Yubico issuer PEM must contain only CERTIFICATE blocks"
        );
        let (remainder, pem) =
            parse_x509_pem(input).expect("embedded Yubico issuer PEM must be valid");
        let consumed = &input[..input.len() - remainder.len()];
        assert!(
            has_exact_pem_footer(consumed),
            "embedded Yubico issuer PEM must close each CERTIFICATE block"
        );
        let (der_remainder, _) = parse_x509_certificate(&pem.contents)
            .expect("embedded Yubico issuer certificate DER must be valid");
        assert!(
            der_remainder.is_empty(),
            "embedded Yubico issuer certificate DER must not have trailing data"
        );
        issuers.push(pem.contents);
        input = remainder;
    }
    assert_eq!(
        issuers.len(),
        4,
        "embedded Yubico issuer PEM must contain four certificates"
    );
    issuers
});

fn has_exact_pem_header(input: &[u8]) -> bool {
    let line = input
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    line.strip_suffix(b"\r").unwrap_or(line) == b"-----BEGIN CERTIFICATE-----"
}

fn has_exact_pem_footer(consumed: &[u8]) -> bool {
    consumed
        .trim_ascii_end()
        .rsplit(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default()
        == b"-----END CERTIFICATE-----"
}
pub fn verify_yubikey_attestations(
    cert: &PgpPublicCert,
    device_attestation_cert_pem: &[u8],
    sig_attestation_pem: &[u8],
    dec_attestation_pem: &[u8],
) -> Result<()> {
    verify_yubikey_attestations_with_issuers(
        cert,
        device_attestation_cert_pem,
        sig_attestation_pem,
        dec_attestation_pem,
        &YUBICO_OPENPGP_ISSUER_DER,
    )
}

fn verify_yubikey_attestations_with_issuers(
    cert: &PgpPublicCert,
    device_attestation_cert_pem: &[u8],
    sig_attestation_pem: &[u8],
    dec_attestation_pem: &[u8],
    trusted_issuer_der: &[Vec<u8>],
) -> Result<()> {
    let device_attestation_der =
        parse_single_certificate_pem(device_attestation_cert_pem, "device attestation")?;
    let sig_attestation_der = parse_single_certificate_pem(sig_attestation_pem, "SIG attestation")?;
    let dec_attestation_der = parse_single_certificate_pem(dec_attestation_pem, "DEC attestation")?;

    let device_attestation = parse_certificate_der(&device_attestation_der, "device attestation")?;
    let sig_attestation = parse_certificate_der(&sig_attestation_der, "SIG attestation")?;
    let dec_attestation = parse_certificate_der(&dec_attestation_der, "DEC attestation")?;

    verify_device_attestation_issuer(&device_attestation, trusted_issuer_der)?;
    let sig_key = verify_attestation_statement(
        &sig_attestation,
        &device_attestation,
        "SIG",
        SIG_COMMON_NAME,
    )?;
    let dec_key = verify_attestation_statement(
        &dec_attestation,
        &device_attestation,
        "DEC",
        DEC_COMMON_NAME,
    )?;

    let signing_key = yubikey_signing_key(&cert.cert)?;
    if signing_key != sig_key {
        anyhow::bail!("SIG attestation key does not match the OpenPGP signing key");
    }
    let encryption_key = yubikey_encryption_key(&cert.cert)?;
    if encryption_key != dec_key {
        anyhow::bail!("DEC attestation key does not match the OpenPGP encryption key");
    }
    Ok(())
}

fn parse_single_certificate_pem(input: &[u8], description: &str) -> Result<Vec<u8>> {
    let start = input
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| anyhow::anyhow!("{description} PEM is empty"))?;
    let input = &input[start..];
    if !has_exact_pem_header(input) {
        anyhow::bail!("{description} PEM does not start with a CERTIFICATE block");
    }
    let (remainder, pem) = parse_x509_pem(input)
        .map_err(|error| anyhow::anyhow!("invalid {description} PEM: {error}"))?;
    let consumed = &input[..input.len() - remainder.len()];
    if !has_exact_pem_footer(consumed) {
        anyhow::bail!("{description} PEM does not end its CERTIFICATE block correctly");
    }
    if remainder.iter().any(|byte| !byte.is_ascii_whitespace()) {
        anyhow::bail!("{description} PEM contains trailing data");
    }
    Ok(pem.contents)
}

fn parse_certificate_der<'a>(der: &'a [u8], description: &str) -> Result<X509Certificate<'a>> {
    let (remainder, certificate) = parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("invalid {description} certificate DER: {error}"))?;
    if !remainder.is_empty() {
        anyhow::bail!("{description} certificate DER contains trailing data");
    }
    Ok(certificate)
}

fn verify_device_attestation_issuer(
    device_attestation: &X509Certificate<'_>,
    trusted_issuer_der: &[Vec<u8>],
) -> Result<()> {
    let mut matched_issuer = false;
    for issuer_der in trusted_issuer_der {
        let issuer = parse_certificate_der(issuer_der, "trusted issuer")?;
        if device_attestation.issuer() != issuer.subject() {
            continue;
        }
        matched_issuer = true;
        if device_attestation
            .verify_signature(Some(issuer.public_key()))
            .is_ok()
        {
            return Ok(());
        }
    }
    if matched_issuer {
        anyhow::bail!("device attestation certificate has an invalid issuer signature");
    }
    anyhow::bail!("device attestation certificate issuer is not trusted")
}

fn verify_attestation_statement<'a>(
    statement: &'a X509Certificate<'_>,
    device_attestation: &X509Certificate<'_>,
    slot: &str,
    expected_common_name: &str,
) -> Result<&'a [u8]> {
    if statement.issuer() != device_attestation.subject() {
        anyhow::bail!("{slot} attestation was not issued by the device certificate");
    }
    statement
        .verify_signature(Some(device_attestation.public_key()))
        .with_context(|| format!("{slot} attestation signature is invalid"))?;

    let mut common_names = statement.subject().iter_common_name();
    let common_name = common_names
        .next()
        .ok_or_else(|| anyhow::anyhow!("{slot} attestation has no subject common name"))?
        .as_str()
        .with_context(|| format!("{slot} attestation subject common name is not a string"))?;
    if common_names.next().is_some() {
        anyhow::bail!("{slot} attestation has multiple subject common names");
    }
    if common_name != expected_common_name {
        anyhow::bail!(
            "{slot} attestation has subject common name {common_name:?}, expected {expected_common_name:?}"
        );
    }

    let key_source = statement
        .get_extension_unique(&YUBICO_KEY_SOURCE_OID)
        .with_context(|| format!("{slot} attestation has duplicate key-source extensions"))?
        .ok_or_else(|| anyhow::anyhow!("{slot} attestation has no key-source extension"))?;
    if key_source.value != [0x02, 0x01, 0x01] {
        anyhow::bail!("{slot} attestation key was not generated on the YubiKey");
    }

    let public_key = &statement.public_key().subject_public_key;
    if public_key.unused_bits != 0 {
        anyhow::bail!("{slot} attestation public key has unused bits");
    }
    match public_key.data.as_ref() {
        key @ [..] if key.len() == 32 => Ok(key),
        [0x40, key @ ..] if key.len() == 32 => Ok(key),
        key => anyhow::bail!(
            "{slot} attestation public key has unsupported {}-byte encoding",
            key.len()
        ),
    }
}

fn yubikey_signing_key(cert: &openpgp::Cert) -> Result<&[u8]> {
    let mut candidates = cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing();
    let candidate = candidates
        .next()
        .ok_or_else(|| anyhow::anyhow!("OpenPGP certificate has no usable signing key"))?;
    if candidates.next().is_some() {
        anyhow::bail!("OpenPGP certificate has multiple usable signing keys");
    }
    match candidate.key().mpis() {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => q
            .decode_point(&Curve::Ed25519)
            .map(|(key, _)| key)
            .context("OpenPGP signing key has invalid Ed25519 encoding"),
        algorithm => anyhow::bail!(
            "OpenPGP signing key does not use the RFC 4880 Ed25519 profile: {algorithm:?}"
        ),
    }
}

fn yubikey_encryption_key(cert: &openpgp::Cert) -> Result<&[u8]> {
    let mut candidates = cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();
    let candidate = candidates
        .next()
        .ok_or_else(|| anyhow::anyhow!("OpenPGP certificate has no usable encryption key"))?;
    if candidates.next().is_some() {
        anyhow::bail!("OpenPGP certificate has multiple usable encryption keys");
    }
    match candidate.key().mpis() {
        mpi::PublicKey::ECDH {
            curve: Curve::Cv25519,
            q,
            ..
        } => q
            .decode_point(&Curve::Cv25519)
            .map(|(key, _)| key)
            .context("OpenPGP encryption key has invalid Curve25519 encoding"),
        algorithm => anyhow::bail!(
            "OpenPGP encryption key does not use the RFC 4880 Curve25519 profile: {algorithm:?}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    use rcgen::BasicConstraints;
    use rcgen::Certificate;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DistinguishedName;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::PKCS_ED25519;
    use rcgen::PublicKeyData;
    use rcgen::SignatureAlgorithm;
    use sequoia_openpgp::cert::prelude::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::types::KeyFlags;
    struct StatementPublicKey(Vec<u8>);

    impl PublicKeyData for StatementPublicKey {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }

        fn algorithm(&self) -> &SignatureAlgorithm {
            &PKCS_ED25519
        }
    }

    struct YubikeyAttestationFixture {
        cert: PgpPublicCert,
        issuer_der: Vec<Vec<u8>>,
        device_pem: String,
        sig_pem: String,
        dec_pem: String,
    }

    fn test_certificate_params(common_name: &str) -> CertificateParams {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params
    }

    fn test_yubikey_pgp_cert(extra_signing_key: bool, extra_encryption_key: bool) -> PgpPublicCert {
        let builder = CertBuilder::new()
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_authentication_subkey();
        let builder = if extra_signing_key {
            builder.add_signing_subkey()
        } else {
            builder
        };
        let builder = if extra_encryption_key {
            builder.add_transport_encryption_subkey()
        } else {
            builder
        };
        let (cert, _) = builder.generate().unwrap();
        let mut public = Vec::new();
        cert.armored().export(&mut public).unwrap();
        PgpPublicCert::new(String::from_utf8(public).unwrap()).unwrap()
    }

    fn test_first_signing_key(cert: &PgpPublicCert) -> Vec<u8> {
        let candidate = cert
            .cert
            .keys()
            .with_policy(&*POLICY, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap();
        match candidate.key().mpis() {
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q,
            } => q.decode_point(&Curve::Ed25519).unwrap().0.to_vec(),
            algorithm => panic!("unexpected signing key: {algorithm:?}"),
        }
    }

    fn test_first_encryption_key(cert: &PgpPublicCert) -> Vec<u8> {
        let candidate = cert
            .cert
            .keys()
            .with_policy(&*POLICY, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .next()
            .unwrap();
        match candidate.key().mpis() {
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                q,
                ..
            } => q.decode_point(&Curve::Cv25519).unwrap().0.to_vec(),
            algorithm => panic!("unexpected encryption key: {algorithm:?}"),
        }
    }

    fn test_attestation_statement(
        device: &Certificate,
        device_key: &KeyPair,
        common_name: &str,
        public_key: Vec<u8>,
        key_sources: &[u8],
    ) -> Certificate {
        let mut params = test_certificate_params(common_name);
        for &key_source in key_sources {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 41482, 5, 2],
                    vec![0x02, 0x01, key_source],
                ));
        }
        params
            .signed_by(&StatementPublicKey(public_key), device, device_key)
            .unwrap()
    }

    fn yubikey_attestation_fixture(
        sig_common_name: &str,
        sig_key_sources: &[u8],
    ) -> YubikeyAttestationFixture {
        yubikey_attestation_fixture_for_cert(
            test_yubikey_pgp_cert(false, false),
            sig_common_name,
            sig_key_sources,
        )
    }

    fn yubikey_attestation_fixture_for_cert(
        cert: PgpPublicCert,
        sig_common_name: &str,
        sig_key_sources: &[u8],
    ) -> YubikeyAttestationFixture {
        let sig_key = test_first_signing_key(&cert);
        let mut dec_key = Vec::with_capacity(33);
        dec_key.push(0x40);
        dec_key.extend_from_slice(&test_first_encryption_key(&cert));

        let issuer_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut issuer_params = test_certificate_params("test OpenPGP attestation issuer");
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = issuer_params.self_signed(&issuer_key).unwrap();

        let device_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let device = test_certificate_params("test YubiKey")
            .signed_by(&device_key, &issuer, &issuer_key)
            .unwrap();
        let sig = test_attestation_statement(
            &device,
            &device_key,
            sig_common_name,
            sig_key,
            sig_key_sources,
        );
        let dec = test_attestation_statement(&device, &device_key, DEC_COMMON_NAME, dec_key, &[1]);

        YubikeyAttestationFixture {
            cert,
            issuer_der: vec![issuer.der().to_vec()],
            device_pem: device.pem(),
            sig_pem: sig.pem(),
            dec_pem: dec.pem(),
        }
    }

    impl YubikeyAttestationFixture {
        fn verify(&self) -> Result<()> {
            self.verify_with(
                &self.cert,
                self.device_pem.as_bytes(),
                self.sig_pem.as_bytes(),
            )
        }

        fn verify_with(
            &self,
            cert: &PgpPublicCert,
            device_pem: &[u8],
            sig_pem: &[u8],
        ) -> Result<()> {
            verify_yubikey_attestations_with_issuers(
                cert,
                device_pem,
                sig_pem,
                self.dec_pem.as_bytes(),
                &self.issuer_der,
            )
        }
    }

    fn certificate_pem(der: &[u8]) -> String {
        let encoded = base64ct::Base64::encode_string(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    fn assert_attestation_error(result: Result<()>, expected: &str) {
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in error, got: {error:#}"
        );
    }

    #[test]
    fn yubikey_attestation_accepts_valid_bundle() {
        let fixture = yubikey_attestation_fixture(SIG_COMMON_NAME, &[1]);

        fixture.verify().unwrap();
    }

    #[test]
    fn yubikey_attestation_rejects_untrusted_and_invalid_statements() {
        let fixture = yubikey_attestation_fixture(SIG_COMMON_NAME, &[1]);
        assert_attestation_error(
            verify_yubikey_attestations(
                &fixture.cert,
                fixture.device_pem.as_bytes(),
                fixture.sig_pem.as_bytes(),
                fixture.dec_pem.as_bytes(),
            ),
            "issuer is not trusted",
        );

        let mut tampered_sig_der =
            parse_single_certificate_pem(fixture.sig_pem.as_bytes(), "SIG attestation").unwrap();
        *tampered_sig_der.last_mut().unwrap() ^= 1;
        let tampered_sig_pem = certificate_pem(&tampered_sig_der);
        assert_attestation_error(
            fixture.verify_with(
                &fixture.cert,
                fixture.device_pem.as_bytes(),
                tampered_sig_pem.as_bytes(),
            ),
            "SIG attestation signature is invalid",
        );

        let imported = yubikey_attestation_fixture(SIG_COMMON_NAME, &[0]);
        assert_attestation_error(
            imported.verify(),
            "SIG attestation key was not generated on the YubiKey",
        );

        let wrong_slot = yubikey_attestation_fixture(DEC_COMMON_NAME, &[1]);
        assert_attestation_error(
            wrong_slot.verify(),
            "SIG attestation has subject common name",
        );

        let duplicate_extension = yubikey_attestation_fixture(SIG_COMMON_NAME, &[1, 1]);
        assert_attestation_error(
            duplicate_extension.verify(),
            "SIG attestation has duplicate key-source extensions",
        );
    }

    #[test]
    fn yubikey_attestation_rejects_malformed_inputs_and_key_mismatches() {
        let fixture = yubikey_attestation_fixture(SIG_COMMON_NAME, &[1]);
        assert_attestation_error(
            fixture.verify_with(
                &fixture.cert,
                b"not a certificate",
                fixture.sig_pem.as_bytes(),
            ),
            "does not start with a CERTIFICATE block",
        );

        let device_with_trailing_data = format!("{}\ntrailing", fixture.device_pem);
        assert_attestation_error(
            fixture.verify_with(
                &fixture.cert,
                device_with_trailing_data.as_bytes(),
                fixture.sig_pem.as_bytes(),
            ),
            "device attestation PEM contains trailing data",
        );

        let device_with_malformed_footer = fixture.device_pem.replace(
            "-----END CERTIFICATE-----",
            "-----END invalid-----END CERTIFICATE-----",
        );
        assert_attestation_error(
            fixture.verify_with(
                &fixture.cert,
                device_with_malformed_footer.as_bytes(),
                fixture.sig_pem.as_bytes(),
            ),
            "does not end its CERTIFICATE block correctly",
        );

        let other_cert = test_yubikey_pgp_cert(false, false);
        assert_attestation_error(
            fixture.verify_with(
                &other_cert,
                fixture.device_pem.as_bytes(),
                fixture.sig_pem.as_bytes(),
            ),
            "SIG attestation key does not match the OpenPGP signing key",
        );

        for (fixture, expected) in [
            (
                yubikey_attestation_fixture_for_cert(
                    test_yubikey_pgp_cert(true, false),
                    SIG_COMMON_NAME,
                    &[1],
                ),
                "multiple usable signing keys",
            ),
            (
                yubikey_attestation_fixture_for_cert(
                    test_yubikey_pgp_cert(false, true),
                    SIG_COMMON_NAME,
                    &[1],
                ),
                "multiple usable encryption keys",
            ),
        ] {
            assert_attestation_error(fixture.verify(), expected);
        }
    }
}
