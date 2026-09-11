// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Narrow OpenPGP attestation verification against four fixed Yubico issuer pins.
//!
//! This checks direct signatures, not RFC 5280 certification paths. The pins are
//! the OpenPGP CA from <https://developers.yubico.com/PKI/yubico-opgp-ca-1.pem>
//! and OPGP A 1, B 1, and B2 1 from
//! <https://developers.yubico.com/PKI/yubico-intermediate.pem>, matched byte-for-byte
//! against Yubico's published certificates on 2026-09-08. Intermediate pins are
//! trusted directly; their ancestors are not additional trust anchors.
//!
//! X.509 validity dates, revocation, touch policy, and freshness are not enforced.
//! OpenPGP keys must be usable under the existing OpenPGP policy. Attestation
//! fingerprint metadata is deliberately ignored: the device administrator can
//! overwrite it. See <https://developers.yubico.com/PGP/Attestation.html>.
//!
//! Statements must use RFC 8410 Ed25519/X25519 SPKI encoding (raw 32-byte keys,
//! absent parameters). Older firmware's nonstandard Curve25519 encoding is not
//! supported; Yubico reports correcting it in 5.7:
//! <https://github.com/Yubico/yubikey-manager/issues/402>.

use super::AttestedPgpKeys;
use super::Fingerprint;
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
const ED25519_OID: Oid<'static> = oid!(1.3.101.112);
const X25519_OID: Oid<'static> = oid!(1.3.101.110);
static TRUSTED_ISSUERS: LazyLock<[Vec<u8>; 4]> = LazyLock::new(|| {
    let mut input = include_bytes!("yubikey_attestation/yubico-openpgp-issuers.pem").as_slice();
    let issuers = std::array::from_fn(|_| {
        let (remainder, der) =
            parse_certificate_pem(input).expect("embedded Yubico issuer PEM must be valid");
        parse_certificate_der(&der, "embedded issuer")
            .expect("embedded Yubico issuer DER must be valid");
        input = remainder;
        der
    });
    assert!(
        input.trim_ascii().is_empty(),
        "unexpected embedded issuer data"
    );
    issuers
});

/// Verify that `cert`'s sole usable signing and transport-encryption keys were
/// generated on a YubiKey, using its device certificate and SIG/DEC statements.
///
/// Each input must contain exactly one PEM `CERTIFICATE` block, with no other
/// non-whitespace data and exactly one DER certificate inside. The device must
/// be signed directly by a pinned Yubico OpenPGP issuer, and both statements by
/// that device. Only legacy OpenPGP Ed25519 signing and Cv25519 encryption keys
/// are supported, with RFC 8410 statement SPKIs (not older firmware encodings).
/// This does not enforce X.509 dates, revocation, touch, or freshness, and does
/// not establish current possession of either private key.
pub fn verify_yubikey_attestations(
    cert: &PgpPublicCert,
    device_pem: &[u8],
    sig_pem: &[u8],
    dec_pem: &[u8],
) -> Result<()> {
    verify_yubikey_attestations_and_keys(cert, device_pem, sig_pem, dec_pem).map(|_| ())
}

pub(crate) fn verify_yubikey_attestations_and_keys(
    cert: &PgpPublicCert,
    device_pem: &[u8],
    sig_pem: &[u8],
    dec_pem: &[u8],
) -> Result<AttestedPgpKeys> {
    let device_der = parse_single_certificate_pem(device_pem).context("device attestation")?;
    let sig_der = parse_single_certificate_pem(sig_pem).context("SIG attestation")?;
    let dec_der = parse_single_certificate_pem(dec_pem).context("DEC attestation")?;
    let issuers = TRUSTED_ISSUERS.each_ref().map(Vec::as_slice);
    verify_yubikey_attestations_with_issuers(cert, &device_der, &sig_der, &dec_der, &issuers)
}

pub(crate) fn verify_yubikey_attestations_with_issuers(
    cert: &PgpPublicCert,
    device_der: &[u8],
    sig_der: &[u8],
    dec_der: &[u8],
    trusted_issuers: &[&[u8]],
) -> Result<AttestedPgpKeys> {
    let device = parse_certificate_der(device_der, "device attestation")?;
    let sig = parse_certificate_der(sig_der, "SIG attestation")?;
    let dec = parse_certificate_der(dec_der, "DEC attestation")?;

    verify_device_issuer(&device, trusted_issuers)?;
    verify_statement(&sig, &device, SIG_COMMON_NAME)?;
    verify_statement(&dec, &device, DEC_COMMON_NAME)?;
    let (signing, signing_bytes) = signing_key(&cert.cert)?;
    let (encryption, encryption_bytes) = encryption_key(&cert.cert)?;
    anyhow::ensure!(
        statement_key(&sig, &ED25519_OID)? == signing_bytes,
        "SIG attestation key does not match the OpenPGP signing key"
    );
    anyhow::ensure!(
        statement_key(&dec, &X25519_OID)? == encryption_bytes,
        "DEC attestation key does not match the OpenPGP encryption key"
    );
    Ok(AttestedPgpKeys {
        signing,
        encryption,
    })
}

fn parse_single_certificate_pem(input: &[u8]) -> Result<Vec<u8>> {
    let (remainder, der) = parse_certificate_pem(input)?;
    anyhow::ensure!(
        remainder.trim_ascii().is_empty(),
        "certificate PEM contains trailing data"
    );
    Ok(der)
}

fn parse_certificate_pem(input: &[u8]) -> Result<(&[u8], Vec<u8>)> {
    let input = input.trim_ascii_start();
    // The library skips preambles and does not check that the footer label
    // matches. Check those boundaries without reimplementing PEM decoding.
    anyhow::ensure!(
        input
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default()
            .trim_ascii_end()
            == b"-----BEGIN CERTIFICATE-----",
        "expected a CERTIFICATE PEM header"
    );
    let (remainder, pem) = parse_x509_pem(input)
        .map_err(|error| anyhow::anyhow!("invalid certificate PEM: {error}"))?;
    let consumed = &input[..input.len() - remainder.len()];
    anyhow::ensure!(
        consumed
            .trim_ascii_end()
            .rsplit(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default()
            == b"-----END CERTIFICATE-----",
        "expected a CERTIFICATE PEM footer"
    );
    Ok((remainder, pem.contents))
}

fn parse_certificate_der<'a>(der: &'a [u8], description: &str) -> Result<X509Certificate<'a>> {
    let (remainder, certificate) = parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("invalid {description} certificate DER: {error}"))?;
    anyhow::ensure!(
        remainder.is_empty(),
        "{description} certificate DER contains trailing data"
    );
    Ok(certificate)
}

fn verify_device_issuer(device: &X509Certificate<'_>, trusted_issuers: &[&[u8]]) -> Result<()> {
    for issuer_der in trusted_issuers {
        let issuer = parse_certificate_der(issuer_der, "trusted issuer")?;
        if device.issuer() == issuer.subject()
            && device.verify_signature(Some(issuer.public_key())).is_ok()
        {
            return Ok(());
        }
    }
    anyhow::bail!("device attestation certificate is not signed by a trusted issuer")
}

fn verify_statement(
    statement: &X509Certificate<'_>,
    device: &X509Certificate<'_>,
    expected_common_name: &str,
) -> Result<()> {
    anyhow::ensure!(
        statement.issuer() == device.subject(),
        "{expected_common_name} was not issued by the device certificate"
    );
    statement
        .verify_signature(Some(device.public_key()))
        .with_context(|| format!("{expected_common_name} signature is invalid"))?;

    let mut common_names = statement.subject().iter_common_name();
    let common_name = common_names
        .next()
        .context("attestation has no subject common name")?
        .as_str()
        .context("attestation subject common name is not a string")?;
    anyhow::ensure!(
        common_names.next().is_none() && common_name == expected_common_name,
        "attestation must have exactly the subject common name {expected_common_name:?}"
    );
    let key_source = statement
        .get_extension_unique(&YUBICO_KEY_SOURCE_OID)
        .context("attestation has duplicate key-source extensions")?
        .context("attestation has no key-source extension")?;
    anyhow::ensure!(
        key_source.value == [0x02, 0x01, 0x01],
        "attested key was not generated on the YubiKey"
    );
    Ok(())
}

fn statement_key<'a>(
    statement: &'a X509Certificate<'_>,
    expected_algorithm: &Oid<'_>,
) -> Result<&'a [u8]> {
    let spki = statement.public_key();
    anyhow::ensure!(
        spki.algorithm.algorithm == *expected_algorithm && spki.algorithm.parameters.is_none(),
        "attestation public key has an unsupported algorithm or parameters"
    );
    let key = &spki.subject_public_key;
    anyhow::ensure!(
        key.unused_bits == 0 && key.data.len() == 32,
        "attestation public key has an unsupported encoding"
    );
    Ok(key.data.as_ref())
}

fn signing_key(cert: &openpgp::Cert) -> Result<(Fingerprint, &[u8])> {
    let mut candidates = cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing();
    let candidate = candidates
        .next()
        .context("OpenPGP certificate has no usable signing key")?;
    anyhow::ensure!(
        candidates.next().is_none(),
        "OpenPGP certificate has multiple usable signing keys"
    );
    match candidate.key().mpis() {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => q
            .decode_point(&Curve::Ed25519)
            .map(|(key, _)| (candidate.key().fingerprint(), key))
            .context("OpenPGP signing key has invalid Ed25519 encoding"),
        _ => anyhow::bail!("OpenPGP signing key does not use legacy Ed25519"),
    }
}

fn encryption_key(cert: &openpgp::Cert) -> Result<(Fingerprint, &[u8])> {
    let mut candidates = cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();
    let candidate = candidates
        .next()
        .context("OpenPGP certificate has no usable encryption key")?;
    anyhow::ensure!(
        candidates.next().is_none(),
        "OpenPGP certificate has multiple usable encryption keys"
    );
    match candidate.key().mpis() {
        mpi::PublicKey::ECDH {
            curve: Curve::Cv25519,
            q,
            ..
        } => q
            .decode_point(&Curve::Cv25519)
            .map(|(key, _)| (candidate.key().fingerprint(), key))
            .context("OpenPGP encryption key has invalid Cv25519 encoding"),
        _ => anyhow::bail!("OpenPGP encryption key does not use legacy Cv25519"),
    }
}

#[cfg(test)]
mod tests;
