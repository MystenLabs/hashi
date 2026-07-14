// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Loading of Sui signing keys for the hashi node.
//!
//! Operators arrive with keys in whatever format their tooling produced:
//! `sui keytool` emits Bech32 `suiprivkey...` strings and legacy Base64
//! keystore entries, while `openssl genpkey` produces PKCS#8 PEM or DER.
//! All of them are accepted, for all three simple Sui signature schemes
//! (Ed25519, secp256k1, and secp256r1).
//!
//! Because a configured value may be inline key material rather than a file
//! path, error messages in this module must never echo the raw value.

use std::path::Path;

use anyhow::Context as _;
use base64ct::Encoding as _;
use sui_crypto::simple::SimpleKeypair;

/// The formats accepted for a Sui private key, referenced in error messages.
const SUPPORTED_FORMATS: &str = "PKCS#8 PEM, PKCS#8 DER, Bech32 `suiprivkey...` (sui keytool), \
     or Base64 keystore (sui.keystore entry)";

/// Load a Sui signing keypair from a file path or an inline value.
///
/// The value is treated as a file path unless it is unambiguously inline key
/// material (a PEM header, a `suiprivkey...` string, or a Base64 keystore
/// entry). File contents may be in any supported format; see the module
/// documentation.
pub fn load_keypair(path_or_key: &str) -> anyhow::Result<SimpleKeypair> {
    let value = path_or_key.trim();
    if value.is_empty() {
        anyhow::bail!(
            "the configured private key is empty; expected a file path or an inline key in one \
             of these formats: {SUPPORTED_FORMATS}"
        );
    }

    // Unambiguous inline values first: a file path cannot start with a PEM
    // header or the `suiprivkey` human-readable part.
    if value.starts_with("-----BEGIN") {
        return SimpleKeypair::from_pem(value)
            .map_err(|e| anyhow::anyhow!("unable to parse the inline PEM private key: {e}"));
    }
    if value.starts_with("suiprivkey") {
        return SimpleKeypair::from_suiprivkey(value).map_err(|e| {
            anyhow::anyhow!("unable to parse the inline `suiprivkey` private key: {e}")
        });
    }

    let path = Path::new(value);
    match std::fs::read(path) {
        Ok(contents) => parse_keypair(&contents)
            .with_context(|| format!("unable to load the private key from '{}'", path.display())),
        Err(read_err) => {
            // Not a readable file. The value may still be an inline Base64
            // keystore entry.
            if let Ok(keypair) = SimpleKeypair::from_base64(value) {
                return Ok(keypair);
            }
            Err(anyhow::anyhow!(
                "unable to load the private key: '{}' is not a readable file ({read_err}) and is \
                 not an inline key in a supported format ({SUPPORTED_FORMATS}); generate a key \
                 with `sui keytool generate ed25519` or `openssl genpkey -algorithm ed25519`",
                redact_secret_like(value),
            ))
        }
    }
}

/// Load a Sui signing keypair from a file path.
pub fn load_keypair_from_path(path: &Path) -> anyhow::Result<SimpleKeypair> {
    let contents = std::fs::read(path)
        .with_context(|| format!("unable to read the private key file '{}'", path.display()))?;
    parse_keypair(&contents)
        .with_context(|| format!("unable to load the private key from '{}'", path.display()))
}

/// Parse a private key from raw file contents in any supported format.
fn parse_keypair(contents: &[u8]) -> anyhow::Result<SimpleKeypair> {
    if let Ok(keypair) = SimpleKeypair::from_der(contents) {
        return Ok(keypair);
    }

    if let Ok(text) = std::str::from_utf8(contents) {
        let text = text.trim();
        if let Ok(keypair) = SimpleKeypair::from_pem(text) {
            return Ok(keypair);
        }
        if let Ok(keypair) = SimpleKeypair::from_suiprivkey(text) {
            return Ok(keypair);
        }
        if let Ok(keypair) = SimpleKeypair::from_base64(text) {
            return Ok(keypair);
        }
    }

    anyhow::bail!("unrecognized private key format; expected {SUPPORTED_FORMATS}")
}

/// Classify a configured private key value the way [`load_keypair`] does,
/// returning the file path it references, or `None` when the value is inline
/// key material (a PEM block, a `suiprivkey...` string, or a Base64 keystore
/// entry) that is already captured by the config itself.
///
/// A value that is neither inline key material nor an existing file is an
/// error; like all errors in this module, it never echoes a value that could
/// be a secret.
pub(crate) fn referenced_key_file(value: &str) -> anyhow::Result<Option<&Path>> {
    let value = value.trim();
    if value.starts_with("-----BEGIN") || value.starts_with("suiprivkey") {
        return Ok(None);
    }

    let path = Path::new(value);
    if path.is_file() {
        return Ok(Some(path));
    }

    if SimpleKeypair::from_base64(value).is_ok() {
        return Ok(None);
    }

    anyhow::bail!(
        "'{}' is neither inline key material nor an existing file",
        redact_secret_like(value)
    )
}

/// Decide whether a failed key value is safe to echo in an error message.
///
/// Paths are useful context and safe; anything that could plausibly be key
/// material (multi-line values, long blobs, or valid Base64) is redacted.
fn redact_secret_like(value: &str) -> &str {
    let looks_like_secret =
        value.contains('\n') || value.len() > 128 || base64ct::Base64::decode_vec(value).is_ok();
    if looks_like_secret {
        "<inline value redacted>"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sui_crypto::SuiSigner as _;
    use sui_crypto::ed25519::Ed25519PrivateKey;
    use sui_crypto::secp256k1::Secp256k1PrivateKey;
    use sui_crypto::secp256r1::Secp256r1PrivateKey;
    use sui_sdk_types::SignatureScheme;

    // The upstream sui-crypto test vector: the same 33-byte payload in both
    // encodings, produced by the Sui CLI from
    // `Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]))`.
    const VECTOR_SUIPRIVKEY: &str =
        "suiprivkey1qzdlfxn2qa2lj5uprl8pyhexs02sg2wrhdy7qaq50cqgnffw4c2477kg9h3";
    const VECTOR_BASE64: &str = "AJv0mmoHVflTgR/OEl8mg9UEKcO7SeB0FH4AiaUurhVf";

    fn ed25519_pem() -> (SimpleKeypair, String) {
        let key = Ed25519PrivateKey::generate(rand::rngs::OsRng);
        let pem = key.to_pem().unwrap();
        (key.into(), pem)
    }

    #[test]
    fn loads_inline_pem() {
        let (key, pem) = ed25519_pem();
        let loaded = load_keypair(&pem).unwrap();
        assert_eq!(
            loaded.verifying_key().derive_address(),
            key.verifying_key().derive_address()
        );
    }

    #[test]
    fn loads_inline_suiprivkey_and_base64() {
        let from_bech32 = load_keypair(VECTOR_SUIPRIVKEY).unwrap();
        let from_base64 = load_keypair(VECTOR_BASE64).unwrap();
        assert_eq!(from_bech32.scheme(), SignatureScheme::Ed25519);
        assert_eq!(
            from_bech32.verifying_key().derive_address(),
            from_base64.verifying_key().derive_address()
        );
    }

    #[test]
    fn loads_all_formats_from_files() {
        let (key, pem) = ed25519_pem();
        let expected = key.verifying_key().derive_address();
        let der = SimpleKeypair::from_pem(&pem).unwrap().to_der().unwrap();
        let suiprivkey = SimpleKeypair::from_pem(&pem)
            .unwrap()
            .to_suiprivkey()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        for (name, contents) in [
            ("key.pem", pem.as_bytes().to_vec()),
            ("key.der", der),
            // Trailing newline mirrors the `<address>.key` files written by
            // `sui keytool generate`.
            ("key.bech32", format!("{suiprivkey}\n").into_bytes()),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, contents).unwrap();

            let via_path_str = load_keypair(path.to_str().unwrap()).unwrap();
            assert_eq!(
                via_path_str.verifying_key().derive_address(),
                expected,
                "{name}"
            );
            let via_path = load_keypair_from_path(&path).unwrap();
            assert_eq!(
                via_path.verifying_key().derive_address(),
                expected,
                "{name}"
            );
        }

        // A base64 keystore entry stored in a file.
        let path = dir.path().join("key.b64");
        std::fs::write(&path, VECTOR_BASE64).unwrap();
        assert_eq!(
            load_keypair_from_path(&path).unwrap().scheme(),
            SignatureScheme::Ed25519
        );
    }

    #[test]
    fn loads_secp_schemes() {
        let secp256k1 = Secp256k1PrivateKey::generate(rand::rngs::OsRng);
        let loaded = load_keypair(&secp256k1.to_suiprivkey().unwrap()).unwrap();
        assert_eq!(loaded.scheme(), SignatureScheme::Secp256k1);

        let secp256r1 = Secp256r1PrivateKey::generate(rand::rngs::OsRng);
        let loaded = load_keypair(&secp256r1.to_suiprivkey().unwrap()).unwrap();
        assert_eq!(loaded.scheme(), SignatureScheme::Secp256r1);
    }

    #[test]
    fn loaded_keypair_signs() {
        // The loaded keypair must be usable as a Sui signer; a self-verify
        // closes the loop.
        use sui_crypto::SuiVerifier as _;

        let keypair = load_keypair(VECTOR_SUIPRIVKEY).unwrap();
        let message = sui_sdk_types::PersonalMessage(b"hashi operator key".as_slice().into());
        let signature = keypair.sign_personal_message(&message).unwrap();
        sui_crypto::simple::SimpleVerifier
            .verify_personal_message(&message, &signature)
            .unwrap();
    }

    #[test]
    fn empty_value_is_a_clear_error() {
        for empty in ["", "   ", "\n"] {
            let err = load_keypair(empty).unwrap_err().to_string();
            assert!(err.contains("empty"), "unexpected error: {err}");
        }
    }

    #[test]
    fn missing_path_error_names_the_path() {
        let err = load_keypair("/nonexistent/operator.pem")
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/operator.pem"), "{err}");
        assert!(err.contains("sui keytool"), "{err}");
    }

    #[test]
    fn errors_never_echo_key_material() {
        let bad_pem = "-----BEGIN PRIVATE KEY-----\nnot-actually-valid\n-----END PRIVATE KEY-----";
        let truncated_suiprivkey = &VECTOR_SUIPRIVKEY[..40];
        // Base64 of a raw 32-byte key without the scheme flag: a plausible
        // operator mistake, and definitely key material.
        let flagless_base64 = base64ct::Base64::encode_string(&[0x42; 32]);
        let long_blob = "A".repeat(200);

        for secret in [
            bad_pem,
            truncated_suiprivkey,
            flagless_base64.as_str(),
            long_blob.as_str(),
        ] {
            let err = load_keypair(secret).unwrap_err();
            let message = format!("{err:#}");
            for line in secret.lines() {
                assert!(
                    !message.contains(line),
                    "error echoed key material: {message}"
                );
            }
        }
    }

    #[test]
    fn unparseable_file_error_names_path_and_formats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.key");
        std::fs::write(&path, b"garbage").unwrap();

        let err = format!("{:#}", load_keypair_from_path(&path).unwrap_err());
        assert!(err.contains("garbage.key"), "{err}");
        assert!(err.contains("PKCS#8 PEM"), "{err}");
    }

    #[test]
    fn rejects_wrong_scheme_flags_and_truncated_payloads() {
        // Flag byte 0x05 (zklogin) is not a simple scheme.
        let bad_flag = base64ct::Base64::encode_string(
            &std::iter::once(0x05).chain([0x42; 32]).collect::<Vec<_>>(),
        );
        load_keypair(&bad_flag).unwrap_err();

        // Truncated key bytes.
        let truncated = base64ct::Base64::encode_string(&[0x00, 0x42, 0x42]);
        load_keypair(&truncated).unwrap_err();
    }

    #[test]
    fn referenced_key_file_classifies_like_the_loader() {
        let (_, pem) = ed25519_pem();

        // Inline key material in every accepted format references no file.
        for inline in [pem.as_str(), VECTOR_SUIPRIVKEY, VECTOR_BASE64] {
            assert_eq!(referenced_key_file(inline).unwrap(), None);
        }

        // An existing file is returned as a path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.pem");
        std::fs::write(&path, &pem).unwrap();
        let value = path.to_str().unwrap();
        assert_eq!(referenced_key_file(value).unwrap(), Some(path.as_path()));

        // A missing path is an error naming the path.
        let err = referenced_key_file("/nonexistent/operator.pem")
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/operator.pem"), "{err}");

        // A secret-shaped value that is neither loadable nor a file is an
        // error that never echoes the value.
        let secret = base64ct::Base64::encode_string(&[0x42; 48]);
        let err = referenced_key_file(&secret).unwrap_err().to_string();
        assert!(!err.contains(&secret), "error echoed key material: {err}");
    }
}
